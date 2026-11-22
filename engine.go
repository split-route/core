package core

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"sync"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"

	"github.com/split-route/core/ruleset"
)

// State is a tunnel's state.
type State string

const (
	StateStopped    State = "stopped"
	StateConnecting State = "connecting"
	StateConnected  State = "connected"
	StateNeedsAuth  State = "needs_auth" // a challenge is waiting for AnswerChallenge
	StateFailed     State = "failed"     // stopped for the reason in Error; Reload or Stop and Start to retry
	StateReady      State = "ready"      // protocols with no session of their own: usable once the engine runs
)

// TunnelInfo is what a connected tunnel reports about itself.
type TunnelInfo struct {
	Server  string    `json:"server,omitempty"`
	Network string    `json:"network,omitempty"`
	Cipher  string    `json:"cipher,omitempty"`
	IPv4    []string  `json:"ipv4,omitempty"`
	IPv6    []string  `json:"ipv6,omitempty"`
	DNS     []string  `json:"dns,omitempty"`
	MTU     int       `json:"mtu,omitempty"`
	Since   time.Time `json:"since,omitzero"`
}

// Challenge is a question a tunnel asks the user: credentials, a one-time
// code, or a message to show.
type Challenge struct {
	ID            string    `json:"id"`
	Kind          string    `json:"kind"`
	Username      string    `json:"username,omitempty"`
	Message       string    `json:"message,omitempty"`
	URL           string    `json:"url,omitempty"`
	SecretMessage string    `json:"secret_message,omitempty"`
	Echo          bool      `json:"echo,omitempty"`
	PreviousError string    `json:"previous_error,omitempty"`
	Deadline      time.Time `json:"deadline,omitzero"`
}

// ChallengeResponse answers a Challenge.
type ChallengeResponse struct {
	Username string
	Password string
	Secret   string
}

// TunnelStatus is one tunnel's state.
type TunnelStatus struct {
	ID        string      `json:"id"`
	State     State       `json:"state"`
	Error     string      `json:"error,omitempty"`
	Info      *TunnelInfo `json:"info,omitempty"`
	Challenge *Challenge  `json:"challenge,omitempty"`
}

// Status is the engine's state; it is the truth, events only say it changed.
type Status struct {
	Running bool `json:"running"`
	// Default is the ID of the tunnel that carries traffic no list names.
	Default string         `json:"default"`
	Tunnels []TunnelStatus `json:"tunnels"`
}

// EventKind says what an Event carries.
type EventKind string

const (
	EventTunnel EventKind = "tunnel" // a tunnel's state changed
	EventLog    EventKind = "log"    // a log line
)

// Event is something the engine tells the app. Delivery is best effort: a slow
// consumer loses events (Status is always right).
type Event struct {
	Time    time.Time     `json:"time"`
	Kind    EventKind     `json:"kind"`
	Tunnel  *TunnelStatus `json:"tunnel,omitempty"`
	Level   string        `json:"level,omitempty"`
	Message string        `json:"message,omitempty"`
}

const eventBuffer = 256

// Engine runs one sing-box instance for a Config. Methods are safe for
// concurrent use.
//
// Two locks. life serializes the lifecycle: Start, Stop, Reload and Close each
// hold it from start to finish, so two callers can never run two instances (two
// tun devices). mu guards what apps read while that happens (status, the tunnels'
// endpoints) and is never held across a wait.
type Engine struct {
	life   sync.Mutex
	cfg    Config
	built  []byte // the sing-box config the running instance was built from
	inst   *box.Box
	cancel context.CancelFunc
	wg     sync.WaitGroup // the watchers

	mu      sync.Mutex
	running bool
	def     string   // the selected (default) tunnel's ID
	ids     []string // tunnel IDs in config order
	status  map[string]*TunnelStatus
	vpn     map[string]adapter.OpenVPNEndpoint

	evMu   sync.RWMutex
	events chan Event
	closed bool
}

// defaultID is the tunnel that carries traffic no list names: Config.Default, or the first tunnel.
func defaultID(c Config) string {
	if c.Default != "" {
		return c.Default
	}
	return c.Tunnels[0].ID
}

func tunnelIDs(c Config) []string {
	ids := make([]string, 0, len(c.Tunnels))
	for _, t := range c.Tunnels {
		ids = append(ids, t.ID)
	}
	return ids
}

// New validates cfg and returns an engine that has started nothing.
func New(cfg Config) (*Engine, error) {
	if _, err := Build(cfg); err != nil {
		return nil, err
	}
	return &Engine{cfg: cfg, ids: tunnelIDs(cfg), def: defaultID(cfg), events: make(chan Event, eventBuffer), status: map[string]*TunnelStatus{}}, nil
}

// Events delivers state changes and log lines until Close.
func (e *Engine) Events() <-chan Event { return e.events }

// emit never blocks and never sends on a closed channel.
func (e *Engine) emit(ev Event) {
	ev.Time = time.Now()
	e.evMu.RLock()
	defer e.evMu.RUnlock()
	if e.closed {
		return
	}
	select {
	case e.events <- ev:
	default:
	}
}

// logWriter hands sing-box's log lines to the events channel.
type logWriter struct{ e *Engine }

func (w logWriter) WriteMessage(level log.Level, message string) {
	w.e.emit(Event{Kind: EventLog, Level: log.FormatLevel(level), Message: message})
}

// Start builds the sing-box config, starts the instance and begins watching
// the tunnels. The rule-set files of lists that have none yet are created
// empty, so an app can start before it has downloaded anything.
func (e *Engine) Start() error {
	e.life.Lock()
	defer e.life.Unlock()
	return e.start()
}

func (e *Engine) start() error {
	if e.inst != nil {
		return errors.New("the engine is already running")
	}
	built, err := Build(e.cfg)
	if err != nil {
		return err
	}
	dir := ruleset.Dir(e.cfg.WorkDir)
	if err := os.MkdirAll(e.cfg.WorkDir, 0o700); err != nil {
		return err
	}
	// The cache file would restore the selector's last choice over the one the app
	// made. Nothing else in it is needed, so start without it.
	if err := os.Remove(cachePath(e.cfg.WorkDir)); err != nil && !os.IsNotExist(err) {
		return err
	}
	ids := make([]string, 0, len(e.cfg.Lists))
	for _, l := range e.cfg.Lists {
		ids = append(ids, l.ID)
		if err := ruleset.Ensure(dir, l.ID, l.Action); err != nil {
			return fmt.Errorf("list %s: %w", l.ID, err)
		}
	}
	if err := ruleset.Prune(dir, ids); err != nil {
		return err
	}

	ctx := include.Context(context.Background())
	var opts option.Options
	if err := json.UnmarshalContext(ctx, built, &opts); err != nil {
		if strings.Contains(err.Error(), "unknown") {
			return fmt.Errorf("%w (is the app built with the sing-box tags %s?)", err, RequiredTags)
		}
		return fmt.Errorf("sing-box config: %w", err)
	}
	inst, err := box.New(box.Options{Context: ctx, Options: opts, PlatformLogWriter: logWriter{e}})
	if err != nil {
		return fmt.Errorf("sing-box: %w", err)
	}
	if err := inst.Start(); err != nil {
		inst.Close()
		return fmt.Errorf("sing-box: %w", err)
	}
	// sing-box chooses the selector's first member until told otherwise: say which one.
	if err := selectDefault(inst, defaultID(e.cfg)); err != nil {
		inst.Close()
		return err
	}
	wctx, cancel := context.WithCancel(context.Background())
	e.inst, e.cancel, e.built = inst, cancel, built

	status := map[string]*TunnelStatus{}
	vpn := map[string]adapter.OpenVPNEndpoint{}
	for _, t := range e.cfg.Tunnels {
		st := &TunnelStatus{ID: t.ID, State: StateReady}
		status[t.ID] = st
		if !protocols[t.Protocol].endpoint {
			continue
		}
		if ep, ok := inst.Endpoint().Get(tunnelTag(t.ID)); ok {
			if v, ok := ep.(adapter.OpenVPNEndpoint); ok {
				vpn[t.ID] = v
				st.State = StateConnecting
			}
		}
	}
	e.mu.Lock()
	e.running, e.ids, e.status, e.vpn, e.def = true, tunnelIDs(e.cfg), status, vpn, defaultID(e.cfg)
	e.mu.Unlock()
	for id, v := range vpn {
		e.wg.Add(1)
		go e.watch(wctx, id, v)
	}
	return nil
}

// selectDefault points the selector at tunnel id. Connections already open
// through another member are closed (interrupt_exist_connections).
func selectDefault(inst *box.Box, id string) error {
	ob, ok := inst.Outbound().Outbound(selectorTag)
	if !ok {
		return errors.New("sing-box has no selector outbound")
	}
	sel, ok := ob.(interface{ SelectOutbound(string) bool })
	if !ok {
		return errors.New("the selector outbound can't be switched")
	}
	if !sel.SelectOutbound(tunnelTag(id)) {
		return fmt.Errorf("tunnel %q is not in the selector", id)
	}
	return nil
}

// watch turns an OpenVPN endpoint's status into the tunnel's state until ctx ends.
func (e *Engine) watch(ctx context.Context, id string, ep adapter.OpenVPNEndpoint) {
	defer e.wg.Done()
	for {
		updated := ep.StatusUpdated() // before the read, so no update is missed
		e.setStatus(id, convertOpenVPN(id, ep.OpenVPNStatus()))
		select {
		case <-ctx.Done():
			return
		case <-updated:
		}
	}
}

func (e *Engine) setStatus(id string, st TunnelStatus) {
	e.mu.Lock()
	old := e.status[id]
	if old == nil || !e.running { // stopped meanwhile
		e.mu.Unlock()
		return
	}
	if reflect.DeepEqual(*old, st) {
		e.mu.Unlock()
		return
	}
	*old = st
	cp := st
	e.mu.Unlock()
	e.emit(Event{Kind: EventTunnel, Tunnel: &cp})
}

func convertOpenVPN(id string, s adapter.OpenVPNStatus) TunnelStatus {
	st := TunnelStatus{ID: id, Error: s.Error}
	switch s.State {
	case adapter.OpenVPNStateConnected:
		st.State = StateConnected
	case adapter.OpenVPNStateAuthPending:
		st.State = StateNeedsAuth
	case adapter.OpenVPNStateError:
		st.State = StateFailed
	default:
		st.State = StateConnecting
	}
	if ti := s.TunnelInfo; ti != nil {
		info := &TunnelInfo{Server: ti.Server, Network: ti.Network, Cipher: ti.Cipher, MTU: int(ti.MTU), Since: ti.ConnectedSince}
		for _, p := range ti.IPv4 {
			info.IPv4 = append(info.IPv4, p.String())
		}
		for _, p := range ti.IPv6 {
			info.IPv6 = append(info.IPv6, p.String())
		}
		for _, a := range ti.DNS {
			info.DNS = append(info.DNS, a.String())
		}
		st.Info = info
	}
	if c := s.Challenge; c != nil {
		st.Challenge = &Challenge{ID: c.ID, Kind: c.Kind, Username: c.Username, Message: c.Message, URL: c.URL,
			SecretMessage: c.SecretMessage, Echo: c.Echo, PreviousError: c.PreviousError, Deadline: c.Deadline}
	}
	return st
}

// Stop stops the instance; the engine can be started again.
func (e *Engine) Stop() error {
	e.life.Lock()
	defer e.life.Unlock()
	return e.stop()
}

func (e *Engine) stop() error {
	if e.inst == nil {
		return nil
	}
	e.mu.Lock()
	e.running = false // the watchers stop reporting
	e.mu.Unlock()
	e.cancel()
	e.wg.Wait()
	err := e.inst.Close()
	e.inst, e.cancel = nil, nil
	e.mu.Lock()
	e.vpn = nil
	var stopped []TunnelStatus
	for _, id := range e.ids {
		if st := e.status[id]; st != nil {
			st.State, st.Error, st.Info, st.Challenge = StateStopped, "", nil, nil
			stopped = append(stopped, *st)
		}
	}
	e.mu.Unlock()
	for i := range stopped {
		e.emit(Event{Kind: EventTunnel, Tunnel: &stopped[i]})
	}
	return err
}

// Close stops the engine and closes the events channel; it can't be used after.
func (e *Engine) Close() error {
	e.life.Lock()
	defer e.life.Unlock()
	err := e.stop()
	e.evMu.Lock()
	if !e.closed {
		e.closed = true
		close(e.events)
	}
	e.evMu.Unlock()
	return err
}

// Reload applies a new config. When the sing-box config it builds is the same
// as the running one (an edit to names, or to a list's entries, which are in
// rule-set files) nothing restarts; otherwise a running engine stops and starts
// again, which reconnects every tunnel. It reports whether it restarted. A
// config that fails validation changes nothing.
func (e *Engine) Reload(cfg Config) (restarted bool, err error) {
	built, err := Build(cfg)
	if err != nil {
		return false, err
	}
	e.life.Lock()
	defer e.life.Unlock()
	same := e.inst != nil && string(built) == string(e.built)
	e.cfg = cfg
	e.mu.Lock()
	e.ids = tunnelIDs(cfg)
	e.def = defaultID(cfg)
	e.mu.Unlock()
	if e.inst == nil {
		return false, nil // stopped: takes effect at Start
	}
	if same {
		// Build doesn't depend on the default tunnel, so a change of it lands
		// here: switch the selector, no restart, no reconnect.
		return false, selectDefault(e.inst, defaultID(cfg))
	}
	if err := e.stop(); err != nil {
		return false, err
	}
	return true, e.start()
}

// Select makes tunnel id the one that carries traffic no list names. A running
// engine switches at once without restarting; connections open through the
// previous tunnel are closed. A stopped engine uses it from Start.
func (e *Engine) Select(id string) error {
	e.life.Lock()
	defer e.life.Unlock()
	found := false
	for _, t := range e.cfg.Tunnels {
		found = found || t.ID == id
	}
	if !found {
		return fmt.Errorf("tunnel %q is not in the engine's config", id)
	}
	if e.inst != nil {
		if err := selectDefault(e.inst, id); err != nil {
			return err
		}
	}
	e.cfg.Default = id
	e.mu.Lock()
	e.def = id
	e.mu.Unlock()
	return nil
}

// Status returns the engine's state; tunnels are in config order.
func (e *Engine) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	s := Status{Running: e.running, Default: e.def, Tunnels: make([]TunnelStatus, 0, len(e.ids))}
	for _, id := range e.ids {
		if st := e.status[id]; st != nil {
			s.Tunnels = append(s.Tunnels, *st)
		} else {
			s.Tunnels = append(s.Tunnels, TunnelStatus{ID: id, State: StateStopped})
		}
	}
	return s
}

// AnswerChallenge answers the challenge a tunnel is waiting on.
func (e *Engine) AnswerChallenge(tunnelID string, r ChallengeResponse) error {
	e.mu.Lock()
	ep, st := e.vpn[tunnelID], e.status[tunnelID]
	var id string
	if st != nil && st.Challenge != nil {
		id = st.Challenge.ID
	}
	e.mu.Unlock()
	if ep == nil || id == "" {
		return fmt.Errorf("tunnel %q has no pending challenge", tunnelID)
	}
	return ep.CompleteChallenge(id, adapter.OpenVPNChallengeResponse{Username: r.Username, Password: r.Password, Secret: r.Secret})
}

// CancelChallenge gives up on the pending challenge, which stops the tunnel's client.
func (e *Engine) CancelChallenge(tunnelID string) error {
	e.mu.Lock()
	ep, st := e.vpn[tunnelID], e.status[tunnelID]
	var id string
	if st != nil && st.Challenge != nil {
		id = st.Challenge.ID
	}
	e.mu.Unlock()
	if ep == nil || id == "" {
		return fmt.Errorf("tunnel %q has no pending challenge", tunnelID)
	}
	return ep.CancelChallenge(id)
}
