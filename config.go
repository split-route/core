// Package core is the engine of the Split Route apps: it runs sing-box
// in-process and routes traffic through tunnels by lists. It stores nothing
// and has no UI; apps own their storage and hand the engine a Config.
//
// The engine's behavior is in three layers: Config (this file) is what an app
// provides and is validated before anything starts; Build turns it into a
// sing-box config; Engine runs it and reports state.
//
// Build tags: sing-box registers its protocols by build tag. An app must build
// with RequiredTags (more tags add more protocols); Start explains a missing one.
package core

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/split-route/core/rules"
)

// RequiredTags are the sing-box build tags an app must pass to `go build` (or
// gomobile) for the protocols the engine supports.
const RequiredTags = "with_gvisor,with_quic,with_utls,with_wireguard,with_openvpn"

// Config is everything the engine needs to run. Apps build it from their own
// storage; the engine never writes to it.
type Config struct {
	Tunnels []Tunnel `json:"tunnels"`
	Lists   []List   `json:"lists"`
	// Default is the tunnel's ID that carries unmatched traffic and lists that
	// name no tunnel. Empty: the first tunnel.
	Default string  `json:"default,omitempty"`
	DNS     DNS     `json:"dns,omitempty"`
	Inbound Inbound `json:"inbound,omitempty"`
	// WorkDir is a directory the engine may write to (rule-set files, cache).
	// It must be absolute and private to the app.
	WorkDir string `json:"work_dir"`
	Log     Log    `json:"log,omitempty"`
}

// Tunnel is one way out: a protocol and its options. Options are what an
// importer returned (importers/...), credentials included, by value.
type Tunnel struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Protocol string          `json:"protocol"`
	Options  json.RawMessage `json:"options"`
}

// List says where the traffic that matches a list goes. Its entries live in
// rule-set files (package ruleset): the engine's config does not depend on
// them, so editing a list never restarts the engine.
type List struct {
	ID     string       `json:"id"`
	Name   string       `json:"name"`
	Action rules.Action `json:"action"`
	// Tunnel is the tunnel's ID for the tunnel action; empty means the default.
	Tunnel string `json:"tunnel,omitempty"`
}

// DNS is how names are resolved. Names in direct lists resolve on the physical
// network; every other name resolves through the tunnel that carries it.
type DNS struct {
	// Remote is the resolver reached through a tunnel. Default 1.1.1.1.
	Remote string `json:"remote,omitempty"`
}

// Inbound is how traffic enters the engine.
type Inbound struct {
	// Mode is "tun" (default: a virtual interface takes the system's traffic;
	// needs privileges or, on mobile, the platform's VPN service) or "proxy" (a
	// local SOCKS/HTTP proxy, for testing and for apps that want one).
	Mode string `json:"mode,omitempty"`
	// Proxy mode: loopback address and port to listen on, optional credentials.
	Listen string `json:"listen,omitempty"`
	Port   int    `json:"port,omitempty"`
	User   string `json:"user,omitempty"`
	Pass   string `json:"pass,omitempty"`
}

// Log is the engine's log level: trace, debug, info (default), warn, error.
type Log struct {
	Level string `json:"level,omitempty"`
}

var (
	validID    = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)
	logLevels  = map[string]bool{"": true, "trace": true, "debug": true, "info": true, "warn": true, "error": true}
	maxName    = 64
	maxTunnels = 64
	maxLists   = 1024
)

// ValidID reports whether s is usable as a tunnel or list ID: it becomes part
// of file names and sing-box tags, so it is lowercase letters, digits, "-" and "_".
func ValidID(s string) bool { return validID.MatchString(s) }

// Validate checks everything an app hands the engine; Build and Start call it.
func (c Config) Validate() error {
	if !filepath.IsAbs(c.WorkDir) {
		return fmt.Errorf("work_dir %q must be an absolute path", c.WorkDir)
	}
	if len(c.Tunnels) == 0 {
		return fmt.Errorf("at least one tunnel is required")
	}
	if len(c.Tunnels) > maxTunnels || len(c.Lists) > maxLists {
		return fmt.Errorf("at most %d tunnels and %d lists", maxTunnels, maxLists)
	}
	tunnels := map[string]bool{}
	for _, t := range c.Tunnels {
		if err := t.validate(); err != nil {
			return fmt.Errorf("tunnel %q: %w", t.ID, err)
		}
		if tunnels[t.ID] {
			return fmt.Errorf("tunnel %q listed twice", t.ID)
		}
		tunnels[t.ID] = true
	}
	if c.Default != "" && !tunnels[c.Default] {
		return fmt.Errorf("default tunnel %q does not exist", c.Default)
	}
	lists := map[string]bool{}
	for _, l := range c.Lists {
		switch {
		case !ValidID(l.ID):
			return fmt.Errorf("list id %q: use lowercase letters, digits, - and _ (1-32 characters)", l.ID)
		case lists[l.ID]:
			return fmt.Errorf("list %q listed twice", l.ID)
		case len(l.Name) > maxName:
			return fmt.Errorf("list %q: name longer than %d characters", l.ID, maxName)
		case !l.Action.Valid():
			return fmt.Errorf("list %q: action must be direct, block or tunnel, not %q", l.ID, l.Action)
		case l.Tunnel != "" && l.Action != rules.Tunnel:
			return fmt.Errorf("list %q: only a tunnel list can name a tunnel", l.ID)
		case l.Tunnel != "" && !tunnels[l.Tunnel]:
			return fmt.Errorf("list %q: tunnel %q does not exist", l.ID, l.Tunnel)
		}
		lists[l.ID] = true
	}
	if c.DNS.Remote != "" {
		if _, err := netip.ParseAddr(c.DNS.Remote); err != nil {
			return fmt.Errorf("dns remote %q: %w", c.DNS.Remote, err)
		}
	}
	if !logLevels[c.Log.Level] {
		return fmt.Errorf("log level %q is not one of trace, debug, info, warn, error", c.Log.Level)
	}
	return c.Inbound.validate()
}

func (i Inbound) validate() error {
	switch i.Mode {
	case "", "tun":
		return nil
	case "proxy":
		ip := net.ParseIP(i.Listen)
		if ip == nil || !ip.IsLoopback() {
			return fmt.Errorf("proxy listen %q must be a loopback address", i.Listen)
		}
		if i.Port < 1 || i.Port > 65535 {
			return fmt.Errorf("proxy port %d is out of range", i.Port)
		}
		if (i.User == "") != (i.Pass == "") {
			return fmt.Errorf("proxy user and pass go together")
		}
		return nil
	}
	return fmt.Errorf("inbound mode %q is not tun or proxy", i.Mode)
}

// protocol is what the engine knows about a tunnel protocol: the sing-box type
// of its options and whether sing-box models it as an endpoint (it has its own
// tun-like session) or an outbound.
type protocol struct {
	typ      string
	endpoint bool
}

var protocols = map[string]protocol{
	"openvpn": {typ: "openvpn-client", endpoint: true},
}

// Protocols lists the protocol names the engine accepts.
func Protocols() []string {
	out := make([]string, 0, len(protocols))
	for n := range protocols {
		out = append(out, n)
	}
	return out
}

func (t Tunnel) validate() error {
	if !ValidID(t.ID) {
		return fmt.Errorf("id: use lowercase letters, digits, - and _ (1-32 characters)")
	}
	if t.Name == "" || len(t.Name) > maxName {
		return fmt.Errorf("name: 1 to %d characters", maxName)
	}
	p, ok := protocols[t.Protocol]
	if !ok {
		return fmt.Errorf("protocol %q is not supported", t.Protocol)
	}
	_, err := t.options(p)
	return err
}

// deniedKeys can reach the disk or steer the engine's own traffic out of its
// routing; they never come from a tunnel's options. Keys ending in _path read
// files. The engine sets tag, system and domain_resolver itself.
var deniedKeys = map[string]bool{
	"detour": true, "bind_interface": true, "inet4_bind_address": true, "inet6_bind_address": true,
	"routing_mark": true, "protect_path": true, "netns": true, "domain_resolver": true,
	"network_strategy": true, "network_type": true, "fallback_network_type": true, "fallback_delay": true,
}

// options checks the tunnel's options and returns them as an object. Options
// come from links and files and run in a privileged process: whatever could
// read a file or change where the engine's own traffic goes is refused, at any depth.
func (t Tunnel) options(p protocol) (map[string]any, error) {
	var o map[string]any
	if err := json.Unmarshal(t.Options, &o); err != nil || o == nil {
		return nil, fmt.Errorf("options must be a JSON object")
	}
	if o["type"] != p.typ {
		return nil, fmt.Errorf("options type %v does not match protocol %s (%s)", o["type"], t.Protocol, p.typ)
	}
	if bad := deniedKey(o); bad != "" {
		return nil, fmt.Errorf("option %q is not allowed", bad)
	}
	return o, nil
}

func deniedKey(v any) string {
	switch x := v.(type) {
	case map[string]any:
		for k, child := range x {
			if deniedKeys[k] || strings.HasSuffix(k, "_path") {
				return k
			}
			if bad := deniedKey(child); bad != "" {
				return bad
			}
		}
	case []any:
		for _, child := range x {
			if bad := deniedKey(child); bad != "" {
				return bad
			}
		}
	}
	return ""
}
