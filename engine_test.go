//go:build with_openvpn

package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"os/exec"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/split-route/core/importers/openvpn"
	"github.com/split-route/core/rules"
	"github.com/split-route/core/ruleset"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func shortDir(t *testing.T) string {
	t.Helper()
	d, err := os.MkdirTemp("", "sr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

// pkiProfile is an .ovpn for a server that isn't there (127.0.0.1:1) with a
// real, throwaway certificate: sing-box checks the TLS material when it starts,
// so the dummy bodies other tests use would be refused.
func pkiProfile(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(key)
	cert := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return "client\ndev tun\nproto udp\nremote 127.0.0.1 1\nremote-cert-tls server\n<ca>\n" + cert + "</ca>\n<cert>\n" + cert +
		"</cert>\n<key>\n" + string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})) + "</key>\n"
}

func pkiTunnel(t *testing.T, id string) Tunnel {
	t.Helper()
	p, err := openvpn.Parse([]byte(pkiProfile(t)))
	if err != nil {
		t.Fatal(err)
	}
	ep, err := openvpn.Endpoint(p, "x", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(ep)
	return Tunnel{ID: id, Name: id, Protocol: "openvpn", Options: b}
}

// needInternet skips a test that routes a real site through the engine when
// the machine can't reach it.
func needInternet(t *testing.T) {
	t.Helper()
	if o, _ := exec.Command("curl", "-s", "-o", "/dev/null", "-m", "5", "-w", "%{http_code}", "https://example.com/").Output(); string(o) != "200" {
		t.Skip("no internet (example.com unreachable)")
	}
}

func waitState(t *testing.T, e *Engine, id string, want State) TunnelStatus {
	t.Helper()
	var last TunnelStatus
	for deadline := time.Now().Add(15 * time.Second); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		for _, s := range e.Status().Tunnels {
			if s.ID == id {
				last = s
				if s.State == want {
					return s
				}
			}
		}
	}
	t.Fatalf("tunnel %s never reached %s; last %+v", id, want, last)
	return last
}

// An engine whose tunnel has nowhere to connect still starts, reports the
// tunnel as connecting, stops cleanly, and can start again.
func TestEngineLifecycleWithoutAServer(t *testing.T) {
	cfg := baseConfig(t)
	cfg.WorkDir = shortDir(t)
	cfg.Inbound.Port = freePort(t)
	cfg.Tunnels = []Tunnel{pkiTunnel(t, "office")}
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if e.Status().Running {
		t.Error("running before Start")
	}
	for i := 0; i < 2; i++ {
		if err := e.Start(); err != nil {
			t.Fatalf("start %d: %v", i, err)
		}
		if err := e.Start(); err == nil {
			t.Error("a second Start was accepted")
		}
		st := waitState(t, e, "office", StateConnecting)
		if !e.Status().Running || st.Info != nil {
			t.Errorf("status = %+v", e.Status())
		}
		if err := e.Stop(); err != nil {
			t.Fatal(err)
		}
		if s := e.Status(); s.Running || s.Tunnels[0].State != StateStopped {
			t.Errorf("after stop: %+v", s)
		}
	}
	// Reload while stopped takes effect at the next Start and restarts nothing.
	if restarted, err := e.Reload(cfg); err != nil || restarted {
		t.Errorf("reload while stopped: %v %v", restarted, err)
	}
	if _, err := e.Reload(Config{}); err == nil {
		t.Error("an invalid config was accepted by Reload")
	}
	// Without a challenge there is nothing to answer.
	if err := e.AnswerChallenge("office", ChallengeResponse{}); err == nil {
		t.Error("answered a challenge that doesn't exist")
	}
	// The rule-set files of the lists exist after Start even though no app wrote them.
	cfg.Lists = []List{{ID: "ads", Name: "Ads", Action: rules.Block}, {ID: "work", Name: "Work", Action: rules.Tunnel}}
	if _, err := e.Reload(cfg); err != nil {
		t.Fatal(err)
	}
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	for _, f := range []string{ruleset.Path(ruleset.Dir(cfg.WorkDir), "ads"), ruleset.DNSPath(ruleset.Dir(cfg.WorkDir), "work")} {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("rule-set file: %v", err)
		}
	}
}

// Opt in with SPLITROUTE_TEST_PROFILE=/path/to/client.ovpn (certificate-only,
// its server running). Runs the whole engine in-process in proxy mode (a tun
// needs privileges) and checks: the tunnel connects, each list goes where it
// says, a list's entries update with no restart, and a structural change restarts.
func TestEngineLive(t *testing.T) {
	prof := os.Getenv("SPLITROUTE_TEST_PROFILE")
	if prof == "" {
		t.Skip("SPLITROUTE_TEST_PROFILE not set")
	}
	needInternet(t)
	text, err := os.ReadFile(prof)
	if err != nil {
		t.Fatal(err)
	}
	p, err := openvpn.Parse(text)
	if err != nil {
		t.Fatal(err)
	}
	ep, err := openvpn.Endpoint(p, "x", "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	opts, _ := json.Marshal(ep)
	port := freePort(t)
	cfg := Config{
		Tunnels: []Tunnel{{ID: "lab", Name: "Lab", Protocol: "openvpn", Options: opts}},
		Lists: []List{
			{ID: "direct", Name: "Direct", Action: rules.Direct},
			{ID: "ads", Name: "Ads", Action: rules.Block},
		},
		WorkDir: shortDir(t),
		Inbound: Inbound{Mode: "proxy", Listen: "127.0.0.1", Port: port},
		Log:     Log{Level: "debug"},
	}
	dir := ruleset.Dir(cfg.WorkDir)
	write := func(id string, a rules.Action, es rules.Entries) {
		t.Helper()
		if _, err := ruleset.Write(dir, id, a, es); err != nil {
			t.Fatal(err)
		}
	}
	write("direct", rules.Direct, rules.Entries{Suffixes: []string{"example.com"}})
	write("ads", rules.Block, rules.Entries{Suffixes: []string{"blocked.example.net"}})

	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	st := waitState(t, e, "lab", StateConnected)
	if st.Info == nil || len(st.Info.IPv4) == 0 || st.Info.Server == "" {
		t.Errorf("a connected tunnel reports no addresses: %+v", st.Info)
	}
	// The events channel carried the change.
	var sawConnected bool
drain:
	for {
		select {
		case ev := <-e.Events():
			if ev.Kind == EventTunnel && ev.Tunnel.State == StateConnected {
				sawConnected = true
			}
		default:
			break drain
		}
	}
	if !sawConnected {
		t.Error("no event for the tunnel connecting")
	}
	curl := func(host string) string {
		o, _ := exec.Command("curl", "-s", "-o", "/dev/null", "-m", "3", "-w", "%{http_code}", "-x", "socks5h://127.0.0.1:"+itoa(port), "https://"+host+"/").Output()
		return string(o)
	}
	if got := curl("example.com"); got != "200" {
		t.Errorf("a direct-list domain returned %q, want 200", got)
	}
	if got := curl("blocked.example.net"); got != "000" {
		t.Errorf("a block-list domain returned %q, want a refused connection", got)
	}
	// example.net isn't in a list: it goes to the tunnel, whose server has no way out.
	if got := curl("example.net"); got != "000" {
		t.Errorf("an unlisted domain returned %q before the list changed", got)
	}

	// A list's entries change: written in place, picked up, no restart.
	write("direct", rules.Direct, rules.Entries{Suffixes: []string{"example.com", "example.net"}})
	// sing-box waits 100 ms after a write before it reloads; a check before that
	// would go to the tunnel, whose server drops everything, and hang on its DNS.
	time.Sleep(500 * time.Millisecond)
	var got string
	for deadline := time.Now().Add(6 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		if got = curl("example.net"); got == "200" {
			break
		}
	}
	if got != "200" {
		t.Errorf("the rewritten rule set wasn't picked up (example.net returned %q)", got)
		for len(e.events) > 0 {
			if ev := <-e.events; ev.Kind == EventLog {
				t.Log(ev.Level, ev.Message)
			}
		}
	}
	renamed := cfg
	renamed.Lists = append([]List(nil), cfg.Lists...)
	renamed.Lists[0].Name = "Renamed"
	if restarted, err := e.Reload(renamed); err != nil || restarted {
		t.Errorf("a name change restarted the engine: %v %v", restarted, err)
	}

	// A list changes where it goes: the config changes, so the engine restarts and reconnects.
	moved := cfg
	moved.Lists = append([]List(nil), cfg.Lists...)
	moved.Lists[1].Action = rules.Direct
	restarted, err := e.Reload(moved)
	if err != nil || !restarted {
		t.Fatalf("a changed action: restarted %v, err %v", restarted, err)
	}
	waitState(t, e, "lab", StateConnected)

	if err := e.Stop(); err != nil {
		t.Fatal(err)
	}
	if s := e.Status(); s.Running || s.Tunnels[0].State != StateStopped {
		t.Errorf("after stop: %+v", s)
	}
}

func itoa(n int) string { return strconv.Itoa(n) }

// A list's rule-set is picked up when an app rewrites it in place, with no
// restart. Needs the internet for example.net (a direct list entry) and no
// tunnel server: the tunnel is the unreachable default, so a domain not in a list fails.
func TestEngineReloadsRuleSetsInPlace(t *testing.T) {
	needInternet(t)
	port := freePort(t)
	cfg := Config{
		Tunnels: []Tunnel{pkiTunnel(t, "lab")},
		Lists:   []List{{ID: "direct", Name: "Direct", Action: rules.Direct}},
		WorkDir: shortDir(t),
		Inbound: Inbound{Mode: "proxy", Listen: "127.0.0.1", Port: port},
		Log:     Log{Level: "debug"},
	}
	dir := ruleset.Dir(cfg.WorkDir)
	if _, err := ruleset.Write(dir, "direct", rules.Direct, rules.Entries{Suffixes: []string{"example.com"}}); err != nil {
		t.Fatal(err)
	}
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	curl := func(host string) string {
		o, _ := exec.Command("curl", "-s", "-o", "/dev/null", "-m", "6", "-w", "%{http_code}", "-x", "socks5h://127.0.0.1:"+itoa(port), "https://"+host+"/").Output()
		return string(o)
	}
	if got := curl("example.com"); got != "200" {
		t.Fatalf("a listed domain returned %q", got)
	}
	if got := curl("example.net"); got == "200" {
		t.Fatalf("an unlisted domain returned 200 before the list changed")
	}
	if _, err := ruleset.Write(dir, "direct", rules.Direct, rules.Entries{Suffixes: []string{"example.com", "example.net"}}); err != nil {
		t.Fatal(err)
	}
	var got string
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(200 * time.Millisecond) {
		if got = curl("example.net"); got == "200" {
			return
		}
	}
	t.Errorf("the rewritten rule set wasn't picked up (example.net returned %q)", got)
	for len(e.events) > 0 {
		if ev := <-e.events; ev.Kind == EventLog {
			t.Log(ev.Level, ev.Message)
		}
	}
}

// Callers can arrive at once (an app's API handles each request on its own
// goroutine): of several concurrent Starts exactly one runs the instance, and
// any mix of lifecycle calls leaves a consistent engine. Run with -race.
func TestEngineConcurrentLifecycle(t *testing.T) {
	cfg := baseConfig(t)
	cfg.WorkDir = shortDir(t)
	cfg.Inbound.Port = freePort(t)
	cfg.Tunnels = []Tunnel{pkiTunnel(t, "office")}
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}

	const n = 8
	errs := make(chan error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- e.Start() }()
	}
	wg.Wait()
	close(errs)
	started := 0
	for err := range errs {
		if err == nil {
			started++
		}
	}
	if started != 1 {
		t.Fatalf("%d concurrent Starts succeeded, want exactly 1 (a second one is a second tun)", started)
	}

	other := cfg
	other.Lists = []List{{ID: "ads", Name: "Ads", Action: rules.Block}}
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 4; j++ {
				switch (i + j) % 5 {
				case 0:
					_ = e.Start()
				case 1:
					_ = e.Stop()
				case 2:
					_, _ = e.Reload(other)
				case 3:
					_, _ = e.Reload(cfg)
				default:
					_ = e.Status()
				}
			}
		}(i)
	}
	wg.Wait()
	if err := e.Stop(); err != nil {
		t.Fatal(err)
	}
	if s := e.Status(); s.Running {
		t.Errorf("running after Stop: %+v", s)
	}
	// And the engine is still usable.
	if err := e.Start(); err != nil {
		t.Fatalf("start after the storm: %v", err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if _, ok := <-e.Events(); ok {
		for range e.Events() { // drain what was buffered; the channel must be closed
		}
	}
	e.emit(Event{}) // after Close: must not panic
}

// Test refuses what it can't measure instead of hanging or panicking: a stopped
// engine, a tunnel that isn't loaded, and a tunnel with no server to reach.
func TestEngineTestRefusesWhatItCannotMeasure(t *testing.T) {
	cfg := baseConfig(t)
	cfg.WorkDir = shortDir(t)
	cfg.Inbound.Port = freePort(t)
	cfg.Tunnels = []Tunnel{pkiTunnel(t, "office")}
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := e.Test(ctx, "office", "http://127.0.0.1:1/generate_204"); err == nil {
		t.Error("a stopped engine was tested")
	}
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	if _, err := e.Test(ctx, "nope", "http://127.0.0.1:1/generate_204"); err == nil {
		t.Error("a tunnel that isn't loaded was tested")
	}
	if _, err := e.Test(ctx, "office", "http://127.0.0.1:1/generate_204"); err == nil {
		t.Error("a tunnel with no server answered")
	}
}
