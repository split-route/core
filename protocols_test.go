//go:build with_openvpn

package core

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/split-route/core/importers/links"
)

// Validate and Build don't know sing-box's option schema, so a wrong field name
// in an importer (server_port, transport.type, tls.reality.public_key) would only
// show when the engine starts. This starts the real engine, in proxy mode, on
// the output of every importer path. An outbound doesn't dial at start, so no
// server is needed.
func TestImportedLinksStart(t *testing.T) {
	const id = "b831381d-6324-4d53-ad4f-8cda48b30811"
	b64u := func(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }
	fixtures := map[string]string{
		"vless reality":     "vless://" + id + "@example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=7xhH4b_VkliBxGulljcyPOH-bYUA2dl-XAdZAsfhk04&sid=6ba85179e30d4fc2&type=tcp#r",
		"vless ws tls":      "vless://" + id + "@example.com:443?security=tls&sni=cdn.example.com&type=ws&host=cdn.example.com&path=%2Fws%3Fed%3D2048&alpn=h2,http/1.1&fp=firefox#w",
		"vless grpc":        "vless://" + id + "@example.com:443?security=tls&sni=example.com&type=grpc&serviceName=svc#g",
		"vless httpupgrade": "vless://" + id + "@example.com:443?security=tls&sni=example.com&type=httpupgrade&path=%2Fu&host=example.com#u",
		"vless h2":          "vless://" + id + "@example.com:443?security=tls&sni=example.com&type=h2&path=%2Fh&host=example.com#h",
		"vless plain":       "vless://" + id + "@[2001:db8::1]:8443?security=none#p",
		"vmess ws tls":      "vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"ps":"v","add":"example.com","port":"443","id":"`+id+`","aid":"0","scy":"auto","net":"ws","host":"example.com","path":"/ws?ed=2048","tls":"tls","sni":"example.com"}`)),
		"vmess tcp":         "vmess://" + base64.StdEncoding.EncodeToString([]byte(`{"ps":"t","add":"1.2.3.4","port":8080,"id":"`+id+`","aid":2,"net":"tcp"}`)),
		"trojan ws":         "trojan://password123@example.com:443?security=tls&sni=example.com&type=ws&host=example.com&path=%2Ftrojan#t",
		"trojan default":    "trojan://pw@example.com:443#d",
		"ss sip002":         "ss://" + b64u("aes-256-gcm:password") + "@example.com:8388#s",
		"ss 2022":           "ss://2022-blake3-aes-256-gcm:YctPZ6U7xPPcU%2Bgp3u%2B0tx%2FtRizJN9K8y%2BuKlW2qjlI%3D@example.com:8388#s2",
		"ss obfs plugin":    "ss://" + b64u("aes-128-gcm:pw") + "@example.com:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dexample.org#o",
		"hysteria2":         "hy2://letmein@example.com:443/?sni=example.com&obfs=salamander&obfs-password=gawrgura&insecure=1&mport=20000-30000#h",
		"tuic":              "tuic://" + id + ":secret@example.com:443?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=example.com#t",
		"anytls":            "anytls://secret@example.com:443?sni=example.com#a",
	}
	for name, link := range fixtures {
		t.Run(name, func(t *testing.T) {
			startsAs(t, link)
		})
	}
	t.Run("sing-box outbound", func(t *testing.T) {
		r, err := links.Parse([]byte(`{"outbounds":[{"type":"trojan","tag":"A","server":"a.example.com","server_port":443,"password":"pw","domain_resolver":"local","tls":{"enabled":true}}]}`))
		if err != nil || len(r.Nodes) != 1 {
			t.Fatalf("parse: %v %+v", err, r)
		}
		startsNode(t, r.Nodes[0])
	})
}

func startsAs(t *testing.T, link string) {
	t.Helper()
	n, err := links.ParseLink(link)
	if err != nil {
		t.Fatal(err)
	}
	startsNode(t, n)
}

func startsNode(t *testing.T, n links.Node) {
	t.Helper()
	opts, err := json.Marshal(n.Options)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckTunnel(n.Protocol, opts); err != nil {
		t.Fatalf("CheckTunnel: %v", err)
	}
	e, err := New(Config{
		Tunnels: []Tunnel{{ID: "n1", Name: n.Name, Protocol: n.Protocol, Options: opts}},
		WorkDir: shortDir(t),
		Inbound: Inbound{Mode: "proxy", Listen: "127.0.0.1", Port: freePort(t)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Start(); err != nil {
		t.Fatalf("the engine refused the importer's options: %v", err)
	}
	defer e.Stop()
	st := e.Status()
	if len(st.Tunnels) != 1 || st.Tunnels[0].State != StateReady {
		t.Errorf("status = %+v, want one ready tunnel", st.Tunnels)
	}
}

func TestCheckTunnelRefusesUnsafeOptions(t *testing.T) {
	for name, opts := range map[string]string{
		"tls file path":  `{"type":"trojan","server":"a.example.com","server_port":443,"password":"x","tls":{"enabled":true,"certificate_path":"/etc/passwd"}}`,
		"detour":         `{"type":"trojan","server":"a.example.com","server_port":443,"password":"x","detour":"direct"}`,
		"bind interface": `{"type":"trojan","server":"a.example.com","server_port":443,"password":"x","bind_interface":"en0"}`,
		"wrong type":     `{"type":"vless","server":"a.example.com","server_port":443}`,
	} {
		if err := CheckTunnel("trojan", []byte(opts)); err == nil {
			t.Errorf("%s: want an error", name)
		}
	}
}

// The control for TestImportedLinksStart: the harness must fail on a field
// sing-box doesn't know, or passing there means nothing.
func TestEngineRefusesUnknownOptionFields(t *testing.T) {
	opts := []byte(`{"type":"trojan","server":"a.example.com","server_port":443,"password":"x","tls":{"enabled":true},"srever_port":1}`)
	e, err := New(Config{
		Tunnels: []Tunnel{{ID: "n1", Name: "n", Protocol: "trojan", Options: opts}},
		WorkDir: shortDir(t),
		Inbound: Inbound{Mode: "proxy", Listen: "127.0.0.1", Port: freePort(t)},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Start(); err == nil {
		e.Stop()
		t.Fatal("the engine accepted an unknown option field")
	}
}

func proxyTunnel(t *testing.T, id string) Tunnel {
	t.Helper()
	opts, _ := json.Marshal(map[string]any{"type": "trojan", "server": id + ".example.com", "server_port": 443, "password": "pw",
		"tls": map[string]any{"enabled": true}})
	return Tunnel{ID: id, Name: id, Protocol: "trojan", Options: opts}
}

// Choosing the default tunnel switches the selector of the running instance: no
// restart, so the OpenVPN endpoint in the same engine keeps its session. Anything
// structural still restarts. The selector is told which member to use at start,
// not left to its own first-member default.
func TestSelectSwitchesWithoutRestarting(t *testing.T) {
	cfg := Config{
		Tunnels: []Tunnel{proxyTunnel(t, "a"), pkiTunnel(t, "office"), proxyTunnel(t, "b")},
		WorkDir: shortDir(t),
		Inbound: Inbound{Mode: "proxy", Listen: "127.0.0.1", Port: freePort(t)},
		Default: "b", // not the first member
	}
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	if got := e.Status().Default; got != "b" {
		t.Errorf("default after Start = %q, want b", got)
	}
	if sel := currentSelection(t, e); sel != "t-b" {
		t.Errorf("selector uses %q after Start, want t-b", sel)
	}
	waitState(t, e, "office", StateConnecting)

	for _, id := range []string{"office", "a", "b"} {
		if err := e.Select(id); err != nil {
			t.Fatalf("Select(%s): %v", id, err)
		}
		if sel := currentSelection(t, e); sel != "t-"+id || e.Status().Default != id {
			t.Errorf("after Select(%s): selector %q, status default %q", id, sel, e.Status().Default)
		}
	}
	if err := e.Select("nope"); err == nil {
		t.Error("an unknown tunnel was selected")
	}

	// Reload with only the default changed: no restart.
	next := cfg
	next.Default = "a"
	if restarted, err := e.Reload(next); err != nil || restarted {
		t.Fatalf("a changed default restarted the engine: %v %v", restarted, err)
	}
	if sel := currentSelection(t, e); sel != "t-a" {
		t.Errorf("after Reload selector uses %q, want t-a", sel)
	}
	// A structural change still restarts, and keeps the choice.
	next.Lists = []List{{ID: "ads", Name: "Ads", Action: "block"}}
	if restarted, err := e.Reload(next); err != nil || !restarted {
		t.Fatalf("a new list did not restart the engine: %v %v", restarted, err)
	}
	if sel := currentSelection(t, e); sel != "t-a" || e.Status().Default != "a" {
		t.Errorf("after the restart: selector %q, default %q, want a", sel, e.Status().Default)
	}
}

func currentSelection(t *testing.T, e *Engine) string {
	t.Helper()
	e.life.Lock()
	defer e.life.Unlock()
	ob, ok := e.inst.Outbound().Outbound(selectorTag)
	if !ok {
		t.Fatal("no selector")
	}
	g, ok := ob.(interface {
		Selected(network string) adapter.Outbound
	})
	if !ok {
		t.Fatalf("%T has no Selected()", ob)
	}
	return g.Selected("tcp").Tag()
}

// Select, Reload, Stop and Start from several goroutines: no race, no panic, and
// the engine ends in a state it can report.
func TestSelectIsRaceFree(t *testing.T) {
	cfg := Config{
		Tunnels: []Tunnel{proxyTunnel(t, "a"), proxyTunnel(t, "b"), proxyTunnel(t, "c")},
		WorkDir: shortDir(t),
		Inbound: Inbound{Mode: "proxy", Listen: "127.0.0.1", Port: freePort(t)},
	}
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Close()
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			ids := []string{"a", "b", "c"}
			for j := 0; j < 20; j++ {
				switch (i + j) % 4 {
				case 0, 1:
					_ = e.Select(ids[j%3])
				case 2:
					c := cfg
					c.Default = ids[(i+j)%3]
					_, _ = e.Reload(c)
				case 3:
					_ = e.Status()
				}
			}
		}(i)
	}
	wg.Wait()
	if s := e.Status(); !s.Running || s.Default == "" {
		t.Errorf("status = %+v", s)
	}
}

// How long the visible parts take. A restart of proxy tunnels must be too quick
// to notice, and hundreds of loaded tunnels must not slow it down much.
func TestRestartAndStartAreFastWithManyTunnels(t *testing.T) {
	for _, n := range []int{5, 500} {
		var ts []Tunnel
		for i := 0; i < n; i++ {
			ts = append(ts, proxyTunnel(t, "n"+strconv.Itoa(i)))
		}
		cfg := Config{Tunnels: ts, WorkDir: shortDir(t), Inbound: Inbound{Mode: "proxy", Listen: "127.0.0.1", Port: freePort(t)}}
		e, err := New(cfg)
		if err != nil {
			t.Fatal(err)
		}
		start := time.Now()
		if err := e.Start(); err != nil {
			t.Fatal(err)
		}
		started := time.Since(start)
		switchStart := time.Now()
		if err := e.Select("n" + strconv.Itoa(n-1)); err != nil {
			t.Fatal(err)
		}
		switched := time.Since(switchStart)
		next := cfg
		next.Lists = []List{{ID: "ads", Name: "Ads", Action: "block"}}
		restart := time.Now()
		if restarted, err := e.Reload(next); err != nil || !restarted {
			t.Fatalf("%v %v", restarted, err)
		}
		restarted := time.Since(restart)
		e.Close()
		t.Logf("%d tunnels: start %v, switch %v, restart %v", n, started, switched, restarted)
		if started > 3*time.Second || restarted > 3*time.Second || switched > 200*time.Millisecond {
			t.Errorf("%d tunnels: start %v, switch %v, restart %v are too slow", n, started, switched, restarted)
		}
	}
}

// Starting the engine must not write "cache.db" into the working directory: for a
// service under launchd that is "/", which is read-only, and every tunnel fails with
// "initialize cache-file: open cache.db: read-only file system". sing-box makes the
// file whenever a log writer is passed, so the config must say where it goes. A stale
// file in the work dir must not decide the selection either.
func TestStartKeepsItsCacheInTheWorkDir(t *testing.T) {
	cwd, _ := os.Getwd()
	for _, name := range []string{"cache.db"} {
		_ = os.Remove(filepath.Join(cwd, name))
	}
	cfg := Config{
		Tunnels: []Tunnel{proxyTunnel(t, "a"), proxyTunnel(t, "b")},
		WorkDir: shortDir(t),
		Inbound: Inbound{Mode: "proxy", Listen: "127.0.0.1", Port: freePort(t)},
		Default: "a",
	}
	// A cache left by an earlier run, remembering another choice.
	stale := filepath.Join(cfg.WorkDir, "cache.db")
	e, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := e.Start(); err != nil {
		t.Fatal(err)
	}
	if err := e.Select("b"); err != nil { // writes the choice into the cache
		t.Fatal(err)
	}
	e.Stop()
	if _, err := os.Stat(stale); err != nil {
		t.Fatalf("no cache file in the work dir: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cwd, "cache.db")); err == nil {
		t.Fatal("the engine wrote cache.db into the working directory")
	}
	e.Close()

	// A new engine for the same work dir (the service restarted) with Default a: the cache
	// left behind says b, and must not win.
	e2, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := e2.Start(); err != nil {
		t.Fatal(err)
	}
	defer e2.Close()
	if sel := currentSelection(t, e2); sel != "t-a" {
		t.Errorf("after a restart the selector uses %q: the old cache decided over Default (a)", sel)
	}
	// A cache file that is damaged doesn't stop the start either.
	e2.Stop()
	if err := os.WriteFile(stale, []byte("not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := e2.Start(); err != nil {
		t.Errorf("a damaged cache stopped the engine: %v", err)
	}
}

// sing-box must accept the uTLS block the engine adds for a fingerprint, on every protocol it is added to.
func TestEngineStartsWithATLSFingerprintAndSTUNBlock(t *testing.T) {
	const id = "b831381d-6324-4d53-ad4f-8cda48b30811"
	for name, tun := range map[string]Tunnel{
		"trojan": {ID: "n1", Name: "n", Protocol: "trojan", Options: []byte(`{"type":"trojan","server":"a.example.com","server_port":443,"password":"x","tls":{"enabled":true,"server_name":"a.example.com"}}`)},
		"vless":  {ID: "n1", Name: "n", Protocol: "vless", Options: []byte(`{"type":"vless","server":"a.example.com","server_port":443,"uuid":"` + id + `","tls":{"enabled":true,"server_name":"a.example.com"}}`)},
		"vmess":  {ID: "n1", Name: "n", Protocol: "vmess", Options: []byte(`{"type":"vmess","server":"a.example.com","server_port":443,"uuid":"` + id + `","security":"auto","tls":{"enabled":true,"server_name":"a.example.com"}}`)},
	} {
		for _, fp := range TLSFingerprints {
			t.Run(name+"/"+fp, func(t *testing.T) {
				e, err := New(Config{Tunnels: []Tunnel{tun}, WorkDir: shortDir(t), BlockSTUN: true, TLSFingerprint: fp,
					Inbound: Inbound{Mode: "proxy", Listen: "127.0.0.1", Port: freePort(t)}})
				if err != nil {
					t.Fatal(err)
				}
				if err := e.Start(); err != nil {
					t.Fatalf("the engine refused fingerprint %s: %v", fp, err)
				}
				e.Stop()
			})
		}
	}
}
