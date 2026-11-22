package core

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"

	"github.com/split-route/core/importers/openvpn"
	"github.com/split-route/core/rules"
)

const profile = "client\ndev tun\nproto udp\nremote vpn.example.net 1194\nremote-cert-tls server\n" +
	"<ca>\n-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n</ca>\n" +
	"<cert>\n-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----\n</cert>\n" +
	"<key>\n-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n</key>\n"

func ovpnTunnel(t *testing.T, id, name string) Tunnel {
	t.Helper()
	p, err := openvpn.Parse([]byte(profile))
	if err != nil {
		t.Fatal(err)
	}
	ep, err := openvpn.Endpoint(p, "x", "", "")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(ep)
	return Tunnel{ID: id, Name: name, Protocol: "openvpn", Options: b}
}

func baseConfig(t *testing.T) Config {
	return Config{
		Tunnels: []Tunnel{ovpnTunnel(t, "office", "Office"), ovpnTunnel(t, "home", "Home")},
		WorkDir: "/data/split-route",
		Inbound: Inbound{Mode: "proxy", Listen: "127.0.0.1", Port: 18080},
	}
}

func parse(t *testing.T, b []byte) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func ruleOrder(cfg map[string]any) []string {
	var order []string
	for _, r := range cfg["route"].(map[string]any)["rules"].([]any) {
		m := r.(map[string]any)
		switch {
		case m["action"] == "sniff", m["action"] == "hijack-dns":
			order = append(order, m["action"].(string))
		case m["ip_is_private"] == true:
			order = append(order, "private")
		default:
			s := m["action"].(string)
			if o, ok := m["outbound"]; ok {
				s += ">" + o.(string)
			}
			order = append(order, s+":"+m["rule_set"].([]any)[0].(string))
		}
	}
	return order
}

func TestBuildRouting(t *testing.T) {
	c := baseConfig(t)
	c.Inbound = Inbound{} // tun
	c.Lists = []List{
		{ID: "social", Name: "Social", Action: rules.Tunnel, Tunnel: "home"},
		{ID: "ir-cidr", Name: "Iran", Action: rules.Direct},
		{ID: "work", Name: "Work", Action: rules.Tunnel}, // the default tunnel
		{ID: "ads", Name: "Ads", Action: rules.Block},
	}
	b, err := Build(c)
	if err != nil {
		t.Fatal(err)
	}
	cfg := parse(t, b)
	want := []string{"sniff", "hijack-dns", "private", "reject:ads", "route>direct:ir-cidr", "route>t-home:social", "route>selected:work"}
	if got := ruleOrder(cfg); !reflect.DeepEqual(got, want) {
		t.Errorf("rule order:\n got %v\nwant %v", got, want)
	}
	route := cfg["route"].(map[string]any)
	if route["final"] != "selected" || route["auto_detect_interface"] != true {
		t.Errorf("route = %v: unmatched traffic goes to the selector, and the tun needs the default interface", route)
	}
	// Both tunnels are endpoints of the one instance, each with its own DNS server through it.
	var tags []string
	for _, e := range cfg["endpoints"].([]any) {
		m := e.(map[string]any)
		tags = append(tags, m["tag"].(string))
		if m["system"] != false || m["domain_resolver"] != "local" {
			t.Errorf("endpoint %v: system/domain_resolver = %v/%v", m["tag"], m["system"], m["domain_resolver"])
		}
	}
	if !reflect.DeepEqual(tags, []string{"t-office", "t-home"}) {
		t.Errorf("endpoints = %v", tags)
	}
	dns := cfg["dns"].(map[string]any)
	if dns["final"] != "dns-selected" {
		t.Errorf("dns final = %v", dns["final"])
	}
	// Direct names resolve locally; a list with its own tunnel through it; the default tunnel's list needs no rule.
	var rs []string
	for _, r := range dns["rules"].([]any) {
		m := r.(map[string]any)
		rs = append(rs, m["rule_set"].([]any)[0].(string)+">"+m["server"].(string))
	}
	if !reflect.DeepEqual(rs, []string{"ir-cidr-dns>local", "social-dns>dns-t-home"}) {
		t.Errorf("dns rules = %v", rs)
	}
	// One resolver through the selector, and one for each tunnel a list names (here only home).
	servers := map[string]string{}
	for _, d := range dns["servers"].([]any) {
		if m := d.(map[string]any); m["type"] == "udp" {
			servers[m["tag"].(string)] = m["detour"].(string)
		}
	}
	if !reflect.DeepEqual(servers, map[string]string{"dns-selected": "selected", "dns-t-home": "t-home"}) {
		t.Errorf("DNS servers (tag > detour) = %v", servers)
	}
	// The selector holds every tunnel, and drops connections of the tunnel it leaves.
	var sel map[string]any
	for _, o := range cfg["outbounds"].([]any) {
		if m := o.(map[string]any); m["tag"] == "selected" {
			sel = m
		}
	}
	if sel == nil || sel["type"] != "selector" || sel["interrupt_exist_connections"] != true ||
		!reflect.DeepEqual(sel["outbounds"], []any{"t-office", "t-home"}) {
		t.Errorf("selector = %v", sel)
	}
	if _, ok := sel["default"]; ok {
		t.Error("the selector has a default: the choice must not be part of the built config")
	}
	// sing-box makes a cache file whether we ask or not (the engine passes a log writer);
	// its path must be in the work directory, never the relative default "cache.db",
	// which is "/" under launchd and read-only.
	cache := cfg["experimental"].(map[string]any)["cache_file"].(map[string]any)
	if cache["enabled"] != true || cache["path"] != "/data/split-route/cache.db" {
		t.Errorf("cache_file = %v", cache)
	}
	// Every rule-set points into the work dir's rulesets directory.
	for _, r := range route["rule_set"].([]any) {
		if p := r.(map[string]any)["path"].(string); !strings.HasPrefix(p, "/data/split-route/rulesets/") {
			t.Errorf("rule-set path %q", p)
		}
	}
}

func TestBuildProxyMode(t *testing.T) {
	c := baseConfig(t)
	c.Inbound = Inbound{Mode: "proxy", Listen: "127.0.0.1", Port: 18080, User: "u", Pass: "p"}
	b, err := Build(c)
	if err != nil {
		t.Fatal(err)
	}
	cfg := parse(t, b)
	in := cfg["inbounds"].([]any)[0].(map[string]any)
	if in["type"] != "mixed" || in["listen"] != "127.0.0.1" || in["listen_port"] != 18080.0 || in["users"] == nil {
		t.Errorf("inbound = %v", in)
	}
	if got := ruleOrder(cfg); !reflect.DeepEqual(got, []string{"sniff"}) {
		t.Errorf("rules in proxy mode = %v (no DNS hijack or private-address rule without a tun)", got)
	}
	if _, ok := cfg["route"].(map[string]any)["auto_detect_interface"]; ok {
		t.Error("auto_detect_interface in proxy mode")
	}
}

// The config changes when something the engine must restart for changes, and
// only then: lists' entries are not in it at all.
func TestBuildConfigDependsOnStructureOnly(t *testing.T) {
	build := func(c Config) string {
		b, err := Build(c)
		if err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	a := baseConfig(t)
	a.Lists = []List{{ID: "a", Name: "A", Action: rules.Direct}, {ID: "b", Name: "B", Action: rules.Block}}
	same := a
	same.Lists = append([]List(nil), a.Lists...)
	same.Lists[0].Name = "Renamed" // a display name
	if build(a) != build(same) {
		t.Error("a display name changed the config")
	}
	for name, mut := range map[string]func(*Config){
		"action":      func(c *Config) { c.Lists[0].Action = rules.Block },
		"a new list":  func(c *Config) { c.Lists = append(c.Lists, List{ID: "c", Name: "C", Action: rules.Block}) },
		"list target": func(c *Config) { c.Lists[1] = List{ID: "b", Name: "B", Action: rules.Tunnel, Tunnel: "home"} },
		"a tunnel":    func(c *Config) { c.Tunnels = c.Tunnels[:1] },
		"dns":         func(c *Config) { c.DNS.Remote = "9.9.9.9" },
	} {
		c := a
		c.Lists = append([]List(nil), a.Lists...)
		mut(&c)
		if build(a) == build(c) {
			t.Errorf("%s did not change the config", name)
		}
	}
}

// The default tunnel is chosen at run time, so it must not be in the built
// config: changing it is a switch of the selector, never a restart.
func TestBuildDoesNotDependOnTheDefaultTunnel(t *testing.T) {
	a := baseConfig(t)
	b := a
	b.Default = "home"
	x, err := Build(a)
	if err != nil {
		t.Fatal(err)
	}
	y, err := Build(b)
	if err != nil {
		t.Fatal(err)
	}
	if string(x) != string(y) {
		t.Error("the default tunnel changed the built config")
	}
}

func TestBuildOverridesWhatTheEngineOwns(t *testing.T) {
	c := baseConfig(t)
	var o map[string]any
	_ = json.Unmarshal(c.Tunnels[0].Options, &o)
	o["system"], o["tag"] = true, "evil"
	c.Tunnels[0].Options, _ = json.Marshal(o)
	b, err := Build(c)
	if err != nil {
		t.Fatal(err)
	}
	ep := parse(t, b)["endpoints"].([]any)[0].(map[string]any)
	if ep["system"] != false || ep["tag"] != "t-office" {
		t.Errorf("endpoint = system %v tag %v: an app's options must not make a second tun or rename the tunnel", ep["system"], ep["tag"])
	}
}

func TestValidate(t *testing.T) {
	bad := map[string]func(*Config){
		"no tunnels":       func(c *Config) { c.Tunnels = nil },
		"relative workdir": func(c *Config) { c.WorkDir = "data" },
		"tunnel id":        func(c *Config) { c.Tunnels[0].ID = "Office!" },
		"tunnel twice":     func(c *Config) { c.Tunnels[1].ID = "office" },
		"tunnel name":      func(c *Config) { c.Tunnels[0].Name = "" },
		"protocol":         func(c *Config) { c.Tunnels[0].Protocol = "carrier-pigeon" },
		"unknown default":  func(c *Config) { c.Default = "lab" },
		"list id":          func(c *Config) { c.Lists = []List{{ID: "../x", Action: rules.Block}} },
		"list twice":       func(c *Config) { c.Lists = []List{{ID: "a", Action: rules.Block}, {ID: "a", Action: rules.Block}} },
		"action":           func(c *Config) { c.Lists = []List{{ID: "a", Action: "vpn"}} },
		"tunnel on block":  func(c *Config) { c.Lists = []List{{ID: "a", Action: rules.Block, Tunnel: "home"}} },
		"unknown tunnel":   func(c *Config) { c.Lists = []List{{ID: "a", Action: rules.Tunnel, Tunnel: "lab"}} },
		"dns":              func(c *Config) { c.DNS.Remote = "dns.example" },
		"log level":        func(c *Config) { c.Log.Level = "loud" },
		"mode":             func(c *Config) { c.Inbound.Mode = "vpn" },
		"proxy not local":  func(c *Config) { c.Inbound.Listen = "0.0.0.0" },
		"proxy port":       func(c *Config) { c.Inbound.Port = 0 },
		"proxy user only":  func(c *Config) { c.Inbound.User = "u" },
	}
	for name, mut := range bad {
		c := baseConfig(t)
		mut(&c)
		if _, err := Build(c); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if err := baseConfig(t).Validate(); err != nil {
		t.Errorf("a good config: %v", err)
	}
}

// Options come from links and files and run privileged: nothing that reads a
// file or steers the engine's own traffic gets in, at any depth.
func TestTunnelOptionsAreChecked(t *testing.T) {
	opts := func(extra string) json.RawMessage {
		return json.RawMessage(`{"type":"openvpn-client","servers":[{"server":"vpn.example.net","server_port":1194,"network":"udp"}],"tls":{"certificate":["x"]` + extra + `}}`)
	}
	for name, extra := range map[string]string{
		"file":        `,"certificate_path":"/etc/ssl/key.pem"`,
		"client key":  `,"client_key_path":"/etc/passwd"`,
		"nested":      `,"control_wrap":{"type":"tls_auth","key_path":"/x"}`,
		"in an array": `,"extra":[{"detour":"direct"}]`,
	} {
		c := baseConfig(t)
		c.Tunnels[0].Options = opts(extra)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, raw := range map[string]string{
		"detour":     `{"type":"openvpn-client","detour":"direct"}`,
		"interface":  `{"type":"openvpn-client","bind_interface":"en0"}`,
		"mark":       `{"type":"openvpn-client","routing_mark":1}`,
		"wrong type": `{"type":"wireguard"}`,
		"not object": `[1]`,
		"null":       `null`,
	} {
		c := baseConfig(t)
		c.Tunnels[0].Options = json.RawMessage(raw)
		if err := c.Validate(); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	c := baseConfig(t)
	c.Tunnels[0].Options = opts("")
	if err := c.Validate(); err != nil {
		t.Errorf("ordinary options refused: %v", err)
	}
}

// A proxy tunnel's server is found by name through DNS over HTTPS to a public
// address, not the system resolver: a network that answers for a filtered name with a
// private block-page address (10.10.34.34) makes every dial time out. OpenVPN keeps
// the system resolver.
func TestBuildResolvesProxyServersOverDoH(t *testing.T) {
	c := baseConfig(t)
	c.Tunnels = append(c.Tunnels, Tunnel{ID: "node", Name: "Node", Protocol: "vless",
		Options: json.RawMessage(`{"type":"vless","server":"node.example.com","server_port":443,"uuid":"b831381d-6324-4d53-ad4f-8cda48b30811"}`)})
	resolvers := func(c Config) (map[string]any, map[string]any) {
		b, err := Build(c)
		if err != nil {
			t.Fatal(err)
		}
		cfg := parse(t, b)
		got := map[string]any{}
		for _, o := range cfg["outbounds"].([]any) {
			if m := o.(map[string]any); m["tag"] == "t-node" {
				got["t-node"] = m["domain_resolver"]
			}
		}
		for _, e := range cfg["endpoints"].([]any) {
			if m := e.(map[string]any); m["tag"] == "t-office" {
				got["t-office"] = m["domain_resolver"]
			}
		}
		servers := map[string]any{}
		for _, s := range cfg["dns"].(map[string]any)["servers"].([]any) {
			m := s.(map[string]any)
			servers[m["tag"].(string)] = m
		}
		return got, servers
	}

	got, servers := resolvers(c)
	if got["t-node"] != "dns-bootstrap" || got["t-office"] != "local" {
		t.Errorf("domain_resolver: proxy %v, openvpn %v", got["t-node"], got["t-office"])
	}
	boot, _ := servers["dns-bootstrap"].(map[string]any)
	if boot["type"] != "https" || boot["server"] != "1.1.1.1" || boot["path"] != "/dns-query" || boot["detour"] != nil {
		t.Errorf("bootstrap server = %v: DoH to a public address, direct", boot)
	}

	c.DNS.Bootstrap = "9.9.9.9"
	if _, servers := resolvers(c); servers["dns-bootstrap"].(map[string]any)["server"] != "9.9.9.9" {
		t.Errorf("custom bootstrap = %v", servers["dns-bootstrap"])
	}
	c.DNS.Bootstrap = BootstrapSystem
	got, servers = resolvers(c)
	if got["t-node"] != "local" || servers["dns-bootstrap"] != nil {
		t.Errorf("system bootstrap: proxy resolves with %v, bootstrap server %v", got["t-node"], servers["dns-bootstrap"])
	}
	c.DNS.Bootstrap = "dns.example.com"
	if _, err := Build(c); err == nil {
		t.Error("a bootstrap that is not an IP address or \"system\" was accepted")
	}
}
