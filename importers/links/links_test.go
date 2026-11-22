package links

import (
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

const uuid = "b831381d-6324-4d53-ad4f-8cda48b30811"

func b64(s string) string  { return base64.StdEncoding.EncodeToString([]byte(s)) }
func b64u(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

func vmessLink(j string) string { return "vmess://" + b64(j) }

// Every link a user can paste, with what must come out of it.
func TestParseLink(t *testing.T) {
	tests := []struct {
		name  string
		link  string
		want  Node // Name, Protocol, Server compared; Options by subset
		check func(t *testing.T, o map[string]any)
	}{
		{
			name: "vless reality",
			link: "vless://" + uuid + "@example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com&fp=chrome&pbk=7xhH4b_VkliBxGulljcyPOH-bYUA2dl-XAdZAsfhk04&sid=6ba85179e30d4fc2&type=tcp&headerType=none#Reality%20%F0%9F%87%BA%F0%9F%87%B8",
			want: Node{Name: "Reality 🇺🇸", Protocol: "vless", Server: "example.com:443"},
			check: func(t *testing.T, o map[string]any) {
				tls := o["tls"].(map[string]any)
				r := tls["reality"].(map[string]any)
				if o["flow"] != "xtls-rprx-vision" || r["public_key"] != "7xhH4b_VkliBxGulljcyPOH-bYUA2dl-XAdZAsfhk04" || r["short_id"] != "6ba85179e30d4fc2" || tls["server_name"] != "www.microsoft.com" {
					t.Errorf("got %v", o)
				}
				if tls["utls"].(map[string]any)["fingerprint"] != "chrome" {
					t.Errorf("utls: %v", tls["utls"])
				}
			},
		},
		{
			name: "vless websocket with early data and bracketed IPv6",
			link: "vless://" + uuid + "@[2001:db8::1]:8443?security=tls&sni=cdn.example.com&type=ws&host=cdn.example.com&path=%2Fws%3Fed%3D2048&alpn=h2,http/1.1#v6",
			want: Node{Name: "v6", Protocol: "vless", Server: "[2001:db8::1]:8443"},
			check: func(t *testing.T, o map[string]any) {
				tr := o["transport"].(map[string]any)
				if o["server"] != "2001:db8::1" || tr["type"] != "ws" || tr["path"] != "/ws" || tr["max_early_data"] != 2048 ||
					tr["early_data_header_name"] != "Sec-WebSocket-Protocol" || tr["headers"].(map[string]any)["Host"] != "cdn.example.com" {
					t.Errorf("got %v", o)
				}
				if !reflect.DeepEqual(o["tls"].(map[string]any)["alpn"], []string{"h2", "http/1.1"}) {
					t.Errorf("alpn: %v", o["tls"])
				}
			},
		},
		{
			name: "vless grpc",
			link: "vless://" + uuid + "@example.com:443?security=tls&sni=example.com&type=grpc&serviceName=svc",
			want: Node{Name: "example.com", Protocol: "vless", Server: "example.com:443"},
			check: func(t *testing.T, o map[string]any) {
				if o["transport"].(map[string]any)["service_name"] != "svc" {
					t.Errorf("got %v", o)
				}
			},
		},
		{
			name: "vmess json with string port and aid",
			link: vmessLink(`{"v":"2","ps":"vm test","add":"example.com","port":"443","id":"` + uuid + `","aid":"0","scy":"auto","net":"ws","type":"none","host":"example.com","path":"/ws?ed=2048","tls":"tls","sni":"example.com"}`),
			want: Node{Name: "vm test", Protocol: "vmess", Server: "example.com:443"},
			check: func(t *testing.T, o map[string]any) {
				if o["uuid"] != uuid || o["alter_id"] != 0 || o["security"] != "auto" || o["transport"].(map[string]any)["max_early_data"] != 2048 {
					t.Errorf("got %v", o)
				}
			},
		},
		{
			name: "vmess json with numeric port, URL-safe base64 without padding",
			link: "vmess://" + b64u(`{"ps":"n","add":"1.2.3.4","port":8080,"id":"`+uuid+`","aid":2,"net":"tcp"}`),
			want: Node{Name: "n", Protocol: "vmess", Server: "1.2.3.4:8080"},
			check: func(t *testing.T, o map[string]any) {
				if o["alter_id"] != 2 || o["server_port"] != 8080 || o["tls"] != nil {
					t.Errorf("got %v", o)
				}
			},
		},
		{
			name: "ss SIP002 with base64url userinfo",
			link: "ss://" + b64u("aes-256-gcm:password") + "@example.com:8388#SS%20node",
			want: Node{Name: "SS node", Protocol: "shadowsocks", Server: "example.com:8388"},
			check: func(t *testing.T, o map[string]any) {
				if o["method"] != "aes-256-gcm" || o["password"] != "password" {
					t.Errorf("got %v", o)
				}
			},
		},
		{
			name: "ss 2022 with percent-encoded userinfo",
			link: "ss://2022-blake3-aes-256-gcm:YctPZ6U7xPPcU%2Bgp3u%2B0tx%2FtRizJN9K8y%2BuKlW2qjlI%3D@example.com:8388#ss2022",
			want: Node{Name: "ss2022", Protocol: "shadowsocks", Server: "example.com:8388"},
			check: func(t *testing.T, o map[string]any) {
				if o["method"] != "2022-blake3-aes-256-gcm" || o["password"] != "YctPZ6U7xPPcU+gp3u+0tx/tRizJN9K8y+uKlW2qjlI=" {
					t.Errorf("got %v", o)
				}
			},
		},
		{
			name: "ss legacy, whole body in base64",
			link: "ss://" + b64("chacha20-ietf-poly1305:pa:ss@example.com:443") + "#legacy",
			want: Node{Name: "legacy", Protocol: "shadowsocks", Server: "example.com:443"},
			check: func(t *testing.T, o map[string]any) {
				if o["method"] != "chacha20-ietf-poly1305" || o["password"] != "pa:ss" {
					t.Errorf("got %v", o)
				}
			},
		},
		{
			name: "ss with obfs plugin",
			link: "ss://" + b64u("aes-128-gcm:pw") + "@example.com:8388/?plugin=obfs-local%3Bobfs%3Dhttp%3Bobfs-host%3Dexample.org#obfs",
			want: Node{Name: "obfs", Protocol: "shadowsocks", Server: "example.com:8388"},
			check: func(t *testing.T, o map[string]any) {
				if o["plugin"] != "obfs-local" || o["plugin_opts"] != "obfs=http;obfs-host=example.org" {
					t.Errorf("got %v", o)
				}
			},
		},
		{
			name: "trojan over websocket",
			link: "trojan://password123@example.com:443?security=tls&sni=example.com&type=ws&host=example.com&path=%2Ftrojan#Trojan",
			want: Node{Name: "Trojan", Protocol: "trojan", Server: "example.com:443"},
			check: func(t *testing.T, o map[string]any) {
				if o["password"] != "password123" || o["transport"].(map[string]any)["path"] != "/trojan" || o["tls"].(map[string]any)["enabled"] != true {
					t.Errorf("got %v", o)
				}
			},
		},
		{
			name: "trojan is TLS by default",
			link: "trojan://pw@example.com:443",
			want: Node{Name: "example.com", Protocol: "trojan", Server: "example.com:443"},
			check: func(t *testing.T, o map[string]any) {
				if o["tls"].(map[string]any)["enabled"] != true {
					t.Errorf("got %v", o)
				}
			},
		},
		{
			name: "hysteria2 with salamander and port hopping, insecure",
			link: "hy2://letmein@example.com:443/?sni=example.com&obfs=salamander&obfs-password=gawrgura&insecure=1&mport=20000-30000#hy2",
			want: Node{Name: "hy2", Protocol: "hysteria2", Server: "example.com:443", Warning: "Certificate checks are off for this server."},
			check: func(t *testing.T, o map[string]any) {
				ob := o["obfs"].(map[string]any)
				if o["password"] != "letmein" || ob["type"] != "salamander" || ob["password"] != "gawrgura" ||
					!reflect.DeepEqual(o["server_ports"], []string{"20000:30000"}) || o["tls"].(map[string]any)["insecure"] != true {
					t.Errorf("got %v", o)
				}
			},
		},
		{
			name: "tuic",
			link: "tuic://" + uuid + ":secret@example.com:443?congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=example.com#tuic",
			want: Node{Name: "tuic", Protocol: "tuic", Server: "example.com:443"},
			check: func(t *testing.T, o map[string]any) {
				if o["uuid"] != uuid || o["password"] != "secret" || o["congestion_control"] != "bbr" || o["udp_relay_mode"] != "native" {
					t.Errorf("got %v", o)
				}
			},
		},
		{
			name: "anytls",
			link: "anytls://secret@example.com:443?sni=example.com#anytls",
			want: Node{Name: "anytls", Protocol: "anytls", Server: "example.com:443"},
			check: func(t *testing.T, o map[string]any) {
				if o["password"] != "secret" || o["tls"].(map[string]any)["server_name"] != "example.com" {
					t.Errorf("got %v", o)
				}
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n, err := ParseLink(tt.link)
			if err != nil {
				t.Fatal(err)
			}
			if n.Name != tt.want.Name || n.Protocol != tt.want.Protocol || n.Server != tt.want.Server || n.Warning != tt.want.Warning {
				t.Errorf("got %+v, want %+v", n, tt.want)
			}
			if n.Options["type"] != tt.want.Protocol {
				t.Errorf("options type = %v", n.Options["type"])
			}
			tt.check(t, n.Options)
			if _, err := json.Marshal(n.Options); err != nil {
				t.Errorf("options must be JSON: %v", err)
			}
		})
	}
}

// A link that asks for something the engine can't do is refused by name, never
// downgraded. The reason must not repeat the link's secrets.
func TestParseLinkRefusals(t *testing.T) {
	tests := []struct{ name, link, reason string }{
		{"reality without public key", "vless://" + uuid + "@example.com:443?security=reality&sni=example.com&fp=chrome", "public key"},
		{"reality without sni", "vless://" + uuid + "@example.com:443?security=reality&pbk=abc", "server name"},
		{"xhttp transport", "vless://" + uuid + "@example.com:443?security=tls&type=xhttp&path=%2Fx", "xhttp"},
		{"splithttp transport", "vless://" + uuid + "@example.com:443?security=tls&type=splithttp", "splithttp"},
		{"mkcp transport", "vless://" + uuid + "@example.com:443?type=kcp", "kcp"},
		{"old xtls flow", "vless://" + uuid + "@example.com:443?security=tls&flow=xtls-rprx-direct", "flow"},
		{"vless encryption", "vless://" + uuid + "@example.com:443?encryption=mlkem768x25519plus.native.0rtt.secret", "encryption"},
		{"tcp http obfuscation", "vless://" + uuid + "@example.com:443?type=tcp&headerType=http", "obfuscation"},
		{"unknown security", "vless://" + uuid + "@example.com:443?security=xtls", "security"},
		{"unknown fingerprint", "vless://" + uuid + "@example.com:443?security=tls&fp=netscape", "fingerprint"},
		{"hysteria2 pin", "hysteria2://pw@example.com:443/?pinSHA256=AB:CD", "pinSHA256"},
		{"vmess over quic", vmessLink(`{"add":"example.com","port":"443","id":"` + uuid + `","net":"quic"}`), "quic"},
		{"ss unknown plugin", "ss://" + b64u("aes-128-gcm:pw") + "@example.com:8388/?plugin=kcptun", "kcptun"},
		{"no port", "trojan://pw@example.com", "port"},
		{"ssr", "ssr://abc", "ssr"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseLink(tt.link)
			if err == nil {
				t.Fatal("expected a refusal")
			}
			if !strings.Contains(err.Error(), tt.reason) {
				t.Errorf("reason %q should mention %q", err, tt.reason)
			}
			for _, secret := range []string{uuid, "pw@", "AB:CD", "secret"} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("reason leaks %q: %v", secret, err)
				}
			}
		})
	}
}

func TestParseBodies(t *testing.T) {
	good1 := "trojan://pw1@a.example.com:443#A"
	good2 := "vless://" + uuid + "@b.example.com:443?security=tls#B"
	bad := "vless://" + uuid + "@c.example.com:443?type=xhttp#C xhttp"
	plain := good1 + "\n# a comment\n\n" + bad + "\r\n" + good2 + "\n"

	t.Run("plain list keeps good nodes and names the skipped one", func(t *testing.T) {
		r, err := Parse([]byte(plain))
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Nodes) != 2 || len(r.Skipped) != 1 || !strings.Contains(r.Skipped[0].Reason, "xhttp") || r.Skipped[0].Label != "C xhttp" {
			t.Errorf("got %+v", r)
		}
	})
	for name, body := range map[string]string{
		"base64 standard":       b64(plain),
		"base64 url-safe":       base64.URLEncoding.EncodeToString([]byte(plain)),
		"base64 unpadded":       strings.TrimRight(b64(plain), "="),
		"base64 wrapped lines":  wrap(b64(plain), 20),
		"base64 with BOM/space": "\ufeff  " + b64(plain) + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			r, err := Parse([]byte(body))
			if err != nil {
				t.Fatal(err)
			}
			if len(r.Nodes) != 2 || len(r.Skipped) != 1 {
				t.Errorf("got %d nodes, %d skipped", len(r.Nodes), len(r.Skipped))
			}
		})
	}

	t.Run("sing-box outbounds", func(t *testing.T) {
		body := `{"outbounds":[
		 {"type":"selector","tag":"proxy","outbounds":["a"]},
		 {"type":"direct","tag":"direct"},
		 {"type":"trojan","tag":"A","server":"a.example.com","server_port":443,"password":"pw","domain_resolver":"local","tls":{"enabled":true,"insecure":true}},
		 {"type":"ssh","tag":"S","server":"s.example.com","server_port":22},
		 {"type":"vless","tag":"NoPort","server":"x.example.com"}
		],"endpoints":[{"type":"wireguard","tag":"wg"}]}`
		r, err := Parse([]byte(body))
		if err != nil {
			t.Fatal(err)
		}
		if len(r.Nodes) != 1 || r.Nodes[0].Name != "A" || r.Nodes[0].Server != "a.example.com:443" || r.Nodes[0].Warning == "" {
			t.Fatalf("nodes: %+v", r.Nodes)
		}
		if _, ok := r.Nodes[0].Options["tag"]; ok {
			t.Error("tag must be removed")
		}
		if _, ok := r.Nodes[0].Options["domain_resolver"]; ok {
			t.Error("domain_resolver must be removed")
		}
		if len(r.Skipped) != 3 {
			t.Errorf("skipped: %+v", r.Skipped)
		}
	})

	for name, tt := range map[string]struct{ body, reason string }{
		"empty":       {"  \n", "nothing"},
		"html page":   {"<html><body>Please log in</body></html>", "not a list"},
		"clash yaml":  {"port: 7890\nproxies:\n  - name: a\n    type: vless\n", "Clash"},
		"plain words": {"hello world", "not a list"},
		"empty json":  {`{"log":{}}`, "no outbounds"},
		"bad json":    {`{"outbounds":`, "malformed"},
	} {
		t.Run("refuses "+name, func(t *testing.T) {
			_, err := Parse([]byte(tt.body))
			if err == nil || !strings.Contains(err.Error(), tt.reason) {
				t.Errorf("got %v, want an error mentioning %q", err, tt.reason)
			}
		})
	}
}

func TestParseTooMany(t *testing.T) {
	var b strings.Builder
	for i := 0; i <= MaxNodes; i++ {
		b.WriteString("trojan://pw@a.example.com:443#n\n")
	}
	if _, err := Parse([]byte(b.String())); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Errorf("got %v", err)
	}
}

// A skip label for an opaque link must not echo its body.
func TestLabelsHideSecrets(t *testing.T) {
	for _, line := range []string{
		"vmess://" + b64(`{"add":"x","id":"secret-id"}`),
		"ss://" + b64("aes-128-gcm:hunter2@example.com:1"),
		"trojan://hunter2@example.com:443?type=xhttp",
	} {
		if l := label(line); strings.Contains(l, "hunter2") || strings.Contains(l, "secret-id") || strings.Contains(l, "eyJ") {
			t.Errorf("label %q leaks", l)
		}
	}
}

func wrap(s string, n int) string {
	var b strings.Builder
	for len(s) > n {
		b.WriteString(s[:n] + "\n")
		s = s[n:]
	}
	return b.String() + s
}
