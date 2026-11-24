package openvpn

import (
	"reflect"
	"strings"
	"testing"
)

const certPEM = "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----"

func TestParse(t *testing.T) {
	base := "client\ndev tun\nremote vpn.example.com 443 tcp\n<ca>\n" + certPEM + "\n</ca>\n"
	tests := []struct {
		name    string
		text    string
		want    Profile
		wantErr string // substring; "" means no error
	}{
		{name: "minimal", text: base,
			want: Profile{Remotes: []string{"vpn.example.com:443"}}},
		{name: "default port, two remotes", text: "remote a.example\nremote b.example 1195\n",
			want: Profile{Remotes: []string{"a.example:1194", "b.example:1195"}}},
		{name: "auth-user-pass bare", text: base + "auth-user-pass\n",
			want: Profile{Remotes: []string{"vpn.example.com:443"}, NeedsAuth: true}},
		{name: "inline auth block", text: base + "<auth-user-pass>\nuser\npass\n</auth-user-pass>\n",
			want: Profile{Remotes: []string{"vpn.example.com:443"}, NeedsAuth: true}},
		{name: "encrypted key", text: base + "<key>\n-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n</key>\n",
			want: Profile{Remotes: []string{"vpn.example.com:443"}, KeyEncrypted: true}},
		{name: "plain key", text: base + "<key>\n-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n</key>\n",
			want: Profile{Remotes: []string{"vpn.example.com:443"}}},
		{name: "scripts are reported, not refused",
			text: base + "script-security 2\nup /etc/up.sh\n--route-up \"/etc/r u.sh\"\nplugin foo.so\n",
			want: Profile{Remotes: []string{"vpn.example.com:443"}, Scripts: []string{"plugin", "route-up", "up"}, ScriptSecurity: 2}},
		{name: "comments and blanks", text: "# c\n; c\n\n  remote h 1 # trailing\n",
			want: Profile{Remotes: []string{"h:1"}}},
		{name: "connection block", text: "<connection>\nremote h 1\n</connection>\n",
			want: Profile{Remotes: []string{"h:1"}}},
		{name: "directive text inside a data block is data", text: base + "<tls-crypt>\nmanagement 1.2.3.4 1\n</tls-crypt>\n",
			want: Profile{Remotes: []string{"vpn.example.com:443"}}},

		{name: "empty", text: "", wantErr: "empty"},
		{name: "no remote", text: "client\n", wantErr: "no remote"},
		{name: "nul", text: base + "\x00", wantErr: "NUL"},
		{name: "management", text: base + "management 127.0.0.1 7505\n", wantErr: `"management"`},
		{name: "dashes do not hide it", text: base + "--management 127.0.0.1 7505\n", wantErr: `"management"`},
		{name: "quotes do not hide it", text: base + "\"management\" 127.0.0.1 7505\n", wantErr: `"management"`},
		{name: "leading space does not hide it", text: base + "   \tlog /tmp/x\n", wantErr: `"log"`},
		{name: "config include", text: base + "config other.ovpn\n", wantErr: `"config"`},
		{name: "writepid", text: base + "writepid /tmp/pid\n", wantErr: `"writepid"`},
		{name: "daemon", text: base + "daemon\n", wantErr: `"daemon"`},
		{name: "cd", text: base + "cd /\n", wantErr: `"cd"`},
		{name: "file ca", text: "remote h\nca ca.crt\n", wantErr: "inline"},
		{name: "file cert", text: "remote h\ncert /etc/c.crt\n", wantErr: "inline"},
		{name: "file auth", text: base + "auth-user-pass /etc/pass\n", wantErr: "inline"},
		{name: "file tls-auth", text: base + "tls-auth ta.key 1\n", wantErr: "inline"},
		{name: "unclosed block", text: base + "<key>\nx\n", wantErr: "not closed"},
		{name: "unknown block", text: base + "<up>\nrm -rf /\n</up>\n", wantErr: "unknown block"},
		{name: "setenv opt hides management", text: base + "setenv opt management 127.0.0.1 1\n", wantErr: `"management"`},
		{name: "setenv-safe opt with dashes", text: base + "setenv-safe opt --log /x\n", wantErr: `"log"`},
		{name: "setenv opt up is reported as a script", text: base + "setenv opt up /x.sh\n",
			want: Profile{Remotes: []string{"vpn.example.com:443"}, Scripts: []string{"up"}}},
		{name: "plain setenv is fine", text: base + "setenv FOO bar\n",
			want: Profile{Remotes: []string{"vpn.example.com:443"}}},
		{name: "providers loads code", text: base + "providers legacy default\n",
			want: Profile{Remotes: []string{"vpn.example.com:443"}, Scripts: []string{"providers"}}},
		{name: "iproute", text: base + "iproute /x\n",
			want: Profile{Remotes: []string{"vpn.example.com:443"}, Scripts: []string{"iproute"}}},
		{name: "proxy auth file", text: base + "http-proxy 1.2.3.4 8080 /etc/master.passwd\n", wantErr: "credentials from a file"},
		{name: "proxy auto is fine", text: base + "http-proxy 1.2.3.4 8080 auto\n",
			want: Profile{Remotes: []string{"vpn.example.com:443"}}},
		{name: "replay-persist writes a file", text: base + "replay-persist /x\n", wantErr: `"replay-persist"`},
		{name: "BOM", text: "\xef\xbb\xbf" + base, wantErr: "byte order mark"},
		{name: "form feed", text: base + "remote\fx\n", wantErr: "form feed"},
		{name: "long line", text: base + "remote " + strings.Repeat("a", 300) + "\n", wantErr: "longer than"},
		{name: "closing tag with trailing text", text: base + "<cert>\nx\n</cert>-\nmanagement 1 2\n", wantErr: "inside <cert>"},
		{name: "other closing tag inside a block", text: "remote h\n<ca>\nx\n</cert>\n</ca>\n", wantErr: "inside <ca>"},
		{name: "stray closing tag", text: base + "</ca>\n", wantErr: "unexpected"},
		{name: "NBSP hides a block tag", text: base + "ignore-unknown-option \u00a0<ca> \u00a0</ca>\nremote x\n", wantErr: "non-ASCII"},
		{name: "NBSP before a tag", text: base + "\u00a0<tls-crypt>\nmanagement 1 2\n\u00a0</tls-crypt>\n", wantErr: "non-ASCII"},
		{name: "NEL before a directive", text: base + "\u0085management 1 2\n", wantErr: "non-ASCII"},
		{name: "non-ASCII in a comment is fine", text: base + "# caf\u00e9\n",
			want: Profile{Remotes: []string{"vpn.example.com:443"}}},
		{name: "unclosed quote", text: base + "remote \"h\n", wantErr: "unclosed"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse([]byte(tt.text))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err = %v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			got.Directives, got.Blocks, got.Connection = nil, nil, false // covered by TestProfileDirectives and the converter tests
			if !reflect.DeepEqual(got, tt.want) {
				t.Fatalf("got %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestProfileDirectives(t *testing.T) {
	p, err := Parse([]byte("client\n--dev tun\nsetenv opt tls-version-min 1.2\nremote vpn.example.com 443 tcp\n" +
		"auth-user-pass\n<ca>\nCA\n</ca>\n<auth-user-pass>\nuser\nsecret\n</auth-user-pass>\n"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, d := range p.Directives {
		names = append(names, d.Name)
	}
	if !reflect.DeepEqual(names, []string{"client", "dev", "tls-version-min", "remote", "auth-user-pass"}) {
		t.Errorf("directives = %v", names)
	}
	if p.Directives[2].Args[0] != "1.2" || p.Directives[3].Args[2] != "tcp" {
		t.Errorf("args: %+v", p.Directives)
	}
	if p.Blocks["ca"] != "CA\n" {
		t.Errorf("ca block = %q", p.Blocks["ca"])
	}
	if _, ok := p.Blocks["auth-user-pass"]; ok {
		t.Error("the inline credentials block was kept")
	}
}

func TestTokenize(t *testing.T) {
	tests := []struct {
		in   string
		want []string
	}{
		{`a b  c`, []string{"a", "b", "c"}},
		{`a "b c" d`, []string{"a", "b c", "d"}},
		{`a 'b "c"' d`, []string{"a", `b "c"`, "d"}},
		{`a "b\"c"`, []string{"a", `b"c`}},
		{`a b\ c`, []string{"a", "b c"}},
		{`a "" b`, []string{"a", "", "b"}},
		{`a # comment`, []string{"a"}},
		{`a;b`, []string{"a;b"}},
	}
	for _, tt := range tests {
		got, err := tokenize(tt.in)
		if err != nil || !reflect.DeepEqual(got, tt.want) {
			t.Errorf("tokenize(%q) = %q, %v; want %q", tt.in, got, err, tt.want)
		}
	}
}
