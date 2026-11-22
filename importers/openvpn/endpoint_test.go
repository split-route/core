package openvpn

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// The shape of a real profile (TCP, tls-crypt-v2, name-checked server, Go-hostile
// OpenSSL names), with dummy PEM bodies and a made-up host.
const aliLike = `client
dev tun
proto tcp-client
remote vpn.example.net 8120
resolv-retry infinite
nobind
persist-tun
auth-user-pass
remote-cert-tls server
verify-x509-name server_AbCd name
cipher AES-128-GCM
data-ciphers AES-128-GCM
auth SHA256
tls-version-min 1.2
tls-cipher TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256
tls-ciphersuites TLS_AES_128_GCM_SHA256
tls-groups X25519:prime256v1:secp384r1
allow-compression no
tun-mtu 1400
mssfix 1340
socket-flags TCP_NODELAY
reneg-sec 0
connect-retry 2
connect-retry-max 0
connect-timeout 10
hand-window 30
ignore-unknown-option block-outside-dns
setenv opt block-outside-dns
verb 3
mute 10
<ca>
-----BEGIN CERTIFICATE-----
CA
-----END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----
CERT
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
KEY
-----END PRIVATE KEY-----
</key>
<tls-crypt-v2>
-----BEGIN OpenVPN tls-crypt-v2 client key-----
WRAP
-----END OpenVPN tls-crypt-v2 client key-----
</tls-crypt-v2>
`

func endpointOf(t *testing.T, text, user, pass string) (map[string]any, error) {
	t.Helper()
	p, err := Parse([]byte(text))
	if err != nil {
		t.Fatalf("ParseProfile: %v", err)
	}
	return Endpoint(p, "ovpn", user, pass)
}

func TestEndpoint(t *testing.T) {
	ep, err := endpointOf(t, aliLike, "u", "p")
	if err != nil {
		t.Fatal(err)
	}
	// Round-trip through JSON: that is what sing-box reads.
	b, _ := json.Marshal(ep)
	var got map[string]any
	_ = json.Unmarshal(b, &got)
	want := map[string]any{
		"type": "openvpn-client", "tag": "ovpn", "mode": "tls", "system": false, "auth_retry": "none",
		"servers":  []any{map[string]any{"server": "vpn.example.net", "server_port": 8120.0, "network": "tcp"}},
		"username": "u", "password": "p",
		"data_ciphers": []any{"AES-128-GCM"}, "data_ciphers_fallback": "AES-128-GCM",
		"auth": "SHA256", "mtu": 1400.0, "mss_fix": 1340.0, "renegotiate_disabled": true, "allow_compression": "no",
	}
	for k, v := range want {
		if !reflect.DeepEqual(got[k], v) {
			t.Errorf("%s = %#v, want %#v", k, got[k], v)
		}
	}
	tls := got["tls"].(map[string]any)
	wantTLS := map[string]any{
		"remote_certificate_tls": "server", "server_name": "server_AbCd", "server_name_type": "name",
		"version_min": "1.2",
		// OpenSSL names become the spellings Go's TLS layer accepts.
		"cipher": "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", "groups": "X25519:P-256:P-384",
		"certificate":        []any{"-----BEGIN CERTIFICATE-----", "CA", "-----END CERTIFICATE-----"},
		"client_certificate": []any{"-----BEGIN CERTIFICATE-----", "CERT", "-----END CERTIFICATE-----"},
		"client_key":         []any{"-----BEGIN PRIVATE KEY-----", "KEY", "-----END PRIVATE KEY-----"},
		"control_wrap": map[string]any{"type": "tls_crypt_v2", "key": []any{
			"-----BEGIN OpenVPN tls-crypt-v2 client key-----", "WRAP", "-----END OpenVPN tls-crypt-v2 client key-----"}},
	}
	for k, v := range wantTLS {
		if !reflect.DeepEqual(tls[k], v) {
			t.Errorf("tls.%s = %#v, want %#v", k, tls[k], v)
		}
	}
}

// Anything that could weaken or change the tunnel must stop the import, by name.
func TestSingboxEndpointFailsClosed(t *testing.T) {
	cases := []struct{ name, edit, want string }{
		{"unknown directive", "+fragment 1300\n", "fragment"},
		{"tap", "dev tap\n", "tap"},
		{"compression", "+comp-lzo\n", "comp-lzo"},
		{"script", "+up /etc/up.sh\n", "up"},
		{"route", "+redirect-gateway def1\n", "redirect-gateway"},
		{"unknown group", "tls-groups X25519:ffdhe2048\n", "ffdhe2048"},
		{"bad proto", "proto tcp-server\n", "tcp-server"},
		{"bad number", "tun-mtu lots\n", "tun-mtu"},
		{"encrypted key", "-----BEGIN PRIVATE KEY-----\nKEY\n", "encrypted"},
		{"connection block", "+<connection>\n", "connection"},
		{"no ca", "<ca>\n-----BEGIN CERTIFICATE-----\nCA\n-----END CERTIFICATE-----\n</ca>\n", "<ca>"},
		{"two wraps", "+tls-auth-extra\n", "tls-auth-extra"},
	}
	for _, c := range cases {
		text := aliLike
		switch {
		case strings.HasPrefix(c.edit, "+<connection>"):
			text += "<connection>\nremote b.example.net 1194 udp\n</connection>\n"
		case strings.HasPrefix(c.edit, "+"):
			text += strings.TrimPrefix(c.edit, "+")
		case c.name == "encrypted key":
			text = strings.Replace(text, c.edit, "-----BEGIN ENCRYPTED PRIVATE KEY-----\nKEY\n", 1)
		case c.name == "no ca":
			text = strings.Replace(text, c.edit, "", 1)
		default:
			k := strings.Fields(c.edit)[0]
			var out []string
			for _, l := range strings.Split(text, "\n") {
				if strings.HasPrefix(l, k+" ") {
					l = strings.TrimSpace(c.edit)
				}
				out = append(out, l)
			}
			text = strings.Join(out, "\n")
		}
		p, err := Parse([]byte(text))
		if err != nil {
			t.Errorf("%s: ParseProfile: %v", c.name, err)
			continue
		}
		if _, err := Endpoint(p, "ovpn", "u", "p"); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want one naming %q", c.name, err, c.want)
		}
	}
	// Credentials are required when the profile asks for them.
	if _, err := endpointOf(t, aliLike, "", ""); err == nil {
		t.Error("a profile that needs credentials converted without them")
	}
	// A TLS-crypt key is not optional: dropping it must not happen silently.
	p, _ := Parse([]byte(aliLike))
	delete(p.Blocks, "tls-crypt-v2")
	if ep, err := Endpoint(p, "ovpn", "u", "p"); err == nil && ep["tls"].(map[string]any)["control_wrap"] != nil {
		t.Error("control_wrap present without a key")
	}
}
