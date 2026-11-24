package openvpn

import (
	"fmt"
	"strconv"
	"strings"
)

// Endpoint converts a parsed profile into the config of sing-box's
// openvpn-client endpoint. It fails closed: every directive is either
// translated, on the short list of ones that change nothing about security or
// routing here, or refused by name. Dropping remote-cert-tls, verify-x509-name
// or a tls-crypt key silently would leave a tunnel anyone could intercept.
//
// user and pass are put in the endpoint only when the profile asks for them. keyPass opens an encrypted
// private key (see DecryptKey); with the key unencrypted it is ignored.
// sing-box's TLS layer is Go's, so names differ from OpenSSL's; the
// translations below were found by trial against `sing-box check`.
func Endpoint(p Profile, tag, user, pass, keyPass string) (map[string]any, error) {
	if p.Connection {
		return nil, fmt.Errorf("<connection> blocks (options per remote) are not supported by the tunnel engine")
	}
	ep := map[string]any{"type": "openvpn-client", "tag": tag, "mode": "tls", "system": false, "auth_retry": "none"}
	tls := map[string]any{}
	proto := "udp"
	type remote struct {
		host, port, proto string
	}
	var remotes []remote
	var problems []string
	bad := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }
	keyDir := ""
	needs := func(d Directive, n int) bool {
		if len(d.Args) < n {
			bad("%s needs %d argument(s)", d.Name, n)
			return false
		}
		return true
	}
	atoi := func(d Directive, i int) (int, bool) {
		if !needs(d, i+1) {
			return 0, false
		}
		v, err := strconv.Atoi(d.Args[i])
		if err != nil || v < 0 {
			bad("%s: %q is not a number", d.Name, d.Args[i])
			return 0, false
		}
		return v, true
	}
	for _, d := range p.Directives {
		switch d.Name {
		case "client", "tls-client", "pull":
		case "dev":
			if !needs(d, 1) {
				break
			}
			if !strings.HasPrefix(d.Args[0], "tun") {
				bad("dev %s: only tun is supported", d.Args[0])
			}
		case "dev-type":
			if needs(d, 1) && d.Args[0] != "tun" {
				bad("dev-type %s: only tun is supported", d.Args[0])
			}
		case "proto":
			if needs(d, 1) {
				pr, ok := engineProto(d.Args[0])
				if !ok {
					bad("proto %s is not supported", d.Args[0])
				}
				proto = pr
			}
		case "remote":
			if !needs(d, 1) {
				break
			}
			r := remote{host: d.Args[0], port: "1194"}
			if len(d.Args) > 1 {
				r.port = d.Args[1]
			}
			if len(d.Args) > 2 {
				pr, ok := engineProto(d.Args[2])
				if !ok {
					bad("remote protocol %s is not supported", d.Args[2])
				}
				r.proto = pr
			}
			remotes = append(remotes, r)
		case "remote-random":
			ep["remote_random"] = true
		case "data-ciphers", "ncp-ciphers":
			if needs(d, 1) {
				ep["data_ciphers"] = strings.Split(d.Args[0], ":")
			}
		case "cipher", "data-ciphers-fallback":
			if needs(d, 1) {
				ep["data_ciphers_fallback"] = d.Args[0] // TLS mode: only the fallback
			}
		case "auth":
			if needs(d, 1) {
				ep["auth"] = d.Args[0]
			}
		case "tun-mtu":
			if v, ok := atoi(d, 0); ok {
				ep["mtu"] = v
			}
		case "mssfix":
			if len(d.Args) == 0 {
				break
			}
			if v, ok := atoi(d, 0); ok {
				if v == 0 {
					ep["mss_fix_disabled"] = true
				} else {
					ep["mss_fix"] = v
				}
			}
		case "reneg-sec":
			if v, ok := atoi(d, 0); ok {
				if v == 0 {
					ep["renegotiate_disabled"] = true
				} else {
					ep["renegotiate_interval"] = strconv.Itoa(v) + "s"
				}
			}
		case "allow-compression":
			if needs(d, 1) {
				if d.Args[0] != "no" && d.Args[0] != "asym" && d.Args[0] != "yes" {
					bad("allow-compression %s is not supported", d.Args[0])
				} else {
					ep["allow_compression"] = d.Args[0]
				}
			}
		case "keepalive":
			if a, ok := atoi(d, 0); ok {
				if b, ok := atoi(d, 1); ok {
					ep["ping_interval"] = strconv.Itoa(a) + "s"
					ep["ping_restart"] = strconv.Itoa(b) + "s"
				}
			}
		case "ping":
			if v, ok := atoi(d, 0); ok {
				ep["ping_interval"] = strconv.Itoa(v) + "s"
			}
		case "ping-restart":
			if v, ok := atoi(d, 0); ok {
				ep["ping_restart"] = strconv.Itoa(v) + "s"
			}
		case "remote-cert-tls":
			if needs(d, 1) {
				if d.Args[0] != "server" && d.Args[0] != "client" {
					bad("remote-cert-tls %s is not supported", d.Args[0])
				} else {
					tls["remote_certificate_tls"] = d.Args[0]
				}
			}
		case "verify-x509-name":
			if needs(d, 1) {
				typ := "subject"
				if len(d.Args) > 1 {
					typ = d.Args[1]
				}
				if typ != "subject" && typ != "name" && typ != "name-prefix" {
					bad("verify-x509-name type %s is not supported", typ)
				}
				tls["server_name"], tls["server_name_type"] = d.Args[0], typ
			}
		case "tls-version-min":
			if needs(d, 1) {
				tls["version_min"] = d.Args[0]
			}
		case "tls-cipher":
			if needs(d, 1) {
				tls["cipher"] = engineCipherList(d.Args[0])
			}
		case "tls-groups":
			if needs(d, 1) {
				g, err := engineGroups(d.Args[0])
				if err != nil {
					bad("%v", err)
				}
				tls["groups"] = g
			}
		case "key-direction":
			if needs(d, 1) {
				switch d.Args[0] {
				case "0":
					keyDir = "server"
				case "1":
					keyDir = "client"
				default:
					bad("key-direction %s is not supported", d.Args[0])
				}
			}
		case "auth-user-pass":
			// credentials come from the caller
		default:
			if !engineIgnorable[d.Name] {
				bad("%s is not supported by the tunnel engine", d.Name)
			}
		}
	}
	if len(remotes) == 0 {
		bad("the profile has no remote line")
	}
	servers := make([]map[string]any, 0, len(remotes))
	for _, r := range remotes {
		port, err := strconv.Atoi(r.port)
		if err != nil || port < 1 || port > 65535 {
			bad("remote %s: bad port %q", r.host, r.port)
			continue
		}
		pr := r.proto
		if pr == "" {
			pr = proto
		}
		servers = append(servers, map[string]any{"server": r.host, "server_port": port, "network": pr})
	}
	ep["servers"] = servers

	lines := func(name string) []string {
		b := strings.TrimSpace(p.Blocks[name])
		if b == "" {
			return nil
		}
		return strings.Split(b, "\n")
	}
	if ca := lines("ca"); ca != nil {
		tls["certificate"] = ca
	} else {
		bad("the profile has no inline <ca> block")
	}
	cert, key := lines("cert"), lines("key")
	if p.KeyEncrypted && key != nil {
		plain, err := DecryptKey(p.Blocks["key"], keyPass)
		if err != nil {
			return nil, err
		}
		key = strings.Split(strings.TrimSpace(plain), "\n")
	}
	switch {
	case cert != nil && key != nil:
		tls["client_certificate"], tls["client_key"] = cert, key
	case cert != nil || key != nil:
		bad("the profile has a <cert> without a <key>, or the reverse")
	case !p.NeedsAuth:
		bad("the profile has neither a client certificate nor auth-user-pass")
	}
	wraps := 0
	for _, w := range []struct{ block, typ string }{{"tls-crypt-v2", "tls_crypt_v2"}, {"tls-crypt", "tls_crypt"}, {"tls-auth", "tls_auth"}} {
		if l := lines(w.block); l != nil {
			wrap := map[string]any{"type": w.typ, "key": l}
			if w.typ == "tls_auth" && keyDir != "" {
				wrap["direction"] = keyDir
			}
			tls["control_wrap"] = wrap
			wraps++
		}
	}
	if wraps > 1 {
		bad("more than one of tls-crypt-v2, tls-crypt and tls-auth")
	}
	if p.NeedsAuth {
		if user == "" && pass == "" {
			bad("the profile needs a username and password")
		}
		ep["username"], ep["password"] = user, pass
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	ep["tls"] = tls
	return ep, nil
}

// engineIgnorable are directives that change nothing here: logging and process
// behavior, retry timing the engine handles itself, or options for other
// platforms. Everything not translated above and not here is refused.
var engineIgnorable = map[string]bool{
	"verb": true, "mute": true, "nobind": true, "persist-tun": true, "persist-key": true,
	"resolv-retry": true, "socket-flags": true, "ignore-unknown-option": true,
	"tls-ciphersuites": true, "connect-retry": true, "connect-retry-max": true,
	"connect-timeout": true, "hand-window": true, "auth-nocache": true, "explicit-exit-notify": true,
	"block-outside-dns": true, "float": true, "setenv": true, "mute-replay-warnings": true,
}

func engineProto(s string) (string, bool) {
	switch s {
	case "udp", "udp4", "udp6", "tcp", "tcp4", "tcp6":
		return s, true
	case "tcp-client":
		return "tcp", true
	case "udp-client":
		return "udp", true
	}
	return "", false
}

// engineCipherList turns OpenVPN's "TLS-ECDHE-ECDSA-WITH-AES-128-GCM-SHA256"
// into the IANA spelling sing-box's Go TLS accepts; other names pass through.
func engineCipherList(s string) string {
	parts := strings.Split(s, ":")
	for i, c := range parts {
		if strings.HasPrefix(c, "TLS-") {
			parts[i] = strings.ReplaceAll(c, "-", "_")
		}
	}
	return strings.Join(parts, ":")
}

var engineGroupNames = map[string]string{
	"x25519": "X25519", "prime256v1": "P-256", "secp256r1": "P-256", "p-256": "P-256",
	"secp384r1": "P-384", "p-384": "P-384", "secp521r1": "P-521", "p-521": "P-521",
}

func engineGroups(s string) (string, error) {
	parts := strings.Split(s, ":")
	for i, g := range parts {
		n, ok := engineGroupNames[strings.ToLower(g)]
		if !ok {
			return "", fmt.Errorf("tls-groups: %q is not supported by the tunnel engine", g)
		}
		parts[i] = n
	}
	return strings.Join(parts, ":"), nil
}
