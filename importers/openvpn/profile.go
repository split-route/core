// Package openvpn reads .ovpn profiles and translates them to the options of
// sing-box's openvpn-client endpoint. It is pure: no files, no network, and
// nothing is started. Parse reports what a profile asks for (credentials,
// script directives) and refuses what can't be handled; Endpoint translates it
// fail-closed.
package openvpn

import (
	"bytes"
	"fmt"
	"slices"
	"strconv"
	"strings"
)

// maxLine is OpenVPN's line buffer minus the terminator.
const maxLine = 255

// MaxProfile is the largest profile accepted (inline certificates and keys
// make them big, but not this big).
const MaxProfile = 1 << 20

// Package openvpn reads .ovpn profiles and translates them to the options of
// sing-box's openvpn-client endpoint. Pure: no files, no network.
//
// Profile is what a .ovpn file says that matters to us.
type Profile struct {
	Remotes        []string // "host:port" of each remote line
	NeedsAuth      bool     // auth-user-pass: the user must supply credentials
	KeyEncrypted   bool     // an inline private key is passphrase-protected
	Scripts        []string // directives that run commands or load code, sorted
	ScriptSecurity int      // script-security level (OpenVPN's default is 1)

	// What the engine that doesn't run OpenVPN (sing-box) needs. Never sent to
	// the app: Blocks holds the client key. The inline credentials block
	// (auth-user-pass) is not kept.
	Directives []Directive       `json:"-"`
	Blocks     map[string]string `json:"-"`
	Connection bool              `json:"-"` // has a <connection> block (per-remote options)
}

// Directive is one config line that passed the checks, with "setenv opt"
// unwrapped and the leading dashes removed.
type Directive struct {
	Name string
	Args []string
}

// owned are directives the daemon must control itself. A profile that sets
// them would break supervision (management, logging, process handling) or
// write files outside the tunnel's directory.
var owned = map[string]bool{
	"management": true, "management-client": true, "management-query-passwords": true,
	"management-hold": true, "management-signal": true, "management-forget-disconnect": true,
	"management-log-cache": true, "management-up-down": true, "management-client-auth": true,
	"management-client-pf": true, "management-client-user": true, "management-client-group": true,
	"management-external-key": true, "management-external-cert": true, "management-query-proxy": true,
	"management-query-remote": true, "management-client-user-group": true,
	"log": true, "log-append": true, "syslog": true, "status": true, "status-version": true,
	"writepid": true, "daemon": true, "config": true, "cd": true, "chroot": true,
	"user": true, "group": true, "tmp-dir": true, "tls-export-cert": true,
	"show-ciphers": true, "show-digests": true, "show-tls": true, "show-engines": true,
	"show-curves": true, "show-groups": true, "genkey": true, "version": true, "help": true,
	"mktun": true, "rmtun": true, "test-crypto": true, "show-gateway": true, "show-net": true,
	"show-net-up": true, "show-pkcs11-ids": true, "show-proxy": true, "dev-node": true,
	"inetd": true, "replay-persist": true, "port-share": true, "ifconfig-pool-persist": true,
	"setenv-safe-file": true,
}

// runsCode are directives that run commands or load code as the user the
// daemon runs as (root). They are allowed after the user confirms them; the
// import lists them first.
var runsCode = map[string]bool{
	"up": true, "down": true, "route-up": true, "route-pre-down": true, "ipchange": true,
	"tls-verify": true, "auth-user-pass-verify": true, "learn-address": true,
	"client-connect": true, "client-disconnect": true, "plugin": true, "engine": true,
	"pkcs11-providers": true, "providers": true, "iproute": true, "tls-crypt-v2-verify": true,
	"dns-updown": true,
}

// fileRef are directives whose argument is a path. The daemon never opens a
// path from a profile; certificates and keys must be inline (<ca>…</ca>).
var fileRef = map[string]bool{
	"ca": true, "cert": true, "key": true, "dh": true, "pkcs12": true, "tls-auth": true,
	"tls-crypt": true, "tls-crypt-v2": true, "crl-verify": true, "extra-certs": true,
	"secret": true, "askpass": true, "auth-user-pass": true, "capath": true,
	"http-proxy-user-pass": true, "client-config-dir": true, "ifconfig-pool-persist": true,
	"auth-gen-token-secret": true,
}

// dataBlocks hold PEM or base64 data, never directives.
var dataBlocks = map[string]bool{
	"ca": true, "cert": true, "key": true, "dh": true, "pkcs12": true, "tls-auth": true,
	"tls-crypt": true, "tls-crypt-v2": true, "crl-verify": true, "extra-certs": true,
	"secret": true, "auth-user-pass": true, "peer-fingerprint": true,
}

// Parse checks a profile and reports what it needs. It refuses
// directives the daemon owns and references to files; scripts are reported
// in Scripts, not refused.
func Parse(text []byte) (Profile, error) {
	var p Profile
	if len(text) == 0 {
		return p, fmt.Errorf("the profile is empty")
	}
	if len(text) > MaxProfile {
		return p, fmt.Errorf("the profile is larger than %d MB", MaxProfile>>20)
	}
	if bytes.IndexByte(text, 0) >= 0 {
		return p, fmt.Errorf("the profile contains a NUL byte")
	}
	// OpenVPN's reader differs from ours on these, and a difference is where
	// a directive hides: it strips a BOM, splits words on \v and \f, and cuts
	// lines at 255 bytes. Refuse them instead of guessing.
	if bytes.HasPrefix(text, []byte("\xef\xbb\xbf")) {
		return p, fmt.Errorf("the profile starts with a byte order mark; save it as plain UTF-8")
	}
	if bytes.ContainsAny(text, "\v\f") {
		return p, fmt.Errorf("the profile contains a form feed or vertical tab")
	}
	var problems []string
	scripts := map[string]bool{}
	sawRemote := false
	var block string // name of the data block being read
	var blockBody strings.Builder
	for n, line := range strings.Split(string(text), "\n") {
		if len(line) > maxLine {
			problems = append(problems, fmt.Sprintf("line %d is longer than %d bytes", n+1, maxLine))
			continue
		}
		// Only what C isspace skips: strings.TrimSpace also strips U+00A0 and
		// U+0085, which OpenVPN doesn't, and that difference hides directives.
		line = strings.Trim(line, " \t\r")
		if block == "" && !strings.HasPrefix(line, "#") && !strings.HasPrefix(line, ";") && !isASCII(line) {
			problems = append(problems, fmt.Sprintf("line %d contains non-ASCII characters outside a comment", n+1))
			continue
		}
		if block != "" {
			// OpenVPN ends a block at a line that starts with the closing tag
			// (anything after it too); require the tag alone so we agree.
			if strings.HasPrefix(line, "</") {
				if line != "</"+block+">" {
					problems = append(problems, fmt.Sprintf("line %d: %q inside <%s>", n+1, line, block))
					continue
				}
				switch block {
				case "key":
					if strings.Contains(blockBody.String(), "ENCRYPTED") {
						p.KeyEncrypted = true
					}
				case "auth-user-pass":
					p.NeedsAuth = true
				}
				if block != "auth-user-pass" {
					if p.Blocks == nil {
						p.Blocks = map[string]string{}
					}
					p.Blocks[block] = blockBody.String()
				}
				block = ""
				blockBody.Reset()
				continue
			}
			blockBody.WriteString(line)
			blockBody.WriteByte('\n')
			continue
		}
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '<' && line[len(line)-1] == '>' && !strings.HasPrefix(line, "</") {
			name := line[1 : len(line)-1]
			if dataBlocks[name] {
				block = name
				continue
			}
			if name == "connection" || name == "/connection" {
				p.Connection = true
				continue // its lines are ordinary directives
			}
			problems = append(problems, fmt.Sprintf("line %d: unknown block <%s>", n+1, name))
			continue
		}
		if strings.HasPrefix(line, "</") {
			if line != "</connection>" {
				problems = append(problems, fmt.Sprintf("line %d: unexpected %s", n+1, line))
			}
			continue
		}
		args, err := tokenize(line)
		if err != nil {
			problems = append(problems, fmt.Sprintf("line %d: %v", n+1, err))
			continue
		}
		if len(args) == 0 {
			continue
		}
		d := strings.TrimLeft(args[0], "-") // OpenVPN accepts "--remote" in a file
		args = args[1:]
		// "setenv opt <option…>" applies the option as if it were on its own line.
		for (d == "setenv" || d == "setenv-safe") && len(args) >= 2 && args[0] == "opt" {
			d, args = strings.TrimLeft(args[1], "-"), args[2:]
		}
		p.Directives = append(p.Directives, Directive{Name: d, Args: args})
		switch {
		case owned[d]:
			problems = append(problems, fmt.Sprintf("line %d: %q is controlled by splitroute and can't be set in a profile", n+1, d))
		case (d == "http-proxy" || d == "socks-proxy") && len(args) >= 3 && args[2] != "auto" && args[2] != "auto-nct" && args[2] != "none":
			problems = append(problems, fmt.Sprintf("line %d: %q reads proxy credentials from a file; the service can't do that", n+1, d))
		case fileRef[d] && len(args) > 0:
			problems = append(problems, fmt.Sprintf("line %d: %q points to a file; put its contents inline (<%s>…</%s>)", n+1, d, d, d))
		case d == "auth-user-pass":
			p.NeedsAuth = true
		case runsCode[d]:
			scripts[d] = true
		case d == "script-security":
			if len(args) > 0 {
				if v, err := strconv.Atoi(args[0]); err == nil {
					p.ScriptSecurity = v
				}
			}
		case d == "remote":
			sawRemote = true
			if len(args) > 0 {
				port := "1194"
				if len(args) > 1 {
					port = args[1]
				}
				p.Remotes = append(p.Remotes, args[0]+":"+port)
			}
		}
	}
	if block != "" {
		problems = append(problems, fmt.Sprintf("block <%s> is not closed", block))
	}
	if !sawRemote {
		problems = append(problems, "the profile has no remote line")
	}
	if len(problems) > 0 {
		return Profile{}, fmt.Errorf("%s", strings.Join(problems, "\n"))
	}
	for s := range scripts {
		p.Scripts = append(p.Scripts, s)
	}
	slices.Sort(p.Scripts)
	return p, nil
}

// tokenize splits a config line like OpenVPN: whitespace separates, "…" and
// '…' group, a backslash escapes the next character (outside single quotes),
// and an unquoted # or ; starts a comment.
func tokenize(line string) ([]string, error) {
	var out []string
	var cur strings.Builder
	has := false
	var quote byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quote != 0:
			switch {
			case c == quote:
				quote = 0
			case c == '\\' && quote == '"' && i+1 < len(line):
				i++
				cur.WriteByte(line[i])
			default:
				cur.WriteByte(c)
			}
		case c == '"' || c == '\'':
			quote, has = c, true
		case c == '\\' && i+1 < len(line):
			i++
			cur.WriteByte(line[i])
			has = true
		case c == ' ' || c == '\t' || c == '\r':
			if has {
				out = append(out, cur.String())
				cur.Reset()
				has = false
			}
		case (c == '#' || c == ';') && !has:
			i = len(line)
		default:
			cur.WriteByte(c)
			has = true
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("unclosed quote")
	}
	if has {
		out = append(out, cur.String())
	}
	return out, nil
}

// ValidName checks a tunnel's display name.
func ValidName(name string) error {
	if name == "" || len(name) > 64 {
		return fmt.Errorf("a tunnel name is 1 to 64 characters")
	}
	if name != strings.TrimSpace(name) {
		return fmt.Errorf("a tunnel name can't start or end with a space")
	}
	for _, r := range name {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("a tunnel name can't contain control characters")
		}
	}
	return nil
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}
