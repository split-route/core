// Package links turns share links (vless://, vmess://, ss://, ...) and the
// subscription formats that carry them into sing-box outbound options. It does
// not import sing-box: it returns plain maps, and the core validates and runs them.
//
// The rule is the same as for OpenVPN profiles: fail closed, per node. A link
// either maps completely or is skipped with a reason that names what it asked
// for. A security parameter is never dropped: a reality link without its public
// key is refused, not downgraded to plain TLS, and a transport sing-box can't
// run (xhttp, mKCP) is refused instead of falling back to TCP. One bad node
// never rejects the rest of a subscription.
package links

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// MaxNodes is the most nodes one import returns. A subscription with more is
// refused whole: a silent cut would drop the nodes the user expects.
const MaxNodes = 2000

// Node is one tunnel to create.
type Node struct {
	// Name is the node's display name from the link, or its host.
	Name string
	// Protocol is the core protocol name; it equals the sing-box outbound type.
	Protocol string
	// Options are the sing-box outbound options, without a tag.
	Options map[string]any
	// Server is "host:port", for display.
	Server string
	// Warning is something the user should know about this node, or "".
	Warning string
}

// Skip is a link that was not imported. Label never holds credentials.
type Skip struct {
	Label  string
	Reason string
}

// Result is what an import found.
type Result struct {
	Nodes   []Node
	Skipped []Skip
}

var clashRe = regexp.MustCompile(`(?m)^proxies\s*:`)

// Parse reads text as a subscription body or pasted links: a list of share
// links (one per line, or base64 of that), or a sing-box config with outbounds.
// It returns an error only when the text is not any of these; per-node
// problems are in Result.Skipped.
func Parse(text []byte) (Result, error) {
	s := strings.TrimSpace(strings.TrimPrefix(string(text), "\ufeff"))
	if s == "" {
		return Result{}, errors.New("nothing to import")
	}
	if strings.HasPrefix(s, "{") {
		return parseSingBox(s)
	}
	if clashRe.MatchString(s) {
		return Result{}, errors.New("this is a Clash configuration, which isn't supported yet; use a link list or sing-box format")
	}
	lines := splitLines(s)
	if !anyLink(lines) {
		raw, ok := decodeBase64(s)
		if !ok {
			return Result{}, errors.New("not a list of share links (vless://, vmess://, trojan://, ss://, hysteria2://, tuic://, anytls://)")
		}
		lines = splitLines(string(raw))
		if !anyLink(lines) {
			return Result{}, errors.New("not a list of share links (vless://, vmess://, trojan://, ss://, hysteria2://, tuic://, anytls://)")
		}
	}
	var res Result
	for _, line := range lines {
		if len(res.Nodes)+len(res.Skipped) >= MaxNodes {
			return Result{}, fmt.Errorf("more than %d links; import fewer at a time", MaxNodes)
		}
		n, err := ParseLink(line)
		if err != nil {
			res.Skipped = append(res.Skipped, Skip{Label: label(line), Reason: err.Error()})
			continue
		}
		res.Nodes = append(res.Nodes, n)
	}
	return res, nil
}

func splitLines(s string) []string {
	var out []string
	for _, l := range strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == '\r' }) {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

func anyLink(lines []string) bool {
	for _, l := range lines {
		if strings.Contains(l, "://") {
			return true
		}
	}
	return false
}

// label names a link in a skip message without its credentials: the scheme and
// the host, or the fragment name when there is one.
func label(line string) string {
	scheme, rest, ok := strings.Cut(line, "://")
	if !ok {
		return "(not a link)"
	}
	if i := strings.LastIndex(line, "#"); i >= 0 {
		if name, err := url.PathUnescape(line[i+1:]); err == nil && name != "" {
			return truncate(name, 48)
		}
	}
	if i := strings.LastIndex(rest, "@"); i >= 0 {
		rest = rest[i+1:]
	}
	if i := strings.IndexAny(rest, "/?#"); i >= 0 {
		rest = rest[:i]
	}
	if len(rest) > 48 || scheme == "vmess" || (scheme == "ss" && !strings.Contains(rest, ".")) {
		return scheme + "://…" // opaque base64 body: nothing safe to show
	}
	return scheme + "://" + rest
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

// decodeBase64 decodes standard or URL-safe base64, padded or not, ignoring
// whitespace inside it (subscriptions wrap lines).
func decodeBase64(s string) ([]byte, bool) {
	s = strings.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, s)
	s = strings.TrimRight(s, "=")
	for _, enc := range []*base64.Encoding{base64.RawStdEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(s); err == nil {
			return b, true
		}
	}
	return nil, false
}

// ParseLink maps one share link. Its error says what is not supported and never
// repeats the link.
func ParseLink(line string) (Node, error) {
	line = strings.TrimSpace(line)
	scheme, _, ok := strings.Cut(line, "://")
	if !ok {
		return Node{}, errors.New("not a link")
	}
	switch strings.ToLower(scheme) {
	case "vless":
		return parseVLESS(line)
	case "vmess":
		return parseVMess(line)
	case "trojan":
		return parseTrojan(line)
	case "ss":
		return parseShadowsocks(line)
	case "hysteria2", "hy2":
		return parseHysteria2(line)
	case "tuic":
		return parseTUIC(line)
	case "anytls":
		return parseAnyTLS(line)
	}
	return Node{}, fmt.Errorf("%s:// links aren't supported", scheme)
}

// ---- shared pieces ----

type endpoint struct {
	host string
	port int
}

func (e endpoint) display() string { return net.JoinHostPort(e.host, strconv.Itoa(e.port)) }

func hostPort(host, port string) (endpoint, error) {
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return endpoint{}, errors.New("the port is missing or out of range")
	}
	if host == "" {
		return endpoint{}, errors.New("the server is missing")
	}
	return endpoint{host: host, port: p}, nil
}

// parseURL splits a link into its URL and display name.
func parseURL(line string) (*url.URL, endpoint, string, error) {
	u, err := url.Parse(line)
	if err != nil {
		return nil, endpoint{}, "", errors.New("malformed link")
	}
	ep, err := hostPort(u.Hostname(), u.Port())
	if err != nil {
		return nil, endpoint{}, "", err
	}
	name := u.Fragment // url.Parse already percent-decoded it
	if strings.TrimSpace(name) == "" {
		name = ep.host
	}
	return u, ep, strings.TrimSpace(name), nil
}

func truthy(s string) bool { return s == "1" || strings.EqualFold(s, "true") }

var utlsFingerprints = map[string]bool{
	"chrome": true, "firefox": true, "edge": true, "safari": true, "360": true, "qq": true,
	"ios": true, "android": true, "random": true, "randomized": true,
}

// tlsOptions maps the TLS part of a link. defaultSecurity is used when the link
// says nothing (trojan and the QUIC protocols are always TLS).
func tlsOptions(q url.Values, defaultSecurity string) (opts map[string]any, insecure bool, err error) {
	sec := q.Get("security")
	if sec == "" {
		sec = defaultSecurity
	}
	switch sec {
	case "none", "":
		return nil, false, nil
	case "tls", "reality":
	default:
		return nil, false, fmt.Errorf("security %q isn't supported", sec)
	}
	t := map[string]any{"enabled": true}
	for _, k := range []string{"sni", "peer", "serverName"} {
		if v := q.Get(k); v != "" {
			t["server_name"] = v
			break
		}
	}
	if v := q.Get("alpn"); v != "" {
		t["alpn"] = splitList(v)
	}
	if truthy(q.Get("allowInsecure")) || truthy(q.Get("insecure")) || truthy(q.Get("allow_insecure")) {
		t["insecure"] = true
		insecure = true
	}
	fp := q.Get("fp")
	if fp != "" && !utlsFingerprints[fp] {
		return nil, false, fmt.Errorf("TLS fingerprint %q isn't supported", fp)
	}
	if sec == "reality" {
		pbk := q.Get("pbk")
		if pbk == "" {
			return nil, false, errors.New("a reality link has no public key (pbk): refusing to fall back to plain TLS")
		}
		if t["server_name"] == nil {
			return nil, false, errors.New("a reality link has no server name (sni)")
		}
		if fp == "" {
			fp = "chrome"
		}
		t["reality"] = map[string]any{"enabled": true, "public_key": pbk, "short_id": q.Get("sid")}
	}
	if fp != "" {
		t["utls"] = map[string]any{"enabled": true, "fingerprint": fp}
	}
	return t, insecure, nil
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// transport is the v2ray transport of a link.
type transport struct{ net, host, path, service, header string }

func transportOf(q url.Values) transport {
	return transport{net: q.Get("type"), host: q.Get("host"), path: q.Get("path"), service: q.Get("serviceName"), header: q.Get("headerType")}
}

func (t transport) options() (map[string]any, error) {
	switch strings.ToLower(t.net) {
	case "", "tcp", "raw":
		if t.header != "" && t.header != "none" {
			return nil, fmt.Errorf("TCP header %q (HTTP obfuscation) isn't supported", t.header)
		}
		return nil, nil
	case "ws", "websocket":
		path := t.path
		o := map[string]any{"type": "ws"}
		if p, query, ok := strings.Cut(path, "?"); ok {
			v, err := url.ParseQuery(query)
			if err == nil && v.Get("ed") != "" {
				if ed, err := strconv.Atoi(v.Get("ed")); err == nil && ed > 0 {
					o["max_early_data"] = ed
					o["early_data_header_name"] = "Sec-WebSocket-Protocol"
					v.Del("ed")
					path = p
					if rest := v.Encode(); rest != "" {
						path += "?" + rest
					}
				}
			}
		}
		if path != "" {
			o["path"] = path
		}
		if t.host != "" {
			o["headers"] = map[string]any{"Host": t.host}
		}
		return o, nil
	case "grpc":
		return map[string]any{"type": "grpc", "service_name": t.service}, nil
	case "h2", "http":
		o := map[string]any{"type": "http"}
		if t.host != "" {
			o["host"] = splitList(t.host)
		}
		if t.path != "" {
			o["path"] = t.path
		}
		return o, nil
	case "httpupgrade":
		o := map[string]any{"type": "httpupgrade"}
		if t.host != "" {
			o["host"] = t.host
		}
		if t.path != "" {
			o["path"] = t.path
		}
		return o, nil
	}
	return nil, fmt.Errorf("transport %q isn't supported by the engine", t.net)
}

func outbound(typ string, ep endpoint, fields map[string]any, tls map[string]any, tr map[string]any) map[string]any {
	o := map[string]any{"type": typ, "server": ep.host, "server_port": ep.port}
	for k, v := range fields {
		if s, ok := v.(string); ok && s == "" {
			continue
		}
		o[k] = v
	}
	if tls != nil {
		o["tls"] = tls
	}
	if tr != nil {
		o["transport"] = tr
	}
	return o
}

func node(name, typ string, ep endpoint, opts map[string]any, insecure bool) Node {
	n := Node{Name: name, Protocol: typ, Options: opts, Server: ep.display()}
	if insecure {
		n.Warning = "Certificate checks are off for this server."
	}
	return n
}

// ---- protocols ----

func parseVLESS(line string) (Node, error) {
	u, ep, name, err := parseURL(line)
	if err != nil {
		return Node{}, err
	}
	q := u.Query()
	if u.User == nil || u.User.Username() == "" {
		return Node{}, errors.New("the user id is missing")
	}
	if e := q.Get("encryption"); e != "" && e != "none" {
		// The value can carry key material: say what it is, never repeat it.
		return Node{}, errors.New("VLESS encryption (the encryption= parameter) isn't supported")
	}
	flow := q.Get("flow")
	if flow != "" && flow != "xtls-rprx-vision" {
		return Node{}, fmt.Errorf("flow %q isn't supported (only xtls-rprx-vision)", flow)
	}
	tls, insecure, err := tlsOptions(q, "none")
	if err != nil {
		return Node{}, err
	}
	tr, err := transportOf(q).options()
	if err != nil {
		return Node{}, err
	}
	o := outbound("vless", ep, map[string]any{"uuid": u.User.Username(), "flow": flow}, tls, tr)
	return node(name, "vless", ep, o, insecure), nil
}

func parseTrojan(line string) (Node, error) {
	u, ep, name, err := parseURL(line)
	if err != nil {
		return Node{}, err
	}
	q := u.Query()
	if u.User == nil || u.User.Username() == "" {
		return Node{}, errors.New("the password is missing")
	}
	pw := u.User.Username()
	if p, ok := u.User.Password(); ok {
		pw += ":" + p
	}
	tls, insecure, err := tlsOptions(q, "tls")
	if err != nil {
		return Node{}, err
	}
	tr, err := transportOf(q).options()
	if err != nil {
		return Node{}, err
	}
	o := outbound("trojan", ep, map[string]any{"password": pw}, tls, tr)
	return node(name, "trojan", ep, o, insecure), nil
}

// parseVMess reads the v2rayN form: vmess:// and base64 of a JSON object.
func parseVMess(line string) (Node, error) {
	body := strings.TrimPrefix(line, line[:len("vmess://")])
	if i := strings.Index(body, "#"); i >= 0 {
		body = body[:i]
	}
	raw, ok := decodeBase64(body)
	if !ok {
		return Node{}, errors.New("this vmess:// form isn't supported (only the base64 JSON form)")
	}
	var j map[string]any
	if err := json.Unmarshal(raw, &j); err != nil {
		return Node{}, errors.New("the vmess link's JSON is malformed")
	}
	str := func(k string) string {
		switch v := j[k].(type) {
		case string:
			return strings.TrimSpace(v)
		case float64:
			return strconv.FormatFloat(v, 'f', -1, 64)
		}
		return ""
	}
	ep, err := hostPort(str("add"), str("port"))
	if err != nil {
		return Node{}, err
	}
	id := str("id")
	if id == "" {
		return Node{}, errors.New("the user id is missing")
	}
	alter := 0
	if a := str("aid"); a != "" {
		if alter, err = strconv.Atoi(a); err != nil || alter < 0 {
			return Node{}, errors.New("alter id (aid) isn't a number")
		}
	}
	sec := str("scy")
	if sec == "" {
		sec = "auto"
	}
	q := url.Values{}
	q.Set("type", str("net"))
	q.Set("host", str("host"))
	q.Set("path", str("path"))
	if strings.EqualFold(str("net"), "grpc") {
		q.Set("serviceName", str("path")) // v2rayN keeps the gRPC service name in "path"
	}
	switch str("type") {
	case "", "none":
	default:
		if n := strings.ToLower(str("net")); n == "" || n == "tcp" {
			q.Set("headerType", str("type"))
		}
	}
	tr, err := transportOf(q).options()
	if err != nil {
		return Node{}, err
	}
	var tls map[string]any
	insecure := false
	if t := str("tls"); t != "" && t != "none" {
		tq := url.Values{"security": {"tls"}, "sni": {str("sni")}, "alpn": {str("alpn")}, "fp": {str("fp")}, "allowInsecure": {str("allowInsecure")}}
		if t != "tls" {
			tq.Set("security", t)
		}
		if tls, insecure, err = tlsOptions(tq, "tls"); err != nil {
			return Node{}, err
		}
	}
	name := str("ps")
	if name == "" {
		name = ep.host
	}
	o := outbound("vmess", ep, map[string]any{"uuid": id, "security": sec, "alter_id": alter}, tls, tr)
	return node(name, "vmess", ep, o, insecure), nil
}

// parseShadowsocks reads SIP002 (ss://base64url(method:password)@host:port, or
// the same with the userinfo percent-encoded for 2022 ciphers) and the legacy
// form (the whole body in base64).
func parseShadowsocks(line string) (Node, error) {
	body := line[len("ss://"):]
	name := ""
	if i := strings.LastIndex(body, "#"); i >= 0 {
		name, _ = url.PathUnescape(body[i+1:])
		body = body[:i]
	}
	query := ""
	if i := strings.Index(body, "?"); i >= 0 {
		query = body[i+1:]
		body = strings.TrimSuffix(body[:i], "/")
	}
	body = strings.TrimSuffix(body, "/")
	var userinfo, hp string
	if i := strings.LastIndex(body, "@"); i >= 0 {
		userinfo, hp = body[:i], body[i+1:]
		if dec, err := url.PathUnescape(userinfo); err == nil && strings.Contains(dec, ":") {
			userinfo = dec
		} else if raw, ok := decodeBase64(userinfo); ok {
			userinfo = string(raw)
		}
	} else {
		raw, ok := decodeBase64(body)
		if !ok {
			return Node{}, errors.New("malformed ss:// link")
		}
		i := strings.LastIndex(string(raw), "@")
		if i < 0 {
			return Node{}, errors.New("malformed ss:// link")
		}
		userinfo, hp = string(raw[:i]), string(raw[i+1:])
	}
	method, password, ok := strings.Cut(userinfo, ":")
	if !ok || method == "" {
		return Node{}, errors.New("the cipher or password is missing")
	}
	host, port, err := net.SplitHostPort(hp)
	if err != nil {
		return Node{}, errors.New("the server address is malformed")
	}
	ep, err := hostPort(host, port)
	if err != nil {
		return Node{}, err
	}
	fields := map[string]any{"method": method, "password": password}
	if query != "" {
		q, err := url.ParseQuery(query)
		if err != nil {
			return Node{}, errors.New("malformed ss:// options")
		}
		if p := q.Get("plugin"); p != "" {
			plugin, opts, _ := strings.Cut(p, ";")
			switch plugin {
			case "obfs-local", "simple-obfs":
				plugin = "obfs-local"
			case "v2ray-plugin":
			default:
				return Node{}, fmt.Errorf("shadowsocks plugin %q isn't supported", plugin)
			}
			fields["plugin"] = plugin
			fields["plugin_opts"] = opts
		}
	}
	if strings.TrimSpace(name) == "" {
		name = ep.host
	}
	return node(strings.TrimSpace(name), "shadowsocks", ep, outbound("shadowsocks", ep, fields, nil, nil), false), nil
}

func parseHysteria2(line string) (Node, error) {
	u, ep, name, err := parseURL(line)
	if err != nil {
		return Node{}, err
	}
	q := u.Query()
	if q.Get("pinSHA256") != "" {
		return Node{}, errors.New("certificate pinning (pinSHA256) isn't supported: refusing to connect without it")
	}
	pw := ""
	if u.User != nil {
		pw = u.User.Username()
		if p, ok := u.User.Password(); ok {
			pw += ":" + p
		}
	}
	tq := url.Values{"security": {"tls"}, "sni": {q.Get("sni")}, "insecure": {q.Get("insecure")}, "alpn": {q.Get("alpn")}}
	tls, insecure, err := tlsOptions(tq, "tls")
	if err != nil {
		return Node{}, err
	}
	fields := map[string]any{"password": pw}
	switch obfs := q.Get("obfs"); obfs {
	case "":
	case "salamander":
		fields["obfs"] = map[string]any{"type": "salamander", "password": q.Get("obfs-password")}
	default:
		return Node{}, fmt.Errorf("obfuscation %q isn't supported", obfs)
	}
	if m := q.Get("mport"); m != "" {
		fields["server_ports"] = splitPorts(m)
	}
	return node(name, "hysteria2", ep, outbound("hysteria2", ep, fields, tls, nil), insecure), nil
}

// splitPorts maps "20000-30000,40000" to sing-box's "20000:30000".
func splitPorts(s string) []string {
	var out []string
	for _, p := range splitList(s) {
		out = append(out, strings.ReplaceAll(p, "-", ":"))
	}
	return out
}

func parseTUIC(line string) (Node, error) {
	u, ep, name, err := parseURL(line)
	if err != nil {
		return Node{}, err
	}
	q := u.Query()
	if u.User == nil || u.User.Username() == "" {
		return Node{}, errors.New("the user id is missing")
	}
	pw, _ := u.User.Password()
	tq := url.Values{"security": {"tls"}, "sni": {q.Get("sni")}, "alpn": {q.Get("alpn")}, "allow_insecure": {q.Get("allow_insecure")}, "insecure": {q.Get("insecure")}}
	tls, insecure, err := tlsOptions(tq, "tls")
	if err != nil {
		return Node{}, err
	}
	fields := map[string]any{"uuid": u.User.Username(), "password": pw,
		"congestion_control": q.Get("congestion_control"), "udp_relay_mode": q.Get("udp_relay_mode")}
	return node(name, "tuic", ep, outbound("tuic", ep, fields, tls, nil), insecure), nil
}

func parseAnyTLS(line string) (Node, error) {
	u, ep, name, err := parseURL(line)
	if err != nil {
		return Node{}, err
	}
	q := u.Query()
	if u.User == nil || u.User.Username() == "" {
		return Node{}, errors.New("the password is missing")
	}
	tq := url.Values{"security": {"tls"}, "sni": {q.Get("sni")}, "alpn": {q.Get("alpn")}, "insecure": {q.Get("insecure")}, "fp": {q.Get("fp")}}
	tls, insecure, err := tlsOptions(tq, "tls")
	if err != nil {
		return Node{}, err
	}
	return node(name, "anytls", ep, outbound("anytls", ep, map[string]any{"password": u.User.Username()}, tls, nil), insecure), nil
}
