package links

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// leafTypes are the sing-box outbound types that are one server. Groups
// (selector, urltest), direct, block and dns are not tunnels.
var leafTypes = map[string]bool{
	"vless": true, "vmess": true, "trojan": true, "shadowsocks": true, "hysteria2": true, "tuic": true, "anytls": true,
}

// parseSingBox reads the outbounds of a sing-box configuration. The options are
// the user's own, so they pass the same checks as any tunnel's (core.CheckTunnel
// refuses file paths and keys that steer the engine's traffic); only the keys
// the engine owns are removed here: a current sing-box export sets
// domain_resolver on every outbound.
func parseSingBox(s string) (Result, error) {
	var c struct {
		Outbounds []map[string]any `json:"outbounds"`
		Endpoints []map[string]any `json:"endpoints"`
	}
	if err := json.Unmarshal([]byte(s), &c); err != nil {
		return Result{}, errors.New("the JSON is malformed")
	}
	if len(c.Outbounds)+len(c.Endpoints) == 0 {
		return Result{}, errors.New("this JSON has no outbounds to import")
	}
	if len(c.Outbounds)+len(c.Endpoints) > MaxNodes {
		return Result{}, fmt.Errorf("more than %d outbounds; import fewer at a time", MaxNodes)
	}
	var res Result
	for _, o := range c.Outbounds {
		typ, _ := o["type"].(string)
		tag, _ := o["tag"].(string)
		switch {
		case leafTypes[typ]:
		case typ == "selector" || typ == "urltest" || typ == "direct" || typ == "block" || typ == "dns":
			continue // not a server; not worth a skip line
		default:
			res.Skipped = append(res.Skipped, Skip{Label: nonEmpty(tag, typ), Reason: fmt.Sprintf("outbound type %q isn't supported", typ)})
			continue
		}
		delete(o, "tag")
		delete(o, "domain_resolver")
		host, _ := o["server"].(string)
		port := portOf(o["server_port"])
		if host == "" || port == 0 {
			res.Skipped = append(res.Skipped, Skip{Label: nonEmpty(tag, typ), Reason: "the server or port is missing"})
			continue
		}
		ep := endpoint{host: host, port: port}
		n := Node{Name: nonEmpty(tag, host), Protocol: typ, Options: o, Server: ep.display()}
		if tls, ok := o["tls"].(map[string]any); ok && tls["insecure"] == true {
			n.Warning = "Certificate checks are off for this server."
		}
		res.Nodes = append(res.Nodes, n)
	}
	for _, e := range c.Endpoints {
		typ, _ := e["type"].(string)
		tag, _ := e["tag"].(string)
		res.Skipped = append(res.Skipped, Skip{Label: nonEmpty(tag, typ), Reason: fmt.Sprintf("%s endpoints aren't supported yet", typ)})
	}
	return res, nil
}

func nonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

func portOf(v any) int {
	switch x := v.(type) {
	case float64:
		if x >= 1 && x <= 65535 {
			return int(x)
		}
	case string:
		if p, err := strconv.Atoi(x); err == nil && p >= 1 && p <= 65535 {
			return p
		}
	}
	return 0
}
