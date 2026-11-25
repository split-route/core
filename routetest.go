package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/srs"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route/rule"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/split-route/core/rules"
)

// RouteResult says where a connection to a name or address would go.
type RouteResult struct {
	// Kind is what decided: "list", "local" (the local network), "ipv6" (refused), or "default" (no list matched).
	Kind string
	// List is the list's name when Kind is "list".
	List string
	// Action is direct, block or tunnel. Tunnel is the tunnel's ID when it names one; empty is the selected tunnel.
	Action rules.Action
	Tunnel string
	// Notes say what a typed name can't show: it is only matched by name, never resolved, and rules about a program or
	// about sniffed traffic (QUIC, STUN) need a real connection.
	Notes []string
}

// RouteTest walks the route rules that Build makes for c, in their order, for a connection (TCP) to query: a name or an
// address, with an optional port ("example.com", "203.0.113.5", "example.com:8443", "[2001:db8::1]:443"). The lists'
// rule-set files are read from c.WorkDir, where the engine reads them, so this answers what the engine would do now.
// Walking Build's own output keeps the order the same as the engine's.
func RouteTest(c Config, query string) (RouteResult, error) {
	host, port, ip, err := parseRouteQuery(query)
	if err != nil {
		return RouteResult{}, err
	}
	built, err := Build(c)
	if err != nil {
		return RouteResult{}, err
	}
	var cfg struct {
		Route struct {
			Rules   []map[string]any `json:"rules"`
			RuleSet []struct {
				Tag    string `json:"tag"`
				Format string `json:"format"`
				Path   string `json:"path"`
			} `json:"rule_set"`
			Final string `json:"final"`
		} `json:"route"`
	}
	if err := json.Unmarshal(built, &cfg); err != nil {
		return RouteResult{}, err
	}
	paths := map[string][2]string{}
	for _, s := range cfg.Route.RuleSet {
		paths[s.Tag] = [2]string{s.Format, s.Path}
	}
	names := map[string]string{}
	for _, l := range c.Lists {
		names[l.ID] = l.Name
	}
	ictx := adapter.InboundContext{Network: "tcp"}
	if ip.IsValid() {
		ictx.Destination = M.SocksaddrFrom(ip, port)
	} else {
		ictx.Destination = M.ParseSocksaddrHostPort(host, port)
		ictx.Domain = host
	}
	res := RouteResult{Notes: []string{"Matched as a TCP connection. A name is matched by name only: lists of addresses apply to the address a program connects to."}}
	outcome := func(r map[string]any) (rules.Action, string) {
		if r["action"] == "reject" {
			return rules.Block, ""
		}
		return outboundAction(c, fmt.Sprint(r["outbound"]))
	}
	for _, r := range cfg.Route.Rules {
		switch {
		case r["action"] == "sniff" || r["action"] == "hijack-dns" || r["protocol"] != nil:
			continue // needs a real connection to read the protocol
		case r["ip_is_private"] == true:
			if ip.IsValid() && (ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast()) {
				res.Kind, res.Action = "local", rules.Direct
				return res, nil
			}
		case r["ip_version"] == float64(6):
			if ip.IsValid() && ip.Is6() && !ip.Is4In6() {
				res.Kind, res.Action = "ipv6", rules.Block
				return res, nil
			}
		case r["network"] == "udp":
			continue // QUIC: a TCP connection isn't one
		case r["rule_set"] != nil:
			tags, _ := r["rule_set"].([]any)
			for _, tg := range tags {
				tag := fmt.Sprint(tg)
				p, ok := paths[tag]
				if !ok {
					continue
				}
				hit, err := ruleSetMatches(p[0], p[1], &ictx)
				if err != nil {
					res.Notes = append(res.Notes, fmt.Sprintf("%s: %v", names[tag], err))
					continue
				}
				if hit {
					res.Kind, res.List = "list", names[tag]
					res.Action, res.Tunnel = outcome(r)
					return res, nil
				}
			}
		case r["action"] == "reject": // the default route's block: matches whatever is left
			res.Kind, res.Action = "default", rules.Block
			return res, nil
		}
	}
	res.Kind = "default"
	res.Action, res.Tunnel = outboundAction(c, cfg.Route.Final)
	return res, nil
}

// outboundAction turns an outbound tag of the built config back into what it means.
func outboundAction(c Config, tag string) (rules.Action, string) {
	switch tag {
	case "direct":
		return rules.Direct, ""
	case selectorTag:
		return rules.Tunnel, ""
	}
	for _, t := range c.Tunnels {
		if tunnelTag(t.ID) == tag {
			return rules.Tunnel, t.ID
		}
	}
	return rules.Block, ""
}

// ruleSetMatches reads a list's rule-set file the way the engine does and says whether any of its rules matches.
func ruleSetMatches(format, path string, m *adapter.InboundContext) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return false, fmt.Errorf("the list isn't loaded yet")
	}
	var compat option.PlainRuleSetCompat
	if format == "binary" {
		if compat, err = srs.Read(bytes.NewReader(data), true); err != nil {
			return false, err
		}
	} else if err := json.Unmarshal(data, &compat); err != nil {
		return false, err
	}
	plain, err := compat.Upgrade()
	if err != nil {
		return false, err
	}
	for _, r := range plain.Rules {
		hr, err := rule.NewHeadlessRule(context.Background(), r)
		if err != nil {
			return false, err
		}
		if hr.Match(m) {
			return true, nil
		}
	}
	return false, nil
}

// parseRouteQuery reads "name", "name:port", "1.2.3.4", "1.2.3.4:443" or "[v6]:443".
func parseRouteQuery(q string) (host string, port uint16, ip netip.Addr, err error) {
	q = strings.TrimSpace(q)
	if q == "" || len(q) > 300 || strings.ContainsAny(q, " \t\r\n/\\@") {
		return "", 0, netip.Addr{}, fmt.Errorf("type a domain name or an IP address, like example.com or 203.0.113.5")
	}
	port = 443
	if ap, e := netip.ParseAddrPort(q); e == nil {
		return ap.Addr().String(), ap.Port(), ap.Addr().Unmap(), nil
	}
	if a, e := netip.ParseAddr(strings.Trim(q, "[]")); e == nil {
		return a.String(), port, a.Unmap(), nil
	}
	if i := strings.LastIndex(q, ":"); i > 0 && strings.Count(q, ":") == 1 {
		p, e := strconv.Atoi(q[i+1:])
		if e != nil || p < 1 || p > 65535 {
			return "", 0, netip.Addr{}, fmt.Errorf("%q is not a port", q[i+1:])
		}
		port, q = uint16(p), q[:i]
	}
	q = strings.ToLower(strings.TrimSuffix(q, "."))
	if q == "" || len(q) > 253 || strings.HasPrefix(q, ".") || strings.Contains(q, "..") {
		return "", 0, netip.Addr{}, fmt.Errorf("that is not a domain name")
	}
	for _, r := range q {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '.' || r == '_' || r > 127) {
			return "", 0, netip.Addr{}, fmt.Errorf("that is not a domain name")
		}
	}
	return q, port, netip.Addr{}, nil
}
