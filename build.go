package core

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/split-route/core/rules"
	"github.com/split-route/core/ruleset"
)

// Routing, in order: sniff, DNS hijack (tun mode), private addresses direct,
// block lists, direct lists, tunnel lists, then the default tunnel. First match
// wins, so block beats direct beats tunnel.
//
// A tunnel list whose tunnel isn't connected is not sent anywhere else: the
// tunnel's endpoint refuses the connection.

func tunnelTag(id string) string { return "t-" + id }

// Build returns the sing-box config for c. It is pure and deterministic, and it
// does not depend on any list's entries (they live in rule-set files), so
// Reload can tell a change that needs a restart from one that doesn't by
// comparing two Build results.
func Build(c Config) ([]byte, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	remote := c.DNS.Remote
	if remote == "" {
		remote = "1.1.1.1"
	}
	def := c.Default
	if def == "" {
		def = c.Tunnels[0].ID
	}
	dir := ruleset.Dir(c.WorkDir)

	var endpoints []map[string]any
	outbounds := []map[string]any{{"type": "direct", "tag": "direct"}}
	dnsServers := []map[string]any{{"type": "local", "tag": "local"}}
	for _, t := range c.Tunnels {
		p := protocols[t.Protocol]
		o, err := t.options(p)
		if err != nil {
			return nil, fmt.Errorf("tunnel %q: %w", t.ID, err)
		}
		o["tag"] = tunnelTag(t.ID)
		o["domain_resolver"] = "local" // the server's own name must not need a tunnel
		if p.endpoint {
			o["system"] = false // only the engine's tun creates a device
			endpoints = append(endpoints, o)
		} else {
			outbounds = append(outbounds, o)
		}
		dnsServers = append(dnsServers, map[string]any{"type": "udp", "tag": "dns-" + tunnelTag(t.ID), "server": remote, "detour": tunnelTag(t.ID)})
	}

	tun := c.Inbound.Mode != "proxy"
	routeRules := []map[string]any{{"action": "sniff"}}
	if tun {
		routeRules = append(routeRules,
			map[string]any{"protocol": "dns", "action": "hijack-dns"},
			// Strict routing sends the LAN into the tunnel too; keep it local.
			map[string]any{"ip_is_private": true, "action": "route", "outbound": "direct"})
	}
	ruleSets, dnsRules := []map[string]any{}, []map[string]any{}
	declare := func(tag, path string) string {
		ruleSets = append(ruleSets, map[string]any{"type": "local", "tag": tag, "format": "source", "path": path})
		return tag
	}
	for _, tier := range []rules.Action{rules.Block, rules.Direct, rules.Tunnel} {
		for _, l := range c.Lists {
			if l.Action != tier {
				continue
			}
			tag := declare(l.ID, ruleset.Path(dir, l.ID))
			switch tier {
			case rules.Block:
				routeRules = append(routeRules, map[string]any{"rule_set": []string{tag}, "action": "reject"})
			case rules.Direct:
				routeRules = append(routeRules, map[string]any{"rule_set": []string{tag}, "action": "route", "outbound": "direct"})
				// Names the user wants direct resolve on the physical network (right answers
				// for local services); everything else resolves through the tunnel.
				dnsRules = append(dnsRules, map[string]any{"rule_set": []string{declare(l.ID+"-dns", ruleset.DNSPath(dir, l.ID))}, "action": "route", "server": "local"})
			case rules.Tunnel:
				target := l.Tunnel
				if target == "" {
					target = def
				}
				routeRules = append(routeRules, map[string]any{"rule_set": []string{tag}, "action": "route", "outbound": tunnelTag(target)})
				if l.Tunnel != "" { // the default tunnel's resolver is the final one anyway
					dnsRules = append(dnsRules, map[string]any{"rule_set": []string{declare(l.ID+"-dns", ruleset.DNSPath(dir, l.ID))}, "action": "route", "server": "dns-" + tunnelTag(l.Tunnel)})
				}
			}
		}
	}

	level := c.Log.Level
	if level == "" {
		level = "info"
	}
	route := map[string]any{
		"default_domain_resolver": "local",
		"rules":                   routeRules,
		"rule_set":                ruleSets,
		"final":                   tunnelTag(def),
	}
	var inbound map[string]any
	if tun {
		// The engine's own sockets (to the tunnels' servers) must not enter its tun.
		route["auto_detect_interface"] = true
		inbound = map[string]any{"type": "tun", "tag": "tun-in", "address": []string{"172.19.0.1/30"}, "auto_route": true, "strict_route": true, "stack": "system"}
	} else {
		inbound = map[string]any{"type": "mixed", "tag": "proxy-in", "listen": c.Inbound.Listen, "listen_port": c.Inbound.Port}
		if c.Inbound.User != "" {
			inbound["users"] = []map[string]any{{"username": c.Inbound.User, "password": c.Inbound.Pass}}
		}
	}
	cfg := map[string]any{
		"log":          map[string]any{"level": level, "timestamp": true},
		"dns":          map[string]any{"servers": dnsServers, "rules": dnsRules, "final": "dns-" + tunnelTag(def)},
		"inbounds":     []map[string]any{inbound},
		"outbounds":    outbounds,
		"route":        route,
		"experimental": map[string]any{"cache_file": map[string]any{"enabled": true, "path": filepath.Join(c.WorkDir, "cache.db")}},
	}
	if len(endpoints) > 0 {
		cfg["endpoints"] = endpoints
	}
	return json.Marshal(cfg)
}
