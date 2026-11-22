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
//
// Everything that names no tunnel (the final route, and lists with no tunnel of
// their own) goes to one selector, selectorTag, whose members are all the tunnels.
// Which member it uses is chosen at run time (Engine.Select), not here: Build's
// output does not depend on Config.Default, so changing the default tunnel is a
// switch of the selector, never a restart.

func tunnelTag(id string) string { return "t-" + id }

// cachePath is sing-box's cache file, inside the work directory.
func cachePath(workDir string) string { return filepath.Join(workDir, "cache.db") }

// selectorTag is the selector outbound that carries all traffic with no tunnel of its own.
const selectorTag = "selected"

// bootstrapTag is the DNS server that finds proxy tunnels' servers by name.
const bootstrapTag = "dns-bootstrap"

// dnsSelectorTag is the DNS server that resolves through the selector.
const dnsSelectorTag = "dns-selected"

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
	bootstrap := c.DNS.Bootstrap
	if bootstrap == "" {
		bootstrap = "1.1.1.1"
	}
	dir := ruleset.Dir(c.WorkDir)

	// Tunnels that a list names get a resolver of their own; everything else
	// resolves through the selector.
	named := map[string]bool{}
	for _, l := range c.Lists {
		if l.Action == rules.Tunnel && l.Tunnel != "" {
			named[l.Tunnel] = true
		}
	}

	var endpoints []map[string]any
	outbounds := []map[string]any{{"type": "direct", "tag": "direct"}}
	dnsServers := []map[string]any{{"type": "local", "tag": "local"},
		{"type": "udp", "tag": dnsSelectorTag, "server": remote, "detour": selectorTag}}
	if bootstrap != BootstrapSystem {
		// The server's own name is looked up here: over HTTPS to a public address, direct
		// (not through a tunnel, which isn't up yet), so a filtered name isn't poisoned.
		dnsServers = append(dnsServers, map[string]any{"type": "https", "tag": bootstrapTag, "server": bootstrap, "path": "/dns-query"})
	}
	members := make([]string, 0, len(c.Tunnels))
	for _, t := range c.Tunnels {
		p := protocols[t.Protocol]
		o, err := t.options(p)
		if err != nil {
			return nil, fmt.Errorf("tunnel %q: %w", t.ID, err)
		}
		o["tag"] = tunnelTag(t.ID)
		o["domain_resolver"] = "local" // the server's own name must not need a tunnel
		if !p.endpoint && bootstrap != BootstrapSystem {
			o["domain_resolver"] = bootstrapTag
		}
		if p.endpoint {
			o["system"] = false // only the engine's tun creates a device
			endpoints = append(endpoints, o)
		} else {
			outbounds = append(outbounds, o)
		}
		members = append(members, tunnelTag(t.ID))
		if named[t.ID] {
			dnsServers = append(dnsServers, map[string]any{"type": "udp", "tag": "dns-" + tunnelTag(t.ID), "server": remote, "detour": tunnelTag(t.ID)})
		}
	}
	// interrupt_exist_connections: after a switch, connections that were open
	// through the old tunnel are closed, so nothing keeps using it.
	outbounds = append(outbounds, map[string]any{"type": "selector", "tag": selectorTag, "outbounds": members, "interrupt_exist_connections": true})

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
				target := selectorTag
				if l.Tunnel != "" {
					target = tunnelTag(l.Tunnel)
				}
				routeRules = append(routeRules, map[string]any{"rule_set": []string{tag}, "action": "route", "outbound": target})
				if l.Tunnel != "" { // the selector's resolver is the final one anyway
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
		"final":                   selectorTag,
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
		"log":       map[string]any{"level": level, "timestamp": true},
		"dns":       map[string]any{"servers": dnsServers, "rules": dnsRules, "final": dnsSelectorTag},
		"inbounds":  []map[string]any{inbound},
		"outbounds": outbounds,
		"route":     route,
		// sing-box turns a cache file on by itself when the host passes a log writer (the
		// engine does), and without a path it opens "cache.db" in the working directory:
		// "/" for a service under launchd, which is read-only. So the path is always ours.
		// It would also keep the selector's last choice; Engine.start removes the file first.
		"experimental": map[string]any{"cache_file": map[string]any{"enabled": true, "path": cachePath(c.WorkDir)}},
	}
	if len(endpoints) > 0 {
		cfg["endpoints"] = endpoints
	}
	return json.Marshal(cfg)
}
