// Package rules holds the routing model: actions and entry validation. It is
// pure: nothing here touches the system.
package rules

import (
	"net/netip"
	"strings"
)

// Action is what happens to traffic that matches a list.
type Action string

const (
	Direct Action = "direct" // leave through the physical network, outside every tunnel
	Block  Action = "block"  // dropped: the connection is rejected
	Tunnel Action = "tunnel" // through a tunnel (the list names one, or the default)
)

// Valid reports whether a is one of the three actions.
func (a Action) Valid() bool { return a == Direct || a == Block || a == Tunnel }

// MinBits: never route anything broader than a /8.
const MinBits = 8

// reserved ranges are never routed: touching them can cut off the LAN, loopback
// or the VPN's own addresses.
var reserved = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("224.0.0.0/3"),
}

// IsReserved reports whether p overlaps a range that is never routed.
func IsReserved(p netip.Prefix) bool {
	list := reserved
	if p.Addr().Is6() {
		list = reserved6
	}
	for _, r := range list {
		if r.Overlaps(p) {
			return true
		}
	}
	return false
}

// ParseEntries parses a custom list's entries. Blank lines and "#" notes are
// skipped. Unlike release lists, a reserved range is an error here: the user
// typed it and should know it has no effect.
func ParseEntries(lines []string) (Entries, error) {
	var es Entries
	for _, l := range lines {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") {
			continue
		}
		e, err := ParseEntry(l)
		if err != nil {
			return Entries{}, err
		}
		es.Add(e)
	}
	return es, nil
}
