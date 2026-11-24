package lists

import (
	"bufio"
	"bytes"
	"fmt"
	"net/netip"
	"strings"

	"github.com/split-route/core/rules"
)

// MaxImportEntries caps one import. The biggest lists we know (AdGuard, the
// full ads list) are under 200k entries.
const MaxImportEntries = 500_000

// MaxImportRegexes caps the patterns one import may hold: each is matched against every name looked up.
const MaxImportRegexes = 1000

// hostsSkip are names hosts files map to themselves; never list entries.
var hostsSkip = map[string]bool{
	"localhost": true, "localhost.localdomain": true, "local": true, "broadcasthost": true,
	"ip6-localhost": true, "ip6-loopback": true, "ip6-localnet": true, "ip6-mcastprefix": true,
	"ip6-allnodes": true, "ip6-allrouters": true, "ip6-allhosts": true, "0.0.0.0": true,
}

// ParseText reads a third-party list in the plain formats most lists use:
//
//   - one entry per line in rules.ParseEntry syntax (203.0.113.0/24,
//     example.com, full:www.example.com, keyword:google, regexp:^ads[0-9]+\.,
//     port:443, AS13335). app: and process: name programs on one Mac, which a
//     shared list can't know, so they are skipped here and counted;
//   - hosts-file lines ("0.0.0.0 ads.example.com tracker.example.com"): each
//     name is an exact domain, because a hosts file blocks exactly that name;
//   - "#" and "!" comment lines, and "#" comments after an entry;
//   - Surge/Clash domain sets: if any line starts with ".", ".example.com"
//     is the domain and its subdomains and a plain "example.com" is that
//     exact name, as that format means. Without such lines a plain name keeps
//     the rules.ParseEntry meaning (the domain and its subdomains).
//
// Third-party lists contain junk, so a line that isn't valid is skipped and
// counted, not fatal. A range broader than /8 (IPv4) or /16 (IPv6) still
// refuses the whole list, and so does more than MaxImportEntries entries.
// Duplicates are dropped.
func ParseText(b []byte) (rules.Entries, Stats, error) {
	var es rules.Entries
	var st Stats
	seen := map[string]bool{}
	add := func(e rules.Entry) {
		if k := e.String(); !seen[k] {
			seen[k] = true
			es.Add(e)
		}
	}
	var lines []string
	domainSet := false
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 0, 64<<10), 1<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if i := strings.Index(line, "#"); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" || strings.HasPrefix(line, "!") {
			continue
		}
		domainSet = domainSet || strings.HasPrefix(line, ".")
		lines = append(lines, line)
	}
	if err := sc.Err(); err != nil {
		return rules.Entries{}, st, err
	}
	for _, line := range lines {
		f := strings.Fields(line)
		if len(f) > 1 {
			if _, err := netip.ParseAddr(f[0]); err != nil {
				st.Invalid++ // not a hosts line, and entries have no spaces
				continue
			}
			for _, name := range f[1:] {
				if hostsSkip[strings.ToLower(name)] {
					continue
				}
				e, err := rules.DomainEntry(rules.Domain, name)
				if err != nil {
					st.Invalid++
					continue
				}
				add(e)
			}
			continue
		}
		if !rules.HasTypedPrefix(line) && (strings.HasPrefix(line, "||") || strings.ContainsAny(line, "$^|@")) {
			st.Other++ // adblock syntax: its own parser, later
			continue
		}
		if p, ok := prefixOf(line); ok {
			var tmp rules.Entries
			if err := addPrefix(&tmp, &st, p); err != nil {
				return rules.Entries{}, st, err
			}
			for _, q := range append(tmp.V4, tmp.V6...) {
				add(rules.Entry{Kind: rules.CIDR, Prefix: q})
			}
			continue
		}
		var e rules.Entry
		var err error
		switch {
		case domainSet && strings.HasPrefix(line, "."):
			e, err = rules.DomainEntry(rules.DomainSuffix, line[1:])
		case domainSet && !strings.Contains(line, ":") && !strings.HasPrefix(strings.ToUpper(line), "AS"):
			e, err = rules.DomainEntry(rules.Domain, line)
		default:
			e, err = rules.ParseEntry(line)
		}
		if err != nil || e.Kind == rules.App || e.Kind == rules.Process {
			st.Invalid++
			continue
		}
		if e.Kind == rules.Regex && len(es.Regexes) >= MaxImportRegexes {
			st.Other++
			continue
		}
		add(e)
	}
	if n := len(seen); n > MaxImportEntries {
		return rules.Entries{}, st, fmt.Errorf("%d entries; the limit for one import is %d", n, MaxImportEntries)
	}
	return es, st, nil
}

// prefixOf parses an address or a range.
func prefixOf(s string) (netip.Prefix, bool) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		return p, err == nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil || a.Zone() != "" {
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(a, a.BitLen()), true
}
