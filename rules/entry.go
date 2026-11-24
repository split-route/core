package rules

import (
	"fmt"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
)

// Kind is the type of a list entry.
type Kind string

const (
	CIDR         Kind = "cidr"          // an IPv4 or IPv6 address or range
	Domain       Kind = "domain"        // exactly this name
	DomainSuffix Kind = "domain_suffix" // this name and every name under it
	ASN          Kind = "asn"           // every range an autonomous system announces
	Keyword      Kind = "keyword"       // names that contain this word
	Regex        Kind = "regex"         // names that match this regular expression
	Port         Kind = "port"          // a destination port, or a range of ports
	App          Kind = "app"           // every program inside this application (a path)
	Process      Kind = "process"       // programs with this name
)

// Limits that keep a typed entry from matching more than the user meant, or from costing too much to match.
const (
	MinKeyword = 3   // "a" would match half the internet
	MaxRegex   = 200 // characters in one pattern
	maxAppPath = 1024
)

// MinBits6: never route anything broader than an IPv6 /16. Real lists go no
// broader than /26 (private ranges aside), and 2000::/3 is all of the
// public IPv6 internet.
const MinBits6 = 16

// reserved6 ranges are never routed, like the IPv4 reserved ranges.
var reserved6 = []netip.Prefix{
	netip.MustParsePrefix("::/8"),          // unspecified, loopback, IPv4-mapped
	netip.MustParsePrefix("64:ff9b::/96"),  // NAT64
	netip.MustParsePrefix("100::/64"),      // discard
	netip.MustParsePrefix("2001:db8::/32"), // documentation
	netip.MustParsePrefix("fc00::/7"),      // unique local
	netip.MustParsePrefix("fe80::/10"),     // link-local
	netip.MustParsePrefix("fec0::/10"),     // old site-local
	netip.MustParsePrefix("ff00::/8"),      // multicast
}

// Entry is one parsed list entry. Which field is set depends on Kind.
type Entry struct {
	Kind   Kind
	Prefix netip.Prefix // CIDR, masked
	Name   string       // Domain, DomainSuffix, Keyword: lowercase ASCII, no trailing dot; Regex: the pattern; Process: the name; App: the path
	AS     uint32       // ASN
	Port   uint16       // Port: the port, or the first of a range
	PortTo uint16       // Port: the last port of a range; 0 for a single port
}

// String is the entry in the syntax ParseEntry reads.
func (e Entry) String() string {
	switch e.Kind {
	case CIDR:
		if e.Prefix.IsSingleIP() {
			return e.Prefix.Addr().String()
		}
		return e.Prefix.String()
	case Domain:
		return "full:" + e.Name
	case DomainSuffix:
		return e.Name
	case ASN:
		return "AS" + strconv.FormatUint(uint64(e.AS), 10)
	case Keyword:
		return "keyword:" + e.Name
	case Regex:
		return "regexp:" + e.Name
	case Port:
		if e.PortTo != 0 {
			return fmt.Sprintf("port:%d-%d", e.Port, e.PortTo)
		}
		return fmt.Sprintf("port:%d", e.Port)
	case App:
		return "app:" + e.Name
	case Process:
		return "process:" + e.Name
	}
	return ""
}

// ParseEntry reads one entry the way users type it:
//
//	203.0.113.7  198.51.100.0/24  2400:cb00::/32   address or range
//	example.com  *.example.com                     the domain and its subdomains
//	full:example.com                               that name only
//	keyword:google                                 names that contain the word
//	regexp:^ads[0-9]+\.                            names that match the pattern
//	port:443  port:8000-9000                       a destination port or range
//	AS13335                                        an autonomous system
//	app:/Applications/Safari.app                   every program in that application
//	process:curl                                   programs with that name
//
// A reserved range, a range broader than /8 (IPv4) or /16 (IPv6), and an
// invalid or non-ASCII domain are errors.
func ParseEntry(s string) (Entry, error) {
	s = strings.TrimSpace(s)
	if e, ok, err := parseTyped(s); ok {
		return e, err
	}
	if p, ok := parsePrefix(s); ok {
		return CIDREntry(p)
	}
	if n, ok := cutFold(s, "AS"); ok && n != "" && n[0] >= '0' && n[0] <= '9' {
		as, err := strconv.ParseUint(n, 10, 32)
		if err != nil {
			return Entry{}, fmt.Errorf("%q is not a valid AS number", s)
		}
		if reservedASN(uint32(as)) {
			return Entry{}, fmt.Errorf("%q is a private or reserved AS number", s)
		}
		return Entry{Kind: ASN, AS: uint32(as)}, nil
	}
	kind, name := DomainSuffix, s
	if n, ok := cutFold(s, "full:"); ok {
		kind, name = Domain, n
	} else if n, ok := strings.CutPrefix(s, "*."); ok {
		name = n
	}
	return DomainEntry(kind, name)
}

// typedPrefixes are the entries that start with their kind. A line that starts with one is never read as a domain, and
// never mistaken for another list syntax.
var typedPrefixes = []string{"keyword:", "regexp:", "port:", "app:", "process:"}

// HasTypedPrefix is whether s starts with one of the prefixes above.
func HasTypedPrefix(s string) bool {
	for _, p := range typedPrefixes {
		if _, ok := cutFold(s, p); ok {
			return true
		}
	}
	return false
}

// parseTyped reads keyword:, regexp:, port:, app: and process: entries. ok says whether s was one of them.
func parseTyped(s string) (e Entry, ok bool, err error) {
	if v, found := cutFold(s, "keyword:"); found {
		return keywordEntry(v)
	}
	if v, found := cutFold(s, "regexp:"); found {
		return regexEntry(v)
	}
	if v, found := cutFold(s, "port:"); found {
		return portEntry(v)
	}
	if v, found := cutFold(s, "app:"); found {
		return appEntry(v)
	}
	if v, found := cutFold(s, "process:"); found {
		return processEntry(v)
	}
	return Entry{}, false, nil
}

func keywordEntry(v string) (Entry, bool, error) {
	k := strings.ToLower(strings.TrimSpace(v))
	if len(k) < MinKeyword || len(k) > 63 {
		return Entry{}, true, fmt.Errorf("keyword %q: use %d to 63 characters, or it would match too many names", v, MinKeyword)
	}
	for _, c := range []byte(k) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_' || c == '.') {
			return Entry{}, true, fmt.Errorf("keyword %q: only letters, digits, - _ and . are allowed", v)
		}
	}
	return Entry{Kind: Keyword, Name: k}, true, nil
}

func regexEntry(v string) (Entry, bool, error) {
	p := strings.TrimSpace(v)
	if p == "" || len(p) > MaxRegex {
		return Entry{}, true, fmt.Errorf("regexp: use 1 to %d characters", MaxRegex)
	}
	re, err := regexp.Compile(p)
	if err != nil {
		return Entry{}, true, fmt.Errorf("regexp %q is not a valid pattern: %v", p, err)
	}
	if re.MatchString("") {
		return Entry{}, true, fmt.Errorf("regexp %q matches every name, so it would route everything", p)
	}
	return Entry{Kind: Regex, Name: p}, true, nil
}

func portEntry(v string) (Entry, bool, error) {
	v = strings.TrimSpace(v)
	from, to, isRange := strings.Cut(v, "-")
	a, errA := strconv.ParseUint(strings.TrimSpace(from), 10, 16)
	if errA != nil || a == 0 {
		return Entry{}, true, fmt.Errorf("port %q: use a number from 1 to 65535, or a range like 8000-9000", v)
	}
	if !isRange {
		return Entry{Kind: Port, Port: uint16(a)}, true, nil
	}
	b, errB := strconv.ParseUint(strings.TrimSpace(to), 10, 16)
	if errB != nil || b == 0 || b <= a {
		return Entry{}, true, fmt.Errorf("port range %q: the second port must be larger than the first", v)
	}
	return Entry{Kind: Port, Port: uint16(a), PortTo: uint16(b)}, true, nil
}

func appEntry(v string) (Entry, bool, error) {
	p := strings.TrimRight(strings.TrimSpace(v), "/")
	if !strings.HasPrefix(p, "/") || len(p) < 2 || len(p) > maxAppPath || strings.ContainsAny(p, "\x00\n\r") {
		return Entry{}, true, fmt.Errorf("app %q: use the full path of the application, like /Applications/Safari.app", v)
	}
	return Entry{Kind: App, Name: p}, true, nil
}

func processEntry(v string) (Entry, bool, error) {
	n := strings.TrimSpace(v)
	if n == "" || len(n) > 128 || strings.ContainsAny(n, "/\x00\n\r") {
		return Entry{}, true, fmt.Errorf("process %q: use the program's name, without a path", v)
	}
	return Entry{Kind: Process, Name: n}, true, nil
}

// CIDREntry checks p against the /8 and /16 floors and the reserved ranges.
func CIDREntry(p netip.Prefix) (Entry, error) {
	p = p.Masked()
	floor := Floor(p.Addr())
	switch {
	case p.Bits() < floor:
		return Entry{}, fmt.Errorf("%q is broader than /%d", p, floor)
	case IsReserved(p):
		return Entry{}, fmt.Errorf("%q is a private or special range and is never routed", p)
	}
	return Entry{Kind: CIDR, Prefix: p}, nil
}

// DomainEntry validates a domain name for kind Domain or DomainSuffix. Names
// end up in DNS answers, routes and logs, so the check is strict:
// lowercase ASCII letters, digits, "-" and "_" (real lists have it), dot-
// separated labels of 1-63 characters, at most 253 in all, and a last label
// shaped like a TLD (letters only, or punycode "xn--"). A single label is
// allowed: "ir" as a suffix is every .ir name.
func DomainEntry(kind Kind, name string) (Entry, error) {
	n := strings.ToLower(strings.TrimSuffix(name, "."))
	bad := func(why string) (Entry, error) {
		return Entry{}, fmt.Errorf("%q is not an IP address, range, domain or AS number: %s", name, why)
	}
	if n == "" || len(n) > 253 {
		return bad("empty or longer than 253 characters")
	}
	labels := strings.Split(n, ".")
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return bad("each dot-separated part must be 1-63 characters")
		}
		for _, c := range []byte(l) {
			switch {
			case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '_':
			case c >= 0x80:
				return bad("non-ASCII; use the punycode form (xn--...)")
			default:
				return bad(fmt.Sprintf("%q is not allowed", c))
			}
		}
	}
	if tld := labels[len(labels)-1]; !strings.HasPrefix(tld, "xn--") && strings.Trim(tld, "abcdefghijklmnopqrstuvwxyz") != "" {
		return bad("the last part must be letters only, like com or ir")
	}
	return Entry{Kind: kind, Name: n}, nil
}

// Floor is the broadest prefix length routed for a's family.
func Floor(a netip.Addr) int {
	if a.Is6() {
		return MinBits6
	}
	return MinBits
}

func parsePrefix(s string) (netip.Prefix, bool) {
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

func cutFold(s, prefix string) (string, bool) {
	if len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix) {
		return s[len(prefix):], true
	}
	return s, false
}

// reservedASN: 0, AS_TRANS, documentation, private use and the last numbers
// of each range (RFC 6996, 5398, 7300).
func reservedASN(as uint32) bool {
	switch {
	case as == 0, as == 23456, as == 65535, as == 4294967295:
		return true
	case as >= 64496 && as <= 65534: // documentation and private
		return true
	case as >= 65536 && as <= 65551: // documentation
		return true
	case as >= 4200000000: // private
		return true
	}
	return false
}

// Entries is a list's entries grouped by kind.
type Entries struct {
	V4, V6     []netip.Prefix
	Domains    []string // exact names
	Suffixes   []string // names and everything under them
	ASNs       []uint32
	Keywords   []string // words a name contains
	Regexes    []string // patterns a name matches
	Ports      []uint16
	PortRanges []string // "8000:9000", the form sing-box reads
	Apps       []string // application paths
	Processes  []string // program names
}

// Add files e under its kind.
func (es *Entries) Add(e Entry) {
	switch e.Kind {
	case CIDR:
		if e.Prefix.Addr().Is4() {
			es.V4 = append(es.V4, e.Prefix)
		} else {
			es.V6 = append(es.V6, e.Prefix)
		}
	case Domain:
		es.Domains = append(es.Domains, e.Name)
	case DomainSuffix:
		es.Suffixes = append(es.Suffixes, e.Name)
	case ASN:
		es.ASNs = append(es.ASNs, e.AS)
	case Keyword:
		es.Keywords = append(es.Keywords, e.Name)
	case Regex:
		es.Regexes = append(es.Regexes, e.Name)
	case Port:
		if e.PortTo != 0 {
			es.PortRanges = append(es.PortRanges, fmt.Sprintf("%d:%d", e.Port, e.PortTo))
		} else {
			es.Ports = append(es.Ports, e.Port)
		}
	case App:
		es.Apps = append(es.Apps, e.Name)
	case Process:
		es.Processes = append(es.Processes, e.Name)
	}
}

// Count is how many entries there are of every kind.
func (es Entries) Count() int {
	return len(es.V4) + len(es.V6) + len(es.Domains) + len(es.Suffixes) + len(es.ASNs) + len(es.Keywords) + len(es.Regexes) +
		len(es.Ports) + len(es.PortRanges) + len(es.Apps) + len(es.Processes)
}

// MatchesPrograms is whether any entry names a program (an application or a process), which the engine can only match
// by looking up which program owns each connection.
func (es Entries) MatchesPrograms() bool { return len(es.Apps)+len(es.Processes) > 0 }

// All returns the entries one by one, IPv4, IPv6, exact names, suffixes, ASNs.
func (es Entries) All() []Entry {
	out := make([]Entry, 0, es.Count())
	for _, p := range es.V4 {
		out = append(out, Entry{Kind: CIDR, Prefix: p})
	}
	for _, p := range es.V6 {
		out = append(out, Entry{Kind: CIDR, Prefix: p})
	}
	for _, n := range es.Domains {
		out = append(out, Entry{Kind: Domain, Name: n})
	}
	for _, n := range es.Suffixes {
		out = append(out, Entry{Kind: DomainSuffix, Name: n})
	}
	for _, as := range es.ASNs {
		out = append(out, Entry{Kind: ASN, AS: as})
	}
	for _, k := range es.Keywords {
		out = append(out, Entry{Kind: Keyword, Name: k})
	}
	for _, r := range es.Regexes {
		out = append(out, Entry{Kind: Regex, Name: r})
	}
	for _, p := range es.Ports {
		out = append(out, Entry{Kind: Port, Port: p})
	}
	for _, r := range es.PortRanges {
		a, b, _ := strings.Cut(r, ":")
		from, _ := strconv.ParseUint(a, 10, 16)
		to, _ := strconv.ParseUint(b, 10, 16)
		out = append(out, Entry{Kind: Port, Port: uint16(from), PortTo: uint16(to)})
	}
	for _, a := range es.Apps {
		out = append(out, Entry{Kind: App, Name: a})
	}
	for _, p := range es.Processes {
		out = append(out, Entry{Kind: Process, Name: p})
	}
	return out
}

// Unrouted describes the entries route mode can't use yet (everything but
// IPv4), e.g. "2 domains, 1 IPv6". Empty if there are none.
func (es Entries) Unrouted() string {
	var parts []string
	if n := len(es.Domains) + len(es.Suffixes); n > 0 {
		parts = append(parts, fmt.Sprintf("%d domains", n))
	}
	if n := len(es.V6); n > 0 {
		parts = append(parts, fmt.Sprintf("%d IPv6", n))
	}
	if n := len(es.ASNs); n > 0 {
		parts = append(parts, fmt.Sprintf("%d AS numbers", n))
	}
	return strings.Join(parts, ", ")
}
