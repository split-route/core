package rules

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func TestParseEntries(t *testing.T) {
	got, err := ParseEntries([]string{" 203.0.113.7 ", "", "# note", "198.51.100.9/24", "Example.COM", "full:api.example.com", "AS13335", "2400:cb00::/32"})
	if err != nil {
		t.Fatal(err)
	}
	want := Entries{
		V4:       []netip.Prefix{pfx("203.0.113.7/32"), pfx("198.51.100.0/24")},
		V6:       []netip.Prefix{pfx("2400:cb00::/32")},
		Domains:  []string{"api.example.com"},
		Suffixes: []string{"example.com"},
		ASNs:     []uint32{13335},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %+v", got)
	}
	if u := got.Unrouted(); u != "2 domains, 1 IPv6, 1 AS numbers" {
		t.Errorf("Unrouted = %q", u)
	}
	if _, err := ParseEntries([]string{"203.0.113.7", "10.0.0.1"}); err == nil {
		t.Error("one bad entry: want error for the list")
	}
}

func TestParseEntry(t *testing.T) {
	ok := []struct{ in, want string }{
		{"203.0.113.7", "203.0.113.7"},
		{"203.0.113.7/32", "203.0.113.7"},
		{"198.51.100.9/24", "198.51.100.0/24"},
		{"2400:cb00::/32", "2400:cb00::/32"},
		{"2a06:98c0::/29", "2a06:98c0::/29"}, // broadest real IPv6 in the lists is /26
		{"example.com", "example.com"},
		{"Example.COM.", "example.com"},
		{"*.example.com", "example.com"},
		{"full:www.example.com", "full:www.example.com"},
		{"FULL:Example.com", "full:example.com"},
		{"xn--mgbai9azgqp6j.xn--mgba3a4f16a", "xn--mgbai9azgqp6j.xn--mgba3a4f16a"},
		{"www.forgotten_dark_angel.tripod.com", "www.forgotten_dark_angel.tripod.com"}, // underscores are in real lists
		{"local", "local"},
		{"AS13335", "AS13335"},
		{"as44244", "AS44244"},
		{"AS4199999999", "AS4199999999"},
	}
	for _, c := range ok {
		e, err := ParseEntry(c.in)
		if err != nil || e.String() != c.want {
			t.Errorf("ParseEntry(%q) = %q, %v; want %q", c.in, e.String(), err, c.want)
		}
	}
	bad := []string{
		"", "1.0.0.0/7", "192.168.1.1", "100.64.0.0/16", // IPv4 floor and reserved
		"2000::/3", "2001:db8::1", "fe80::1", "fd00::/8", "::1", "::ffff:1.2.3.4", // IPv6 floor and reserved
		"fe80::1%en0",                                        // zone
		"../etc/passwd", "a/b.com", "a..com", ".example.com", // path-like names are refused
		"exa mple.com", "*example.com", "*.*.example.com", "example.com:443", "http://example.com",
		"exämple.com", "1.2.3", "300.1.1.1", "full:", "full:1.2.3.4.5",
		strings.Repeat("a", 64) + ".com", strings.Repeat("a.", 127) + "com",
		"AS0", "AS23456", "AS64512", "AS65535", "AS4200000000", "AS4294967296", "AS-1", "AS12x",
	}
	for _, in := range bad {
		if e, err := ParseEntry(in); err == nil {
			t.Errorf("ParseEntry(%q) = %+v, want error", in, e)
		}
	}
}

func TestActionValid(t *testing.T) {
	for a, want := range map[Action]bool{Direct: true, Block: true, Tunnel: true, "vpn": false, "": false, "proxy": false} {
		if a.Valid() != want {
			t.Errorf("Action(%q).Valid() = %v", a, !want)
		}
	}
}
