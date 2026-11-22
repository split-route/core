package lists

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/split-route/core/rules"
)

func pfx(s string) netip.Prefix { return netip.MustParsePrefix(s) }

func TestParseList(t *testing.T) {
	es, st, err := Parse([]byte("# NAME: x\nIP-CIDR,2.144.0.1/14,no-resolve\nIP-CIDR6,2400::/32,no-resolve\nIP-CIDR6,fe80::/64,no-resolve\n" +
		"DOMAIN-SUFFIX,IR\nDOMAIN,www.example.com\nDOMAIN,../etc\nDOMAIN-KEYWORD,ads\nIP-CIDR,10.0.0.0/8,no-resolve\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := rules.Entries{
		V4:       []netip.Prefix{pfx("2.144.0.0/14")},
		V6:       []netip.Prefix{pfx("2400::/32")},
		Domains:  []string{"www.example.com"},
		Suffixes: []string{"ir"},
	}
	if !reflect.DeepEqual(es, want) {
		t.Fatalf("entries %+v", es)
	}
	if st != (Stats{Reserved: 2, Invalid: 1, Other: 1}) {
		t.Fatalf("stats %+v", st)
	}
	// A poisoned list must fail, not route half the internet outside the VPN.
	for _, bad := range []string{"IP-CIDR,0.0.0.0/1,no-resolve", "IP-CIDR,128.0.0.0/7", "IP-CIDR,nonsense",
		"IP-CIDR6,2000::/3,no-resolve", "IP-CIDR,2400::/32", "IP-CIDR6,1.2.3.0/24"} {
		if _, _, err := Parse([]byte(bad)); err == nil {
			t.Errorf("%q: want error", bad)
		}
	}
}

func TestFetchWithNoNamesTouchesNothing(t *testing.T) {
	out, warn, err := Fetch("http://127.0.0.1:1/never-contacted", t.TempDir(), nil, true)
	if err != nil || len(out) != 0 || len(warn) != 0 {
		t.Errorf("Fetch with no names = %v, %v, %v", out, warn, err)
	}
}
