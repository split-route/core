package lists

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/split-route/core/rules"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Real StevenBlack hosts header and first entries.
func TestParseTextHosts(t *testing.T) {
	es, st, err := ParseText(fixture(t, "stevenblack-hosts.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if len(es.V4)+len(es.V6)+len(es.Suffixes)+len(es.ASNs) != 0 {
		t.Fatalf("hosts produced non-exact entries: %+v", es)
	}
	if len(es.Domains) < 20 || es.Domains[0] != "ad-assets.futurecdn.net" {
		t.Fatalf("domains %d, first %q", len(es.Domains), first(es.Domains))
	}
	for _, d := range es.Domains {
		if hostsSkip[d] {
			t.Errorf("kept %q", d)
		}
	}
	if st.Invalid != 0 || st.Other != 0 {
		t.Errorf("stats %+v", st)
	}
}

// Real routing-rules domain set: ".x" suffixes.
func TestParseTextDomainSet(t *testing.T) {
	es, st, err := ParseText(fixture(t, "domainset.txt"))
	if err != nil || st != (Stats{}) {
		t.Fatalf("%v %+v", err, st)
	}
	if len(es.Suffixes) != 15 || es.Suffixes[0] != "1rx.io" || len(es.Domains) != 0 {
		t.Fatalf("got %+v", es)
	}
	// In a domain set a plain name is exact.
	es, _, _ = ParseText([]byte(".ads.example\nexact.example.com\n203.0.113.0/24\nAS13335\nfull:x.example.org\n"))
	want := rules.Entries{
		V4:       es.V4,
		Domains:  []string{"exact.example.com", "x.example.org"},
		Suffixes: []string{"ads.example"},
		ASNs:     []uint32{13335},
	}
	if !reflect.DeepEqual(es, want) || len(es.V4) != 1 {
		t.Fatalf("mixed domain set: %+v", es)
	}
}

func TestParseTextCIDR(t *testing.T) {
	es, st, err := ParseText(fixture(t, "cidr4.txt"))
	if err != nil || len(es.V4) != 12 || st != (Stats{}) {
		t.Fatalf("%d ranges, %+v, %v", len(es.V4), st, err)
	}
}

func TestParseTextMixed(t *testing.T) {
	in := `! AdGuard-style comment
# comment
example.com  # trailing note
Example.com
full:www.example.org
203.0.113.7
198.51.100.9/24
10.0.0.0/8
2400:cb00::/32
AS13335
0.0.0.0 tracker.example.net localhost bad_host..name
||ads.example.com^
not a valid line
exa mple
exämple.com
`
	es, st, err := ParseText([]byte(in))
	if err != nil {
		t.Fatal(err)
	}
	want := rules.Entries{
		V4:       es.V4,
		V6:       es.V6,
		Domains:  []string{"www.example.org", "tracker.example.net"},
		Suffixes: []string{"example.com"},
		ASNs:     []uint32{13335},
	}
	if !reflect.DeepEqual(es, want) || len(es.V4) != 2 || len(es.V6) != 1 {
		t.Fatalf("got %+v", es)
	}
	if st != (Stats{Reserved: 1, Invalid: 4, Other: 1}) {
		t.Fatalf("stats %+v", st)
	}
}

func TestParseTextRefuses(t *testing.T) {
	for _, bad := range []string{"0.0.0.0/1", "example.com\n128.0.0.0/7\n", "2000::/3"} {
		if _, _, err := ParseText([]byte(bad)); err == nil {
			t.Errorf("%q: want error", bad)
		}
	}
	var b strings.Builder
	for i := range MaxImportEntries + 1 {
		b.WriteString("h")
		b.WriteString(strings.Repeat("x", i%3))
		b.WriteString(itoa(i))
		b.WriteString(".example.com\n")
	}
	if _, _, err := ParseText([]byte(b.String())); err == nil || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("over the cap: %v", err)
	}
}

func first(s []string) string {
	if len(s) == 0 {
		return ""
	}
	return s[0]
}

func itoa(i int) string {
	s := ""
	for {
		s = string(rune('0'+i%10)) + s
		if i /= 10; i == 0 {
			return s
		}
	}
}
