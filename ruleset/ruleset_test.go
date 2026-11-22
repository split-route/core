package ruleset

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/split-route/core/rules"
)

func pfx(ss ...string) (out []netip.Prefix) {
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return
}

func TestSource(t *testing.T) {
	es := rules.Entries{V4: pfx("5.0.0.0/24", "1.0.0.0/24", "1.0.0.0/24"), V6: pfx("2001:db8::/32"),
		Suffixes: []string{"digikala.com"}, Domains: []string{"api.test.ir", "api.test.ir"}}
	if got := string(Source(es, true)); got != `{"rules":[{"ip_cidr":["1.0.0.0/24","5.0.0.0/24","2001:db8::/32"]},{"domain":["api.test.ir"]},{"domain_suffix":["digikala.com"]}],"version":3}` {
		t.Errorf("full = %s", got)
	}
	// Names only: IP entries in a DNS rule are a deprecated answer filter.
	if got := string(Source(es, false)); got != `{"rules":[{"domain":["api.test.ir"]},{"domain_suffix":["digikala.com"]}],"version":3}` {
		t.Errorf("names = %s", got)
	}
	if got := string(Source(rules.Entries{}, true)); got != `{"rules":[],"version":3}` {
		t.Errorf("empty = %s", got)
	}
}

func TestFiles(t *testing.T) {
	es := rules.Entries{Suffixes: []string{"a.test"}, ASNs: []uint32{13335}}
	f, warn, err := Files("work", rules.Direct, es)
	if err != nil || f["work.json"] == nil || f["work.dns.json"] == nil || !strings.Contains(warn, "AS numbers") {
		t.Errorf("direct: %v %q %v", f, warn, err)
	}
	if f, _, _ := Files("ads", rules.Block, es); f["ads.dns.json"] != nil {
		t.Error("a block list has a names-only twin")
	}
	if _, _, err := Files("x", rules.Direct, rules.Entries{Domains: make([]string, MaxEntries+1)}); err == nil {
		t.Error("an oversized list was accepted")
	}
}

// Rule sets are rewritten in place: sing-box reloads a rewritten file but not a
// replaced one (checked against sing-box 1.14.4).
func TestWriteInPlace(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "rulesets")
	if _, err := Write(dir, "work", rules.Direct, rules.Entries{V4: pfx("5.0.0.0/24")}); err != nil {
		t.Fatal(err)
	}
	p := Path(dir, "work")
	before, _ := os.Stat(p)
	if fi, _ := os.Stat(dir); fi.Mode().Perm() != 0o700 || before.Mode().Perm() != 0o600 {
		t.Errorf("modes: dir %v file %v", fi.Mode().Perm(), before.Mode().Perm())
	}
	if _, err := Write(dir, "work", rules.Direct, rules.Entries{V4: pfx("5.0.0.0/24", "6.0.0.0/24")}); err != nil {
		t.Fatal(err)
	}
	after, _ := os.Stat(p)
	if !os.SameFile(before, after) {
		t.Error("the file was replaced, not rewritten in place")
	}
	if b, _ := os.ReadFile(p); !strings.Contains(string(b), "6.0.0.0/24") {
		t.Errorf("content = %s", b)
	}
	// A list that starts blocking loses its twin.
	if _, err := Write(dir, "work", rules.Block, rules.Entries{V4: pfx("5.0.0.0/24")}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(DNSPath(dir, "work")); !os.IsNotExist(err) {
		t.Errorf("the twin of a block list is still there: %v", err)
	}
}

func TestEnsureAndPrune(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "rulesets")
	if err := Ensure(dir, "a", rules.Direct); err != nil {
		t.Fatal(err)
	}
	if _, err := Write(dir, "a", rules.Direct, rules.Entries{Suffixes: []string{"x.test"}}); err != nil {
		t.Fatal(err)
	}
	if err := Ensure(dir, "a", rules.Direct); err != nil { // keeps what is there
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(Path(dir, "a")); !strings.Contains(string(b), "x.test") {
		t.Error("Ensure replaced an existing file")
	}
	for _, id := range []string{"b", "c"} {
		if err := Ensure(dir, id, rules.Tunnel); err != nil {
			t.Fatal(err)
		}
	}
	other := filepath.Join(dir, "notes.txt")
	os.WriteFile(other, []byte("x"), 0o600)
	if err := Prune(dir, []string{"a", "c"}); err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{Path(dir, "b"), DNSPath(dir, "b")} {
		if _, err := os.Stat(f); !os.IsNotExist(err) {
			t.Errorf("%s survived the prune", f)
		}
	}
	for _, f := range []string{Path(dir, "a"), DNSPath(dir, "c"), other} {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("%s was pruned: %v", f, err)
		}
	}
	if err := Prune(filepath.Join(t.TempDir(), "none"), nil); err != nil {
		t.Errorf("pruning a missing dir: %v", err)
	}
}
