package rules

import (
	"strings"
	"testing"
)

func TestTypedEntries(t *testing.T) {
	for in, want := range map[string]string{
		"keyword:Google":                "keyword:google",
		"KEYWORD: tracker ":             "keyword:tracker",
		`regexp:^[a-z]+\.google\.com$`:  `regexp:^[a-z]+\.google\.com$`,
		"port:443":                      "port:443",
		"port:8000-9000":                "port:8000-9000",
		"app:/Applications/Safari.app/": "app:/Applications/Safari.app",
		"process:curl":                  "process:curl",
		"full:www.example.com":          "full:www.example.com",
		"example.com":                   "example.com",
		"203.0.113.0/24":                "203.0.113.0/24",
		"AS13335":                       "AS13335",
	} {
		e, err := ParseEntry(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if got := e.String(); got != want {
			t.Errorf("%q -> %q, want %q", in, got, want)
		}
		if again, err := ParseEntry(e.String()); err != nil || again.String() != e.String() {
			t.Errorf("%q does not read back as itself: %v %v", e.String(), again, err)
		}
	}
}

func TestTypedEntriesRefuseWhatWouldRouteTooMuchOrNothing(t *testing.T) {
	for in, why := range map[string]string{
		"keyword:a":        "too short",
		"keyword:":         "empty",
		"keyword:bad word": "a space",
		"regexp:":          "empty",
		"regexp:[":         "not a pattern",
		"regexp:.*":        "matches every name",
		"regexp:a*":        "matches the empty name",
		"regexp:" + strings.Repeat("a", MaxRegex+1): "too long",
		"port:0":                      "no such port",
		"port:70000":                  "no such port",
		"port:abc":                    "not a number",
		"port:9000-8000":              "backwards",
		"port:9000-9000":              "not a range",
		"app:Applications/Safari.app": "not absolute",
		"app:/":                       "the whole disk",
		"process:/usr/bin/curl":       "a path, not a name",
		"process:":                    "empty",
	} {
		if e, err := ParseEntry(in); err == nil {
			t.Errorf("%q (%s) was accepted as %v", in, why, e)
		}
	}
}

func TestEntriesFileTypedEntriesByKind(t *testing.T) {
	es, err := ParseEntries([]string{"keyword:foo", `regexp:^a`, "port:80", "port:1000-2000", "app:/A.app", "process:p", "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(es.Keywords) != 1 || len(es.Regexes) != 1 || len(es.Ports) != 1 || len(es.PortRanges) != 1 || es.PortRanges[0] != "1000:2000" ||
		len(es.Apps) != 1 || len(es.Processes) != 1 || len(es.Suffixes) != 1 {
		t.Errorf("entries = %+v", es)
	}
	if es.Count() != 7 || !es.MatchesPrograms() {
		t.Errorf("count %d, programs %v", es.Count(), es.MatchesPrograms())
	}
	var back []string
	for _, e := range es.All() {
		back = append(back, e.String())
	}
	if len(back) != 7 {
		t.Errorf("All() gave %v", back)
	}
}
