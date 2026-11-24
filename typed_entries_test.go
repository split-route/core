package core

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route/rule"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/split-route/core/rules"
	"github.com/split-route/core/ruleset"
)

// The rule-set files for typed entries are read by sing-box itself and match what a user means by each kind: this builds
// them from entries, loads them with sing-box's own rule code, and asks it about connections.
func TestTypedEntriesMatchInSingBox(t *testing.T) {
	es, err := rules.ParseEntries([]string{
		"example.com", "full:www.exact.org", "keyword:tracker", `regexp:^ads[0-9]+\.net$`,
		"203.0.113.0/24", "port:8443", "port:9000-9100",
		"app:/Applications/Foo Bar.app", "process:curl",
	})
	if err != nil {
		t.Fatal(err)
	}
	var compat option.PlainRuleSetCompat
	if err := json.Unmarshal(ruleset.Source(es, true), &compat); err != nil {
		t.Fatal(err)
	}
	plain, err := compat.Upgrade()
	if err != nil {
		t.Fatal(err)
	}
	matches := func(m adapter.InboundContext) bool {
		for _, r := range plain.Rules {
			hr, err := rule.NewHeadlessRule(context.Background(), r)
			if err != nil {
				t.Fatal(err)
			}
			if hr.Match(&m) {
				return true
			}
		}
		return false
	}
	to := func(host string, port uint16) adapter.InboundContext {
		return adapter.InboundContext{Network: "tcp", Destination: M.ParseSocksaddrHostPort(host, port), Domain: host}
	}
	owner := func(path string) adapter.InboundContext {
		return adapter.InboundContext{Network: "tcp", Destination: M.ParseSocksaddrHostPort("198.51.100.9", 80), ProcessInfo: &adapter.ConnectionOwner{ProcessPath: path}}
	}
	for name, tc := range map[string]struct {
		m    adapter.InboundContext
		want bool
	}{
		"suffix itself":             {to("example.com", 80), true},
		"suffix subdomain":          {to("a.example.com", 80), true},
		"not a suffix":              {to("notexample.com", 80), false},
		"exact":                     {to("www.exact.org", 80), true},
		"exact is not a suffix":     {to("a.www.exact.org", 80), false},
		"keyword":                   {to("my-tracker-cdn.io", 80), true},
		"regexp":                    {to("ads42.net", 80), true},
		"regexp is anchored":        {to("xads42.net", 80), false},
		"cidr":                      {adapter.InboundContext{Network: "tcp", Destination: M.ParseSocksaddrHostPort("203.0.113.7", 80)}, true},
		"port":                      {adapter.InboundContext{Network: "tcp", Destination: M.ParseSocksaddrHostPort("198.51.100.9", 8443)}, true},
		"port range":                {adapter.InboundContext{Network: "tcp", Destination: M.ParseSocksaddrHostPort("198.51.100.9", 9050)}, true},
		"just outside range":        {adapter.InboundContext{Network: "tcp", Destination: M.ParseSocksaddrHostPort("198.51.100.9", 9101)}, false},
		"app main program":          {owner("/Applications/Foo Bar.app/Contents/MacOS/Foo Bar"), true},
		"app helper":                {owner("/Applications/Foo Bar.app/Contents/Frameworks/Helper.app/Contents/MacOS/Helper"), true},
		"app at the cryptex path":   {owner("/System/Volumes/Preboot/Cryptexes/App/System/Applications/Foo Bar.app/Contents/MacOS/Foo Bar"), true},
		"app with a longer name":    {owner("/Applications/Foo Bar Pro.app/Contents/MacOS/x"), false},
		"app path is not a pattern": {owner("/Applications/FooXBar.app/Contents/MacOS/x"), false},
		"process name":              {owner("/usr/bin/curl"), true},
		"process name is whole":     {owner("/usr/bin/curlx"), false},
		"nothing":                   {to("other.org", 80), false},
	} {
		if got := matches(tc.m); got != tc.want {
			t.Errorf("%s: matched = %v, want %v", name, got, tc.want)
		}
	}
}

// Naming a program turns process lookup on, and only then.
func TestBuildFindsProcessesOnlyWhenAListNamesPrograms(t *testing.T) {
	c := baseConfig(t)
	c.Lists = []List{{ID: "a", Name: "A", Action: rules.Block}}
	find := func() any {
		b, err := Build(c)
		if err != nil {
			t.Fatal(err)
		}
		return parse(t, b)["route"].(map[string]any)["find_process"]
	}
	if find() == true {
		t.Error("find_process on with no program entries")
	}
	c.Lists[0].Programs = true
	if find() != true {
		t.Error("find_process off although a list names programs")
	}
}
