//go:build with_openvpn

package core

import (
	"testing"

	"github.com/split-route/core/rules"
	"github.com/split-route/core/ruleset"
)

func TestRouteTest(t *testing.T) {
	dir := shortDir(t)
	write := func(id string, a rules.Action, lines ...string) {
		es, err := rules.ParseEntries(lines)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ruleset.Write(ruleset.Dir(dir), id, a, es); err != nil {
			t.Fatal(err)
		}
	}
	write("ads", rules.Block, "ads.example", "full:exact.example")
	write("work", rules.Direct, "corp.example", "198.51.100.0/24")
	write("tv", rules.Tunnel, "tv.example")
	trojan := func(id string) Tunnel {
		return Tunnel{ID: id, Name: id, Protocol: "trojan", Options: []byte(`{"type":"trojan","server":"a.example.com","server_port":443,"password":"x"}`)}
	}
	cfg := func(final rules.Action, tunnel string) Config {
		return Config{
			Tunnels: []Tunnel{trojan("a"), trojan("b")}, WorkDir: dir, Default: "a", BlockIPv6: true,
			Lists: []List{
				{ID: "ads", Name: "Ads", Action: rules.Block},
				{ID: "work", Name: "Work", Action: rules.Direct},
				{ID: "tv", Name: "TV", Action: rules.Tunnel, Tunnel: "b"},
			},
			Final: Final{Action: final, Tunnel: tunnel},
		}
	}
	type want struct {
		kind, list string
		action     rules.Action
		tunnel     string
	}
	for _, tc := range []struct {
		name  string
		c     Config
		query string
		want  want
	}{
		{"a blocked name", cfg(rules.Tunnel, ""), "tracker.ads.example", want{"list", "Ads", rules.Block, ""}},
		{"the list's own name", cfg(rules.Tunnel, ""), "ads.example", want{"list", "Ads", rules.Block, ""}},
		{"exact is not a suffix", cfg(rules.Tunnel, ""), "a.exact.example", want{"default", "", rules.Tunnel, ""}},
		{"a direct name with a port", cfg(rules.Tunnel, ""), "www.corp.example:8443", want{"list", "Work", rules.Direct, ""}},
		{"a list that names a tunnel", cfg(rules.Direct, ""), "tv.example", want{"list", "TV", rules.Tunnel, "b"}},
		{"an address in a direct list", cfg(rules.Tunnel, ""), "198.51.100.7", want{"list", "Work", rules.Direct, ""}},
		{"the local network", cfg(rules.Tunnel, ""), "192.168.1.20", want{"local", "", rules.Direct, ""}},
		{"IPv6 is refused", cfg(rules.Tunnel, ""), "2001:db8::1", want{"ipv6", "", rules.Block, ""}},
		{"IPv6 with a port", cfg(rules.Tunnel, ""), "[2001:db8::1]:443", want{"ipv6", "", rules.Block, ""}},
		{"no list: the selected server", cfg(rules.Tunnel, ""), "unlisted.example", want{"default", "", rules.Tunnel, ""}},
		{"no list: a named server", cfg(rules.Tunnel, "b"), "unlisted.example", want{"default", "", rules.Tunnel, "b"}},
		{"no list: direct", cfg(rules.Direct, ""), "unlisted.example", want{"default", "", rules.Direct, ""}},
		{"no list: blocked", cfg(rules.Block, ""), "unlisted.example", want{"default", "", rules.Block, ""}},
		{"case and a trailing dot", cfg(rules.Tunnel, ""), "WWW.Corp.Example.", want{"list", "Work", rules.Direct, ""}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := RouteTest(tc.c, tc.query)
			if err != nil {
				t.Fatal(err)
			}
			if (want{got.Kind, got.List, got.Action, got.Tunnel}) != tc.want {
				t.Errorf("got %+v, want %+v", got, tc.want)
			}
		})
	}
	t.Run("IPv6 allowed goes on to the default route", func(t *testing.T) {
		c := cfg(rules.Tunnel, "")
		c.BlockIPv6 = false
		got, err := RouteTest(c, "2001:db8::1")
		if err != nil || got.Kind != "default" {
			t.Errorf("got %+v, %v", got, err)
		}
	})
	for _, bad := range []string{"", "a b", "http://x.example/path", "x..example", "x.example:99999", "user@x.example"} {
		if _, err := RouteTest(cfg(rules.Tunnel, ""), bad); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	t.Run("a list not written yet says so and the walk goes on", func(t *testing.T) {
		c := cfg(rules.Tunnel, "")
		c.Lists = append(c.Lists, List{ID: "late", Name: "Late", Action: rules.Block})
		got, err := RouteTest(c, "unlisted.example")
		if err != nil || got.Kind != "default" || len(got.Notes) < 2 {
			t.Errorf("got %+v, %v", got, err)
		}
	})
}
