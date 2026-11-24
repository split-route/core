package core

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route/rule"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/split-route/core/rules"
)

// matcher loads a binary rule-set with sing-box's own rule code: it matches when any rule of the set does.
func matcher(t *testing.T, data []byte) func(adapter.InboundContext) bool {
	t.Helper()
	compat, err := srs.Read(bytes.NewReader(data), true)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := compat.Upgrade()
	if err != nil {
		t.Fatal(err)
	}
	return func(m adapter.InboundContext) bool {
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
}

func conn(host string, port uint16, network, exe string) adapter.InboundContext {
	m := adapter.InboundContext{Network: network, Destination: M.ParseSocksaddrHostPort(host, port), Domain: host}
	if exe != "" {
		m.ProcessInfo = &adapter.ConnectionOwner{ProcessPath: exe}
	}
	return m
}

func TestRuleModesCombineFieldsAsSingBoxDoes(t *testing.T) {
	spec := RuleSpec{DomainSuffix: []string{"example.com"}, Port: []uint16{8443}}
	for name, tc := range map[string]struct {
		spec RuleSpec
		c    adapter.InboundContext
		want bool
	}{
		"or: the name":              {spec, conn("a.example.com", 80, "tcp", ""), true},
		"or: the port":              {spec, conn("other.org", 8443, "tcp", ""), true},
		"or: neither":               {spec, conn("other.org", 80, "tcp", ""), false},
		"and: both":                 {RuleSpec{Mode: "and", DomainSuffix: spec.DomainSuffix, Port: spec.Port}, conn("a.example.com", 8443, "tcp", ""), true},
		"and: only the name":        {RuleSpec{Mode: "and", DomainSuffix: spec.DomainSuffix, Port: spec.Port}, conn("a.example.com", 80, "tcp", ""), false},
		"and: only the port":        {RuleSpec{Mode: "and", DomainSuffix: spec.DomainSuffix, Port: spec.Port}, conn("other.org", 8443, "tcp", ""), false},
		"invert: the name":          {RuleSpec{Invert: true, DomainSuffix: []string{"example.com"}}, conn("a.example.com", 80, "tcp", ""), false},
		"invert: anything else":     {RuleSpec{Invert: true, DomainSuffix: []string{"example.com"}}, conn("other.org", 80, "tcp", ""), true},
		"and + invert":              {RuleSpec{Mode: "and", Invert: true, DomainSuffix: spec.DomainSuffix, Port: spec.Port}, conn("a.example.com", 80, "tcp", ""), true},
		"network":                   {RuleSpec{Network: []string{"udp"}}, conn("x.org", 53, "udp", ""), true},
		"network, other":            {RuleSpec{Network: []string{"udp"}}, conn("x.org", 53, "tcp", ""), false},
		"port range":                {RuleSpec{PortRange: []string{"9000:9100"}}, conn("x.org", 9050, "tcp", ""), true},
		"open port range":           {RuleSpec{PortRange: []string{":1024"}}, conn("x.org", 22, "tcp", ""), true},
		"applications":              {RuleSpec{Applications: []string{"/Applications/Foo.app"}}, conn("x.org", 80, "tcp", "/Applications/Foo.app/Contents/MacOS/Foo"), true},
		"applications, other":       {RuleSpec{Applications: []string{"/Applications/Foo.app"}}, conn("x.org", 80, "tcp", "/Applications/Foobar.app/Contents/MacOS/x"), false},
		"app + own regex":           {RuleSpec{Applications: []string{"/Applications/Foo.app"}, ProcessPathRegex: []string{`^/opt/tool/`}}, conn("x.org", 80, "tcp", "/opt/tool/bin/t"), true},
		"process name":              {RuleSpec{ProcessName: []string{"curl"}}, conn("x.org", 80, "tcp", "/usr/bin/curl"), true},
		"process path":              {RuleSpec{ProcessPath: []string{"/usr/bin/curl"}}, conn("x.org", 80, "tcp", "/usr/bin/curl"), true},
		"app and domain (and)":      {RuleSpec{Mode: "and", Applications: []string{"/Applications/Foo.app"}, DomainSuffix: []string{"example.com"}}, conn("a.example.com", 80, "tcp", "/Applications/Foo.app/Contents/MacOS/Foo"), true},
		"app and domain, other app": {RuleSpec{Mode: "and", Applications: []string{"/Applications/Foo.app"}, DomainSuffix: []string{"example.com"}}, conn("a.example.com", 80, "tcp", "/usr/bin/curl"), false},
	} {
		data, err := CompileRules(tc.spec)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got := matcher(t, data)(tc.c); got != tc.want {
			t.Errorf("%s: matched = %v, want %v", name, got, tc.want)
		}
	}
}

func TestRuleSpecRefusesWhatWouldBeWrong(t *testing.T) {
	for name, s := range map[string]RuleSpec{
		"nothing":                      {},
		"bad mode":                     {Mode: "xor", Domain: []string{"a.com"}},
		"domain with a space":          {Domain: []string{"a b.com"}},
		"keyword too short":            {DomainKeyword: []string{"ab"}},
		"regex that won't compile":     {DomainRegex: []string{"["}},
		"regex matching every name":    {DomainRegex: []string{".*"}},
		"ip that is not one":           {IPCIDR: []string{"example.com"}},
		"range too broad":              {IPCIDR: []string{"0.0.0.0/0"}},
		"port zero":                    {Port: []uint16{0}},
		"backwards port range":         {PortRange: []string{"9000:8000"}},
		"port range, no colon":         {PortRange: []string{"8000"}},
		"process name with a path":     {ProcessName: []string{"/usr/bin/curl"}},
		"relative process path":        {ProcessPath: []string{"usr/bin/curl"}},
		"regex matching every program": {ProcessPathRegex: []string{".*"}},
		"relative application":         {Applications: []string{"Foo.app"}},
		"unknown network":              {Network: []string{"sctp"}},
	} {
		if _, err := CompileRules(s); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestNormalizeRuleSetKeepsABinaryAsItCameAndReadsJSON(t *testing.T) {
	// A binary rule-set with an AdGuard rule: nothing can be said about it as entries, and it must survive untouched.
	adguard := []option.HeadlessRule{
		{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultHeadlessRule{AdGuardDomain: []string{"||ads.example^"}}},
		{Type: C.RuleTypeDefault, DefaultOptions: option.DefaultHeadlessRule{DomainSuffix: []string{"example.org"}, Invert: true}},
	}
	var buf bytes.Buffer
	if err := srs.Write(&buf, option.PlainRuleSet{Rules: adguard}, C.RuleSetVersionCurrent); err != nil {
		t.Fatal(err)
	}
	got, n, err := NormalizeRuleSet(buf.Bytes())
	if err != nil || n != 2 || !bytes.Equal(got, buf.Bytes()) {
		t.Fatalf("a binary rule-set must come back as it was: n=%d err=%v same=%v", n, err, bytes.Equal(got, buf.Bytes()))
	}
	// JSON source becomes the binary file.
	src, _ := json.Marshal(map[string]any{"version": 3, "rules": []map[string]any{{"domain_suffix": []string{"example.net"}, "port": []int{443}, "invert": false}}})
	bin, n, err := NormalizeRuleSet(src)
	if err != nil || n != 1 || !IsRuleSetBinary(bin) {
		t.Fatalf("json source: n=%d err=%v binary=%v", n, err, IsRuleSetBinary(bin))
	}
	for name, bad := range map[string][]byte{
		"not a rule-set":   []byte("example.com\n"),
		"no rules":         []byte(`{"version":3,"rules":[]}`),
		"broken binary":    []byte("SRS\x05not zlib"),
		"unknown version":  []byte(`{"version":99,"rules":[{"domain":["a.com"]}]}`),
		"bad regex inside": []byte(`{"version":3,"rules":[{"domain_regex":["["]}]}`),
	} {
		if _, _, err := NormalizeRuleSet(bad); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestRuleSetFilesForABinaryList(t *testing.T) {
	data, err := CompileRules(RuleSpec{DomainSuffix: []string{"example.com"}, Port: []uint16{443}, Applications: []string{"/Applications/Foo.app"}})
	if err != nil {
		t.Fatal(err)
	}
	files, programs, err := RuleSetFiles("l-1", rules.Direct, data)
	if err != nil || !programs || !bytes.Equal(files["l-1.srs"], data) {
		t.Fatalf("direct: programs=%v err=%v files=%v", programs, err, files)
	}
	twin := string(files["l-1.dns.json"])
	if !strings.Contains(twin, `"domain_suffix":["example.com"]`) || strings.Contains(twin, "port") || strings.Contains(twin, "process") {
		t.Errorf("the names-only twin = %s", twin)
	}
	if files, _, _ := RuleSetFiles("l-1", rules.Block, data); len(files) != 1 {
		t.Errorf("a blocking list has a names-only twin: %v", files)
	}
	plain, err := CompileRules(RuleSpec{Domain: []string{"example.org"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, programs, _ := RuleSetFiles("l-2", rules.Direct, plain); programs {
		t.Error("programs set for a list that names none")
	}
}

func TestBuildDeclaresABinaryListAsBinary(t *testing.T) {
	c := baseConfig(t)
	c.Inbound = Inbound{}
	c.Lists = []List{{ID: "b", Name: "B", Action: rules.Block, Binary: true}, {ID: "s", Name: "S", Action: rules.Block}}
	b, err := Build(c)
	if err != nil {
		t.Fatal(err)
	}
	formats := map[string]string{}
	for _, r := range parse(t, b)["route"].(map[string]any)["rule_set"].([]any) {
		m := r.(map[string]any)
		formats[m["tag"].(string)] = m["format"].(string) + " " + m["path"].(string)
	}
	if !strings.HasPrefix(formats["b"], "binary ") || !strings.HasSuffix(formats["b"], "/b.srs") || !strings.HasPrefix(formats["s"], "source ") {
		t.Errorf("rule_set = %v", formats)
	}
}
