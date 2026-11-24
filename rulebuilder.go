package core

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/route/rule"
	"github.com/split-route/core/rules"
	"github.com/split-route/core/ruleset"
)

// RuleSpec is a rule built from fields, the way sing-box describes one: the fields keep sing-box's own names
// (domain, domain_suffix, domain_keyword, domain_regex, ip_cidr, port, port_range, process_name, process_path,
// process_path_regex, network) and mean what they mean there. Mode says how the fields combine: "or" (the default: a
// connection matching any field matches the rule) or "and" (it must match every field). Invert negates the whole
// rule. Applications is the one addition: application paths picked from Finder, matched as the application and
// everything inside it (compiled to process_path_regex).
type RuleSpec struct {
	Mode   string `json:"mode,omitempty"`
	Invert bool   `json:"invert,omitempty"`

	Domain        []string `json:"domain,omitempty"`
	DomainSuffix  []string `json:"domain_suffix,omitempty"`
	DomainKeyword []string `json:"domain_keyword,omitempty"`
	DomainRegex   []string `json:"domain_regex,omitempty"`
	IPCIDR        []string `json:"ip_cidr,omitempty"`

	Port      []uint16 `json:"port,omitempty"`
	PortRange []string `json:"port_range,omitempty"` // "8000:9000"

	ProcessName      []string `json:"process_name,omitempty"`
	ProcessPath      []string `json:"process_path,omitempty"`
	ProcessPathRegex []string `json:"process_path_regex,omitempty"`
	Applications     []string `json:"applications,omitempty"`

	Network []string `json:"network,omitempty"` // tcp, udp, icmp
}

// MaxRuleValues bounds the values of one rule, like an import's entry limit.
const MaxRuleValues = 100_000

// Empty is whether no field has a value.
func (s RuleSpec) Empty() bool {
	return len(s.Domain)+len(s.DomainSuffix)+len(s.DomainKeyword)+len(s.DomainRegex)+len(s.IPCIDR)+len(s.Port)+len(s.PortRange)+
		len(s.ProcessName)+len(s.ProcessPath)+len(s.ProcessPathRegex)+len(s.Applications)+len(s.Network) == 0
}

// Programs is whether the rule looks at which program a connection comes from.
func (s RuleSpec) Programs() bool {
	return len(s.ProcessName)+len(s.ProcessPath)+len(s.ProcessPathRegex)+len(s.Applications) > 0
}

// Validate checks every value the way the engine will use it, and says which one is wrong.
func (s RuleSpec) Validate() error {
	if s.Mode != "" && s.Mode != "or" && s.Mode != "and" {
		return fmt.Errorf("mode must be or or and, not %q", s.Mode)
	}
	if s.Empty() {
		return fmt.Errorf("add at least one value")
	}
	n := 0
	for _, f := range s.fields() {
		n += len(f.values)
		for _, v := range f.values {
			if err := f.check(v); err != nil {
				return fmt.Errorf("%s: %w", f.name, err)
			}
		}
	}
	if n > MaxRuleValues {
		return fmt.Errorf("%d values; the limit is %d", n, MaxRuleValues)
	}
	return nil
}

type specField struct {
	name   string
	values []string
	check  func(string) error
	apply  func(*option.DefaultHeadlessRule, []string)
}

// entry checks a value as the list-entry parser would, for the kind that `prefix` names.
func entry(prefix string, want rules.Kind) func(string) error {
	return func(v string) error {
		e, err := rules.ParseEntry(prefix + strings.TrimSpace(v))
		if err != nil {
			return err
		}
		if e.Kind != want {
			return fmt.Errorf("%q is not valid here", v)
		}
		return nil
	}
}

func (s RuleSpec) fields() []specField {
	ports := make([]string, len(s.Port))
	for i, p := range s.Port {
		ports[i] = strconv.Itoa(int(p))
	}
	return []specField{
		{"domain", s.Domain, entry("full:", rules.Domain), func(d *option.DefaultHeadlessRule, v []string) { d.Domain = lowered(v) }},
		{"domain_suffix", s.DomainSuffix, entry("", rules.DomainSuffix), func(d *option.DefaultHeadlessRule, v []string) { d.DomainSuffix = lowered(v) }},
		{"domain_keyword", s.DomainKeyword, entry("keyword:", rules.Keyword), func(d *option.DefaultHeadlessRule, v []string) { d.DomainKeyword = lowered(v) }},
		{"domain_regex", s.DomainRegex, entry("regexp:", rules.Regex), func(d *option.DefaultHeadlessRule, v []string) { d.DomainRegex = trimmed(v) }},
		{"ip_cidr", s.IPCIDR, entry("", rules.CIDR), func(d *option.DefaultHeadlessRule, v []string) { d.IPCIDR = trimmed(v) }},
		{"port", ports, func(v string) error {
			if p, err := strconv.ParseUint(v, 10, 16); err != nil || p == 0 {
				return fmt.Errorf("%q is not a port from 1 to 65535", v)
			}
			return nil
		}, func(d *option.DefaultHeadlessRule, _ []string) { d.Port = s.Port }},
		{"port_range", s.PortRange, checkPortRange, func(d *option.DefaultHeadlessRule, v []string) { d.PortRange = trimmed(v) }},
		{"process_name", s.ProcessName, entry("process:", rules.Process), func(d *option.DefaultHeadlessRule, v []string) { d.ProcessName = trimmed(v) }},
		{"process_path", s.ProcessPath, func(v string) error {
			if p := strings.TrimSpace(v); !strings.HasPrefix(p, "/") || len(p) > 1024 || strings.ContainsAny(p, "\x00\n\r") {
				return fmt.Errorf("%q is not an absolute path", v)
			}
			return nil
		}, func(d *option.DefaultHeadlessRule, v []string) { d.ProcessPath = trimmed(v) }},
		{"process_path_regex", s.ProcessPathRegex, func(v string) error {
			re, err := regexp.Compile(strings.TrimSpace(v))
			if err != nil {
				return fmt.Errorf("%q is not a valid pattern: %v", v, err)
			}
			if strings.TrimSpace(v) == "" || re.MatchString("") {
				return fmt.Errorf("%q matches every program", v)
			}
			return nil
		}, func(d *option.DefaultHeadlessRule, v []string) { d.ProcessPathRegex = v }},
		{"applications", s.Applications, entry("app:", rules.App), nil}, // joins process_path_regex when compiled
		{"network", s.Network, func(v string) error {
			if v != "tcp" && v != "udp" && v != "icmp" {
				return fmt.Errorf("%q is not tcp, udp or icmp", v)
			}
			return nil
		}, func(d *option.DefaultHeadlessRule, v []string) { d.Network = v }},
	}
}

func lowered(in []string) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = strings.TrimPrefix(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(v)), "*"), ".")
	}
	return out
}

func trimmed(in []string) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = strings.TrimSpace(v)
	}
	return out
}

// checkPortRange reads sing-box's "8000:9000" (either side may be left out: ":9000", "8000:").
func checkPortRange(v string) error {
	a, b, ok := strings.Cut(strings.TrimSpace(v), ":")
	if !ok {
		return fmt.Errorf("%q: write a range like 8000:9000", v)
	}
	var from, to uint64 = 0, 65535
	var err error
	if a != "" {
		if from, err = strconv.ParseUint(a, 10, 16); err != nil {
			return fmt.Errorf("%q is not a port range", v)
		}
	}
	if b != "" {
		if to, err = strconv.ParseUint(b, 10, 16); err != nil {
			return fmt.Errorf("%q is not a port range", v)
		}
	}
	if a == "" && b == "" || from >= to {
		return fmt.Errorf("%q: the second port must be larger than the first", v)
	}
	return nil
}

// applicationPatterns are the process_path_regex patterns of Applications: the application's path and everything
// under it, with or without a prefix (the system may report a program's real location, a cryptex path for some Apple apps).
func (s RuleSpec) applicationPatterns() []string {
	var out []string
	for _, a := range s.Applications {
		out = append(out, "(^|/)"+regexp.QuoteMeta(strings.TrimPrefix(strings.TrimRight(strings.TrimSpace(a), "/"), "/"))+"(/|$)")
	}
	return out
}

// headless builds the rules sing-box reads: one default rule per field, joined as Mode says.
func (s RuleSpec) headless() ([]option.HeadlessRule, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	var subs []option.HeadlessRule
	for _, f := range s.fields() {
		if f.apply == nil {
			continue
		}
		values := f.values
		if f.name == "process_path_regex" { // the applications are patterns of this same field
			values = append(trimmed(values), s.applicationPatterns()...)
		}
		if len(values) == 0 {
			continue
		}
		var d option.DefaultHeadlessRule
		f.apply(&d, values)
		subs = append(subs, option.HeadlessRule{Type: C.RuleTypeDefault, DefaultOptions: d})
	}
	mode := s.Mode
	if mode == "" {
		mode = "or"
	}
	switch {
	case len(subs) == 1 && !s.Invert:
		return subs, nil
	case len(subs) == 1:
		subs[0].DefaultOptions.Invert = true
		return subs, nil
	case mode == "or" && !s.Invert:
		return subs, nil // a rule-set matches if any of its rules does
	}
	lm := C.LogicalTypeOr
	if mode == "and" {
		lm = C.LogicalTypeAnd
	}
	return []option.HeadlessRule{{Type: C.RuleTypeLogical, LogicalOptions: option.LogicalHeadlessRule{Mode: lm, Rules: subs, Invert: s.Invert}}}, nil
}

// CompileRules builds a rule from fields into sing-box's binary rule-set.
func CompileRules(s RuleSpec) ([]byte, error) {
	hr, err := s.headless()
	if err != nil {
		return nil, err
	}
	return writeRuleSet(hr)
}

func writeRuleSet(rs []option.HeadlessRule) ([]byte, error) {
	var buf bytes.Buffer
	if err := srs.Write(&buf, option.PlainRuleSet{Rules: rs}, C.RuleSetVersionCurrent); err != nil {
		return nil, fmt.Errorf("rule-set: %w", err)
	}
	if err := checkRules(rs); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// checkRules loads every rule the way the engine will, so a rule-set that can't run is refused when it is added.
func checkRules(rs []option.HeadlessRule) error {
	for i, r := range rs {
		if _, err := rule.NewHeadlessRule(context.Background(), r); err != nil {
			return fmt.Errorf("rule %d: %w", i+1, err)
		}
	}
	return nil
}

// IsRuleSetBinary is whether data is a sing-box binary rule-set (.srs): they start with "SRS".
func IsRuleSetBinary(data []byte) bool { return bytes.HasPrefix(data, srs.MagicBytes[:]) }

// MaxRuleSetBytes bounds one rule-set file.
const MaxRuleSetBytes = 16 << 20

// NormalizeRuleSet reads a rule-set as people share them, a binary .srs or sing-box's JSON source, checks that the engine
// can run it, and returns it as the binary file the engine reads. A binary one is returned as it came: nothing in it
// is changed, so everything sing-box supports in a rule-set is supported here, and the number of rules.
func NormalizeRuleSet(data []byte) (srsData []byte, nRules int, err error) {
	if len(data) > MaxRuleSetBytes {
		return nil, 0, fmt.Errorf("the rule-set is larger than %d MB", MaxRuleSetBytes>>20)
	}
	var compat option.PlainRuleSetCompat
	if IsRuleSetBinary(data) {
		compat, err = srs.Read(bytes.NewReader(data), true)
		if err != nil {
			return nil, 0, fmt.Errorf("rule-set: %w", err)
		}
		srsData = data
	} else {
		if err := json.Unmarshal(data, &compat); err != nil {
			return nil, 0, fmt.Errorf("this is not a sing-box rule-set (.srs or JSON): %w", err)
		}
	}
	plain, err := compat.Upgrade()
	if err != nil {
		return nil, 0, fmt.Errorf("rule-set: %w", err)
	}
	if len(plain.Rules) == 0 {
		return nil, 0, fmt.Errorf("the rule-set has no rules")
	}
	if srsData == nil {
		if srsData, err = writeRuleSet(plain.Rules); err != nil {
			return nil, 0, err
		}
	} else if err := checkRules(plain.Rules); err != nil {
		return nil, 0, err
	}
	return srsData, len(plain.Rules), nil
}

// RuleSetFiles are the files the engine reads for a list that is a binary rule-set: <id>.srs and, unless the list
// blocks, the names-only twin the DNS rules use. programs says whether any rule looks at the program a connection comes from.
func RuleSetFiles(id string, action rules.Action, srsData []byte) (files map[string][]byte, programs bool, err error) {
	compat, err := srs.Read(bytes.NewReader(srsData), true)
	if err != nil {
		return nil, false, fmt.Errorf("rule-set: %w", err)
	}
	plain, err := compat.Upgrade()
	if err != nil {
		return nil, false, fmt.Errorf("rule-set: %w", err)
	}
	files = map[string][]byte{id + ".srs": srsData}
	if action != rules.Block {
		twin, _ := json.Marshal(map[string]any{"version": 3, "rules": namesOnly(plain.Rules)})
		files[id+".dns.json"] = twin
	}
	return files, needsPrograms(plain.Rules), nil
}

// namesOnly keeps what names a domain, from the rules that match on their own: the DNS rules use it to pick a resolver
// for a name, and an address, a port or a program says nothing about that. A logical rule is kept only if it is an
// or, and not inverted.
func namesOnly(rs []option.HeadlessRule) []map[string]any {
	out := []map[string]any{}
	for _, r := range rs {
		switch r.Type {
		case C.RuleTypeLogical:
			if r.LogicalOptions.Mode == C.LogicalTypeOr && !r.LogicalOptions.Invert {
				out = append(out, namesOnly(r.LogicalOptions.Rules)...)
			}
		default:
			d := r.DefaultOptions
			if d.Invert {
				continue
			}
			m := map[string]any{}
			if len(d.Domain) > 0 {
				m["domain"] = []string(d.Domain)
			}
			if len(d.DomainSuffix) > 0 {
				m["domain_suffix"] = []string(d.DomainSuffix)
			}
			if len(d.DomainKeyword) > 0 {
				m["domain_keyword"] = []string(d.DomainKeyword)
			}
			if len(d.DomainRegex) > 0 {
				m["domain_regex"] = []string(d.DomainRegex)
			}
			if len(m) > 0 {
				out = append(out, m)
			}
		}
	}
	return out
}

func needsPrograms(rs []option.HeadlessRule) bool {
	for _, r := range rs {
		if r.Type == C.RuleTypeLogical {
			if needsPrograms(r.LogicalOptions.Rules) {
				return true
			}
			continue
		}
		d := r.DefaultOptions
		if len(d.ProcessName)+len(d.ProcessPath)+len(d.ProcessPathRegex) > 0 {
			return true
		}
	}
	return false
}

// EnsureRuleSetFile makes sure a binary list has a file the engine can load before it has any content: an empty rule-set.
func EnsureRuleSetFile(dir, id string, action rules.Action) error {
	files, _, err := RuleSetFiles(id, action, emptyRuleSet())
	if err != nil {
		return err
	}
	return ruleset.WriteFiles(dir, id, files)
}

func emptyRuleSet() []byte {
	var buf bytes.Buffer
	_ = srs.Write(&buf, option.PlainRuleSet{}, C.RuleSetVersionCurrent)
	return buf.Bytes()
}
