package core

import (
	"bytes"
	"sort"
	"strings"
	"testing"

	"github.com/sagernet/sing-box/common/srs"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

func srsBytes(t *testing.T, rules ...option.HeadlessRule) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := srs.Write(&buf, option.PlainRuleSet{Rules: rules}, C.RuleSetVersionCurrent); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func def(d option.DefaultHeadlessRule) option.HeadlessRule {
	return option.HeadlessRule{Type: C.RuleTypeDefault, DefaultOptions: d}
}

func TestRuleSetText(t *testing.T) {
	data := srsBytes(t,
		def(option.DefaultHeadlessRule{
			Domain:        []string{"exact.example.com"},
			DomainSuffix:  []string{"example.org", "sub.example.net"},
			DomainKeyword: []string{"track"},
			DomainRegex:   []string{`^ads\d+\.`},
			IPCIDR:        []string{"203.0.113.0/24", "2001:db8::/32"},
		}),
		def(option.DefaultHeadlessRule{DomainSuffix: []string{"inverted.example"}, Invert: true}),
		def(option.DefaultHeadlessRule{DomainSuffix: []string{"port-only.example"}, Port: []uint16{443}}),
		option.HeadlessRule{Type: C.RuleTypeLogical, LogicalOptions: option.LogicalHeadlessRule{Mode: C.LogicalTypeAnd}},
	)
	if !IsRuleSetBinary(data) || IsRuleSetBinary([]byte("example.com\n")) {
		t.Fatal("magic check")
	}
	text, skipped, err := RuleSetText(data)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Fields(text)
	sort.Strings(got)
	want := []string{"2001:db8::/32", "203.0.113.0/24", "example.org", "full:exact.example.com", "sub.example.net"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("entries = %v, want %v", got, want)
	}
	// keyword + regex (2), the inverted rule, the port rule and the logical rule.
	if skipped != 5 {
		t.Errorf("skipped = %d, want 5", skipped)
	}
	if _, _, err := RuleSetText([]byte("SRSnot a rule-set")); err == nil {
		t.Error("a broken rule-set was accepted")
	}
}
