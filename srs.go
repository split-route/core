package core

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/sagernet/sing-box/common/srs"
	"github.com/sagernet/sing-box/option"
)

// IsRuleSetBinary is whether data is a sing-box binary rule-set (.srs): they start with "SRS".
func IsRuleSetBinary(data []byte) bool { return bytes.HasPrefix(data, srs.MagicBytes[:]) }

// RuleSetText reads a sing-box binary rule-set (.srs) as list text, one entry per line, in the syntax the list
// parsers read (a domain is "full:name", a domain with subdomains is the bare name, an address range is CIDR).
// What a list of entries can't say is counted in skipped, never guessed: keywords, regular expressions, an
// inverted rule, a logical (and/or) rule, and a rule that also tests ports, networks or processes.
// The rule-set reader is sing-box's own, so every rule-set version it reads is read here.
func RuleSetText(data []byte) (text string, skipped int, err error) {
	compat, err := srs.Read(bytes.NewReader(data), true)
	if err != nil {
		return "", 0, fmt.Errorf("rule-set: %w", err)
	}
	var b strings.Builder
	for _, r := range compat.Options.Rules {
		if r.Type != "" && r.Type != "default" { // logical
			skipped++
			continue
		}
		d := r.DefaultOptions
		if d.Invert || hasOtherConditions(d) {
			skipped++
			continue
		}
		skipped += len(d.DomainKeyword) + len(d.DomainRegex)
		for _, s := range d.Domain {
			b.WriteString("full:" + s + "\n")
		}
		for _, s := range d.DomainSuffix {
			b.WriteString(strings.TrimPrefix(s, ".") + "\n")
		}
		for _, s := range d.IPCIDR {
			b.WriteString(s + "\n")
		}
	}
	return b.String(), skipped, nil
}

// hasOtherConditions: the rule needs more than a destination name or address to match, so its entries alone
// would route more than the rule does.
func hasOtherConditions(d option.DefaultHeadlessRule) bool {
	return len(d.QueryType) > 0 || len(d.Network) > 0 || len(d.SourceIPCIDR) > 0 || len(d.SourcePort) > 0 ||
		len(d.SourcePortRange) > 0 || len(d.Port) > 0 || len(d.PortRange) > 0 || len(d.ProcessName) > 0 ||
		len(d.ProcessPath) > 0 || len(d.ProcessPathRegex) > 0 || len(d.PackageName) > 0 || len(d.PackageNameRegex) > 0 ||
		len(d.NetworkType) > 0 || d.NetworkIsExpensive || d.NetworkIsConstrained || len(d.WIFISSID) > 0 ||
		len(d.WIFIBSSID) > 0 || d.NetworkInterfaceAddress != nil || len(d.DefaultInterfaceAddress) > 0
}
