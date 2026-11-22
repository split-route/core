// Package ruleset turns a list's entries into sing-box source rule-sets and
// keeps them on disk. The engine's config refers to a list's files by id and
// never contains its entries, so an app updates a list by calling Write and
// sing-box reloads the file: no restart, no reconnect.
//
// Each list is two files in the directory: <id>.json with every entry, and
// (unless the list blocks) <id>.dns.json with the names only. sing-box treats
// IP entries in a DNS rule's rule-set as a deprecated filter on the answer, so
// the engine's DNS rules use the names-only twin.
package ruleset

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/split-route/core/rules"
)

// MaxEntries bounds the entries in one list, like an import's limit.
const MaxEntries = 500_000

// Dir is where the rule-set files of a work directory live.
func Dir(workDir string) string { return filepath.Join(workDir, "rulesets") }

// Path is a list's full rule-set file; DNSPath is its names-only twin.
func Path(dir, id string) string    { return filepath.Join(dir, id+".json") }
func DNSPath(dir, id string) string { return filepath.Join(dir, id+".dns.json") }

// Source is the rule-set in sing-box's source format. Each kind is its own rule
// (a rule-set matches if any rule does), so matching never depends on how
// fields combine within one rule. withIPs false leaves the CIDRs out.
func Source(es rules.Entries, withIPs bool) []byte {
	rs := []map[string]any{}
	if withIPs {
		var ips []string
		for _, p := range es.V4 {
			ips = append(ips, p.String())
		}
		for _, p := range es.V6 {
			ips = append(ips, p.String())
		}
		slices.SortFunc(ips, func(a, b string) int {
			pa, pb := netip.MustParsePrefix(a), netip.MustParsePrefix(b)
			if c := pa.Addr().Compare(pb.Addr()); c != 0 {
				return c
			}
			return pa.Bits() - pb.Bits()
		})
		if ips = slices.Compact(ips); len(ips) > 0 {
			rs = append(rs, map[string]any{"ip_cidr": ips})
		}
	}
	if d := sortedUnique(es.Domains); len(d) > 0 {
		rs = append(rs, map[string]any{"domain": d})
	}
	if d := sortedUnique(es.Suffixes); len(d) > 0 {
		rs = append(rs, map[string]any{"domain_suffix": d})
	}
	b, _ := json.Marshal(map[string]any{"version": 3, "rules": rs})
	return b
}

func sortedUnique(in []string) []string {
	out := slices.Clone(in)
	slices.Sort(out)
	return slices.Compact(out)
}

// Files returns the files of a list by file name, and a warning when entries
// can't be routed here (AS numbers need a list of their prefixes).
func Files(id string, action rules.Action, es rules.Entries) (files map[string][]byte, warning string, err error) {
	if n := len(es.V4) + len(es.V6) + len(es.Domains) + len(es.Suffixes); n > MaxEntries {
		return nil, "", fmt.Errorf("list %s has %d entries; the limit is %d", id, n, MaxEntries)
	}
	if len(es.ASNs) > 0 {
		warning = fmt.Sprintf("%d AS numbers are not routed (resolve them to prefixes first)", len(es.ASNs))
	}
	files = map[string][]byte{id + ".json": Source(es, true)}
	if action != rules.Block {
		files[id+".dns.json"] = Source(es, false)
	}
	return files, warning, nil
}

// Write writes a list's files in place: truncate and write, not rename, because
// sing-box reloads a file that is rewritten in place and does not notice a
// replaced one. Unchanged files are left alone; the directory is created 0700
// and the files are 0600. A list that stopped blocking (or started) gains (or
// loses) its names-only twin.
func Write(dir, id string, action rules.Action, es rules.Entries) (warning string, err error) {
	files, warning, err := Files(id, action, es)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	for name, b := range files {
		p := filepath.Join(dir, name)
		if old, err := os.ReadFile(p); err == nil && string(old) == string(b) {
			continue
		}
		if err := os.WriteFile(p, b, 0o600); err != nil {
			return "", err
		}
	}
	if _, ok := files[id+".dns.json"]; !ok {
		if err := os.Remove(DNSPath(dir, id)); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return "", err
		}
	}
	return warning, nil
}

// Ensure creates empty files for the lists that have none yet, so an engine can
// start before an app has downloaded anything. Existing files are left alone.
func Ensure(dir, id string, action rules.Action) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	files, _, _ := Files(id, action, rules.Entries{})
	for name, b := range files {
		p := filepath.Join(dir, name)
		if _, err := os.Stat(p); errors.Is(err, fs.ErrNotExist) {
			if err := os.WriteFile(p, b, 0o600); err != nil {
				return err
			}
		}
	}
	return nil
}

// Prune removes the files of lists that are not in keep. The directory is the
// engine's own (WorkDir/rulesets); only .json files are touched.
func Prune(dir string, keep []string) error {
	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, e := range entries {
		name := e.Name()
		id, ok := strings.CutSuffix(name, ".json")
		if !ok {
			continue
		}
		id = strings.TrimSuffix(id, ".dns")
		if !slices.Contains(keep, id) {
			if err := os.Remove(filepath.Join(dir, name)); err != nil && !errors.Is(err, fs.ErrNotExist) {
				return err
			}
		}
	}
	return nil
}
