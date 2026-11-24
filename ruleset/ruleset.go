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
	"regexp"
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

// BinaryPath is a list that is a sing-box binary rule-set (.srs) instead of entries.
func BinaryPath(dir, id string) string { return filepath.Join(dir, id+".srs") }

// Source is the rule-set in sing-box's source format. Each kind is its own rule
// (a rule-set matches if any rule does), so matching never depends on how
// fields combine within one rule. full false is the names-only twin for the DNS rules: only what names a domain stays
// (not addresses, ports or programs, which say nothing about which server a DNS answer should come from).
func Source(es rules.Entries, full bool) []byte {
	rs := []map[string]any{}
	if full {
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
	if d := sortedUnique(es.Keywords); len(d) > 0 {
		rs = append(rs, map[string]any{"domain_keyword": d})
	}
	if d := sortedUnique(es.Regexes); len(d) > 0 {
		rs = append(rs, map[string]any{"domain_regex": d})
	}
	if full {
		if d := slices.Compact(slices.Sorted(slices.Values(es.Ports))); len(d) > 0 {
			rs = append(rs, map[string]any{"port": d})
		}
		if d := sortedUnique(es.PortRanges); len(d) > 0 {
			rs = append(rs, map[string]any{"port_range": d})
		}
		// An application is a folder of programs (helpers and renderers run from inside it), so the match is its path
		// and everything under it. The path is escaped: it is text to match, not a pattern. It may follow a prefix:
		// the system reports where a program really lives, which for some of Apple's own apps (Safari) is a cryptex
		// path ending in /Applications/Safari.app, and for a copy on another volume starts with the volume.
		var apps []string
		for _, a := range sortedUnique(es.Apps) {
			apps = append(apps, "(^|/)"+regexp.QuoteMeta(strings.TrimPrefix(a, "/"))+"(/|$)")
		}
		if len(apps) > 0 {
			rs = append(rs, map[string]any{"process_path_regex": apps})
		}
		if d := sortedUnique(es.Processes); len(d) > 0 {
			rs = append(rs, map[string]any{"process_name": d})
		}
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
	if n := es.Count() - len(es.ASNs); n > MaxEntries {
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
	return warning, WriteFiles(dir, id, files)
}

// WriteFiles writes the files of one list (see Write for how). The list's main file is either <id>.json or <id>.srs: the one
// it doesn't have is removed, so a list that changes kind leaves nothing stale. The names-only twin (<id>.dns.json) goes
// when the files don't have one.
func WriteFiles(dir, id string, files map[string][]byte) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	for name, b := range files {
		p := filepath.Join(dir, name)
		if old, err := os.ReadFile(p); err == nil && string(old) == string(b) {
			continue
		}
		if err := os.WriteFile(p, b, 0o600); err != nil {
			return err
		}
	}
	gone := []string{DNSPath(dir, id)}
	if _, ok := files[id+".srs"]; ok {
		gone = append(gone, Path(dir, id))
	} else {
		gone = append(gone, BinaryPath(dir, id))
	}
	for name := range files {
		gone = slices.DeleteFunc(gone, func(p string) bool { return filepath.Base(p) == name })
	}
	for _, p := range gone {
		if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}
	return nil
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
// engine's own (WorkDir/rulesets); only .json and .srs files are touched.
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
			id, ok = strings.CutSuffix(name, ".srs")
		}
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
