// Package lists downloads routing-rules release lists, checks them against
// SHA256SUMS, keeps a last-good cache and parses them.
package lists

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/split-route/core/internal/fileutil"
	"github.com/split-route/core/rules"
)

const maxBytes = 64 << 20 // per downloaded file

// UserAgent is sent with every download; main sets it to include the version.
var UserAgent = "splitroute/dev"

// Stats counts lines a list had that are skipped.
type Stats struct {
	Reserved int // private or special ranges, never routed
	Invalid  int // domains that fail validation
	Other    int // rule types splitroute doesn't read
}

// Parse reads a Shadowrocket-style .list file: IP-CIDR, IP-CIDR6, DOMAIN and
// DOMAIN-SUFFIX lines. A range broader than /8 (IPv4) or /16 (IPv6) is an
// error: it would hijack a large share of all traffic, so the whole list is
// refused. Reserved ranges, invalid domains and other rule types are skipped
// and counted.
func Parse(b []byte) (rules.Entries, Stats, error) {
	var es rules.Entries
	var st Stats
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		typ, rest, _ := strings.Cut(line, ",")
		val, _, _ := strings.Cut(rest, ",")
		switch typ {
		case "IP-CIDR", "IP-CIDR6":
			p, err := netip.ParsePrefix(val)
			if err != nil || p.Addr().Is4() != (typ == "IP-CIDR") {
				return rules.Entries{}, st, fmt.Errorf("bad %s line %q", typ, line)
			}
			if err := addPrefix(&es, &st, p); err != nil {
				return rules.Entries{}, st, err
			}
		case "DOMAIN", "DOMAIN-SUFFIX":
			kind := rules.Domain
			if typ == "DOMAIN-SUFFIX" {
				kind = rules.DomainSuffix
			}
			e, err := rules.DomainEntry(kind, val)
			if err != nil {
				st.Invalid++
				continue
			}
			es.Add(e)
		default:
			st.Other++
		}
	}
	return es, st, sc.Err()
}

// addPrefix adds a range from a downloaded list. Broader than the /8 or /16
// floor is an error for the whole list (a poisoned list must not hijack a
// large share of all traffic); a reserved range is skipped and counted.
func addPrefix(es *rules.Entries, st *Stats, p netip.Prefix) error {
	p = p.Masked()
	if floor := rules.Floor(p.Addr()); p.Bits() < floor {
		return fmt.Errorf("refusing %s: broader than /%d", p, floor)
	}
	if rules.IsReserved(p) {
		st.Reserved++
		return nil
	}
	es.Add(rules.Entry{Kind: rules.CIDR, Prefix: p})
	return nil
}

// parseSums reads a sha256sum file into file name → hex digest.
func parseSums(b []byte) map[string]string {
	m := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 {
			m[strings.TrimPrefix(f[1], "*")] = f[0]
		}
	}
	return m
}

var client = &http.Client{Timeout: 60 * time.Second}

func httpGet(url string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", UserAgent)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxBytes))
}

// Fetch downloads each named list and checks it against the release's
// SHA256SUMS. A list that can't be downloaded or verified falls back to the
// last verified copy in cacheDir, so a network hiccup never drops routes.
func Fetch(base, cacheDir string, names []string, save bool) (map[string][]byte, []string, error) {
	if len(names) == 0 {
		return map[string][]byte{}, nil, nil // nothing to download: not even the checksums
	}
	var warn []string
	var sums map[string]string
	if b, err := httpGet(base + "/SHA256SUMS"); err != nil {
		warn = append(warn, fmt.Sprintf("download SHA256SUMS: %v", err))
	} else {
		sums = parseSums(b)
	}
	out := map[string][]byte{}
	for _, n := range names {
		file := n + ".list"
		cached := filepath.Join(cacheDir, file)
		var err error
		if sums == nil {
			err = errors.New("no checksums")
		} else if want, ok := sums[file]; !ok {
			return nil, warn, fmt.Errorf("unknown list %q (run `splitroute lists`)", n)
		} else if b, gerr := httpGet(base + "/" + file); gerr != nil {
			err = gerr
		} else if got := sha256.Sum256(b); hex.EncodeToString(got[:]) != want {
			err = errors.New("checksum mismatch")
		} else {
			out[n] = b
			if save {
				if werr := fileutil.WriteAtomic(cached, b); werr != nil {
					warn = append(warn, fmt.Sprintf("cache %s: %v", file, werr))
				}
			}
			continue
		}
		b, cerr := os.ReadFile(cached)
		if cerr != nil {
			return nil, warn, fmt.Errorf("%s: %v, and no cached copy", file, err)
		}
		warn = append(warn, fmt.Sprintf("%s: %v; using cached copy", file, err))
		out[n] = b
	}
	return out, warn, nil
}

// Available returns the list names in the release at base.
func Available(base string) ([]string, error) {
	b, err := httpGet(base + "/SHA256SUMS")
	if err != nil {
		return nil, err
	}
	var names []string
	for f := range parseSums(b) {
		if n, ok := strings.CutSuffix(f, ".list"); ok {
			names = append(names, n)
		}
	}
	slices.Sort(names)
	return names, nil
}
