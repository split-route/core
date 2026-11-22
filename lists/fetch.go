package lists

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"
)

// ImportClient downloads imports: https only, redirects only to https (at
// most 5), no cookies, 60 s for the whole download.
var ImportClient = &http.Client{Timeout: 60 * time.Second, CheckRedirect: HTTPSOnly}

// HTTPSOnly is an http.Client CheckRedirect that refuses redirects to
// anything but https URLs without credentials.
func HTTPSOnly(req *http.Request, via []*http.Request) error {
	switch {
	case len(via) >= 5:
		return errors.New("more than 5 redirects")
	case req.URL.Scheme != "https":
		return fmt.Errorf("redirect to %s: only https is allowed", req.URL.Redacted())
	case req.URL.User != nil:
		return fmt.Errorf("redirect to %s: no credentials in URLs", req.URL.Redacted())
	}
	return nil
}

// Fetched is the result of an import download.
type Fetched struct {
	Body         []byte
	ETag         string
	LastModified string
	NotModified  bool // 304: keep what we have
}

// FetchImport downloads url, conditionally on etag / lastModified when set.
// A body over 64 MB is an error, never truncated: a cut-off list would
// silently lose entries.
func FetchImport(ctx context.Context, c *http.Client, url, etag, lastModified string) (Fetched, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return Fetched{}, err
	}
	req.Header.Set("User-Agent", UserAgent)
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	if lastModified != "" {
		req.Header.Set("If-Modified-Since", lastModified)
	}
	resp, err := c.Do(req)
	if err != nil {
		return Fetched{}, err
	}
	defer resp.Body.Close()
	f := Fetched{ETag: resp.Header.Get("ETag"), LastModified: resp.Header.Get("Last-Modified")}
	switch resp.StatusCode {
	case http.StatusNotModified:
		f.NotModified = true
		return f, nil
	case http.StatusOK:
	default:
		return Fetched{}, fmt.Errorf("GET %s: %s", url, resp.Status)
	}
	f.Body, err = io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return Fetched{}, err
	}
	if len(f.Body) > maxBytes {
		return Fetched{}, fmt.Errorf("GET %s: larger than %d MB", url, maxBytes>>20)
	}
	return f, nil
}

// CheckImport rejects a download that parsed to nothing useful: no entries,
// or more invalid lines than entries. That is what a captive portal or an
// HTML error page served with 200 looks like, and saving it would wipe the
// last good list.
func CheckImport(entries int, st Stats) error {
	switch {
	case entries == 0 && st.Invalid > 0:
		return fmt.Errorf("no entries and %d invalid lines; not a list (a login page or an error page?)", st.Invalid)
	case entries == 0:
		return errors.New("no entries")
	case st.Invalid > entries:
		return fmt.Errorf("%d invalid lines and only %d entries; not a list in a format splitroute reads", st.Invalid, entries)
	}
	return nil
}
