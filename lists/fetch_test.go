package lists

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func tlsServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, *http.Client) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	c := srv.Client()
	c.CheckRedirect = HTTPSOnly
	return srv, c
}

func TestFetchImport(t *testing.T) {
	var gotUA, gotINM string
	srv, c := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotUA, gotINM = r.Header.Get("User-Agent"), r.Header.Get("If-None-Match")
		if gotINM == `"v1"` {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Last-Modified", "Mon, 16 Nov 2026 10:00:00 GMT")
		w.Write([]byte("example.com\n"))
	})
	f, err := FetchImport(context.Background(), c, srv.URL+"/list.txt", "", "")
	if err != nil || string(f.Body) != "example.com\n" || f.ETag != `"v1"` || f.LastModified == "" || f.NotModified {
		t.Fatalf("%+v, %v", f, err)
	}
	if gotUA != UserAgent {
		t.Errorf("User-Agent %q", gotUA)
	}
	f, err = FetchImport(context.Background(), c, srv.URL+"/list.txt", `"v1"`, "")
	if err != nil || !f.NotModified || f.Body != nil {
		t.Fatalf("conditional: %+v, %v", f, err)
	}
}

func TestFetchImportRefuses(t *testing.T) {
	big := strings.Repeat("a", maxBytes+1)
	srv, c := tlsServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/big":
			w.Write([]byte(big))
		case "/to-http":
			http.Redirect(w, r, "http://example.com/list.txt", http.StatusFound)
		case "/loop":
			http.Redirect(w, r, "/loop", http.StatusFound)
		default:
			http.NotFound(w, r)
		}
	})
	for _, path := range []string{"/big", "/to-http", "/loop", "/missing"} {
		if f, err := FetchImport(context.Background(), c, srv.URL+path, "", ""); err == nil {
			t.Errorf("%s: want error, got %d bytes", path, len(f.Body))
		}
	}
}

func TestCheckImport(t *testing.T) {
	html := "<!DOCTYPE html>\n<html>\n<head><title>Login</title></head>\n<body>Sign in to Wi-Fi</body>\n</html>\n"
	es, st, err := ParseText([]byte(html))
	if err != nil {
		t.Fatal(err)
	}
	n := len(es.V4) + len(es.V6) + len(es.Domains) + len(es.Suffixes) + len(es.ASNs)
	if err := CheckImport(n, st); err == nil {
		t.Fatalf("captive portal page accepted: %d entries, %+v", n, st)
	}
	if err := CheckImport(10, Stats{Invalid: 3, Reserved: 50}); err != nil {
		t.Errorf("mostly valid list refused: %v", err)
	}
	if err := CheckImport(0, Stats{}); err == nil {
		t.Error("empty list accepted")
	}
}
