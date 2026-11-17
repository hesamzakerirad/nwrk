package fixtures

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// HTTPServer starts a server on 127.0.0.1 with these routes:
//
//	/ok            200 with a small body and a Set-Cookie header
//	/status/N      status N
//	/redirect      302 to /ok
//	/chain         302 to /redirect
//	/loop-a        302 to /loop-b
//	/loop-b        302 to /loop-a
//	/endless/N     302 to /endless/N+1, without end
//	/big           a 200 whose body is much larger than any sane limit
//	/slow          waits for 3 seconds, or until the client leaves
//	/ftp           302 to an ftp:// URL
//
// A non-nil cert makes it an HTTPS server.
func HTTPServer(t testing.TB, cert *tls.Certificate) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/ok", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nw-fixture")
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Set-Cookie", "session=secret")
		fmt.Fprint(w, "hello")
	})
	mux.HandleFunc("/status/", func(w http.ResponseWriter, r *http.Request) {
		var n int
		fmt.Sscanf(strings.TrimPrefix(r.URL.Path, "/status/"), "%d", &n)
		w.WriteHeader(n)
	})
	redirect := func(to string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, to, http.StatusFound) }
	}
	mux.HandleFunc("/redirect", redirect("/ok"))
	mux.HandleFunc("/chain", redirect("/redirect"))
	mux.HandleFunc("/loop-a", redirect("/loop-b"))
	mux.HandleFunc("/loop-b", redirect("/loop-a"))
	mux.HandleFunc("/ftp", redirect("ftp://example.com/"))
	mux.HandleFunc("/endless/", func(w http.ResponseWriter, r *http.Request) {
		var n int
		fmt.Sscanf(strings.TrimPrefix(r.URL.Path, "/endless/"), "%d", &n)
		http.Redirect(w, r, fmt.Sprintf("/endless/%d", n+1), http.StatusFound)
	})
	mux.HandleFunc("/big", func(w http.ResponseWriter, r *http.Request) {
		chunk := []byte(strings.Repeat("x", 4096))
		for range 1024 { // 4 MiB
			if _, err := w.Write(chunk); err != nil {
				return
			}
		}
	})
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(3 * time.Second):
		case <-r.Context().Done():
		}
	})
	srv := httptest.NewUnstartedServer(mux)
	if cert != nil {
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{*cert}, NextProtos: []string{"h2", "http/1.1"}}
		srv.EnableHTTP2 = true
		srv.StartTLS()
	} else {
		srv.Start()
	}
	t.Cleanup(srv.Close)
	return srv
}
