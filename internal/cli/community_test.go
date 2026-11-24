package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/radestsam/nwrk/contracts"
	"github.com/radestsam/nwrk/internal/community"
	"github.com/radestsam/nwrk/internal/domain"
	"github.com/radestsam/nwrk/internal/exit"
	"github.com/radestsam/nwrk/internal/measurement/dns"
	nwhttp "github.com/radestsam/nwrk/internal/measurement/http"
	"github.com/radestsam/nwrk/internal/measurement/tcp"
	nwtls "github.com/radestsam/nwrk/internal/measurement/tls"
)

const (
	cliULID  = "01JD5X8Q4M7R2N6T9V3W5Y0ZAB"
	cliToken = "cJHl_MaUFYGUQlPDRsVqs1HOZDM5IwFWOS1hHRlAg-4"
)

// stubEngine measures nothing: every layer succeeds.
type stubEngine struct{ ran *atomic.Int32 }

func (s stubEngine) DNS(_ context.Context, host string) *domain.Measurement {
	s.ran.Add(1)
	m := domain.Begin(domain.TypeDNS, "1", domain.Target{Host: host})
	return m.Succeed(&dns.Result{Queries: []dns.QueryResult{
		{Type: "A", Answers: []string{"203.0.113.9"}, DurationMS: 5},
		{Type: "AAAA", Answers: []string{"2001:db8::9"}, DurationMS: 5},
	}})
}
func (stubEngine) TCP(_ context.Context, _ string, a netip.AddrPort) *domain.Measurement {
	return domain.Begin(domain.TypeTCP, "1", domain.Target{}).Succeed(&tcp.Result{})
}
func (stubEngine) TLS(_ context.Context, _ string, _ netip.AddrPort) *domain.Measurement {
	return domain.Begin(domain.TypeTLS, "1", domain.Target{}).Succeed(&nwtls.Result{})
}
func (stubEngine) HTTP(_ context.Context, _ contracts.Endpoint, _ netip.AddrPort) (*domain.Measurement, int) {
	return domain.Begin(domain.TypeHTTP, "1", domain.Target{}).Succeed(&nwhttp.Result{StatusCode: 200}), 200
}

type communityEnv struct {
	ran      *atomic.Int32
	requests *atomic.Int32
	server   *httptest.Server
}

// setupCommunity installs a stub engine and a counting API server.
func setupCommunity(t *testing.T, stdin string, handler http.HandlerFunc) *communityEnv {
	t.Helper()
	env := &communityEnv{ran: &atomic.Int32{}, requests: &atomic.Int32{}}
	if handler == nil {
		handler = func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/v1/contributions/challenge":
				w.WriteHeader(201)
				_, _ = w.Write([]byte(`{"challenge_id":"` + cliULID + `","token":"` + cliToken + `","expires_at":"2099-01-01T00:00:00Z","pow":{"algorithm":"sha256-leading-zero-bits","difficulty_bits":4},"accepted":{"schema_versions":["community-contribution.v1"],"profiles":[{"id":"ir-core-v1","version":1}]}}`))
			default:
				w.WriteHeader(202)
				_, _ = w.Write([]byte(`{"status":"accepted","submission_id":"` + cliULID + `","received_at":"2026-11-22T08:00:00Z","observed_country":"IR","observed_asn":12880}`))
			}
		}
	}
	env.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		env.requests.Add(1)
		handler(w, r)
	}))
	t.Cleanup(env.server.Close)
	communitySeams.stdin = strings.NewReader(stdin)
	communitySeams.runner = func() *community.Runner {
		return &community.Runner{Engine: stubEngine{ran: env.ran}, Routes: func(context.Context) community.Routes { return community.Routes{IPv4: true, IPv6: true} }}
	}
	t.Cleanup(func() { communitySeams.stdin, communitySeams.runner, communitySeams.transport = nil, nil, nil })
	t.Setenv(EnvCommunityAPI, env.server.URL)
	return env
}

func TestCommunityInfoSendsNothing(t *testing.T) {
	env := setupCommunity(t, "", nil)
	code, out, _ := run(t, "community", "info")
	if code != exit.OK {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"ir-core-v1", "hosted in Iran", "without a set limit", "--dry-run", "Cloudflare"} {
		if want == "Cloudflare" {
			continue
		}
		if !strings.Contains(out, want) {
			t.Errorf("info output lacks %q:\n%s", want, out)
		}
	}
	if env.requests.Load() != 0 || env.ran.Load() != 0 {
		t.Fatal("info made a request or a measurement")
	}
	code, out, _ = run(t, "community", "info", "--output", "json")
	var doc map[string]any
	if code != exit.OK || json.Unmarshal([]byte(out), &doc) != nil || doc["disclosure"] == nil {
		t.Fatalf("%d %s", code, out)
	}
}

func TestDeclinedRunMeasuresAndSendsNothing(t *testing.T) {
	for name, stdin := range map[string]string{"no": "n\n", "empty": "\n", "end of input": "", "junk": "maybe\n", "upper N": "N\n"} {
		t.Run(name, func(t *testing.T) {
			env := setupCommunity(t, stdin, nil)
			code, _, errOut := run(t, "community", "contribute")
			if code != exit.OK || env.ran.Load() != 0 || env.requests.Load() != 0 {
				t.Fatalf("exit %d, measured %d, requests %d", code, env.ran.Load(), env.requests.Load())
			}
			if !strings.Contains(errOut, "Nothing was measured and nothing was sent") {
				t.Fatalf("%s", errOut)
			}
		})
	}
}

func TestDryRunNeverCallsTheServer(t *testing.T) {
	env := setupCommunity(t, "y\n", nil)
	file := filepath.Join(t.TempDir(), "payload.json")
	code, out, errOut := run(t, "community", "contribute", "--dry-run", "--payload-file", file, "--api", env.server.URL)
	if code != exit.OK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if env.requests.Load() != 0 {
		t.Fatalf("dry run sent %d requests", env.requests.Load())
	}
	if env.ran.Load() == 0 || !strings.Contains(out, "Dry run: nothing was sent") {
		t.Fatalf("%s", out)
	}
	raw, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := contracts.ValidateContribution(raw, mustProfiles()); err != nil {
		t.Fatalf("payload file is not valid: %v", err)
	}
	// Windows has no Unix permission bits, so the mode cannot be checked there.
	if st, _ := os.Stat(file); runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
		t.Fatalf("payload file mode %v", st.Mode())
	}
}

func TestDryRunJSONPrintsTheDocument(t *testing.T) {
	env := setupCommunity(t, "y\n", nil)
	code, out, _ := run(t, "community", "contribute", "--dry-run", "-o", "json")
	if code != exit.OK || env.requests.Load() != 0 {
		t.Fatalf("exit %d", code)
	}
	if _, err := contracts.ValidateContribution([]byte(out), mustProfiles()); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
}

func TestDeclinedUploadSendsNothing(t *testing.T) {
	env := setupCommunity(t, "y\nn\n", nil)
	code, _, errOut := run(t, "community", "contribute")
	if code != exit.OK || env.requests.Load() != 0 || env.ran.Load() == 0 {
		t.Fatalf("exit %d, requests %d, ran %d", code, env.requests.Load(), env.ran.Load())
	}
	if !strings.Contains(errOut, "Nothing was sent") {
		t.Fatal(errOut)
	}
}

func TestShowThenAgreeUploads(t *testing.T) {
	env := setupCommunity(t, "y\ns\ny\n", nil)
	code, _, errOut := run(t, "community", "contribute")
	if code != exit.OK {
		t.Fatalf("exit %d: %s", code, errOut)
	}
	if env.requests.Load() != 2 {
		t.Fatalf("%d requests, want challenge and submit", env.requests.Load())
	}
	for _, want := range []string{`"schema_version": "community-contribution.v1"`, "Accepted. Thank you.", cliULID, "IR, AS12880"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("missing %q in:\n%s", want, errOut)
		}
	}
	for _, secret := range []string{"203.0.113.9", "2001:db8::9"} {
		if strings.Contains(errOut, secret) {
			t.Errorf("address %s shown", secret)
		}
	}
}

func TestSubmittedBodyIsTheShownDocument(t *testing.T) {
	var body []byte
	env := setupCommunity(t, "y\ny\n", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/contributions" {
			var b bytes.Buffer
			_, _ = b.ReadFrom(r.Body)
			body = b.Bytes()
			w.WriteHeader(202)
			_, _ = w.Write([]byte(`{"status":"accepted","submission_id":"` + cliULID + `","received_at":"2026-11-22T08:00:00Z"}`))
			return
		}
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"challenge_id":"` + cliULID + `","token":"` + cliToken + `","expires_at":"2099-01-01T00:00:00Z","pow":{"algorithm":"sha256-leading-zero-bits","difficulty_bits":0},"accepted":{"schema_versions":["community-contribution.v1"],"profiles":[{"id":"ir-core-v1","version":1}]}}`))
	})
	if code, _, e := run(t, "community", "contribute"); code != exit.OK {
		t.Fatalf("%d %s", code, e)
	}
	if env.requests.Load() != 2 {
		t.Fatalf("%d", env.requests.Load())
	}
	if err := contracts.ValidateAPI("submission", body); err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"203.0.113.9", "2001:db8::9", "hostname", "resolver"} {
		if strings.Contains(string(body), secret) {
			t.Errorf("body holds %q", secret)
		}
	}
}

func TestServerRefusalIsExplainedAndNotRetried(t *testing.T) {
	env := setupCommunity(t, "y\ny\n", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "90")
		w.WriteHeader(429)
		_, _ = w.Write([]byte(`{"error":{"code":"rate_limited","message":"Too many requests."}}`))
	})
	code, _, errOut := run(t, "community", "contribute")
	if code != exit.Failure {
		t.Fatalf("exit %d", code)
	}
	for _, want := range []string{"rate_limited", "Try again in 90 seconds", "not saved anywhere"} {
		if !strings.Contains(errOut, want) {
			t.Errorf("missing %q in %q", want, errOut)
		}
	}
	if env.requests.Load() != 1 {
		t.Fatalf("%d requests: the client retried", env.requests.Load())
	}
}

func TestExcludedAnswerIsExplained(t *testing.T) {
	setupCommunity(t, "y\ny\n", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/contributions" {
			_, _ = w.Write([]byte(`{"status":"excluded","reason":"outside_scope","observed_country":"DE"}`))
			return
		}
		w.WriteHeader(201)
		_, _ = w.Write([]byte(`{"challenge_id":"` + cliULID + `","token":"` + cliToken + `","expires_at":"2099-01-01T00:00:00Z","pow":{"algorithm":"sha256-leading-zero-bits","difficulty_bits":0},"accepted":{"schema_versions":["community-contribution.v1"],"profiles":[{"id":"ir-core-v1","version":1}]}}`))
	})
	code, _, errOut := run(t, "community", "contribute")
	if code != exit.OK || !strings.Contains(errOut, "Not stored") || !strings.Contains(errOut, "(DE)") {
		t.Fatalf("%d %s", code, errOut)
	}
}

func TestUsageErrors(t *testing.T) {
	setupCommunity(t, "y\n", nil)
	cases := map[string][]string{
		"unknown profile":    {"community", "contribute", "--profile", "nope", "--dry-run"},
		"json needs dry-run": {"community", "contribute", "-o", "json"},
		"file needs dry-run": {"community", "contribute", "--payload-file", "x.json"},
		"http api":           {"community", "contribute", "--api", "http://api.nwrk.ir"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			if code, _, _ := run(t, args...); code != exit.Failure {
				t.Fatalf("exit %d", code)
			}
		})
	}
}

func TestOtherCommandsNeverContactTheAPI(t *testing.T) {
	env := setupCommunity(t, "", nil)
	for _, args := range [][]string{
		{"version"}, {"config", "show"}, {"network", "show"}, {"network", "interfaces"},
		{"community", "info"}, {"community"}, {"--help"},
	} {
		run(t, args...)
	}
	if env.requests.Load() != 0 {
		t.Fatalf("%d requests reached the API host", env.requests.Load())
	}
}
