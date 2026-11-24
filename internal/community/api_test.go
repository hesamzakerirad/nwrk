package community

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/radestsam/nwrk/contracts"
)

const (
	testULID  = "01JD5X8Q4M7R2N6T9V3W5Y0ZAB"
	testToken = "cJHl_MaUFYGUQlPDRsVqs1HOZDM5IwFWOS1hHRlAg-4"
)

func challengeJSON(bits int) string {
	b, _ := json.Marshal(map[string]any{
		"challenge_id": testULID, "token": testToken, "expires_at": "2026-11-22T08:19:01Z",
		"pow":      map[string]any{"algorithm": "sha256-leading-zero-bits", "difficulty_bits": bits},
		"accepted": map[string]any{"schema_versions": []string{"community-contribution.v1"}, "profiles": []map[string]any{{"id": "ir-dev-v1", "version": 1}}},
	})
	return string(b)
}

func testClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	c, err := NewClient(srv.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestClientAddressRules(t *testing.T) {
	ok := []string{"https://api.nwrk.ir", "http://localhost:8080", "http://127.0.0.1:8080", "http://[::1]:8080", "https://api.nwrk.ir/"}
	bad := []string{"http://api.nwrk.ir", "ftp://x", "https://", "https://u:p@api.nwrk.ir", "https://api.nwrk.ir/path", "https://api.nwrk.ir?x=1", "api.nwrk.ir", "http://localhost.evil.example"}
	for _, a := range ok {
		if _, err := NewClient(a, nil); err != nil {
			t.Errorf("%s: %v", a, err)
		}
	}
	for _, a := range bad {
		if _, err := NewClient(a, nil); err == nil {
			t.Errorf("%s was accepted", a)
		}
	}
}

func TestChallengeThenSubmitAccepted(t *testing.T) {
	p := profile(t, "ir-dev-v1")
	doc, err := fakeRunner(&fakeEngine{status: 200}, Routes{IPv4: true}).Run(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	var challenged, submitted atomic.Int32
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Header.Get("Content-Type") != "application/json" || len(r.Cookies()) != 0 || !strings.HasPrefix(r.UserAgent(), "nwrk/") {
			t.Errorf("headers: %v", r.Header)
		}
		switch r.URL.Path {
		case "/api/v1/contributions/challenge":
			challenged.Add(1)
			if err := contracts.ValidateAPI("challengeRequest", body); err != nil {
				t.Errorf("challenge request: %v", err)
			}
			w.WriteHeader(201)
			_, _ = w.Write([]byte(challengeJSON(8)))
		case "/api/v1/contributions":
			submitted.Add(1)
			if err := contracts.ValidateAPI("submission", body); err != nil {
				t.Errorf("submission: %v", err)
			}
			var s struct {
				Challenge struct {
					Nonce string `json:"pow_nonce"`
				}
			}
			_ = json.Unmarshal(body, &s)
			if !contracts.CheckPoW(testULID, testToken, s.Challenge.Nonce, 8) {
				t.Errorf("proof of work does not hold")
			}
			w.WriteHeader(202)
			_, _ = w.Write([]byte(`{"status":"accepted","submission_id":"` + testULID + `","received_at":"2026-11-22T08:00:00Z","observed_country":"IR","observed_asn":12880}`))
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})
	ch, err := c.Challenge(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	nonce, err := SolvePoW(context.Background(), ch)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := c.Submit(context.Background(), ch, nonce, doc)
	if err != nil {
		t.Fatal(err)
	}
	if !rc.Accepted || rc.SubmissionID != testULID || rc.ObservedCountry != "IR" || rc.ObservedASN != 12880 || challenged.Load() != 1 || submitted.Load() != 1 {
		t.Fatalf("%+v", rc)
	}
}

func TestExcludedAnswer(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"status":"excluded","reason":"outside_scope","observed_country":"DE"}`))
	})
	rc, err := c.Submit(context.Background(), &Challenge{ID: testULID, Token: testToken}, "1", &contracts.Contribution{SchemaVersion: contracts.SchemaVersion})
	if err != nil || rc.Accepted || rc.Reason != "outside_scope" || rc.ObservedCountry != "DE" {
		t.Fatalf("%+v %v", rc, err)
	}
}

func TestServerErrorsKeepTheContractCode(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "120")
		w.WriteHeader(429)
		_, _ = w.Write([]byte(`{"error":{"code":"rate_limited","message":"Too many requests."}}`))
	})
	_, err := c.Challenge(context.Background(), profile(t, "ir-dev-v1"))
	var ae *APIError
	if !errors.As(err, &ae) || ae.Code != "rate_limited" || ae.Status != 429 || ae.RetryAfter != 2*time.Minute {
		t.Fatalf("%v", err)
	}
}

func TestUnexpectedAnswersAreRefused(t *testing.T) {
	cases := map[string]struct {
		status int
		body   string
	}{
		"html":                {502, "<html>bad gateway</html>"},
		"wrong shape":         {201, `{"challenge_id":"x"}`},
		"difficulty too high": {201, challengeJSON(40)},
		"empty":               {201, ``},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			})
			if _, err := c.Challenge(context.Background(), profile(t, "ir-dev-v1")); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	var other atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { other.Add(1) }))
	defer target.Close()
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	})
	_, err := c.Submit(context.Background(), &Challenge{ID: testULID, Token: testToken}, "1", &contracts.Contribution{SchemaVersion: contracts.SchemaVersion})
	if err == nil || other.Load() != 0 {
		t.Fatalf("err %v, other server hit %d times", err, other.Load())
	}
}

func TestTransportErrorHoldsNoURL(t *testing.T) {
	c, _ := NewClient("http://127.0.0.1:1", nil)
	_, err := c.Challenge(context.Background(), profile(t, "ir-dev-v1"))
	if err == nil || strings.Contains(err.Error(), "/api/v1") {
		t.Fatalf("%v", err)
	}
}

func TestSolvePoWStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := SolvePoW(ctx, &Challenge{ID: testULID, Token: testToken, DifficultyBit: 64}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("%v", err)
	}
}

func TestSolvePoWMatchesTheContractVectors(t *testing.T) {
	ch := &Challenge{ID: testULID, Token: testToken, DifficultyBit: 12}
	nonce, err := SolvePoW(context.Background(), ch)
	if err != nil || nonce != contracts.SolvePoW(ch.ID, ch.Token, 12) {
		t.Fatalf("%s %v", nonce, err)
	}
}
