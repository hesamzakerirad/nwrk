package reach

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	apptest "github.com/hesamzakerirad/nwrk/internal/app/test"
	"github.com/hesamzakerirad/nwrk/internal/domain"
	"github.com/hesamzakerirad/nwrk/internal/endpoints"
	"github.com/hesamzakerirad/nwrk/internal/fixtures"
	"github.com/hesamzakerirad/nwrk/schema"
)

func run(t *testing.T, o Options) *domain.Report {
	t.Helper()
	rep := Run(context.Background(), o)
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if err := schema.ValidateReport(b); err != nil {
		t.Fatalf("report does not match schema v1: %v\n%s", err, b)
	}
	return rep
}

func codes(rep *domain.Report) []string {
	var out []string
	for _, f := range rep.Findings {
		out = append(out, f.Code)
	}
	return out
}

func httpsServer(t *testing.T, pki *fixtures.PKI) *httptest.Server {
	t.Helper()
	cert := pki.Valid("127.0.0.1")
	return fixtures.HTTPServer(t, &cert)
}

func options(pki *fixtures.PKI, urls ...string) Options {
	p := endpoints.Preset{Name: "test"}
	for _, u := range urls {
		p.Endpoints = append(p.Endpoints, endpoints.Endpoint{URL: u})
	}
	return Options{
		Test:      apptest.Options{Timeout: 2 * time.Second, ToolVersion: "test", RootCAs: pki.Pool},
		Preset:    p,
		SkipHTTP3: true,
	}
}

func TestHealthyEndpointsGiveNoFindings(t *testing.T) {
	pki := fixtures.NewPKI(t)
	srv := httpsServer(t, pki)
	rep := run(t, options(pki, srv.URL+"/ok"))
	if got := codes(rep); len(got) != 0 {
		t.Fatalf("findings = %v", got)
	}
	if len(rep.Measurements) != 1 || rep.Measurements[0].Target.Family != "ipv4" {
		t.Fatalf("measurements = %+v", rep.Measurements)
	}
}

func TestRefusalIsAServerSideRestriction(t *testing.T) {
	pki := fixtures.NewPKI(t)
	srv := httpsServer(t, pki)
	rep := run(t, options(pki, srv.URL+"/status/403"))
	if got := codes(rep); !slices.Equal(got, []string{"REACH_SERVER_SIDE_RESTRICTION"}) {
		t.Fatalf("findings = %v", got)
	}
}

func TestSilentServerLooksLikeInterference(t *testing.T) {
	pki := fixtures.NewPKI(t)
	ok := httpsServer(t, pki)
	mute := fixtures.MuteServer(t) // accepts connections and never answers
	rep := run(t, options(pki, ok.URL+"/ok", "https://"+mute+"/"))
	if got := codes(rep); !slices.Equal(got, []string{"REACH_NETWORK_INTERFERENCE"}) {
		t.Fatalf("findings = %v", got)
	}
}

func TestHTTP3ProbeIsSkippedForPlainHTTP(t *testing.T) {
	pki := fixtures.NewPKI(t)
	srv := fixtures.HTTPServer(t, nil)
	o := options(pki, srv.URL+"/ok")
	o.SkipHTTP3 = false
	rep := run(t, o)
	for _, m := range rep.Measurements {
		if m.Probe() == domain.ProbeHTTP3 {
			t.Fatalf("no HTTP/3 probe expected for an http URL: %+v", m)
		}
	}
}
