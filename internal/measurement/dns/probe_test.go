package dns

import (
	"context"
	"testing"
	"time"

	"github.com/radestsam/nwrk/internal/domain"
	"github.com/radestsam/nwrk/internal/fixtures"
	"github.com/radestsam/nwrk/internal/target"
)

func probeServer(t *testing.T) *fixtures.DNSServer {
	return fixtures.NewDNS(t, map[string]fixtures.DNSRule{
		"clean.test":       {A: []string{"192.0.2.10"}},
		"injected.test":    {A: []string{"192.0.2.20"}, Inject: []string{"198.51.100.66"}},
		"signed.test":      {A: []string{"192.0.2.30"}, Signed: true, AD: true},
		"unsigned.test":    {A: []string{"192.0.2.31"}},
		"unvalidated.test": {A: []string{"192.0.2.32"}, Signed: true},
		"bogus.test":       {A: []string{"192.0.2.33"}, Signed: true, ServFailUnlessCD: true},
		"alias.test":       {A: []string{"192.0.2.34"}, CNAME: "target.test"},
		"silent.test":      {Behavior: fixtures.DNSSilent},
	})
}

func udp(t *testing.T, addr string) target.Resolver {
	r, err := target.ParseResolver(addr)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestMultipleResponses(t *testing.T) {
	srv := probeServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	m := MultipleResponses(ctx, "clean.test", udp(t, srv.Addr), 300*time.Millisecond)
	res := m.Result.(*ProbeResult)
	if m.Status != domain.StatusSuccess || len(res.Responses) != 1 || res.Distinct != 1 {
		t.Fatalf("a normal resolver answers once: %+v %v", res, m.Error)
	}
	if m.Params["probe"] != ProbeMultipleResponses {
		t.Fatalf("%v", m.Params)
	}

	m = MultipleResponses(ctx, "injected.test", udp(t, srv.Addr), 400*time.Millisecond)
	res = m.Result.(*ProbeResult)
	if len(res.Responses) != 2 || res.Distinct != 2 {
		t.Fatalf("two different replies to one query must both be recorded: %+v", res)
	}
	if res.Responses[0].Answers[0] != "198.51.100.66" || res.Responses[1].Answers[0] != "192.0.2.20" || res.Responses[1].DelayMS <= res.Responses[0].DelayMS {
		t.Fatalf("%+v", res.Responses)
	}
}

func TestMultipleResponsesEdgeCases(t *testing.T) {
	srv := probeServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	m := MultipleResponses(ctx, "silent.test", udp(t, srv.Addr), 200*time.Millisecond)
	if m.Error == nil || m.Error.Code != domain.DNSTimeout {
		t.Fatalf("%v", m.Error)
	}
	m = MultipleResponses(ctx, "clean.test", udp(t, "tcp://"+srv.Addr), 200*time.Millisecond)
	if m.Status != domain.StatusSkipped || m.Note == "" {
		t.Fatalf("only plain UDP can be probed: %+v", m)
	}
}

func TestInspectDNSSECAndCNAME(t *testing.T) {
	srv := probeServer(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	get := func(name string) *InspectResult {
		m := Inspect(ctx, name, udp(t, srv.Addr), Options{})
		if m.Status != domain.StatusSuccess || m.Params["probe"] != ProbeDNSSEC {
			t.Fatalf("%s: %+v %v", name, m, m.Error)
		}
		return m.Result.(*InspectResult)
	}
	if r := get("signed.test"); !r.Signed || !r.Authenticated || r.ValidationFailure {
		t.Fatalf("%+v", r)
	}
	if r := get("unsigned.test"); r.Signed || r.Authenticated || r.ValidationFailure {
		t.Fatalf("%+v", r)
	}
	if r := get("unvalidated.test"); !r.Signed || r.Authenticated {
		t.Fatalf("signed without the AD flag is not validated: %+v", r)
	}
	if r := get("bogus.test"); !r.ValidationFailure || r.Authenticated || len(r.Answers) == 0 {
		t.Fatalf("SERVFAIL that disappears with checking disabled is a validation failure: %+v", r)
	}
	if r := get("alias.test"); len(r.CNAMEs) != 1 || r.CNAMEs[0] != "target.test" {
		t.Fatalf("%+v", r)
	}
	// An ordinary SERVFAIL is not a validation failure.
	m := Inspect(ctx, "nx.test", udp(t, srv.Addr), Options{})
	if res := m.Result.(*InspectResult); res.ValidationFailure || res.RCode != "NXDOMAIN" {
		t.Fatalf("%+v", res)
	}
}

func TestInspectOverDoT(t *testing.T) {
	srv := probeServer(t)
	pki := fixtures.NewPKI(t)
	dot := srv.StartDoT(t, pki.Valid("127.0.0.1"))
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	m := Inspect(ctx, "signed.test", udp(t, "tls://"+dot), Options{RootCAs: pki.Pool})
	if m.Status != domain.StatusSuccess || !m.Result.(*InspectResult).Authenticated {
		t.Fatalf("%+v %v", m.Result, m.Error)
	}
}
