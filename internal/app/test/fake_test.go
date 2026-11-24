package test

import "github.com/radestsam/nwrk/internal/measurement/dns"

func fakeResult(a ...string) *dns.Result {
	return &dns.Result{
		A:       a,
		AAAA:    []string{},
		Queries: []dns.QueryResult{{Type: "A", Answers: a, RCode: "NOERROR"}, {Type: "AAAA", Answers: []string{}}},
	}
}
