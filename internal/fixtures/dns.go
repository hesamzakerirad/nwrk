// Package fixtures provides local servers for tests: DNS, TLS and HTTP
// servers with controlled behavior, so no core test needs the internet.
package fixtures

import (
	"net"
	"strings"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
)

// DNSBehavior says how the fixture DNS server treats one name.
type DNSBehavior int

const (
	// DNSAnswer returns the records listed for the name.
	DNSAnswer DNSBehavior = iota
	// DNSNXDomain returns NXDOMAIN.
	DNSNXDomain
	// DNSEmpty returns NOERROR with no records (NODATA).
	DNSEmpty
	// DNSServFail returns SERVFAIL.
	DNSServFail
	// DNSRefused returns REFUSED.
	DNSRefused
	// DNSSilent never answers.
	DNSSilent
	// DNSTruncate sets the truncated bit over UDP and answers fully over TCP.
	DNSTruncate
)

// DNSRule describes the answer for one name.
type DNSRule struct {
	Behavior DNSBehavior
	A        []string
	AAAA     []string
	CNAME    string
}

// DNSServer is a local DNS server on one UDP and one TCP port.
type DNSServer struct {
	// Addr is host:port, valid for both UDP and TCP.
	Addr  string
	Rules map[string]DNSRule
	srvs  []*mdns.Server
}

// NewDNS starts a DNS server on 127.0.0.1. Names not in rules get NXDOMAIN.
// Rule keys are lowercase names without the trailing dot.
func NewDNS(t testing.TB, rules map[string]DNSRule) *DNSServer {
	t.Helper()
	s := &DNSServer{Rules: rules}
	var pc net.PacketConn
	var ln net.Listener
	for range 20 {
		var err error
		pc, err = net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ln, err = net.Listen("tcp", pc.LocalAddr().String())
		if err == nil {
			break
		}
		pc.Close()
		pc, ln = nil, nil
	}
	if pc == nil {
		t.Fatal("could not find a port free for both UDP and TCP")
	}
	s.Addr = pc.LocalAddr().String()

	started := make(chan struct{}, 2)
	notify := func() { started <- struct{}{} }
	udp := &mdns.Server{PacketConn: pc, Handler: s.handler("udp"), NotifyStartedFunc: notify}
	tcp := &mdns.Server{Listener: ln, Handler: s.handler("tcp"), NotifyStartedFunc: notify}
	s.srvs = []*mdns.Server{udp, tcp}
	for _, srv := range s.srvs {
		go func() { _ = srv.ActivateAndServe() }()
	}
	for range 2 {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("DNS fixture did not start")
		}
	}
	t.Cleanup(func() {
		for _, srv := range s.srvs {
			_ = srv.Shutdown()
		}
	})
	return s
}

func (s *DNSServer) handler(network string) mdns.HandlerFunc {
	return func(w mdns.ResponseWriter, req *mdns.Msg) {
		resp := new(mdns.Msg)
		resp.SetReply(req)
		if len(req.Question) != 1 {
			resp.Rcode = mdns.RcodeFormatError
			_ = w.WriteMsg(resp)
			return
		}
		q := req.Question[0]
		name := strings.ToLower(strings.TrimSuffix(q.Name, "."))
		rule, ok := s.Rules[name]
		if !ok {
			resp.Rcode = mdns.RcodeNameError
			_ = w.WriteMsg(resp)
			return
		}
		switch rule.Behavior {
		case DNSSilent:
			return
		case DNSNXDomain:
			resp.Rcode = mdns.RcodeNameError
		case DNSServFail:
			resp.Rcode = mdns.RcodeServerFailure
		case DNSRefused:
			resp.Rcode = mdns.RcodeRefused
		case DNSEmpty:
		case DNSTruncate, DNSAnswer:
			if rule.Behavior == DNSTruncate && network == "udp" {
				resp.Truncated = true
				break
			}
			if rule.CNAME != "" {
				resp.Answer = append(resp.Answer, &mdns.CNAME{
					Hdr:    mdns.RR_Header{Name: q.Name, Rrtype: mdns.TypeCNAME, Class: mdns.ClassINET, Ttl: 60},
					Target: mdns.Fqdn(rule.CNAME),
				})
			}
			hdr := mdns.RR_Header{Name: q.Name, Class: mdns.ClassINET, Ttl: 60}
			if q.Qtype == mdns.TypeA {
				for _, a := range rule.A {
					h := hdr
					h.Rrtype = mdns.TypeA
					resp.Answer = append(resp.Answer, &mdns.A{Hdr: h, A: net.ParseIP(a)})
				}
			}
			if q.Qtype == mdns.TypeAAAA {
				for _, a := range rule.AAAA {
					h := hdr
					h.Rrtype = mdns.TypeAAAA
					resp.Answer = append(resp.Answer, &mdns.AAAA{Hdr: h, AAAA: net.ParseIP(a)})
				}
			}
		}
		_ = w.WriteMsg(resp)
	}
}

// SilentUDP returns the address of a UDP socket that reads queries and never
// answers, so a lookup against it must time out.
func SilentUDP(t testing.TB) string {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 512)
		for {
			if _, _, err := pc.ReadFrom(buf); err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { pc.Close(); <-done })
	return pc.LocalAddr().String()
}
