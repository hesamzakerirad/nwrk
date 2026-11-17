// Package path implements nw path ping, trace and mtu.
//
// ICMP is often filtered, deprioritized or rate-limited, so a missing reply
// is a missing reply and nothing more: it never proves that a router is
// broken or that traffic is blocked. Where ICMP is not permitted the
// commands fall back to TCP and say so.
package path

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/netip"
	"sort"
	"time"
)

// Methods.
const (
	MethodAuto = "auto"
	MethodICMP = "icmp"
	MethodTCP  = "tcp"
)

// ErrPrivilege means the operating system refused the socket the method
// needs. The wrapped message says what would allow it.
var ErrPrivilege = errors.New("not permitted")

// ErrUnsupported means the method does not exist on this platform.
var ErrUnsupported = errors.ErrUnsupported

// ValidMethod reports whether m is one of the methods.
func ValidMethod(m string) bool { return m == MethodAuto || m == MethodICMP || m == MethodTCP }

// Reply is one probe's outcome. RTT is nil when there was no reply.
type Reply struct {
	Seq   int      `json:"seq"`
	RTTMS *float64 `json:"rtt_ms"`
	Note  string   `json:"note,omitempty"`
}

// PingResult is the outcome of nw path ping.
type PingResult struct {
	Method   string  `json:"method"`
	Target   string  `json:"target"`
	Address  string  `json:"address"`
	Port     int     `json:"port,omitempty"`
	Sent     int     `json:"sent"`
	Received int     `json:"received"`
	LossPct  float64 `json:"loss_percent"`
	MinMS    float64 `json:"min_ms,omitempty"`
	AvgMS    float64 `json:"avg_ms,omitempty"`
	MaxMS    float64 `json:"max_ms,omitempty"`
	// Why names the reason a fallback was used, when it was.
	Fallback string  `json:"fallback,omitempty"`
	Replies  []Reply `json:"replies"`
}

// Pinger sends one probe and returns how long the reply took.
type Pinger interface {
	Name() string
	Ping(ctx context.Context, addr netip.Addr, seq int, timeout time.Duration) (time.Duration, error)
	Close() error
}

// PingOptions control a ping run.
type PingOptions struct {
	Count    int
	Interval time.Duration
	Timeout  time.Duration
	Method   string
	Port     int // for the TCP method
	// ICMP and TCP replace the real pingers in tests.
	ICMP func(netip.Addr) (Pinger, error)
	TCP  func(port int) Pinger
}

// Ping probes addr Count times. With the auto method it tries ICMP and falls
// back to TCP when ICMP is not permitted, saying why.
func Ping(ctx context.Context, target string, addr netip.Addr, o PingOptions) (*PingResult, error) {
	res := &PingResult{Target: target, Address: addr.String(), Replies: []Reply{}}
	var p Pinger
	var err error
	newICMP := o.ICMP
	if newICMP == nil {
		newICMP = func(a netip.Addr) (Pinger, error) { return NewICMPPinger(a) }
	}
	newTCP := o.TCP
	if newTCP == nil {
		newTCP = func(port int) Pinger { return NewTCPPinger(port) }
	}
	switch o.Method {
	case MethodTCP:
		p = newTCP(o.Port)
	case MethodICMP:
		if p, err = newICMP(addr); err != nil {
			return nil, err
		}
	default:
		if p, err = newICMP(addr); err != nil {
			if !errors.Is(err, ErrPrivilege) && !errors.Is(err, ErrUnsupported) {
				return nil, err
			}
			res.Fallback = err.Error()
			p = newTCP(o.Port)
		}
	}
	defer p.Close()
	res.Method = p.Name()
	if res.Method == MethodTCP {
		res.Port = o.Port
	}

	var rtts []float64
	for i := 1; i <= o.Count; i++ {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		d, err := p.Ping(ctx, addr, i, o.Timeout)
		res.Sent++
		r := Reply{Seq: i}
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			r.Note = describe(err)
		} else {
			ms := float64(d.Microseconds()) / 1000
			r.RTTMS = &ms
			rtts = append(rtts, ms)
			res.Received++
		}
		res.Replies = append(res.Replies, r)
		if i < o.Count {
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(o.Interval):
			}
		}
	}
	res.LossPct = math.Round(float64(res.Sent-res.Received)*1000/float64(max(res.Sent, 1))) / 10
	if len(rtts) > 0 {
		sort.Float64s(rtts)
		res.MinMS, res.MaxMS = rtts[0], rtts[len(rtts)-1]
		var sum float64
		for _, v := range rtts {
			sum += v
		}
		res.AvgMS = math.Round(sum/float64(len(rtts))*1000) / 1000
	}
	return res, nil
}

func describe(err error) string {
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return "no reply before the deadline"
	}
	return err.Error()
}

// Hop is one TTL of a trace.
type Hop struct {
	TTL int `json:"ttl"`
	// Address is the router that answered, when it could be learned.
	Address string     `json:"address,omitempty"`
	RTTMS   []*float64 `json:"rtt_ms"`
	// Reached is true when the destination itself answered at this TTL.
	Reached bool   `json:"reached"`
	Note    string `json:"note,omitempty"`
}

// TraceResult is the outcome of nw path trace.
type TraceResult struct {
	Method   string `json:"method"`
	Target   string `json:"target"`
	Address  string `json:"address"`
	Port     int    `json:"port,omitempty"`
	Reached  bool   `json:"reached"`
	MaxHops  int    `json:"max_hops"`
	Fallback string `json:"fallback,omitempty"`
	// Note explains what the result does and does not show.
	Note string `json:"note"`
	Hops []Hop  `json:"hops"`
}

// ProbeReply is the answer to one traceroute probe.
type ProbeReply struct {
	// From is the router or host that answered; it is invalid for methods
	// that cannot see intermediate routers.
	From    netip.Addr
	RTT     time.Duration
	Reached bool
}

// Prober sends one probe with the given TTL.
type Prober interface {
	Name() string
	// Probe returns an error when nothing answered before the timeout.
	Probe(ctx context.Context, ttl int, timeout time.Duration) (ProbeReply, error)
	// SeesRouters says whether the method can learn the addresses of the
	// routers on the path.
	SeesRouters() bool
	Close() error
}

// TraceOptions control a trace run.
type TraceOptions struct {
	MaxHops int
	Queries int
	Timeout time.Duration
	Method  string
	Port    int
	// MaxSilent stops the trace after this many hops in a row without any
	// reply, so a filtered path does not take minutes.
	MaxSilent int
	// ICMP and TCP replace the real probers in tests.
	ICMP func(netip.Addr) (Prober, error)
	TCP  func(addr netip.Addr, port int) Prober
}

// Trace walks the path to addr by raising the TTL one step at a time.
func Trace(ctx context.Context, target string, addr netip.Addr, o TraceOptions) (*TraceResult, error) {
	res := &TraceResult{Target: target, Address: addr.String(), MaxHops: o.MaxHops, Hops: []Hop{}}
	newICMP := o.ICMP
	if newICMP == nil {
		newICMP = func(a netip.Addr) (Prober, error) { return NewICMPProber(a) }
	}
	newTCP := o.TCP
	if newTCP == nil {
		newTCP = func(a netip.Addr, port int) Prober { return NewTCPProber(a, port) }
	}
	var p Prober
	var err error
	switch o.Method {
	case MethodTCP:
		p = newTCP(addr, o.Port)
	case MethodICMP:
		if p, err = newICMP(addr); err != nil {
			return nil, err
		}
	default:
		if p, err = newICMP(addr); err != nil {
			if !errors.Is(err, ErrPrivilege) && !errors.Is(err, ErrUnsupported) {
				return nil, err
			}
			res.Fallback = err.Error()
			p = newTCP(addr, o.Port)
		}
	}
	defer p.Close()
	res.Method = p.Name()
	if res.Method == MethodTCP {
		res.Port = o.Port
	}

	// A method that cannot see routers gets no reply at all until the TTL is
	// high enough to reach the destination, so silence is expected there:
	// it is neither a reason to stop nor worth repeating at each hop.
	queries, stopOnSilence := o.Queries, p.SeesRouters()
	if !p.SeesRouters() {
		queries = 1
	}
	silent := 0
	for ttl := 1; ttl <= o.MaxHops; ttl++ {
		hop := Hop{TTL: ttl, RTTMS: []*float64{}}
		answered := false
		for q := 0; q < queries; q++ {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			r, err := p.Probe(ctx, ttl, o.Timeout)
			if err != nil {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				hop.RTTMS = append(hop.RTTMS, nil)
				continue
			}
			answered = true
			ms := float64(r.RTT.Microseconds()) / 1000
			hop.RTTMS = append(hop.RTTMS, &ms)
			if r.From.IsValid() && hop.Address == "" {
				hop.Address = r.From.Unmap().String()
			}
			if r.Reached {
				hop.Reached = true
			}
		}
		res.Hops = append(res.Hops, hop)
		if hop.Reached {
			res.Reached = true
			break
		}
		if answered {
			silent = 0
		} else {
			silent++
			if stopOnSilence && o.MaxSilent > 0 && silent >= o.MaxSilent {
				res.Hops[len(res.Hops)-1].Note = fmt.Sprintf("stopped after %d hops without a reply", silent)
				break
			}
		}
	}
	res.Note = traceNote(res, p.SeesRouters())
	return res, nil
}

func traceNote(r *TraceResult, sees bool) string {
	var s string
	switch {
	case !sees && r.Reached:
		s = fmt.Sprintf("The destination answered at TTL %d, so it is at most %d hops away. This method cannot see the routers on the way; run nw path trace with ICMP privileges to list them.", len(r.Hops), len(r.Hops))
	case !sees:
		s = "The destination did not answer within the hop limit. This method cannot see the routers on the way."
	case r.Reached:
		s = "The destination answered."
	default:
		s = "The destination did not answer."
	}
	return s + " A hop with no reply is not evidence that the router is broken or that traffic is blocked: routers often filter, deprioritize or rate-limit these messages while forwarding traffic normally."
}
