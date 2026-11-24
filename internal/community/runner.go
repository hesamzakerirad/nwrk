package community

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/radestsam/nwrk/contracts"
	"github.com/radestsam/nwrk/internal/buildinfo"
	"github.com/radestsam/nwrk/internal/domain"
	"github.com/radestsam/nwrk/internal/measurement/dns"
	nwhttp "github.com/radestsam/nwrk/internal/measurement/http"
	"github.com/radestsam/nwrk/internal/measurement/local"
	"github.com/radestsam/nwrk/internal/measurement/tcp"
	nwtls "github.com/radestsam/nwrk/internal/measurement/tls"
)

// ClientName is the client name in every contribution.
const ClientName = "nwrk"

// ErrNoRoute means that this machine has no route to the internet.
var ErrNoRoute = errors.New("this machine has no route to the internet")

// Engine runs one measurement for each layer. The default engine uses the
// measurement packages. Tests use their own.
type Engine interface {
	// DNS resolves host with the operating system resolver.
	DNS(ctx context.Context, host string) *domain.Measurement
	// TCP connects to addr.
	TCP(ctx context.Context, host string, addr netip.AddrPort) *domain.Measurement
	// TLS runs a handshake with the name host, to addr.
	TLS(ctx context.Context, host string, addr netip.AddrPort) *domain.Measurement
	// HTTP sends the request of ep to addr. It returns the measurement and
	// the status code of the first response.
	HTTP(ctx context.Context, ep contracts.Endpoint, addr netip.AddrPort) (*domain.Measurement, int)
}

// Routes says which IP families this machine can use.
type Routes struct{ IPv4, IPv6 bool }

// Has reports whether the family ("ipv4" or "ipv6") has a route.
func (r Routes) Has(family string) bool {
	if family == "ipv6" {
		return r.IPv6
	}
	return r.IPv4
}

// Progress is called after each endpoint finishes.
type Progress func(done, total int, targetID string)

// Runner runs a profile.
type Runner struct {
	Engine   Engine
	Routes   func(ctx context.Context) Routes
	Progress Progress
}

// NewRunner returns a runner that measures this machine.
func NewRunner() *Runner {
	return &Runner{Engine: systemEngine{}, Routes: systemRoutes}
}

func systemRoutes(ctx context.Context) Routes {
	m := local.Route(ctx, nil)
	res, ok := m.Result.(*local.RouteResult)
	if !ok {
		return Routes{}
	}
	return Routes{IPv4: res.IPv4.Available, IPv6: res.IPv6.Available}
}

// Run measures every endpoint of p and returns the contribution document.
// An endpoint, or a family of it, that could not be reached for a reason of
// this machine is left out, because a missing measurement is not a failed one.
// When the time budget of the profile ends, the layers that did not finish are
// left out too.
func (r *Runner) Run(ctx context.Context, p *contracts.Profile) (*contracts.Contribution, error) {
	routes := r.Routes(ctx)
	if !routes.IPv4 && !routes.IPv6 {
		return nil, ErrNoRoute
	}
	budget, cancel := context.WithTimeout(ctx, time.Duration(p.Limits.TotalBudgetMS)*time.Millisecond)
	defer cancel()

	results := make([]*contracts.Result, len(p.Endpoints))
	sem := make(chan struct{}, max(1, p.Limits.Concurrency))
	var wg sync.WaitGroup
	var mu sync.Mutex
	done := 0
loop:
	for i := range p.Endpoints {
		select {
		case sem <- struct{}{}:
		case <-budget.Done():
			break loop
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer func() { <-sem }()
			ep := p.Endpoints[i]
			ms := r.measureEndpoint(budget, p, ep, routes)
			if len(ms) > 0 {
				results[i] = &contracts.Result{TargetID: ep.TargetID, Measurements: ms}
			}
			mu.Lock()
			done++
			if r.Progress != nil {
				r.Progress(done, len(p.Endpoints), ep.TargetID)
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	c := &contracts.Contribution{SchemaVersion: contracts.SchemaVersion}
	c.Client.Name = ClientName
	c.Client.Version = clientVersion(buildinfo.Get().Version)
	c.Profile.ID = p.ID
	c.Profile.Version = p.Version
	c.Results = []contracts.Result{}
	for _, res := range results {
		if res != nil {
			c.Results = append(c.Results, *res)
		}
	}
	if len(c.Results) == 0 {
		return nil, errors.New("no measurement finished before the time budget ended")
	}
	return c, nil
}

var semver = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$`)

// clientVersion returns the version in the form that the contract accepts. A
// build without a release version, such as "dev", is reported as 0.0.0-dev.
func clientVersion(v string) string {
	v = strings.TrimPrefix(v, "v")
	if semver.MatchString(v) && len(v) <= 32 {
		return v
	}
	return "0.0.0-dev"
}

// layerCtx limits one layer to its time from the profile.
func layerCtx(parent context.Context, p *contracts.Profile, layer string) (context.Context, context.CancelFunc) {
	return context.WithTimeout(parent, time.Duration(p.Limits.TimeoutsMS[layer])*time.Millisecond)
}

// measureEndpoint runs the layers of one endpoint in order, once for each
// family. The layers after a failed layer do not run.
func (r *Runner) measureEndpoint(ctx context.Context, p *contracts.Profile, ep contracts.Endpoint, routes Routes) []contracts.Measurement {
	var out []contracts.Measurement
	uses := func(layer string) bool { return slices.Contains(ep.MeasurementTypes, layer) }

	dctx, cancel := layerCtx(ctx, p, "dns")
	dm := r.Engine.DNS(dctx, ep.Hostname)
	cancel()
	if ctx.Err() != nil {
		return nil
	}
	res, _ := dm.Result.(*dns.Result)
	if res == nil {
		return nil
	}

	for _, family := range ep.Families {
		if !routes.Has(family) {
			continue
		}
		qtype := "A"
		if family == "ipv6" {
			qtype = "AAAA"
		}
		var q *dns.QueryResult
		for i := range res.Queries {
			if res.Queries[i].Type == qtype {
				q = &res.Queries[i]
			}
		}
		if q == nil {
			continue
		}
		if uses("dns") {
			out = append(out, dnsMeasurement(family, *q))
		}
		if q.Error != nil || len(q.Answers) == 0 {
			continue
		}
		ip, err := netip.ParseAddr(q.Answers[0])
		if err != nil {
			continue
		}
		// One address, pinned: all layers of a family describe one path.
		addr := netip.AddrPortFrom(ip.Unmap(), uint16(ep.Port))

		if uses("tcp") {
			m, ok := r.step(ctx, p, "tcp", family, func(c context.Context) *domain.Measurement { return r.Engine.TCP(c, ep.Hostname, addr) })
			if !ok {
				return out
			}
			out = append(out, m)
			if m.Outcome != outcomeSuccess {
				continue
			}
		}
		if uses("tls") {
			m, ok := r.step(ctx, p, "tls", family, func(c context.Context) *domain.Measurement { return r.Engine.TLS(c, ep.Hostname, addr) })
			if !ok {
				return out
			}
			out = append(out, m)
			if m.Outcome != outcomeSuccess {
				continue
			}
		}
		if uses("http") {
			hctx, hcancel := layerCtx(ctx, p, "http")
			hm, status := r.Engine.HTTP(hctx, ep, addr)
			hcancel()
			if ctx.Err() != nil {
				return out
			}
			out = append(out, httpMeasurement(family, status, hm))
		}
	}
	return out
}

// step runs one TCP or TLS layer. It returns false when the budget ended
// before the layer finished: that measurement is not kept.
func (r *Runner) step(ctx context.Context, p *contracts.Profile, layer, family string, run func(context.Context) *domain.Measurement) (contracts.Measurement, bool) {
	lctx, cancel := layerCtx(ctx, p, layer)
	defer cancel()
	m := run(lctx)
	if ctx.Err() != nil {
		return contracts.Measurement{}, false
	}
	return stepMeasurement(layer, family, m), true
}

// systemEngine measures with the operating system and the network.
type systemEngine struct{}

func (systemEngine) DNS(ctx context.Context, host string) *domain.Measurement {
	return dns.System(ctx, host)
}

func (systemEngine) TCP(ctx context.Context, host string, addr netip.AddrPort) *domain.Measurement {
	return tcp.Connect(ctx, host, addr, nil)
}

func (systemEngine) TLS(ctx context.Context, host string, addr netip.AddrPort) *domain.Measurement {
	return nwtls.Handshake(ctx, host, addr, nwtls.Options{})
}

func (systemEngine) HTTP(ctx context.Context, ep contracts.Endpoint, addr netip.AddrPort) (*domain.Measurement, int) {
	u := &url.URL{Scheme: ep.Scheme, Host: ep.Hostname, Path: ep.Path}
	if (ep.Scheme == "https" && ep.Port != 443) || (ep.Scheme == "http" && ep.Port != 80) {
		u.Host = net.JoinHostPort(ep.Hostname, strconv.Itoa(ep.Port))
	}
	network := "tcp4"
	if addr.Addr().Is6() {
		network = "tcp6"
	}
	pinned := addr.String()
	m := nwhttp.Get(ctx, u, nwhttp.Options{
		Method:     ep.Method,
		NoRedirect: ep.RedirectPolicy == "none",
		MaxBody:    int64(ep.MaxResponseBytes),
		// The name resolves to the address that the DNS step found.
		DialContext: func(c context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(c, network, pinned)
		},
	})
	status := 0
	if res, ok := m.Result.(*nwhttp.Result); ok {
		status = res.StatusCode
	}
	return m, status
}
