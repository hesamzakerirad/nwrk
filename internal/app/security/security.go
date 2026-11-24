// Package security runs nw security inspect and nw security interference.
// Both build on the same measurements as nw diagnose and add probes: the
// extra, comparative measurements that the interference and security rules
// need.
package security

import (
	"context"

	"github.com/radestsam/nwrk/internal/app/diagnose"
	"github.com/radestsam/nwrk/internal/app/probes"
	apptest "github.com/radestsam/nwrk/internal/app/test"
	"github.com/radestsam/nwrk/internal/diagnostics/rules"
	"github.com/radestsam/nwrk/internal/domain"
)

// Options configure a run.
type Options struct {
	Test apptest.Options
	// Control is the neutral server name for the interference comparison.
	Control string
	// Window and PlainPort are for tests; see probes.Options.
	PlainPort int
}

func (o Options) probes() probes.Options {
	return probes.Options{Test: o.Test, ControlSNI: o.Control, PlainPort: o.PlainPort}
}

// Interference investigates signs of interference with DNS, TLS and HTTP
// for t. It compares what different resolvers return, listens for several
// replies to one query, compares handshakes that differ only in the server
// name, and compares http with https. Nothing here concludes that
// interference happened: each finding says what else could explain it.
func Interference(ctx context.Context, t diagnose.Target, o Options) *domain.Report {
	rep := diagnose.Measure(ctx, t, diagnose.Options{Test: o.Test, Profile: diagnose.Standard})
	rep.Run.Command = "security interference"
	rep.Run.Profile = ""
	if ctx.Err() == nil {
		probes.Interference(ctx, rep, t.Host, t.Port, t.TLS, t.URL, o.probes())
	}
	diagnose.Finish(rep, append(rules.All(), rules.Interference()...))
	return rep
}

// Inspect makes security-oriented observations about t: DNSSEC status and
// the alias chain, certificate expiry, whether deprecated TLS versions are
// accepted, and basic transport-security headers.
func Inspect(ctx context.Context, t diagnose.Target, o Options) *domain.Report {
	rep := diagnose.Measure(ctx, t, diagnose.Options{Test: o.Test, Profile: diagnose.Standard})
	rep.Run.Command = "security inspect"
	rep.Run.Profile = ""
	if ctx.Err() == nil {
		probes.Security(ctx, rep, t.Host, t.Port, t.TLS, t.URL, o.probes())
	}
	diagnose.Finish(rep, append(rules.All(), rules.Security()...))
	return rep
}
