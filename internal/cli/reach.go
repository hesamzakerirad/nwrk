package cli

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/hesamzakerirad/nwrk/internal/app/reach"
	"github.com/hesamzakerirad/nwrk/internal/endpoints"
	"github.com/hesamzakerirad/nwrk/internal/exit"
	"github.com/hesamzakerirad/nwrk/internal/target"
)

func newReachCmd(a *app) *cobra.Command {
	var preset string
	var noHTTP3 bool
	cmd := &cobra.Command{
		Use:   "reach [url...]",
		Short: "Request a set of endpoints and say whether a failure looks like a server-side restriction or network interference",
		Long: "Request every endpoint of an endpoint preset, or the URLs you list, and sort what went wrong into two groups with neutral wording:\n" +
			"a server-side restriction (the server answered and refused: HTTP 403 or 451) or network interference (a reset, a timeout, a failed handshake, or a private address for a public name).\n" +
			"Each endpoint is requested once per IP family that has an address, and HTTP/3 over UDP is probed when the server advertises it. The report shows the difference between IPv4 and IPv6.\n\n" +
			"The built-in preset is dev (code hosts and package registries). Add your own with [[endpoint_presets]] in the config file. Only the endpoints are contacted; see docs/privacy.md.\n\n" +
			"Exit status: 0 when no actionable finding was made, 1 when there is a problem, 2 on a usage error, 130 when interrupted.",
		Example: "  nw reach\n  nw reach --preset work\n  nw reach github.com proxy.golang.org --output json",
	}
	cmd.Flags().StringVar(&preset, "preset", endpoints.Default, "endpoint preset: "+strings.Join(endpoints.Names(nil), ", ")+", or one from the config file")
	cmd.Flags().BoolVar(&noHTTP3, "no-http3", false, "skip the HTTP/3 probe")
	cmd.RunE = func(c *cobra.Command, args []string) error {
		user := a.settings.EndpointPresets()
		var p endpoints.Preset
		var err error
		if len(args) > 0 {
			p = endpoints.Preset{Name: "custom"}
			for _, s := range args {
				u, err := target.URL(s)
				if err != nil {
					return exit.Usage(err)
				}
				p.Endpoints = append(p.Endpoints, endpoints.Endpoint{URL: u.String()})
			}
			if err := p.Validate(false); err != nil {
				return exit.Usage(err)
			}
		} else if p, err = endpoints.Load(preset, user); err != nil {
			return exit.Usage(err)
		}
		o, err := a.testOptions(nil)
		if err != nil {
			return err
		}
		rep := reach.Run(c.Context(), reach.Options{Test: o, Preset: p, SkipHTTP3: noHTTP3})
		return a.emit(c.Context(), rep, true)
	}
	return cmd
}
