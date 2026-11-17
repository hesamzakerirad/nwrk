package cli

import (
	"github.com/spf13/cobra"

	"github.com/hesamzakerirad/nwrk/internal/app/diagnose"
	"github.com/hesamzakerirad/nwrk/internal/exit"
	"github.com/hesamzakerirad/nwrk/internal/output"
	"github.com/hesamzakerirad/nwrk/internal/reporting"
)

func newDiagnoseCmd(a *app) *cobra.Command {
	var profile string
	cmd := &cobra.Command{
		Use:   "diagnose <target>",
		Short: "Investigate a destination across DNS, TCP, TLS and HTTP",
		Long: "Measure how this machine reaches a destination, layer by layer, and say what the evidence shows.\n\n" +
			"The target is a host name, host:port, or a URL. A bare host means https on port 443; port 80 means http.\n" +
			"Layers that cannot run because an earlier one failed are skipped, with the reason. Findings state what was observed;\n" +
			"hypotheses are possible explanations and say what supports them and what was not checked.\n\n" +
			"Profiles: quick (DNS and TCP), standard (adds TLS and HTTP, tested per IP family; the default), deep (every reachable address).\n\n" +
			"Exit status: 0 when no actionable finding was made, 1 when the target has a problem, 2 on a usage error, 130 when interrupted.",
		Example: "  nw diagnose example.com\n  nw diagnose https://example.com/health --profile deep\n  nw diagnose example.com:8443 --resolver 1.1.1.1",
		Args:    cobra.ExactArgs(1),
	}
	resolvers := resolverFlag(cmd)
	cmd.Flags().StringVar(&profile, "profile", string(diagnose.DefaultProfile), "how much to measure: quick, standard or deep")
	cmd.RunE = func(c *cobra.Command, args []string) error {
		t, err := diagnose.ParseTarget(args[0])
		if err != nil {
			return exit.Usage(err)
		}
		p, err := diagnose.ParseProfile(profile)
		if err != nil {
			return exit.Usage(err)
		}
		o, err := a.testOptions(*resolvers)
		if err != nil {
			return err
		}
		rep := diagnose.Run(c.Context(), t, diagnose.Options{Test: o, Profile: p})
		if err := c.Context().Err(); err != nil {
			return err
		}
		if a.out.Format == output.JSON {
			if err := a.out.JSON(rep); err != nil {
				return exit.Execution(err)
			}
		} else {
			reporting.Diagnosis(a.out, rep, a.opts.quiet, a.opts.verbose)
		}
		if rep.Actionable() {
			return exit.ErrFindings
		}
		return nil
	}
	return cmd
}
