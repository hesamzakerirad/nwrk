package cli

import (
	"context"

	"github.com/spf13/cobra"

	"github.com/hesamzakerirad/nwrk/internal/app/doctor"
	"github.com/hesamzakerirad/nwrk/internal/domain"
	"github.com/hesamzakerirad/nwrk/internal/exit"
	"github.com/hesamzakerirad/nwrk/internal/output"
	"github.com/hesamzakerirad/nwrk/internal/regions"
	"github.com/hesamzakerirad/nwrk/internal/reporting"
	"github.com/hesamzakerirad/nwrk/internal/settings"
)

func newDoctorCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check this machine and the reference targets of a region, and say which layer is at fault",
		Long: "Check this machine's own network setup (interfaces, default route, resolvers, proxies), then request the reference targets of a region preset and compare resolvers.\n" +
			"The verdict says whether the problem is local, domestic or international.\n\n" +
			"Presets: " + presetList() + ". The default is global; choose one with --region, NW_REGION or the config file. nw never detects your country.\n" +
			"The reference targets are contacted when you run this command, and nothing else is: see docs/privacy.md.\n\n" +
			"Exit status: 0 when no actionable finding was made, 1 when there is a problem, 2 on a usage error, 130 when interrupted.",
		Example: "  nw doctor\n  nw doctor --region ir\n  nw doctor --region ir --resolver 1.1.1.1 --resolver tcp://9.9.9.9",
		Args:    cobra.NoArgs,
	}
	resolvers := resolverFlag(cmd)
	cmd.RunE = func(c *cobra.Command, _ []string) error {
		preset, err := regions.Load(a.settings.Region)
		if err != nil {
			return exit.Usage(err)
		}
		o, err := a.testOptions(nil)
		if err != nil {
			return err
		}
		rs, src, err := a.settings.Resolvers(*resolvers)
		if err != nil {
			return exit.Usage(err)
		}
		chosen := src == settings.SourceFlag || src != settings.SourceDefault && !hasPrefix(src, settings.SourcePreset)
		if len(rs) == 0 {
			if rs, err = a.settings.PresetResolvers(); err != nil {
				return exit.Usage(err)
			}
			chosen = false
		}
		o.Resolvers = rs
		rep := doctor.Run(c.Context(), doctor.Options{
			Test: o, Region: a.settings.Region, Preset: preset, ChosenResolvers: chosen,
			Inspector: seams.inspector, Dial: seams.dial,
		})
		return a.emit(c.Context(), rep, true)
	}
	return cmd
}

func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }

func presetList() string {
	out := ""
	for i, n := range regions.Names() {
		if i > 0 {
			out += ", "
		}
		out += n
	}
	return out
}

// emit prints a diagnosis-style report and returns the command result.
func (a *app) emit(ctx context.Context, rep *domain.Report, diagnosis bool) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if a.out.Format == output.JSON {
		if err := a.out.JSON(rep); err != nil {
			return exit.Execution(err)
		}
	} else if diagnosis {
		reporting.Diagnosis(a.out, rep, a.opts.quiet, a.opts.verbose)
	} else {
		reporting.Human(a.out, rep, a.opts.quiet)
	}
	if diagnosis && rep.Actionable() {
		return exit.ErrFindings
	}
	return nil
}
