package cli

import (
	"github.com/spf13/cobra"

	"github.com/hesamzakerirad/nwrk/internal/app/diagnose"
	"github.com/hesamzakerirad/nwrk/internal/app/probes"
	"github.com/hesamzakerirad/nwrk/internal/app/security"
	"github.com/hesamzakerirad/nwrk/internal/exit"
)

func newSecurityCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "security",
		Short: "Security-oriented checks and signs of interference",
		Long: "Checks built on the same measurements as nw diagnose.\n" +
			"They test only the target you name, with a small, fixed set of extra requests, and change nothing on your system.",
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error { return c.Help() },
	}
	cmd.AddCommand(newSecurityInspectCmd(a), newSecurityInterferenceCmd(a))
	return cmd
}

func securityTarget(arg string) (diagnose.Target, error) {
	t, err := diagnose.ParseTarget(arg)
	if err != nil {
		return t, exit.Usage(err)
	}
	return t, nil
}

func newSecurityInspectCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "inspect <target>",
		Short: "DNSSEC, certificate expiry, deprecated TLS versions and transport-security headers",
		Long: "Make security-oriented observations about a target: whether its name is DNSSEC-signed and validated, its CNAME chain, how soon its certificate expires, whether it still accepts TLS 1.0 or 1.1, whether plain http is upgraded to https, and whether it sends Strict-Transport-Security.\n" +
			"The target is a host name, host:port or URL, as for nw diagnose. Findings carry caveats; none of these is a verdict.\n\n" +
			"Exit status: 0 when no actionable finding was made, 1 when there is one, 2 on a usage error, 130 when interrupted.",
		Example: "  nw security inspect example.com\n  nw security inspect example.com --resolver tls://9.9.9.9",
		Args:    cobra.ExactArgs(1),
	}
	resolvers := resolverFlag(cmd)
	cmd.RunE = func(c *cobra.Command, args []string) error {
		t, err := securityTarget(args[0])
		if err != nil {
			return err
		}
		o, err := a.testOptions(*resolvers)
		if err != nil {
			return err
		}
		rep := security.Inspect(c.Context(), t, security.Options{Test: o, PlainPort: seams.plainPort})
		return a.emit(c.Context(), rep, true)
	}
	return cmd
}

func newSecurityInterferenceCmd(a *app) *cobra.Command {
	var control string
	cmd := &cobra.Command{
		Use:   "interference <target>",
		Short: "Look for signs that DNS, TLS or HTTP traffic to a target is being altered",
		Long: "Compare what different resolvers return, listen for several different replies to one DNS query, compare TLS handshakes that differ only in the server name sent, and compare http with https.\n" +
			"Every finding says what else could explain it and what was not checked. nw never labels an event from a single timeout or mismatch, and no finding reaches high confidence from one measurement.\n" +
			"Comparisons need something to compare with: add resolvers with --resolver, ideally over an encrypted transport (tls:// or https://). Without them the report says what could not be established.\n\n" +
			"Exit status: 0 when no actionable finding was made, 1 when there is one, 2 on a usage error, 130 when interrupted.",
		Example: "  nw security interference example.com --resolver tls://9.9.9.9 --resolver 1.1.1.1\n  nw security interference example.com --control www.example.net",
		Args:    cobra.ExactArgs(1),
	}
	resolvers := resolverFlag(cmd)
	cmd.Flags().StringVar(&control, "control", probes.DefaultControlSNI, "neutral server name for the TLS server-name comparison")
	cmd.RunE = func(c *cobra.Command, args []string) error {
		t, err := securityTarget(args[0])
		if err != nil {
			return err
		}
		o, err := a.testOptions(*resolvers)
		if err != nil {
			return err
		}
		rep := security.Interference(c.Context(), t, security.Options{Test: o, Control: control, PlainPort: seams.plainPort})
		return a.emit(c.Context(), rep, true)
	}
	return cmd
}
