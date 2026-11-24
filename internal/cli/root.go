// Package cli wires the nw commands to flags and output.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/radestsam/nwrk/internal/buildinfo"
	"github.com/radestsam/nwrk/internal/config"
	"github.com/radestsam/nwrk/internal/exit"
	"github.com/radestsam/nwrk/internal/output"
	"github.com/radestsam/nwrk/internal/regions"
	"github.com/radestsam/nwrk/internal/settings"
)

// SchemaVersion is the version of every JSON document nw prints.
const SchemaVersion = "1"

type options struct {
	output  string
	noColor bool
	verbose bool
	quiet   bool
	timeout time.Duration
	region  string
}

// app holds what commands need at run time. It is filled in before any
// command runs, once the global flags have been parsed.
type app struct {
	opts     options
	settings *settings.Effective
	stdout   io.Writer
	stderr   io.Writer
	out      *output.Renderer
	log      *slog.Logger
}

// Execute runs nw and returns the process exit code.
func Execute(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	a := &app{stdout: stdout, stderr: stderr}
	root := newRootCmd(a)
	root.SetArgs(args)

	err := root.ExecuteContext(ctx)
	if err == nil {
		return exit.OK
	}
	if ctx.Err() != nil {
		return exit.Interrupted
	}
	if errors.Is(err, exit.ErrFindings) {
		return exit.Findings
	}
	// Flags are not parsed yet when the command itself is unknown, so read
	// them again, ignoring errors, to honor --output json in the error.
	_ = root.ParseFlags(args)
	a.printError(err)
	return exit.CodeOf(err)
}

func newRootCmd(a *app) *cobra.Command {
	root := &cobra.Command{
		Use:           "nw",
		Short:         "Diagnose network problems and collect evidence",
		Long:          "nw measures how your network reaches a destination and explains what the evidence shows.\nDocumentation: https://nwrk.ir",
		Version:       buildinfo.Get().Version,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(c *cobra.Command, _ []string) error {
			return a.setup(c)
		},
	}
	root.SetOut(a.stdout)
	root.SetErr(a.stderr)
	root.SetVersionTemplate("nw {{.Version}}\n")
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return exit.Usage(err)
	})

	f := root.PersistentFlags()
	f.StringVarP(&a.opts.output, "output", "o", string(output.Human), "output format: human or json")
	f.BoolVar(&a.opts.noColor, "no-color", false, "disable colored output (the NO_COLOR variable also works)")
	f.BoolVarP(&a.opts.verbose, "verbose", "v", false, "show additional detail and debug logs on stderr")
	f.BoolVarP(&a.opts.quiet, "quiet", "q", false, "suppress nonessential output; errors and exit status remain")
	f.DurationVar(&a.opts.timeout, "timeout", settings.DefaultTimeout, "deadline for each network operation (also NW_TIMEOUT or the config file)")
	f.StringVar(&a.opts.region, "region", regions.Default, "region preset: "+strings.Join(regions.Names(), " or ")+" (also NW_REGION or the config file)")

	root.AddCommand(newVersionCmd(a))
	root.AddCommand(newTestCmd(a))
	root.AddCommand(newDiagnoseCmd(a))
	root.AddCommand(newConfigCmd(a))
	root.AddCommand(newDoctorCmd(a))
	root.AddCommand(newReachCmd(a))
	root.AddCommand(newSecurityCmd(a))
	root.AddCommand(newPathCmd(a))
	root.AddCommand(newNetworkCmd(a))
	root.AddCommand(newCommunityCmd(a))

	// An unknown shell must be a usage error, not a help page with exit 0.
	root.InitDefaultCompletionCmd()
	if c, _, err := root.Find([]string{"completion"}); err == nil && c != root {
		c.Annotations = map[string]string{noConfig: "true"}
		c.Args = cobra.NoArgs
		c.RunE = func(c *cobra.Command, _ []string) error { return c.Help() }
	}
	return root
}

// noConfig marks commands that must keep working when the configuration
// file is broken, because they are how you find or fix it.
const noConfig = "nwrk/no-config"

func skipsConfig(c *cobra.Command) bool {
	for ; c != nil; c = c.Parent() {
		if c.Annotations[noConfig] == "true" {
			return true
		}
	}
	return false
}

// setup validates the global flags, resolves every setting from flags, the
// environment and the config file, and prepares output and logging.
func (a *app) setup(cmd *cobra.Command) error {
	format, err := output.ParseFormat(a.opts.output)
	if err != nil {
		return exit.Usage(err)
	}
	if a.opts.verbose && a.opts.quiet {
		return exit.Usage(errors.New("--verbose and --quiet cannot be combined"))
	}

	var fl settings.Flags
	if cmd.Flags().Changed("timeout") {
		fl.Timeout = &a.opts.timeout
	}
	if cmd.Flags().Changed("region") {
		fl.Region = &a.opts.region
	}
	path := config.DefaultPath()
	eff, err := settings.Load(os.Getenv, path, fl)
	if err != nil && skipsConfig(cmd) {
		eff, err = settings.Load(os.Getenv, filepath.Join(os.TempDir(), "nwrk-no-such-config.toml"), fl)
		if eff != nil {
			eff.ConfigPath = path
		}
	}
	if err != nil {
		return exit.Usage(err)
	}
	a.settings = eff
	a.opts.timeout = eff.Timeout

	a.out = &output.Renderer{
		Out:    a.stdout,
		Format: format,
		Color:  output.ColorEnabledMode(eff.Color, a.opts.noColor, a.stdout, os.Getenv),
	}

	level := slog.LevelWarn
	switch {
	case a.opts.verbose:
		level = slog.LevelDebug
	case a.opts.quiet:
		level = slog.LevelError
	}
	a.log = slog.New(slog.NewTextHandler(a.stderr, &slog.HandlerOptions{Level: level}))
	return nil
}

// printError writes err to stderr, as JSON when the user asked for it.
func (a *app) printError(err error) {
	if a.opts.output == string(output.JSON) {
		doc := map[string]any{
			"schema_version": SchemaVersion,
			"error": map[string]string{
				"kind":    string(exit.KindOf(err)),
				"message": err.Error(),
			},
		}
		_ = json.NewEncoder(a.stderr).Encode(doc)
		return
	}
	fmt.Fprintf(a.stderr, "nw: %s\n", err)
	if exit.KindOf(err) == exit.KindUsage {
		fmt.Fprintln(a.stderr, "Run 'nw --help' for usage.")
	}
}
