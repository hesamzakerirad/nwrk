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
	"time"

	"github.com/spf13/cobra"

	"github.com/hesamzakerirad/nwrk/internal/buildinfo"
	"github.com/hesamzakerirad/nwrk/internal/exit"
	"github.com/hesamzakerirad/nwrk/internal/output"
)

// SchemaVersion is the version of every JSON document nw prints.
const SchemaVersion = "1"

type options struct {
	output  string
	noColor bool
	verbose bool
	quiet   bool
	timeout time.Duration
}

// app holds what commands need at run time. It is filled in before any
// command runs, once the global flags have been parsed.
type app struct {
	opts   options
	stdout io.Writer
	stderr io.Writer
	out    *output.Renderer
	log    *slog.Logger
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
		PersistentPreRunE: func(*cobra.Command, []string) error {
			return a.setup()
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
	f.DurationVar(&a.opts.timeout, "timeout", 10*time.Second, "deadline for each network operation")

	root.AddCommand(newVersionCmd(a))

	// An unknown shell must be a usage error, not a help page with exit 0.
	root.InitDefaultCompletionCmd()
	if c, _, err := root.Find([]string{"completion"}); err == nil && c != root {
		c.Args = cobra.NoArgs
		c.RunE = func(c *cobra.Command, _ []string) error { return c.Help() }
	}
	return root
}

// setup validates the global flags and prepares output and logging.
func (a *app) setup() error {
	format, err := output.ParseFormat(a.opts.output)
	if err != nil {
		return exit.Usage(err)
	}
	if a.opts.verbose && a.opts.quiet {
		return exit.Usage(errors.New("--verbose and --quiet cannot be combined"))
	}
	if a.opts.timeout <= 0 {
		return exit.Usage(errors.New("--timeout must be greater than zero"))
	}

	a.out = &output.Renderer{
		Out:    a.stdout,
		Format: format,
		Color:  output.ColorEnabled(a.opts.noColor, a.stdout, os.Getenv),
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
