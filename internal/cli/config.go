package cli

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/hesamzakerirad/nwrk/internal/exit"
	"github.com/hesamzakerirad/nwrk/internal/output"
	"github.com/hesamzakerirad/nwrk/internal/settings"
)

func newConfigCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Show where the configuration file is and what is in effect",
		Long: "nw reads an optional TOML file with the keys region, resolvers, timeout and color.\n" +
			"Every setting follows one order: command-line flag, then NW_* environment variable, then the config file, then the default.\n" +
			"The file never holds credentials, and nw never writes it.",
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error { return c.Help() },
	}
	cmd.AddCommand(newConfigPathCmd(a), newConfigShowCmd(a))
	return cmd
}

type configPathDoc struct {
	SchemaVersion string `json:"schema_version"`
	Path          string `json:"path"`
	Exists        bool   `json:"exists"`
}

func newConfigPathCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:         "path",
		Short:       "Print the location of the configuration file",
		Long:        "Print where nw looks for its configuration file, whether or not it exists. NW_CONFIG overrides the location.",
		Args:        cobra.NoArgs,
		Annotations: map[string]string{noConfig: "true"},
		RunE: func(*cobra.Command, []string) error {
			if a.out.Format == output.JSON {
				return a.out.JSON(configPathDoc{SchemaVersion: SchemaVersion, Path: a.settings.ConfigPath, Exists: a.settings.ConfigExists})
			}
			fmt.Fprintln(a.out.Out, a.settings.ConfigPath)
			if !a.settings.ConfigExists && a.opts.verbose {
				fmt.Fprintln(a.stderr, "nw: the file does not exist; every setting uses its default")
			}
			return nil
		},
	}
}

type configValue struct {
	Value  any    `json:"value"`
	Source string `json:"source"`
}

type configShowDoc struct {
	SchemaVersion string                 `json:"schema_version"`
	ConfigPath    string                 `json:"config_path"`
	ConfigExists  bool                   `json:"config_exists"`
	Settings      map[string]configValue `json:"settings"`
}

func newConfigShowCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Print the effective settings and where each value came from",
		Long:  "Print region, resolvers, timeout and color as they are in effect for this run, with the source of each: flag, environment, config file or default.",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			s := a.settings
			resolvers, src, err := s.Resolvers(nil)
			if err != nil {
				return exit.Usage(err)
			}
			list := []string{}
			for _, r := range resolvers {
				list = append(list, r.String())
			}
			doc := configShowDoc{
				SchemaVersion: SchemaVersion, ConfigPath: s.ConfigPath, ConfigExists: s.ConfigExists,
				Settings: map[string]configValue{
					"region":    {s.Region, s.RegionSource},
					"resolvers": {list, src},
					"timeout":   {s.Timeout.String(), s.TimeoutSource},
					"color":     {s.Color, s.ColorSource},
				},
			}
			if a.out.Format == output.JSON {
				return a.out.JSON(doc)
			}
			state := "found"
			if !s.ConfigExists {
				state = "not found; defaults are in use"
			}
			fmt.Fprintf(a.out.Out, "config file: %s (%s)\n\n", s.ConfigPath, state)
			rows := [][3]string{
				{"region", fmt.Sprintf("%q", s.Region), s.RegionSource},
				{"resolvers", "[" + strings.Join(quote(list), ", ") + "]", src},
				{"timeout", fmt.Sprintf("%q", s.Timeout.String()), s.TimeoutSource},
				{"color", fmt.Sprintf("%q", s.Color), s.ColorSource},
			}
			for _, r := range rows {
				fmt.Fprintf(a.out.Out, "%-10s = %-34s %s\n", r[0], r[1], a.out.Dim("("+r[2]+")"))
			}
			if s.RegionSource == settings.SourceDefault {
				fmt.Fprintf(a.out.Out, "\n%s\n", a.out.Dim("The default region is used by nw doctor only; other commands use a region's resolvers only when you choose one."))
			}
			return nil
		},
	}
}

func quote(in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = fmt.Sprintf("%q", s)
	}
	return out
}
