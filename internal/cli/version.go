package cli

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/hesamzakerirad/nwrk/internal/buildinfo"
	"github.com/hesamzakerirad/nwrk/internal/output"
)

type versionDoc struct {
	SchemaVersion string `json:"schema_version"`
	Tool          string `json:"tool"`
	buildinfo.Info
}

func newVersionCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print version and build information",
		Long:  "Print the version, commit, build date and platform of this nw binary.\nThis command makes no network requests.",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			info := buildinfo.Get()
			if a.out.Format == output.JSON {
				return a.out.JSON(versionDoc{SchemaVersion: SchemaVersion, Tool: "nw", Info: info})
			}
			fmt.Fprintf(a.out.Out, "%s %s\n", a.out.Bold("nw"), info.Version)
			rows := [][2]string{
				{"commit", info.Commit},
				{"built", info.BuildDate},
				{"go", info.GoVersion},
				{"platform", info.OS + "/" + info.Arch},
			}
			for _, row := range rows {
				if row[1] != "" {
					fmt.Fprintf(a.out.Out, "  %s %s\n", a.out.Dim(fmt.Sprintf("%-9s", row[0])), row[1])
				}
			}
			return nil
		},
	}
}
