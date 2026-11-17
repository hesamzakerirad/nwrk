// Package buildinfo exposes the version of the running binary.
package buildinfo

import (
	"runtime"
	"runtime/debug"
	"strings"
)

// Set at link time by GoReleaser and the Makefile.
var (
	Version = ""
	Commit  = ""
	Date    = ""
)

// Info describes the running binary.
type Info struct {
	Version   string `json:"version"`
	Commit    string `json:"commit,omitempty"`
	BuildDate string `json:"build_date,omitempty"`
	GoVersion string `json:"go_version"`
	OS        string `json:"os"`
	Arch      string `json:"arch"`
}

// Get returns build information. Values not injected at link time are read
// from the module build info, which covers `go install` builds.
func Get() Info {
	info := Info{
		Version:   Version,
		Commit:    Commit,
		BuildDate: Date,
		GoVersion: runtime.Version(),
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
	}
	if bi, ok := debug.ReadBuildInfo(); ok {
		if info.Version == "" && bi.Main.Version != "" && bi.Main.Version != "(devel)" {
			info.Version = strings.TrimPrefix(bi.Main.Version, "v")
		}
		for _, s := range bi.Settings {
			switch s.Key {
			case "vcs.revision":
				if info.Commit == "" {
					info.Commit = s.Value
				}
			case "vcs.time":
				if info.BuildDate == "" {
					info.BuildDate = s.Value
				}
			}
		}
	}
	if info.Version == "" {
		info.Version = "dev"
	}
	return info
}
