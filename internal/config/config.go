// Package config reads nw's TOML configuration file.
//
// The file never holds credentials. Unknown keys are an error, so a typo
// cannot silently do nothing.
package config

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"runtime"
	"strings"

	"github.com/BurntSushi/toml"

	"github.com/hesamzakerirad/nwrk/internal/endpoints"
)

// EnvPath names the environment variable that overrides the file location.
const EnvPath = "NW_CONFIG"

// File is the content of the configuration file. Every key is optional.
type File struct {
	Region    string   `toml:"region"`
	Resolvers []string `toml:"resolvers"`
	Timeout   string   `toml:"timeout"`
	Color     string   `toml:"color"`
	// EndpointPresets are user-defined presets for nw reach, in the same
	// format as the built-in ones.
	EndpointPresets []endpoints.Preset `toml:"endpoint_presets"`
}

// Path returns where the configuration file lives for the given operating
// system, environment and home directory. NW_CONFIG overrides it.
//
//	Linux:   $XDG_CONFIG_HOME/nwrk/config.toml, else ~/.config/nwrk/config.toml
//	macOS:   ~/Library/Application Support/nwrk/config.toml
//	Windows: %LOCALAPPDATA%\nwrk\config.toml
func Path(goos string, getenv func(string) string, home string) string {
	if p := getenv(EnvPath); p != "" {
		return p
	}
	sep := "/"
	if goos == "windows" {
		sep = `\`
	}
	join := func(parts ...string) string { return strings.Join(parts, sep) }
	switch goos {
	case "windows":
		base := getenv("LOCALAPPDATA")
		if base == "" {
			base = join(home, "AppData", "Local")
		}
		return join(base, "nwrk", "config.toml")
	case "darwin":
		return join(home, "Library", "Application Support", "nwrk", "config.toml")
	}
	base := getenv("XDG_CONFIG_HOME")
	if base == "" {
		base = join(home, ".config")
	}
	return join(base, "nwrk", "config.toml")
}

// DefaultPath is Path for the running system.
func DefaultPath() string {
	home, _ := os.UserHomeDir()
	return Path(runtime.GOOS, os.Getenv, home)
}

// Load reads the file at path. A missing file is not an error: exists is
// false and the file is empty.
func Load(path string) (f File, exists bool, err error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return File{}, false, nil
	}
	if err != nil {
		return File{}, false, err
	}
	md, err := toml.Decode(string(b), &f)
	if err != nil {
		return File{}, true, fmt.Errorf("%s: %w", path, err)
	}
	if u := md.Undecoded(); len(u) > 0 {
		return File{}, true, fmt.Errorf("%s: unknown key %q (valid keys: region, resolvers, timeout, color, endpoint_presets)", path, u[0].String())
	}
	if err := endpoints.ValidateUser(f.EndpointPresets); err != nil {
		return File{}, true, fmt.Errorf("%s: %w", path, err)
	}
	return f, true, nil
}
