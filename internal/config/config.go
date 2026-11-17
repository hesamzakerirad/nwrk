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
	"path/filepath"
	"runtime"

	"github.com/BurntSushi/toml"
)

// EnvPath names the environment variable that overrides the file location.
const EnvPath = "NW_CONFIG"

// File is the content of the configuration file. Every key is optional.
type File struct {
	Region    string   `toml:"region"`
	Resolvers []string `toml:"resolvers"`
	Timeout   string   `toml:"timeout"`
	Color     string   `toml:"color"`
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
	switch goos {
	case "windows":
		base := getenv("LOCALAPPDATA")
		if base == "" {
			base = filepath.Join(home, "AppData", "Local")
		}
		return filepath.Join(base, "nwrk", "config.toml")
	case "darwin":
		return filepath.Join(home, "Library", "Application Support", "nwrk", "config.toml")
	}
	base := getenv("XDG_CONFIG_HOME")
	if base == "" {
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "nwrk", "config.toml")
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
		return File{}, true, fmt.Errorf("%s: unknown key %q (valid keys: region, resolvers, timeout, color)", path, u[0].String())
	}
	return f, true, nil
}
