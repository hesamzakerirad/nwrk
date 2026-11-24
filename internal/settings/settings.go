// Package settings resolves every setting from its sources, in one order:
// command-line flag, then NW_* environment variable, then the config file,
// then the built-in default (or the region preset, for resolvers). It also
// records which source each value came from, for nw config show.
package settings

import (
	"fmt"
	"strings"
	"time"

	"github.com/radestsam/nwrk/internal/config"
	"github.com/radestsam/nwrk/internal/endpoints"
	"github.com/radestsam/nwrk/internal/regions"
	"github.com/radestsam/nwrk/internal/target"
)

// Sources of a value.
const (
	SourceFlag    = "flag"
	SourceEnv     = "env"
	SourceConfig  = "config file"
	SourceDefault = "default"
	SourcePreset  = "region preset"
)

// Environment variables.
const (
	EnvRegion  = "NW_REGION"
	EnvTimeout = "NW_TIMEOUT"
	EnvColor   = "NW_COLOR"
)

// Defaults.
const (
	DefaultTimeout = 10 * time.Second
	DefaultColor   = "auto"
)

// Effective holds the resolved settings.
type Effective struct {
	ConfigPath   string
	ConfigExists bool

	Region        string
	RegionSource  string
	Timeout       time.Duration
	TimeoutSource string
	Color         string
	ColorSource   string

	cfg    config.File
	getenv func(string) string
}

// Flags carries the command-line values that were set. A nil pointer means
// the flag was not given.
type Flags struct {
	Region  *string
	Timeout *time.Duration
}

// Load resolves the settings. getenv is os.Getenv in the real program.
func Load(getenv func(string) string, path string, fl Flags) (*Effective, error) {
	cfg, exists, err := config.Load(path)
	if err != nil {
		return nil, err
	}
	e := &Effective{ConfigPath: path, ConfigExists: exists, cfg: cfg, getenv: getenv}

	if e.Region, e.RegionSource, err = pick(fl.Region, getenv(EnvRegion), EnvRegion, cfg.Region, regions.Default); err != nil {
		return nil, err
	}
	if !regions.Valid(e.Region) {
		return nil, fmt.Errorf("unknown region %q from %s (available: %s)", e.Region, e.RegionSource, strings.Join(regions.Names(), ", "))
	}

	timeout, src, err := pickDuration(fl.Timeout, getenv(EnvTimeout), cfg.Timeout)
	if err != nil {
		return nil, err
	}
	e.Timeout, e.TimeoutSource = timeout, src

	if e.Color, e.ColorSource, err = pick(nil, getenv(EnvColor), EnvColor, cfg.Color, DefaultColor); err != nil {
		return nil, err
	}
	switch e.Color {
	case "auto", "always", "never":
	default:
		return nil, fmt.Errorf("invalid color %q from %s (want auto, always or never)", e.Color, e.ColorSource)
	}
	return e, nil
}

// pick returns the first of flag, env, config that is set, else def, with
// the source. env names the variable for the source text.
func pick(flag *string, env, envName, cfg, def string) (string, string, error) {
	switch {
	case flag != nil:
		return *flag, SourceFlag, nil
	case env != "":
		return env, SourceEnv + " " + envName, nil
	case cfg != "":
		return cfg, SourceConfig, nil
	}
	return def, SourceDefault, nil
}

func pickDuration(flag *time.Duration, env, cfg string) (time.Duration, string, error) {
	if flag != nil {
		if *flag <= 0 {
			return 0, "", fmt.Errorf("--timeout must be greater than zero")
		}
		return *flag, SourceFlag, nil
	}
	for _, c := range []struct{ v, src string }{{env, SourceEnv + " " + EnvTimeout}, {cfg, SourceConfig}} {
		if c.v == "" {
			continue
		}
		d, err := time.ParseDuration(c.v)
		if err != nil || d <= 0 {
			return 0, "", fmt.Errorf("invalid timeout %q from %s (want a duration such as 5s)", c.v, c.src)
		}
		return d, c.src, nil
	}
	return DefaultTimeout, SourceDefault, nil
}

// RegionExplicit reports whether the user selected the region, as opposed
// to it being the default.
func (e *Effective) RegionExplicit() bool { return e.RegionSource != SourceDefault }

// Resolvers returns the resolvers to use and where they came from, taking
// the first source that sets any:
//
//  1. the --resolver flags (flagValues)
//  2. the NW_RESOLVERS environment variable
//  3. the config file
//  4. the resolvers of the region preset, only when the region was chosen
//     explicitly, so nothing contacts a public resolver unasked
//
// The system resolver is measured regardless; these are the ones compared
// with it.
func (e *Effective) Resolvers(flagValues []string) ([]target.Resolver, string, error) {
	if len(flagValues) > 0 {
		rs, err := target.ParseResolvers(flagValues)
		return rs, SourceFlag, err
	}
	if v := strings.TrimSpace(e.getenv(target.EnvResolvers)); v != "" {
		rs, err := target.Resolvers(nil, e.getenv)
		return rs, SourceEnv + " " + target.EnvResolvers, err
	}
	if len(e.cfg.Resolvers) > 0 {
		rs, err := target.ParseResolvers(e.cfg.Resolvers)
		if err != nil {
			return nil, "", fmt.Errorf("%s: resolvers: %v", e.ConfigPath, err)
		}
		return rs, SourceConfig, nil
	}
	if e.RegionExplicit() {
		rs, err := e.PresetResolvers()
		return rs, SourcePreset + " " + e.Region, err
	}
	return nil, SourceDefault, nil
}

// PresetResolvers returns the resolvers of the selected region preset.
func (e *Effective) PresetResolvers() ([]target.Resolver, error) {
	p, err := regions.Load(e.Region)
	if err != nil {
		return nil, err
	}
	var out []target.Resolver
	for _, r := range p.Resolvers {
		tr, err := target.ParseResolver(r.Address)
		if err != nil {
			return nil, err
		}
		out = append(out, tr)
	}
	return out, nil
}

// ConfigResolvers returns the resolver list as written in the config file.
func (e *Effective) ConfigResolvers() []string { return e.cfg.Resolvers }

// EndpointPresets returns the endpoint presets defined in the config file.
func (e *Effective) EndpointPresets() []endpoints.Preset { return e.cfg.EndpointPresets }
