package settings

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func cfgFile(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func str(s string) *string { return &s }

func TestDefaults(t *testing.T) {
	e, err := Load(env(nil), filepath.Join(t.TempDir(), "none.toml"), Flags{})
	if err != nil {
		t.Fatal(err)
	}
	if e.Region != "global" || e.RegionSource != SourceDefault || e.Timeout != DefaultTimeout || e.Color != "auto" || e.ConfigExists {
		t.Fatalf("%+v", e)
	}
	if e.RegionExplicit() {
		t.Fatal("a default region is not explicit")
	}
}

// Precedence: flag, then environment, then config file, then default.
func TestPrecedence(t *testing.T) {
	path := cfgFile(t, "region = \"ir\"\ntimeout = \"3s\"\ncolor = \"never\"\n")

	e, err := Load(env(nil), path, Flags{})
	if err != nil || e.Region != "ir" || e.RegionSource != SourceConfig || e.Timeout != 3*time.Second || e.Color != "never" {
		t.Fatalf("config: %+v %v", e, err)
	}
	vars := env(map[string]string{"NW_REGION": "global", "NW_TIMEOUT": "7s", "NW_COLOR": "always"})
	e, _ = Load(vars, path, Flags{})
	if e.Region != "global" || !strings.Contains(e.RegionSource, "NW_REGION") || e.Timeout != 7*time.Second || e.Color != "always" {
		t.Fatalf("env must beat config: %+v", e)
	}
	d := 2 * time.Second
	e, _ = Load(vars, path, Flags{Region: str("ir"), Timeout: &d})
	if e.Region != "ir" || e.RegionSource != SourceFlag || e.Timeout != 2*time.Second || e.TimeoutSource != SourceFlag {
		t.Fatalf("flag must beat env: %+v", e)
	}
}

func TestInvalidValuesNameTheirSource(t *testing.T) {
	good := filepath.Join(t.TempDir(), "x.toml")
	cases := map[string]struct {
		vars map[string]string
		want string
	}{
		"region":  {map[string]string{"NW_REGION": "zz"}, "NW_REGION"},
		"timeout": {map[string]string{"NW_TIMEOUT": "soon"}, "NW_TIMEOUT"},
		"zero":    {map[string]string{"NW_TIMEOUT": "0s"}, "NW_TIMEOUT"},
		"color":   {map[string]string{"NW_COLOR": "rainbow"}, "NW_COLOR"},
	}
	for name, c := range cases {
		if _, err := Load(env(c.vars), good, Flags{}); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if _, err := Load(env(nil), cfgFile(t, "timeout = \"-1s\"\n"), Flags{}); err == nil || !strings.Contains(err.Error(), "config file") {
		t.Errorf("a bad config value must name the config file: %v", err)
	}
	d := time.Duration(0)
	if _, err := Load(env(nil), good, Flags{Timeout: &d}); err == nil {
		t.Error("a zero --timeout is invalid")
	}
}

// Resolver precedence (SPEC 7.2.1): flag, NW_RESOLVERS, config, region preset.
func TestResolverPrecedence(t *testing.T) {
	path := cfgFile(t, "resolvers = [\"8.8.4.4\"]\nregion = \"ir\"\n")
	vars := env(map[string]string{"NW_RESOLVERS": "9.9.9.9"})
	e, err := Load(vars, path, Flags{})
	if err != nil {
		t.Fatal(err)
	}
	rs, src, err := e.Resolvers([]string{"1.1.1.1"})
	if err != nil || len(rs) != 1 || rs[0].Host != "1.1.1.1" || src != SourceFlag {
		t.Fatalf("flag: %+v %s %v", rs, src, err)
	}
	rs, src, _ = e.Resolvers(nil)
	if rs[0].Host != "9.9.9.9" || !strings.Contains(src, "NW_RESOLVERS") {
		t.Fatalf("env: %+v %s", rs, src)
	}
	e, _ = Load(env(nil), path, Flags{})
	rs, src, _ = e.Resolvers(nil)
	if rs[0].Host != "8.8.4.4" || src != SourceConfig {
		t.Fatalf("config: %+v %s", rs, src)
	}
	e, _ = Load(env(nil), cfgFile(t, "region = \"global\"\n"), Flags{})
	rs, src, _ = e.Resolvers(nil)
	if len(rs) != 3 || !strings.HasPrefix(src, SourcePreset) {
		t.Fatalf("an explicit region supplies its preset resolvers: %+v %s", rs, src)
	}
}

func TestNoPresetResolversUnlessTheRegionWasChosen(t *testing.T) {
	e, _ := Load(env(nil), filepath.Join(t.TempDir(), "none.toml"), Flags{})
	rs, src, err := e.Resolvers(nil)
	if err != nil || rs != nil || src != SourceDefault {
		t.Fatalf("nothing may contact a public resolver unasked: %+v %s %v", rs, src, err)
	}
}

func TestBadConfigResolverIsReported(t *testing.T) {
	e, _ := Load(env(nil), cfgFile(t, "resolvers = [\"dns.example\"]\n"), Flags{})
	if _, _, err := e.Resolvers(nil); err == nil {
		t.Fatal("a name is not a resolver address")
	}
}
