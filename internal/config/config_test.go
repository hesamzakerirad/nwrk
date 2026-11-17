package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPath(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	cases := []struct {
		goos string
		env  map[string]string
		home string
		want string
	}{
		{"linux", nil, "/home/u", "/home/u/.config/nwrk/config.toml"},
		{"linux", map[string]string{"XDG_CONFIG_HOME": "/x"}, "/home/u", "/x/nwrk/config.toml"},
		{"darwin", nil, "/Users/u", "/Users/u/Library/Application Support/nwrk/config.toml"},
		{"windows", map[string]string{"LOCALAPPDATA": `C:\L`}, `C:\Users\u`, filepath.Join(`C:\L`, "nwrk", "config.toml")},
		{"windows", nil, `C:\Users\u`, filepath.Join(`C:\Users\u`, "AppData", "Local", "nwrk", "config.toml")},
		{"linux", map[string]string{"NW_CONFIG": "/etc/nw.toml", "XDG_CONFIG_HOME": "/x"}, "/h", "/etc/nw.toml"},
	}
	for _, c := range cases {
		if got := Path(c.goos, env(c.env), c.home); got != c.want {
			t.Errorf("Path(%s) = %q, want %q", c.goos, got, c.want)
		}
	}
}

func write(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoad(t *testing.T) {
	p := write(t, "region = \"ir\"\nresolvers = [\"1.1.1.1\", \"tcp://9.9.9.9\"]\ntimeout = \"5s\"\ncolor = \"never\"\n")
	f, exists, err := Load(p)
	if err != nil || !exists {
		t.Fatalf("%v %v", exists, err)
	}
	if f.Region != "ir" || len(f.Resolvers) != 2 || f.Timeout != "5s" || f.Color != "never" {
		t.Fatalf("%+v", f)
	}
}

func TestMissingFileIsNotAnError(t *testing.T) {
	f, exists, err := Load(filepath.Join(t.TempDir(), "nope.toml"))
	if err != nil || exists || len(f.Resolvers) != 0 {
		t.Fatalf("%+v %v %v", f, exists, err)
	}
}

func TestBadFiles(t *testing.T) {
	for name, content := range map[string]string{
		"syntax":      "region = ",
		"unknown key": "regoin = \"ir\"\n",
		"wrong type":  "timeout = 5\n",
	} {
		_, _, err := Load(write(t, content))
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if name == "unknown key" && !strings.Contains(err.Error(), "regoin") {
			t.Errorf("the error must name the key: %v", err)
		}
	}
}
