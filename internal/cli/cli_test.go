package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/radestsam/nwrk/internal/exit"
)

func run(t *testing.T, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	// Never read the developer's own configuration file.
	if os.Getenv("NW_CONFIG") == "" {
		t.Setenv("NW_CONFIG", filepath.Join(t.TempDir(), "none.toml"))
	}
	var out, errb bytes.Buffer
	code = Execute(context.Background(), args, &out, &errb)
	return code, out.String(), errb.String()
}

func TestVersionHuman(t *testing.T) {
	code, out, _ := run(t, "version")
	if code != exit.OK {
		t.Fatalf("exit = %d, want %d", code, exit.OK)
	}
	if !strings.HasPrefix(out, "nw ") {
		t.Errorf("output = %q, want prefix %q", out, "nw ")
	}
	if strings.Contains(out, "\x1b[") {
		t.Errorf("output to a buffer must not contain ANSI escapes: %q", out)
	}
}

func TestVersionJSON(t *testing.T) {
	code, out, _ := run(t, "version", "--output", "json")
	if code != exit.OK {
		t.Fatalf("exit = %d, want %d", code, exit.OK)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	for _, key := range []string{"schema_version", "tool", "version", "go_version", "os", "arch"} {
		if _, ok := doc[key]; !ok {
			t.Errorf("missing key %q in %s", key, out)
		}
	}
	if doc["tool"] != "nw" || doc["schema_version"] != SchemaVersion {
		t.Errorf("unexpected tool or schema_version in %s", out)
	}
}

func TestVersionFlag(t *testing.T) {
	code, out, _ := run(t, "--version")
	if code != exit.OK || !strings.HasPrefix(out, "nw ") {
		t.Errorf("code = %d, out = %q", code, out)
	}
}

func TestUsageErrorsExitWithTwo(t *testing.T) {
	cases := map[string][]string{
		"unknown flag":       {"--bogus"},
		"unknown command":    {"bogus"},
		"bad output":         {"version", "--output", "xml"},
		"verbose and quiet":  {"version", "-v", "-q"},
		"zero timeout":       {"version", "--timeout", "0s"},
		"unexpected arg":     {"version", "extra"},
		"unknown completion": {"completion", "tcsh"},
	}
	for name, args := range cases {
		t.Run(name, func(t *testing.T) {
			code, out, errOut := run(t, args...)
			if code != exit.Failure {
				t.Errorf("exit = %d, want %d", code, exit.Failure)
			}
			if out != "" {
				t.Errorf("stdout must stay empty on error, got %q", out)
			}
			if !strings.HasPrefix(errOut, "nw: ") {
				t.Errorf("stderr = %q, want prefix %q", errOut, "nw: ")
			}
		})
	}
}

func TestErrorAsJSON(t *testing.T) {
	for _, args := range [][]string{
		{"version", "--output", "json", "--timeout", "0s"},
		{"bogus", "--output", "json"},
	} {
		code, out, errOut := run(t, args...)
		if code != exit.Failure || out != "" {
			t.Fatalf("%v: code = %d, stdout = %q", args, code, out)
		}
		var doc struct {
			SchemaVersion string `json:"schema_version"`
			Error         struct{ Kind, Message string }
		}
		if err := json.Unmarshal([]byte(errOut), &doc); err != nil {
			t.Fatalf("%v: stderr is not JSON: %v\n%s", args, err, errOut)
		}
		if doc.Error.Kind != "usage" || doc.Error.Message == "" || doc.SchemaVersion != SchemaVersion {
			t.Errorf("%v: unexpected error document %s", args, errOut)
		}
	}
}

func TestCompletionShells(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish", "powershell"} {
		t.Run(shell, func(t *testing.T) {
			code, out, errOut := run(t, "completion", shell)
			if code != exit.OK || strings.TrimSpace(out) == "" {
				t.Errorf("code = %d, stdout empty = %t, stderr = %q", code, out == "", errOut)
			}
		})
	}
}
