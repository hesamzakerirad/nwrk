package output

import (
	"bytes"
	"os"
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string {
	return func(k string) string { return m[k] }
}

func TestColorDisabledForNonTerminals(t *testing.T) {
	var buf bytes.Buffer
	if ColorEnabled(false, &buf, env(nil)) {
		t.Error("a buffer is not a terminal; color must be off")
	}
	f, err := os.CreateTemp(t.TempDir(), "out")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if ColorEnabled(false, f, env(nil)) {
		t.Error("a regular file is not a terminal; color must be off")
	}
}

func TestColorDisabledByFlagAndEnvironment(t *testing.T) {
	// /dev/tty is not available everywhere, so these only prove that the
	// opt-outs win; the terminal case is covered by the check above.
	for name, e := range map[string]map[string]string{
		"NO_COLOR":  {"NO_COLOR": "1"},
		"TERM=dumb": {"TERM": "dumb"},
	} {
		if ColorEnabled(false, os.Stdout, env(e)) {
			t.Errorf("%s must disable color", name)
		}
	}
	if ColorEnabled(true, os.Stdout, env(nil)) {
		t.Error("--no-color must disable color")
	}
}

func TestStyles(t *testing.T) {
	plain := &Renderer{Color: false}
	if got := plain.Bold("x"); got != "x" {
		t.Errorf("plain Bold = %q, want %q", got, "x")
	}
	colored := &Renderer{Color: true}
	got := colored.Green("ok")
	if !strings.HasPrefix(got, "\x1b[32m") || !strings.HasSuffix(got, "\x1b[0m") || !strings.Contains(got, "ok") {
		t.Errorf("Green = %q", got)
	}
}

func TestJSONOutput(t *testing.T) {
	var buf bytes.Buffer
	r := &Renderer{Out: &buf, Format: JSON}
	if err := r.JSON(map[string]int{"a": 1}); err != nil {
		t.Fatal(err)
	}
	if got, want := buf.String(), "{\n  \"a\": 1\n}\n"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestParseFormat(t *testing.T) {
	for _, ok := range []string{"human", "json"} {
		if _, err := ParseFormat(ok); err != nil {
			t.Errorf("ParseFormat(%q): %v", ok, err)
		}
	}
	if _, err := ParseFormat("yaml"); err == nil {
		t.Error("ParseFormat(yaml) must fail")
	}
}
