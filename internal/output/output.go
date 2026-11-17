// Package output renders results for humans and for scripts.
package output

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

// Format selects how results are rendered.
type Format string

const (
	Human Format = "human"
	JSON  Format = "json"
)

// ParseFormat validates a value of the --output flag.
func ParseFormat(s string) (Format, error) {
	switch Format(s) {
	case Human, JSON:
		return Format(s), nil
	}
	return "", fmt.Errorf("invalid --output %q (want human or json)", s)
}

// ColorEnabled reports whether ANSI colors should be written to w.
//
// Color is on by default for terminals and off for --no-color, the NO_COLOR
// environment variable (https://no-color.org), TERM=dumb, and anything that
// is not a terminal, such as a pipe or a file.
func ColorEnabled(noColorFlag bool, w io.Writer, getenv func(string) string) bool {
	if noColorFlag || getenv("NO_COLOR") != "" || getenv("TERM") == "dumb" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return false
	}
	return enableANSI(f)
}

// ColorEnabledMode is ColorEnabled with the user's color setting: "never"
// turns color off, "always" turns it on even when the output is not a
// terminal, and "auto" decides as ColorEnabled does. NO_COLOR and
// --no-color win over "always", as the NO_COLOR convention requires.
func ColorEnabledMode(mode string, noColorFlag bool, w io.Writer, getenv func(string) string) bool {
	if noColorFlag || getenv("NO_COLOR") != "" {
		return false
	}
	switch mode {
	case "never":
		return false
	case "always":
		if f, ok := w.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
			enableANSI(f)
		}
		return true
	}
	return ColorEnabled(noColorFlag, w, getenv)
}

// Renderer writes results to Out. Logs and errors belong on stderr.
type Renderer struct {
	Out    io.Writer
	Format Format
	Color  bool
}

// JSON writes v as indented JSON followed by a newline.
func (r *Renderer) JSON(v any) error {
	enc := json.NewEncoder(r.Out)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func (r *Renderer) style(code, s string) string {
	if !r.Color {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

// Bold, Dim and the status colors never carry meaning alone: callers must
// also write the meaning in words.
func (r *Renderer) Bold(s string) string   { return r.style("1", s) }
func (r *Renderer) Dim(s string) string    { return r.style("2", s) }
func (r *Renderer) Red(s string) string    { return r.style("31", s) }
func (r *Renderer) Green(s string) string  { return r.style("32", s) }
func (r *Renderer) Yellow(s string) string { return r.style("33", s) }
