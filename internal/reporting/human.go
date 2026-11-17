// Package reporting renders reports for people. It serializes what the
// domain describes and never measures anything itself.
package reporting

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/hesamzakerirad/nwrk/internal/domain"
	"github.com/hesamzakerirad/nwrk/internal/output"
)

// Human writes rep to r as plain text. Status is always written as a word;
// color only reinforces it. When quiet is true only the measurements that
// did not succeed are shown.
func Human(r *output.Renderer, rep *domain.Report, quiet bool) {
	w := r.Out
	if !quiet {
		fmt.Fprintf(w, "%s %s\n\n", r.Bold("nw "+rep.Run.Command), rep.Run.Target)
	}
	for _, m := range rep.Measurements {
		if quiet && (m.Status == domain.StatusSuccess) {
			continue
		}
		measurementLines(r, m, !quiet)
	}
	if !quiet {
		fmt.Fprintf(w, "\n%s\n", Summary(rep))
	}
}

// Summary is the one-line verdict about the measurements. It says what was
// measured, not what is wrong: interpretation comes with diagnose.
func Summary(rep *domain.Report) string {
	var ok, failed, other int
	for _, m := range rep.Measurements {
		switch m.Status {
		case domain.StatusSuccess:
			ok++
		case domain.StatusFailure:
			failed++
		default:
			other++
		}
	}
	total := len(rep.Measurements)
	switch {
	case failed == 0 && other == 0:
		return fmt.Sprintf("%d of %d measurements succeeded.", ok, total)
	case failed == 0:
		return fmt.Sprintf("%d of %d measurements succeeded, %d not run.", ok, total, other)
	}
	return fmt.Sprintf("%d of %d measurements succeeded, %d failed.", ok, total, failed)
}

func badge(r *output.Renderer, s domain.Status) string {
	switch s {
	case domain.StatusSuccess:
		return r.Green("ok  ")
	case domain.StatusFailure:
		return r.Red("FAIL")
	case domain.StatusSkipped:
		return r.Dim("skip")
	}
	return r.Yellow("????")
}

func label(m domain.Measurement) string {
	var s string
	t := m.Target
	switch {
	case t.URL != "":
		s = t.URL
		if t.Family != "" {
			s += " (" + t.Family + ")"
		}
	case t.IP != "":
		s = net.JoinHostPort(t.IP, strconv.Itoa(t.Port))
		if t.Host != "" && t.Host != t.IP {
			s += " (" + t.Host + ")"
		}
	default:
		s = t.Host
		if t.Port != 0 {
			s = net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
		}
		if t.Family != "" {
			s += " (" + t.Family + ")"
		}
	}
	if m.Resolver != nil {
		via := m.Resolver.Kind
		if m.Resolver.Address != "" {
			via += " " + m.Resolver.Address
		}
		if len(m.Resolver.Servers) > 0 {
			via += " (" + strings.Join(m.Resolver.Servers, ", ") + ")"
		}
		s += " via " + strings.TrimSpace(via)
	}
	return s
}

// measurementLines writes one measurement: a status line, its error or
// note, and optionally the details of its result.
func measurementLines(r *output.Renderer, m domain.Measurement, details bool) {
	w := r.Out
	fmt.Fprintf(w, "%s  %-4s  %s", badge(r, m.Status), m.Type, label(m))
	if m.Status == domain.StatusSuccess || m.Status == domain.StatusFailure {
		fmt.Fprintf(w, "  %s", r.Dim(fmt.Sprintf("%.1f ms", m.DurationMS)))
	}
	fmt.Fprintln(w)
	if m.Error != nil {
		fmt.Fprintf(w, "      %s: %s\n", m.Error.Code, m.Error.Message)
	}
	if m.Note != "" {
		fmt.Fprintf(w, "      %s\n", m.Note)
	}
	if d, ok := m.Result.(domain.Detailer); ok && details {
		for _, line := range d.Details() {
			fmt.Fprintf(w, "      %s\n", line)
		}
	}
}
