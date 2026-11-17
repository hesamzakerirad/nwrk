package reporting

import (
	"fmt"
	"strings"

	"github.com/hesamzakerirad/nwrk/internal/domain"
	"github.com/hesamzakerirad/nwrk/internal/output"
)

// Diagnosis writes the full diagnosis report: summary, measurements,
// findings, hypotheses, next steps and the environment. Observations come
// before explanations, and explanations are labeled as such.
//
// With quiet, only the findings are written, one line each. With verbose,
// the measurement details are included.
func Diagnosis(r *output.Renderer, rep *domain.Report, quiet, verbose bool) {
	w := r.Out
	if quiet {
		for _, f := range rep.Findings {
			fmt.Fprintf(w, "%s  %s  %s\n", severityBadge(r, f.Severity), f.Code, f.Summary)
		}
		return
	}

	fmt.Fprintf(w, "%s %s  %s\n\n", r.Bold("nw diagnose"), rep.Run.Target, r.Dim("(profile "+rep.Run.Profile+")"))

	if rep.Summary != nil {
		fmt.Fprintln(w, r.Bold("Summary"))
		for _, l := range rep.Summary.Layers {
			fmt.Fprintf(w, "  %-4s  %s\n", l.Layer, layerBadge(r, l.Status))
		}
		fmt.Fprintf(w, "\n%s\n\n", resultLine(r, rep))
	}

	fmt.Fprintln(w, r.Bold("Measurements"))
	for _, m := range rep.Measurements {
		measurementLines(r, m, verbose)
	}

	if len(rep.Findings) > 0 {
		fmt.Fprintf(w, "\n%s %s\n", r.Bold("Findings"), r.Dim("(what was observed)"))
		for _, f := range rep.Findings {
			fmt.Fprintf(w, "  %s  %s  %s\n", f.ID, severityBadge(r, f.Severity), f.Code)
			fmt.Fprintf(w, "      %s\n", f.Summary)
			fmt.Fprintf(w, "      evidence: %s\n", strings.Join(f.MeasurementIDs, ", "))
			for _, c := range f.Caveats {
				fmt.Fprintf(w, "      %s\n", r.Dim("caveat: "+c))
			}
		}
	}

	if len(rep.Hypotheses) > 0 {
		fmt.Fprintf(w, "\n%s %s\n", r.Bold("Hypotheses"), r.Dim("(possible explanations, not conclusions)"))
		for _, h := range rep.Hypotheses {
			fmt.Fprintf(w, "  %s  %s confidence  for %s\n", h.ID, h.Confidence, strings.Join(h.FindingIDs, ", "))
			fmt.Fprintf(w, "      %s\n", h.Summary)
			evidence(w, "supported by", h.Supporting)
			evidence(w, "against", h.Contradicting)
			evidence(w, "not observed", h.Missing)
		}
	}

	if len(rep.Recommendations) > 0 {
		fmt.Fprintf(w, "\n%s\n", r.Bold("Next steps"))
		for _, rec := range rep.Recommendations {
			fmt.Fprintf(w, "  - %s\n", rec.Summary)
			if rec.Command != "" {
				fmt.Fprintf(w, "      %s\n", rec.Command)
			}
		}
	}

	fmt.Fprintf(w, "\n%s\n", r.Bold("Environment"))
	fmt.Fprintf(w, "  nw %s on %s/%s, run %s\n", rep.Run.ToolVersion, rep.Run.Platform.OS, rep.Run.Platform.Arch, rep.Run.ID)
	for _, m := range rep.Measurements {
		if m.Type == domain.TypeDNS && m.Resolver != nil {
			fmt.Fprintf(w, "  resolver: %s\n", strings.TrimSpace(resolverLabel(m)))
		}
	}
	fmt.Fprintf(w, "  Nothing was uploaded. Cookies, response bodies and authorization headers are never recorded.\n")
}

func resolverLabel(m domain.Measurement) string {
	via := m.Resolver.Kind
	if m.Resolver.Address != "" {
		via += " " + m.Resolver.Address
	}
	if len(m.Resolver.Servers) > 0 {
		via += " (" + strings.Join(m.Resolver.Servers, ", ") + ")"
	}
	return via
}

func evidence(w interface{ Write([]byte) (int, error) }, label string, list []domain.Evidence) {
	for _, e := range list {
		text := e.Text
		if len(e.MeasurementIDs) > 0 {
			text += " [" + strings.Join(e.MeasurementIDs, ", ") + "]"
		}
		fmt.Fprintf(w, "      %-12s %s\n", label+":", text)
		label = ""
	}
}

func resultLine(r *output.Renderer, rep *domain.Report) string {
	var errs, warns, infos int
	for _, f := range rep.Findings {
		switch f.Severity {
		case domain.SeverityError:
			errs++
		case domain.SeverityWarning:
			warns++
		default:
			infos++
		}
	}
	if !rep.Actionable() {
		s := r.Green("No actionable findings.")
		if infos > 0 {
			s += fmt.Sprintf(" %d informational.", infos)
		}
		return s
	}
	return r.Red("Problem found:") + fmt.Sprintf(" %d error, %d warning, %d informational.", errs, warns, infos)
}

func severityBadge(r *output.Renderer, s domain.Severity) string {
	switch s {
	case domain.SeverityError:
		return r.Red("ERROR  ")
	case domain.SeverityWarning:
		return r.Yellow("WARNING")
	}
	return r.Dim("INFO   ")
}

func layerBadge(r *output.Renderer, status string) string {
	switch status {
	case "success":
		return r.Green("ok")
	case "failure":
		return r.Red("FAIL")
	case domain.LayerPartial:
		return r.Yellow("partial")
	case "skipped":
		return r.Dim("skipped")
	}
	return r.Dim("not run")
}
