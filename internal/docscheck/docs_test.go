// Package docscheck keeps the documentation in step with the code. It has
// tests only.
package docscheck

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/hesamzakerirad/nwrk/internal/diagnostics/engine"
	"github.com/hesamzakerirad/nwrk/internal/diagnostics/rules"
	"github.com/hesamzakerirad/nwrk/internal/domain"
	"github.com/hesamzakerirad/nwrk/internal/regions"
)

func doc(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "docs", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestEveryRuleIsDocumentedWithItsCaveats(t *testing.T) {
	findings := doc(t, "findings.md")
	for _, r := range rules.All() {
		i := strings.Index(findings, "## "+r.ID)
		if i < 0 {
			t.Errorf("docs/findings.md has no section for %s", r.ID)
			continue
		}
		section := findings[i:]
		if j := strings.Index(section[3:], "\n## "); j >= 0 {
			section = section[:j+3]
		}
		if !strings.Contains(section, "When it can be wrong") {
			t.Errorf("%s: its section must list when it can be wrong", r.ID)
		}
	}
	for _, r := range rules.Doctor() {
		i := strings.Index(findings, "### "+r.ID)
		if i < 0 {
			t.Errorf("docs/findings.md has no section for the doctor rule %s", r.ID)
			continue
		}
		section := findings[i:]
		if j := strings.Index(section[4:], "\n#"); j >= 0 {
			section = section[:j+4]
		}
		// DOMESTIC_UNREACHABLE is documented by reference to its twin.
		if r.ID != "DOMESTIC_UNREACHABLE" && !strings.Contains(section, "When it can be wrong") {
			t.Errorf("%s: its section must list when it can be wrong", r.ID)
		}
	}
	for _, list := range [][]engineRule{asRules(rules.Interference()), asRules(rules.Security())} {
		for _, r := range list {
			i := strings.Index(findings, "### "+r.ID)
			if i < 0 {
				t.Errorf("docs/findings.md has no section for %s", r.ID)
				continue
			}
			section := findings[i:]
			if j := strings.Index(section[4:], "\n#"); j >= 0 {
				section = section[:j+4]
			}
			if !strings.Contains(section, "When it can be wrong") {
				t.Errorf("%s: its section must list when it can be wrong", r.ID)
			}
		}
	}
	if !strings.Contains(findings, "## UNCLASSIFIED_FAILURE") {
		t.Error("docs/findings.md must document UNCLASSIFIED_FAILURE")
	}
}

func TestEveryErrorCodeIsDocumented(t *testing.T) {
	m := doc(t, "measurements.md")
	for _, c := range domain.AllErrorCodes {
		if !strings.Contains(m, "`"+string(c)+"`") {
			t.Errorf("docs/measurements.md does not document %s", c)
		}
	}
}

// Every reference target and resolver of every preset is documented with
// its reason, and every platform adapter limit is listed.
func TestPresetsAndPlatformLimitsAreDocumented(t *testing.T) {
	regionsDoc := doc(t, "regions.md")
	for _, name := range regions.Names() {
		p, err := regions.Load(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range p.Resolvers {
			if !strings.Contains(regionsDoc, "`"+r.Address+"`") {
				t.Errorf("docs/regions.md does not list the resolver %s of %s", r.Address, name)
			}
		}
		for _, tg := range p.Targets {
			if !strings.Contains(regionsDoc, tg.Host()) {
				t.Errorf("docs/regions.md does not list the target %s of %s", tg.Host(), name)
			}
		}
	}
	platformDoc := doc(t, "platform-support.md")
	for _, w := range []string{"Windows: the routing table", "systemd-resolved", "system proxy settings", "/proc/net/route"} {
		if !strings.Contains(platformDoc, w) {
			t.Errorf("docs/platform-support.md lacks %q", w)
		}
	}
	privacy := doc(t, "privacy.md")
	for _, w := range []string{"nw doctor", "Cookies", "never", "Nothing is uploaded"} {
		if !strings.Contains(privacy, w) {
			t.Errorf("docs/privacy.md lacks %q", w)
		}
	}
}

func TestProfilesAndCommandsAreDocumented(t *testing.T) {
	d := doc(t, "diagnostics.md")
	for _, p := range []string{"`quick`", "`standard`", "`deep`"} {
		if !strings.Contains(d, p) {
			t.Errorf("docs/diagnostics.md does not document the profile %s", p)
		}
	}
	c := doc(t, "commands.md")
	for _, w := range []string{"## nw diagnose", "## nw test", "## nw version", "## nw completion", "## nw doctor", "## nw network", "## nw config", "## nw security", "## nw path", "tls://", "https://", "--profile", "--resolver", "--region", "NW_CONFIG"} {
		if !strings.Contains(c, w) {
			t.Errorf("docs/commands.md lacks %q", w)
		}
	}
}

// The documentation must not use dash characters the project avoids, and
// must keep to technical wording (SPEC 8.5).
func TestDocsKeepToTheWordingPolicy(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join("..", "..", "docs"))
	if err != nil {
		t.Fatal(err)
	}
	banned := []string{"censorship", "bypass", "sanction", "unblock"}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".md") || e.Name() == "SPEC.md" || e.Name() == "ROADMAP.md" {
			continue
		}
		text := strings.ToLower(doc(t, e.Name()))
		for _, w := range banned {
			if strings.Contains(text, w) {
				t.Errorf("docs/%s uses %q", e.Name(), w)
			}
		}
	}
}

type engineRule struct{ ID string }

func asRules(in []engine.Rule) []engineRule {
	out := make([]engineRule, len(in))
	for i, r := range in {
		out[i] = engineRule{r.ID}
	}
	return out
}
