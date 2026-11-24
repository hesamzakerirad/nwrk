package cli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/radestsam/nwrk/contracts"
	"github.com/radestsam/nwrk/internal/community"
	"github.com/radestsam/nwrk/internal/exit"
	"github.com/radestsam/nwrk/internal/output"
)

// EnvCommunityAPI sets the address of the NWRK Status API.
const EnvCommunityAPI = "NW_COMMUNITY_API"

// defaultProfile is the profile that is used when --profile is not set.
const defaultProfile = "ir-core-v1"

// communitySeams lets tests replace the network and the terminal.
var communitySeams struct {
	stdin     io.Reader
	runner    func() *community.Runner
	transport http.RoundTripper
}

type communityFlags struct {
	profile     string
	api         string
	dryRun      bool
	payloadFile string
}

func newCommunityCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "community",
		Short: "Share anonymous reachability results with the NWRK Status project",
		Long: "Measure a fixed list of public services and, if you agree, share the results with NWRK Status.\n" +
			"Nothing runs in the background and nothing is uploaded without your agreement. Run 'nw community info' first.",
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error { return c.Help() },
	}
	cmd.AddCommand(newCommunityInfoCmd(a), newCommunityContributeCmd(a))
	return cmd
}

func addCommunityFlags(cmd *cobra.Command, f *communityFlags) {
	cmd.Flags().StringVar(&f.profile, "profile", defaultProfile, "measurement profile to use")
}

func findProfile(id string) (*contracts.Profile, error) {
	ps, err := contracts.Profiles()
	if err != nil {
		return nil, exit.Execution(err)
	}
	var found *contracts.Profile
	var names []string
	for _, p := range ps {
		if !slices.Contains(names, p.ID) {
			names = append(names, p.ID)
		}
		if p.ID == id && (found == nil || p.Version > found.Version) {
			found = p
		}
	}
	if found == nil {
		return nil, exit.Usage(fmt.Errorf("unknown profile %q. Available: %s", id, strings.Join(names, ", ")))
	}
	return found, nil
}

func serviceName(p *contracts.Profile, id string) string {
	for _, s := range p.Services {
		if s.ID == id {
			return s.Name
		}
	}
	return id
}

type infoDoc struct {
	SchemaVersion string   `json:"schema_version"`
	Profile       any      `json:"profile"`
	Disclosure    []string `json:"disclosure"`
	Targets       []string `json:"targets"`
	Limits        any      `json:"limits"`
}

func newCommunityInfoCmd(a *app) *cobra.Command {
	var f communityFlags
	cmd := &cobra.Command{
		Use:   "info",
		Short: "Show what a contribution measures, sends and stores",
		Long:  "Show what the community profile measures and what a contribution holds. This command sends nothing over the network.",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			p, err := findProfile(f.profile)
			if err != nil {
				return err
			}
			var targets []string
			for _, e := range p.Endpoints {
				targets = append(targets, fmt.Sprintf("%s (%s)", serviceName(p, e.ServiceID), e.Hostname))
			}
			if a.out.Format == output.JSON {
				return a.out.JSON(infoDoc{
					SchemaVersion: SchemaVersion,
					Profile:       map[string]any{"id": p.ID, "version": p.Version, "description": p.Description},
					Disclosure:    community.Disclosure, Targets: targets, Limits: p.Limits,
				})
			}
			w := a.out.Out
			fmt.Fprintf(w, "%s\n\n", a.out.Bold(fmt.Sprintf("Profile %s version %d", p.ID, p.Version)))
			fmt.Fprintf(w, "%s\n\n", p.Description)
			fmt.Fprintf(w, "%s\n", a.out.Bold("Services checked"))
			for _, t := range targets {
				fmt.Fprintf(w, "  %s\n", t)
			}
			fmt.Fprintf(w, "\nThe run takes at most %d seconds.\n\n", p.Limits.TotalBudgetMS/1000)
			fmt.Fprintf(w, "%s\n", a.out.Bold("What you should know"))
			for _, line := range community.Disclosure {
				fmt.Fprintf(w, "  * %s\n", line)
			}
			fmt.Fprintf(w, "\nTry it without sending anything: nw community contribute --dry-run\n")
			return nil
		},
	}
	addCommunityFlags(cmd, &f)
	return cmd
}

func newCommunityContributeCmd(a *app) *cobra.Command {
	var f communityFlags
	cmd := &cobra.Command{
		Use:   "contribute",
		Short: "Measure the profile services and, if you agree, share the results",
		Long: "Run the checks of a community profile on this machine, show the exact result, and upload it only if you agree.\n" +
			"Each question defaults to no. The profile sets the time limits, so --timeout does not apply here.\n" +
			"With --dry-run nw measures and shows the result and never contacts the NWRK server.",
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error { return a.contribute(c.Context(), &f) },
	}
	addCommunityFlags(cmd, &f)
	cmd.Flags().StringVar(&f.api, "api", "", "NWRK Status API address (default "+community.DefaultAPI+", or "+EnvCommunityAPI+")")
	cmd.Flags().BoolVar(&f.dryRun, "dry-run", false, "measure and show the result, never contact the NWRK server")
	cmd.Flags().StringVar(&f.payloadFile, "payload-file", "", "write the exact message to this file (with --dry-run)")
	return cmd
}

// prompter asks yes or no questions on stderr and reads answers from stdin.
// Anything but an explicit yes, including end of input, is no.
type prompter struct {
	in  *bufio.Reader
	out io.Writer
}

func (p *prompter) ask(question string, extra ...string) string {
	hint := "[y/N]"
	if len(extra) > 0 {
		hint = "[y/N/" + strings.Join(extra, "/") + "]"
	}
	fmt.Fprintf(p.out, "%s %s ", question, hint)
	line, _ := p.in.ReadString('\n')
	return strings.ToLower(strings.TrimSpace(line))
}

func yes(answer string) bool { return answer == "y" || answer == "yes" }

func (a *app) contribute(ctx context.Context, f *communityFlags) error {
	if a.out.Format == output.JSON && !f.dryRun {
		return exit.Usage(errors.New("--output json works only with --dry-run, because an upload needs your answers at a terminal"))
	}
	if f.payloadFile != "" && !f.dryRun {
		return exit.Usage(errors.New("--payload-file works only with --dry-run"))
	}
	p, err := findProfile(f.profile)
	if err != nil {
		return err
	}
	var client *community.Client
	if !f.dryRun {
		base := f.api
		if base == "" {
			base = os.Getenv(EnvCommunityAPI)
		}
		if base == "" {
			base = community.DefaultAPI
		}
		if client, err = community.NewClient(base, communitySeams.transport); err != nil {
			return exit.Usage(err)
		}
	}

	var stdin io.Reader = os.Stdin
	if communitySeams.stdin != nil {
		stdin = communitySeams.stdin
	}
	ask := &prompter{in: bufio.NewReader(stdin), out: a.stderr}
	say := func(format string, args ...any) { fmt.Fprintf(a.stderr, format, args...) }

	// 1. Disclosure and consent to measure.
	say("%s\n", a.out.Bold(fmt.Sprintf("Profile %s version %d", p.ID, p.Version)))
	say("nw will contact these services from this machine:\n")
	for _, e := range p.Endpoints {
		say("  %s (%s)\n", serviceName(p, e.ServiceID), e.Hostname)
	}
	say("\n")
	for _, line := range community.Disclosure {
		say("  * %s\n", line)
	}
	say("\n")
	if !yes(ask.ask(fmt.Sprintf("Run these checks now? (up to %d seconds)", p.Limits.TotalBudgetMS/1000))) {
		say("Nothing was measured and nothing was sent.\n")
		return nil
	}

	// 2. Measure.
	runner := community.NewRunner()
	if communitySeams.runner != nil {
		runner = communitySeams.runner()
	}
	if !a.opts.quiet {
		runner.Progress = func(done, total int, target string) { say("  %d/%d %s\n", done, total, target) }
	}
	doc, err := runner.Run(ctx, p)
	if err != nil {
		if errors.Is(err, community.ErrNoRoute) {
			return exit.Execution(errors.New("this machine has no route to the internet. Nothing was measured"))
		}
		return exit.Execution(err)
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return exit.Execution(err)
	}
	if _, err := contracts.ValidateContribution(raw, mustProfiles()); err != nil {
		// A bug in nw. Never send a document that the contract rejects.
		return exit.Execution(fmt.Errorf("the result does not match the contract, so it was not used: %w", err))
	}

	// 3. Show the result.
	pretty, _ := json.MarshalIndent(doc, "", "  ")
	if f.dryRun {
		return a.finishDryRun(f, p, doc, pretty)
	}
	a.printSummary(a.stderr, p, doc)
	for {
		switch ans := ask.ask("Upload these results to "+client.Host()+"?", "s=show the exact message"); {
		case yes(ans):
			return a.upload(ctx, client, p, doc)
		case ans == "s" || ans == "show":
			say("%s\n", pretty)
		default:
			say("Nothing was sent.\n")
			return nil
		}
	}
}

func mustProfiles() []*contracts.Profile {
	ps, _ := contracts.Profiles()
	return ps
}

func (a *app) finishDryRun(f *communityFlags, p *contracts.Profile, doc *contracts.Contribution, pretty []byte) error {
	if f.payloadFile != "" {
		if err := os.WriteFile(f.payloadFile, append(pretty, '\n'), 0o600); err != nil {
			return exit.Execution(fmt.Errorf("could not write the payload file: %w", err))
		}
	}
	if a.out.Format == output.JSON {
		return a.out.JSON(doc)
	}
	a.printSummary(a.out.Out, p, doc)
	if f.payloadFile != "" {
		fmt.Fprintf(a.out.Out, "The exact message was written to %s.\n", f.payloadFile)
	}
	fmt.Fprintln(a.out.Out, "Dry run: nothing was sent.")
	return nil
}

// printSummary shows one line for each target and IP version.
func (a *app) printSummary(w io.Writer, p *contracts.Profile, doc *contracts.Contribution) {
	fmt.Fprintf(w, "\n%s\n", a.out.Bold("Result"))
	for _, r := range doc.Results {
		e, _ := p.Endpoint(r.TargetID)
		name := r.TargetID
		if e != nil {
			name = serviceName(p, e.ServiceID)
		}
		fmt.Fprintf(w, "  %s\n", name)
		for _, fam := range []string{"ipv4", "ipv6"} {
			var parts []string
			for _, m := range r.Measurements {
				if m.Family != fam {
					continue
				}
				parts = append(parts, a.measurementText(m))
			}
			if len(parts) > 0 {
				fmt.Fprintf(w, "    %s  %s\n", fam, strings.Join(parts, ", "))
			}
		}
	}
	if missing := len(p.Endpoints) - len(doc.Results); missing > 0 {
		fmt.Fprintf(w, "  %d service(s) were left out: they did not finish in time.\n", missing)
	}
	fmt.Fprintln(w)
}

func (a *app) measurementText(m contracts.Measurement) string {
	switch {
	case m.Outcome == "failure":
		return a.out.Red(m.Layer + " " + m.Error)
	case m.Layer == "http":
		return fmt.Sprintf("http %d", m.StatusCode)
	}
	return a.out.Green(m.Layer + " ok")
}

func (a *app) upload(ctx context.Context, client *community.Client, p *contracts.Profile, doc *contracts.Contribution) error {
	say := func(format string, args ...any) { fmt.Fprintf(a.stderr, format, args...) }
	say("Requesting a challenge from %s\n", client.Host())
	ch, err := client.Challenge(ctx, p)
	if err != nil {
		return uploadError(err)
	}
	say("Solving the proof of work (%d bits)\n", ch.DifficultyBit)
	nonce, err := community.SolvePoW(ctx, ch)
	if err != nil {
		return exit.Execution(err)
	}
	if time.Now().After(ch.ExpiresAt) {
		return exit.Execution(errors.New("the challenge expired before the proof of work was done. Run the command again"))
	}
	rc, err := client.Submit(ctx, ch, nonce, doc)
	if err != nil {
		return uploadError(err)
	}
	w := a.stderr
	if rc.Accepted {
		fmt.Fprintf(w, "%s\n", a.out.Green("Accepted. Thank you."))
		fmt.Fprintf(w, "Submission ID: %s\n", rc.SubmissionID)
		fmt.Fprintf(w, "Received at:   %s\n", rc.ReceivedAt.UTC().Format(time.RFC3339))
		if rc.ObservedCountry != "" {
			net := rc.ObservedCountry
			if rc.ObservedASN != 0 {
				net += fmt.Sprintf(", AS%d", rc.ObservedASN)
			}
			fmt.Fprintf(w, "Seen as:       %s\n", net)
		}
		return nil
	}
	switch rc.Reason {
	case "outside_scope":
		fmt.Fprintf(w, "Not stored. The server places this connection outside Iran (%s), and the statistics cover Iran only.\n", rc.ObservedCountry)
	default:
		fmt.Fprintln(w, "Not stored. The server could not tell which country this connection is in.")
	}
	return nil
}

// uploadError explains a failed upload. There is no queue and no retry.
func uploadError(err error) error {
	var ae *community.APIError
	if errors.As(err, &ae) {
		msg := err.Error()
		if ae.RetryAfter > 0 {
			msg += fmt.Sprintf(". Try again in %d seconds", int(ae.RetryAfter.Seconds()))
		}
		return exit.Execution(errors.New(msg + ". The results were not saved anywhere. Run the command again to retry"))
	}
	return exit.Execution(fmt.Errorf("%w. The results were not saved anywhere. Run the command again to retry", err))
}
