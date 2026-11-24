package cli

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/netip"
	"strings"

	"github.com/spf13/cobra"

	apptest "github.com/radestsam/nwrk/internal/app/test"
	"github.com/radestsam/nwrk/internal/buildinfo"
	"github.com/radestsam/nwrk/internal/domain"
	"github.com/radestsam/nwrk/internal/exit"
	"github.com/radestsam/nwrk/internal/measurement/local"
	"github.com/radestsam/nwrk/internal/output"
	"github.com/radestsam/nwrk/internal/path"
	"github.com/radestsam/nwrk/internal/reporting"
	"github.com/radestsam/nwrk/internal/target"
)

func newTestCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "test",
		Short: "Run one measurement: dns, tcp, tls or http",
		Long: "Run a single measurement and print what it observed.\n\n" +
			"Exit status: 0 when every measurement succeeded, 1 when one failed, 2 on a usage error.",
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error { return c.Help() },
	}
	cmd.AddCommand(newTestDNSCmd(a), newTestTCPCmd(a), newTestTLSCmd(a), newTestHTTPCmd(a))
	return cmd
}

// resolverFlag registers --resolver and returns where its values land.
func resolverFlag(cmd *cobra.Command) *[]string {
	var v []string
	cmd.Flags().StringArrayVar(&v, "resolver", nil,
		"DNS resolver to compare with the system one: host[:port] or tcp://host[:port] (repeatable; also NW_RESOLVERS)")
	return &v
}

// seams lets tests replace the parts of a run that would touch the host's
// own resolver and trust store. They are nil in the real program.
var seams struct {
	systemDNS func(ctx context.Context, name string) *domain.Measurement
	rootCAs   *x509.CertPool
	inspector local.Inspector
	dial      local.Dial
	network   inspection
	plainPort int
	pingICMP  func(netip.Addr) (path.Pinger, error)
	pingTCP   func(int) path.Pinger
	traceICMP func(netip.Addr) (path.Prober, error)
	traceTCP  func(netip.Addr, int) path.Prober
}

func (a *app) testOptions(resolvers []string) (apptest.Options, error) {
	rs, _, err := a.settings.Resolvers(resolvers)
	if err != nil {
		return apptest.Options{}, exit.Usage(err)
	}
	return apptest.Options{
		Timeout:     a.opts.timeout,
		Resolvers:   rs,
		ToolVersion: buildinfo.Get().Version,
		SystemDNS:   seams.systemDNS,
		RootCAs:     seams.rootCAs,
	}, nil
}

// finish prints rep and turns its outcome into the command result.
func (a *app) finish(ctx context.Context, rep *domain.Report) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if a.out.Format == output.JSON {
		if err := a.out.JSON(rep); err != nil {
			return exit.Execution(err)
		}
	} else {
		reporting.Human(a.out, rep, a.opts.quiet)
	}
	if rep.HasFailure() {
		return exit.ErrFindings
	}
	return nil
}

func newTestDNSCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "dns <host>",
		Short: "Resolve a name with the system resolver and optionally others",
		Long: "Ask for the A and AAAA records of a name and report the response code, the answers and the time taken.\n" +
			"The system resolver is always measured as the baseline; each --resolver is measured next to it.",
		Example: "  nw test dns example.com\n  nw test dns example.com --resolver 1.1.1.1 --resolver tcp://9.9.9.9",
		Args:    cobra.ExactArgs(1),
	}
	resolvers := resolverFlag(cmd)
	cmd.RunE = func(c *cobra.Command, args []string) error {
		host, err := target.Host(args[0])
		if err != nil {
			return exit.Usage(err)
		}
		o, err := a.testOptions(*resolvers)
		if err != nil {
			return err
		}
		return a.finish(c.Context(), apptest.DNS(c.Context(), host, o))
	}
	return cmd
}

func newTestTCPCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "tcp <host:port>",
		Short:   "Open a TCP connection to every address of a host",
		Long:    "Resolve the host, then connect to each of its addresses on the port, IPv4 and IPv6 separately.",
		Example: "  nw test tcp example.com:443\n  nw test tcp [2001:db8::1]:22",
		Args:    cobra.ExactArgs(1),
	}
	resolvers := resolverFlag(cmd)
	cmd.RunE = func(c *cobra.Command, args []string) error {
		host, port, err := target.HostPort(args[0], 0)
		if err != nil {
			return exit.Usage(err)
		}
		o, err := a.testOptions(*resolvers)
		if err != nil {
			return err
		}
		return a.finish(c.Context(), apptest.TCP(c.Context(), host, port, o))
	}
	return cmd
}

func newTestTLSCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tls <host[:port]>",
		Short: "Complete a TLS handshake and inspect the certificate",
		Long: "Resolve the host, then handshake with each address (port 443 unless given) and verify the certificate chain and the name.\n" +
			"Verification is always on.",
		Example: "  nw test tls example.com\n  nw test tls example.com:8443",
		Args:    cobra.ExactArgs(1),
	}
	resolvers := resolverFlag(cmd)
	cmd.RunE = func(c *cobra.Command, args []string) error {
		host, port, err := target.HostPort(args[0], 443)
		if err != nil {
			return exit.Usage(err)
		}
		o, err := a.testOptions(*resolvers)
		if err != nil {
			return err
		}
		return a.finish(c.Context(), apptest.TLS(c.Context(), host, port, o))
	}
	return cmd
}

func newTestHTTPCmd(a *app) *cobra.Command {
	var method string
	var maxRedirects int
	cmd := &cobra.Command{
		Use:   "http <url>",
		Short: "Make one HTTP or HTTPS request and time its stages",
		Long: "Request a URL (https unless a scheme is given), follow a bounded number of redirects and report the status, the redirect chain and the time of each stage.\n" +
			"The request goes direct, ignoring proxy variables. Bodies, cookies and credentials are never recorded.",
		Example: "  nw test http example.com\n  nw test http http://example.com/path --max-redirects 3",
		Args:    cobra.ExactArgs(1),
	}
	resolvers := resolverFlag(cmd)
	cmd.Flags().StringVar(&method, "method", "GET", "request method: GET or HEAD")
	cmd.Flags().IntVar(&maxRedirects, "max-redirects", 10, "maximum redirects to follow")
	cmd.RunE = func(c *cobra.Command, args []string) error {
		u, err := target.URL(args[0])
		if err != nil {
			return exit.Usage(err)
		}
		method = strings.ToUpper(method)
		if method != "GET" && method != "HEAD" {
			return exit.Usage(fmt.Errorf("invalid --method %q (want GET or HEAD)", method))
		}
		if maxRedirects < 1 || maxRedirects > 50 {
			return exit.Usage(fmt.Errorf("invalid --max-redirects %d (want 1 to 50)", maxRedirects))
		}
		o, err := a.testOptions(*resolvers)
		if err != nil {
			return err
		}
		return a.finish(c.Context(), apptest.HTTP(c.Context(), u, method, maxRedirects, o))
	}
	return cmd
}
