package cli

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/radestsam/nwrk/internal/exit"
	"github.com/radestsam/nwrk/internal/output"
	"github.com/radestsam/nwrk/internal/path"
	"github.com/radestsam/nwrk/internal/target"
)

func newPathCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "path",
		Short: "Probe the path to a destination: ping, trace and MTU",
		Long: "Controlled probes of the path to one destination you name.\n" +
			"ICMP is often filtered, deprioritized or rate-limited, so a missing reply is never shown as proof that a router is broken or that traffic is blocked.\n" +
			"ICMP needs privileges on some systems; when it is not permitted, ping and trace use TCP instead and say why.",
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error { return c.Help() },
	}
	cmd.AddCommand(newPathPingCmd(a), newPathTraceCmd(a), newPathMTUCmd(a))
	return cmd
}

// resolveAddr turns host into one address: the host itself when it is an IP
// address, else the first address the system resolver returns, IPv4 first.
func resolveAddr(ctx context.Context, host string) (netip.Addr, error) {
	h, err := target.Host(host)
	if err != nil {
		return netip.Addr{}, exit.Usage(err)
	}
	if a, err := netip.ParseAddr(h); err == nil {
		return a.Unmap(), nil
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", h)
	if err != nil || len(addrs) == 0 {
		if ctx.Err() != nil {
			return netip.Addr{}, ctx.Err()
		}
		return netip.Addr{}, exit.Execution(fmt.Errorf("could not resolve %s: %v", h, err))
	}
	for _, a := range addrs {
		if a.Unmap().Is4() {
			return a.Unmap(), nil
		}
	}
	return addrs[0], nil
}

func methodFlag(cmd *cobra.Command, v *string) {
	cmd.Flags().StringVar(v, "method", path.MethodAuto, "icmp, tcp, or auto (icmp, falling back to tcp when it is not permitted)")
}

func checkMethod(m string) error {
	if !path.ValidMethod(m) {
		return exit.Usage(fmt.Errorf("invalid --method %q (want auto, icmp or tcp)", m))
	}
	return nil
}

type pingDoc struct {
	SchemaVersion string `json:"schema_version"`
	*path.PingResult
}

func newPathPingCmd(a *app) *cobra.Command {
	var method string
	var count, port int
	var interval, wait time.Duration
	cmd := &cobra.Command{
		Use:   "ping <host>",
		Short: "Measure round-trip time with ICMP echo, or TCP connects where ICMP is not permitted",
		Long: "Send a few probes to a host and report loss and round-trip times.\n" +
			"With ICMP, an echo request is sent; with TCP, the time to open a connection to --port is measured, which works through most filters that drop ICMP and needs no privileges.\n\n" +
			"Exit status: 0 when at least one reply arrived, 1 when none did, 2 on a usage error or when the requested method is not permitted.",
		Example: "  nw path ping example.com\n  nw path ping example.com --method tcp --port 443 -c 10",
		Args:    cobra.ExactArgs(1),
	}
	methodFlag(cmd, &method)
	cmd.Flags().IntVarP(&count, "count", "c", 4, "number of probes")
	cmd.Flags().IntVar(&port, "port", 443, "TCP port for the tcp method")
	cmd.Flags().DurationVar(&interval, "interval", time.Second, "time between probes")
	cmd.Flags().DurationVar(&wait, "wait", 2*time.Second, "how long to wait for each reply")
	cmd.RunE = func(c *cobra.Command, args []string) error {
		if err := checkMethod(method); err != nil {
			return err
		}
		if count < 1 || count > 100 {
			return exit.Usage(errors.New("invalid --count (want 1 to 100)"))
		}
		if p, err := target.Port(fmt.Sprint(port)); err != nil || p != port {
			return exit.Usage(fmt.Errorf("invalid --port %d", port))
		}
		if wait <= 0 || interval < 0 {
			return exit.Usage(errors.New("--wait must be greater than zero and --interval cannot be negative"))
		}
		addr, err := resolveAddr(c.Context(), args[0])
		if err != nil {
			return err
		}
		res, err := path.Ping(c.Context(), args[0], addr, path.PingOptions{
			Count: count, Interval: interval, Timeout: wait, Method: method, Port: port,
			ICMP: seams.pingICMP, TCP: seams.pingTCP,
		})
		if err != nil {
			if c.Context().Err() != nil {
				return c.Context().Err()
			}
			return exit.Execution(err)
		}
		if a.out.Format == output.JSON {
			if err := a.out.JSON(pingDoc{SchemaVersion: SchemaVersion, PingResult: res}); err != nil {
				return exit.Execution(err)
			}
		} else if !a.opts.quiet {
			printPing(a, res)
		}
		if res.Received == 0 {
			return exit.ErrFindings
		}
		return nil
	}
	return cmd
}

func printPing(a *app, r *path.PingResult) {
	w := a.out.Out
	what := r.Method
	if r.Method == path.MethodTCP {
		what = fmt.Sprintf("tcp connect to port %d", r.Port)
	}
	fmt.Fprintf(w, "%s %s (%s) via %s\n", a.out.Bold("nw path ping"), r.Target, r.Address, what)
	if r.Fallback != "" {
		fmt.Fprintf(w, "%s\n", a.out.Dim("note: "+r.Fallback+"; measuring with TCP instead"))
	}
	for _, rp := range r.Replies {
		if rp.RTTMS != nil {
			fmt.Fprintf(w, "seq %d: %.1f ms\n", rp.Seq, *rp.RTTMS)
		} else {
			fmt.Fprintf(w, "seq %d: no reply (%s)\n", rp.Seq, rp.Note)
		}
	}
	fmt.Fprintf(w, "%d sent, %d received, %.1f%% loss", r.Sent, r.Received, r.LossPct)
	if r.Received > 0 {
		fmt.Fprintf(w, "; min/avg/max = %.1f/%.1f/%.1f ms", r.MinMS, r.AvgMS, r.MaxMS)
	}
	fmt.Fprintln(w)
	if r.Received == 0 {
		fmt.Fprintln(w, a.out.Dim("No reply is not proof that the host is down or that traffic is blocked: replies can be filtered or rate-limited."))
	}
}

type traceDoc struct {
	SchemaVersion string `json:"schema_version"`
	*path.TraceResult
}

func newPathTraceCmd(a *app) *cobra.Command {
	var method string
	var maxHops, queries, port, maxSilent int
	var wait time.Duration
	cmd := &cobra.Command{
		Use:   "trace <host>",
		Short: "Show the hops toward a destination",
		Long: "Walk the path by raising the TTL one step at a time.\n" +
			"With ICMP (needs administrator privileges: root or CAP_NET_RAW; not available on Windows) the routers on the way are listed. Without privileges the TCP method reports how many hops away the destination answers, and cannot see the routers.\n" +
			"A hop with no reply is not evidence that a router is broken or that traffic is blocked.\n\n" +
			"Exit status: 0 when the destination answered, 1 when it did not, 2 on a usage error or when the requested method is not permitted.",
		Example: "  sudo nw path trace example.com\n  nw path trace example.com --method tcp --port 443",
		Args:    cobra.ExactArgs(1),
	}
	methodFlag(cmd, &method)
	cmd.Flags().IntVar(&maxHops, "max-hops", 30, "highest TTL to try")
	cmd.Flags().IntVar(&queries, "queries", 3, "probes per hop")
	cmd.Flags().IntVar(&port, "port", 443, "TCP port for the tcp method")
	cmd.Flags().IntVar(&maxSilent, "max-silent", 5, "stop after this many hops in a row without any reply")
	cmd.Flags().DurationVar(&wait, "wait", time.Second, "how long to wait for each reply")
	cmd.RunE = func(c *cobra.Command, args []string) error {
		if err := checkMethod(method); err != nil {
			return err
		}
		if maxHops < 1 || maxHops > 64 || queries < 1 || queries > 10 || maxSilent < 1 {
			return exit.Usage(errors.New("invalid --max-hops (1 to 64), --queries (1 to 10) or --max-silent (at least 1)"))
		}
		if wait <= 0 {
			return exit.Usage(errors.New("--wait must be greater than zero"))
		}
		addr, err := resolveAddr(c.Context(), args[0])
		if err != nil {
			return err
		}
		res, err := path.Trace(c.Context(), args[0], addr, path.TraceOptions{
			MaxHops: maxHops, Queries: queries, Timeout: wait, Method: method, Port: port, MaxSilent: maxSilent,
			ICMP: seams.traceICMP, TCP: seams.traceTCP,
		})
		if err != nil {
			if c.Context().Err() != nil {
				return c.Context().Err()
			}
			return exit.Execution(err)
		}
		if a.out.Format == output.JSON {
			if err := a.out.JSON(traceDoc{SchemaVersion: SchemaVersion, TraceResult: res}); err != nil {
				return exit.Execution(err)
			}
		} else if !a.opts.quiet {
			printTrace(a, res)
		}
		if !res.Reached {
			return exit.ErrFindings
		}
		return nil
	}
	return cmd
}

func printTrace(a *app, r *path.TraceResult) {
	w := a.out.Out
	how := r.Method
	if r.Method == path.MethodTCP {
		how = fmt.Sprintf("tcp to port %d", r.Port)
	}
	fmt.Fprintf(w, "%s %s (%s), max %d hops, via %s\n", a.out.Bold("nw path trace"), r.Target, r.Address, r.MaxHops, how)
	if r.Fallback != "" {
		fmt.Fprintf(w, "%s\n", a.out.Dim("note: "+r.Fallback+"; using TCP instead"))
	}
	for _, h := range r.Hops {
		var parts []string
		for _, t := range h.RTTMS {
			if t == nil {
				parts = append(parts, "*")
			} else {
				parts = append(parts, fmt.Sprintf("%.1f ms", *t))
			}
		}
		addr := h.Address
		if addr == "" {
			addr = "-"
		}
		marker := ""
		if h.Reached {
			marker = "  <- destination"
		}
		fmt.Fprintf(w, "%2d  %-39s %s%s\n", h.TTL, addr, strings.Join(parts, "  "), marker)
		if h.Note != "" {
			fmt.Fprintf(w, "    %s\n", a.out.Dim(h.Note))
		}
	}
	fmt.Fprintf(w, "\n%s\n", r.Note)
}

type mtuDoc struct {
	SchemaVersion string `json:"schema_version"`
	*path.MTUResult
}

func newPathMTUCmd(a *app) *cobra.Command {
	var port int
	cmd := &cobra.Command{
		Use:   "mtu <host>",
		Short: "Report the interface MTU and the segment size of a connection to a host",
		Long: "Open one TCP connection and report the MTU of the interface it uses and the maximum segment size it negotiated, and whether the second is clearly lower than the first.\n" +
			"This is a hint about the path, not a discovery of it: finding the exact path MTU needs Don't-Fragment probes and ICMP feedback, which nw does not do. Windows does not report the segment size.\n\n" +
			"Exit status: 0 when the connection was made, 1 when it could not be, 2 on a usage error.",
		Example: "  nw path mtu example.com",
		Args:    cobra.ExactArgs(1),
	}
	cmd.Flags().IntVar(&port, "port", 443, "TCP port to connect to")
	cmd.RunE = func(c *cobra.Command, args []string) error {
		if p, err := target.Port(fmt.Sprint(port)); err != nil || p != port {
			return exit.Usage(fmt.Errorf("invalid --port %d", port))
		}
		addr, err := resolveAddr(c.Context(), args[0])
		if err != nil {
			return err
		}
		res, err := path.MTU(c.Context(), args[0], addr, port, a.opts.timeout)
		if err != nil {
			if c.Context().Err() != nil {
				return c.Context().Err()
			}
			if !a.opts.quiet {
				fmt.Fprintf(a.stderr, "nw: could not connect to %s: %v\n", net.JoinHostPort(addr.String(), fmt.Sprint(port)), err)
			}
			return exit.ErrFindings
		}
		if a.out.Format == output.JSON {
			if err := a.out.JSON(mtuDoc{SchemaVersion: SchemaVersion, MTUResult: res}); err != nil {
				return exit.Execution(err)
			}
			return nil
		}
		w := a.out.Out
		fmt.Fprintf(w, "%s %s (%s) port %d\n", a.out.Bold("nw path mtu"), res.Target, res.Address, res.Port)
		fmt.Fprintf(w, "interface MTU:    %d\n", res.InterfaceMTU)
		if res.MSS > 0 {
			fmt.Fprintf(w, "segment size:     %d (implies packets of up to %d bytes)\n", res.MSS, res.ImpliedPathMTU)
		} else {
			fmt.Fprintln(w, "segment size:     not reported on this platform")
		}
		fmt.Fprintf(w, "\n%s\n", res.Note)
		return nil
	}
	return cmd
}
