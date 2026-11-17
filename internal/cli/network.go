package cli

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/hesamzakerirad/nwrk/internal/exit"
	"github.com/hesamzakerirad/nwrk/internal/output"
	"github.com/hesamzakerirad/nwrk/internal/platform"
)

// inspection is the platform data the network commands print. Tests replace
// it; the real program reads the operating system.
type inspection interface {
	Interfaces() ([]platform.Interface, error)
	Routes() ([]platform.Route, error)
	DNS() (platform.DNSConfig, error)
	Proxies() []platform.ProxySetting
}

type realInspection struct{}

func (realInspection) Interfaces() ([]platform.Interface, error) { return platform.Interfaces() }
func (realInspection) Routes() ([]platform.Route, error)         { return platform.Routes() }
func (realInspection) DNS() (platform.DNSConfig, error)          { return platform.DNS() }
func (realInspection) Proxies() []platform.ProxySetting          { return platform.Proxies() }

func (a *app) inspect() inspection {
	if seams.network != nil {
		return seams.network
	}
	return realInspection{}
}

func newNetworkCmd(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "network",
		Short: "Show this machine's own network setup",
		Long: "Read the network setup from the operating system: interfaces, routes, DNS servers and proxies.\n" +
			"These commands send nothing over the network. They show addresses, because showing them is their purpose; reports from nw doctor leave them out.",
		Args: cobra.NoArgs,
		RunE: func(c *cobra.Command, _ []string) error { return c.Help() },
	}
	cmd.AddCommand(newNetworkShowCmd(a), newNetworkInterfacesCmd(a), newNetworkRoutesCmd(a), newNetworkDNSCmd(a), newNetworkProxyCmd(a))
	return cmd
}

func execErr(err error) error {
	if errors.Is(err, platform.ErrUnsupported) {
		return exit.Execution(fmt.Errorf("%v (see docs/platform-support.md)", err))
	}
	return exit.Execution(err)
}

type interfacesDoc struct {
	SchemaVersion string               `json:"schema_version"`
	Interfaces    []platform.Interface `json:"interfaces"`
}

func newNetworkInterfacesCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "interfaces",
		Short: "List network interfaces and their addresses",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			ifs, err := a.inspect().Interfaces()
			if err != nil {
				return execErr(err)
			}
			if a.out.Format == output.JSON {
				return a.out.JSON(interfacesDoc{SchemaVersion: SchemaVersion, Interfaces: ifs})
			}
			tw := tabwriter.NewWriter(a.out.Out, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, a.out.Bold("NAME")+"\tSTATE\tMTU\tADDRESSES")
			for _, i := range ifs {
				state := "down"
				if i.Up {
					state = "up"
				}
				if i.Loopback {
					state += " (loopback)"
				}
				var addrs []string
				for _, ad := range i.Addresses {
					addrs = append(addrs, ad.CIDR+" "+ad.Kind)
				}
				fmt.Fprintf(tw, "%s\t%s\t%d\t%s\n", i.Name, state, i.MTU, strings.Join(addrs, ", "))
			}
			return tw.Flush()
		},
	}
}

type routesDoc struct {
	SchemaVersion string           `json:"schema_version"`
	Routes        []platform.Route `json:"routes"`
}

func newNetworkRoutesCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "routes",
		Short: "Show the routing table",
		Long:  "Show the routing table. It is read from the operating system on Linux and macOS; on Windows it is not available yet, see docs/platform-support.md.",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			rs, err := a.inspect().Routes()
			if err != nil {
				return execErr(err)
			}
			if a.out.Format == output.JSON {
				return a.out.JSON(routesDoc{SchemaVersion: SchemaVersion, Routes: rs})
			}
			tw := tabwriter.NewWriter(a.out.Out, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, a.out.Bold("DESTINATION")+"\tGATEWAY\tINTERFACE\tFAMILY\tMETRIC")
			for _, r := range rs {
				gw := r.Gateway
				if gw == "" {
					gw = "-"
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", r.Destination, gw, r.Interface, r.Family, metric(r.Metric))
			}
			return tw.Flush()
		},
	}
}

func metric(m int) string {
	if m == 0 {
		return "-"
	}
	return strconv.Itoa(m)
}

type dnsDoc struct {
	SchemaVersion string `json:"schema_version"`
	platform.DNSConfig
}

func newNetworkDNSCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "dns-config",
		Short: "Show the DNS servers this machine is configured to use",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			cfg, err := a.inspect().DNS()
			if err != nil {
				return execErr(err)
			}
			if cfg.Servers == nil {
				cfg.Servers = []string{}
			}
			if a.out.Format == output.JSON {
				return a.out.JSON(dnsDoc{SchemaVersion: SchemaVersion, DNSConfig: cfg})
			}
			fmt.Fprintf(a.out.Out, "source: %s\n", cfg.Source)
			if len(cfg.Servers) == 0 {
				fmt.Fprintln(a.out.Out, "no DNS server is configured")
			}
			for _, s := range cfg.Servers {
				fmt.Fprintf(a.out.Out, "server: %s\n", s)
			}
			if len(cfg.SearchDomains) > 0 {
				fmt.Fprintf(a.out.Out, "search: %s\n", strings.Join(cfg.SearchDomains, " "))
			}
			return nil
		},
	}
}

type proxyDoc struct {
	SchemaVersion string                  `json:"schema_version"`
	Proxies       []platform.ProxySetting `json:"proxies"`
}

func newNetworkProxyCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "proxy",
		Short: "Show proxy settings that applications may use",
		Long: "Show proxies set in the environment (HTTP_PROXY, HTTPS_PROXY, ALL_PROXY, NO_PROXY) and, on Windows, in the system settings. Credentials are never shown.\n" +
			"nw itself ignores proxies and measures the direct path.",
		Args: cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			ps := a.inspect().Proxies()
			if ps == nil {
				ps = []platform.ProxySetting{}
			}
			if a.out.Format == output.JSON {
				return a.out.JSON(proxyDoc{SchemaVersion: SchemaVersion, Proxies: ps})
			}
			if len(ps) == 0 {
				fmt.Fprintln(a.out.Out, "no proxy is configured in the environment or the system settings")
				return nil
			}
			for _, p := range ps {
				if p.NoProxy != "" {
					fmt.Fprintf(a.out.Out, "%s: %s\n", p.Source, p.NoProxy)
					continue
				}
				fmt.Fprintf(a.out.Out, "%s: %s\n", p.Source, strings.TrimSpace(p.Scheme+" "+p.Host))
			}
			fmt.Fprintln(a.out.Out, a.out.Dim("nw ignores proxies and measures the direct path."))
			return nil
		},
	}
}

type showDoc struct {
	SchemaVersion string `json:"schema_version"`
	Interfaces    struct {
		Total  int      `json:"total"`
		Up     int      `json:"up"`
		Usable int      `json:"usable"`
		Names  []string `json:"usable_names"`
	} `json:"interfaces"`
	DefaultRoute struct {
		Known     bool   `json:"known"`
		Gateway   string `json:"gateway,omitempty"`
		Interface string `json:"interface,omitempty"`
	} `json:"default_route"`
	DNSServers []string `json:"dns_servers"`
	Proxy      bool     `json:"proxy_configured"`
}

func newNetworkShowCmd(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "show",
		Short: "Show a short summary of this machine's network setup",
		Args:  cobra.NoArgs,
		RunE: func(*cobra.Command, []string) error {
			in := a.inspect()
			var d showDoc
			d.SchemaVersion = SchemaVersion
			d.DNSServers = []string{}
			d.Interfaces.Names = []string{}
			ifs, err := in.Interfaces()
			if err != nil {
				return execErr(err)
			}
			d.Interfaces.Total = len(ifs)
			for _, i := range ifs {
				if i.Up {
					d.Interfaces.Up++
				}
				if i.Usable() {
					d.Interfaces.Usable++
					d.Interfaces.Names = append(d.Interfaces.Names, i.Name)
				}
			}
			if rs, err := in.Routes(); err == nil {
				d.DefaultRoute.Known = true
				for _, r := range rs {
					if r.Default && r.Family == "ipv4" {
						d.DefaultRoute.Gateway, d.DefaultRoute.Interface = r.Gateway, r.Interface
						break
					}
				}
			}
			if cfg, err := in.DNS(); err == nil && cfg.Servers != nil {
				d.DNSServers = cfg.Servers
			}
			d.Proxy = len(in.Proxies()) > 0
			if a.out.Format == output.JSON {
				return a.out.JSON(d)
			}
			w := a.out.Out
			fmt.Fprintf(w, "interfaces:     %d, %d up, %d able to reach beyond this machine (%s)\n", d.Interfaces.Total, d.Interfaces.Up, d.Interfaces.Usable, strings.Join(d.Interfaces.Names, ", "))
			switch {
			case !d.DefaultRoute.Known:
				fmt.Fprintln(w, "default route:  not available on this platform (nw doctor still checks that a route exists)")
			case d.DefaultRoute.Interface == "" && d.DefaultRoute.Gateway == "":
				fmt.Fprintln(w, "default route:  none in the IPv4 table")
			default:
				fmt.Fprintf(w, "default route:  via %s on %s\n", orDash(d.DefaultRoute.Gateway), orDash(d.DefaultRoute.Interface))
			}
			fmt.Fprintf(w, "dns servers:    %s\n", orDash(strings.Join(d.DNSServers, ", ")))
			fmt.Fprintf(w, "proxy:          %s\n", map[bool]string{true: "configured (nw network proxy)", false: "none"}[d.Proxy])
			return nil
		},
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
