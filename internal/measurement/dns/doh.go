package dns

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"

	mdns "github.com/miekg/dns"

	"github.com/hesamzakerirad/nwrk/internal/buildinfo"
	"github.com/hesamzakerirad/nwrk/internal/target"
)

// maxDoHResponse bounds how much of a DoH reply is read.
const maxDoHResponse = 64 << 10

// sendDoH sends msg as a DNS over HTTPS POST (RFC 8484).
func sendDoH(ctx context.Context, msg *mdns.Msg, r target.Resolver, o Options) (*mdns.Msg, error) {
	m := msg.Copy()
	m.Id = 0 // RFC 8484 asks for a zero ID, which helps HTTP caches
	wire, err := m.Pack()
	if err != nil {
		return nil, err
	}
	url := "https://" + r.Address() + r.Path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	req.Header.Set("User-Agent", "nw/"+buildinfo.Get().Version)

	tr := &http.Transport{
		Proxy:             nil, // measure the direct path
		DisableKeepAlives: true,
		ForceAttemptHTTP2: true,
		TLSClientConfig:   &tls.Config{RootCAs: o.RootCAs, MinVersion: tls.VersionTLS12},
	}
	defer tr.CloseIdleConnections()
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("the DoH server answered HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDoHResponse))
	if err != nil {
		return nil, err
	}
	out := new(mdns.Msg)
	if err := out.Unpack(body); err != nil {
		return nil, fmt.Errorf("the DoH reply is not a DNS message: %w", err)
	}
	out.Id = msg.Id
	return out, nil
}
