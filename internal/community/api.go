package community

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/radestsam/nwrk/contracts"
	"github.com/radestsam/nwrk/internal/buildinfo"
)

// DefaultAPI is the address of the NWRK Status API.
const DefaultAPI = "https://api.nwrk.ir"

// maxResponseBytes bounds what the client reads from the server.
const maxResponseBytes = 1 << 20

// APIError is an error that the server reported, in the contract form.
type APIError struct {
	Status     int
	Code       string
	Message    string
	RetryAfter time.Duration
}

func (e *APIError) Error() string {
	return fmt.Sprintf("the server refused the request (%s): %s", e.Code, e.Message)
}

// Challenge is a one-time proof-of-work challenge from the server.
type Challenge struct {
	ID            string
	Token         string
	ExpiresAt     time.Time
	DifficultyBit int
}

// Receipt is the answer to a submission.
type Receipt struct {
	// Accepted is false when the server read the document but excluded it.
	Accepted        bool
	SubmissionID    string
	ReceivedAt      time.Time
	ObservedCountry string
	ObservedASN     int
	// Reason is set when the document is excluded.
	Reason string
}

// Client talks to the NWRK Status API. It sends nothing but the two
// documents of the contract, and it keeps no cookies and no connection state.
type Client struct {
	base *url.URL
	http *http.Client
}

// NewClient checks the base address and returns a client. The address must use
// https. Plain http is allowed only for a loopback host, for local development.
func NewClient(base string, rt http.RoundTripper) (*Client, error) {
	u, err := url.Parse(strings.TrimRight(base, "/"))
	if err != nil || u.Host == "" || u.User != nil {
		return nil, fmt.Errorf("%q is not a valid API address", base)
	}
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopback(u.Hostname()) {
			return nil, fmt.Errorf("the API address must use https. Plain http is allowed only for localhost")
		}
	default:
		return nil, fmt.Errorf("the API address must use https")
	}
	if u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("the API address must be a host name, without a path")
	}
	return &Client{base: u, http: &http.Client{
		Transport: rt,
		Timeout:   30 * time.Second,
		// A redirect could send the document to another host.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}, nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Host returns the host of the API, for messages to the person.
func (c *Client) Host() string { return c.base.Host }

type profileRef struct {
	ID      string `json:"id"`
	Version int    `json:"version"`
}

// Challenge asks the server for a challenge for the profile.
func (c *Client) Challenge(ctx context.Context, p *contracts.Profile) (*Challenge, error) {
	req := map[string]any{
		"schema_version": contracts.SchemaVersion,
		"client":         map[string]string{"name": ClientName, "version": clientVersion(buildinfo.Get().Version)},
		"profile":        profileRef{ID: p.ID, Version: p.Version},
	}
	body, _ := json.Marshal(req)
	raw, err := c.post(ctx, "/api/v1/contributions/challenge", body, http.StatusCreated, "challengeResponse")
	if err != nil {
		return nil, err
	}
	var r struct {
		ID      string `json:"challenge_id"`
		Token   string `json:"token"`
		Expires string `json:"expires_at"`
		PoW     struct {
			Bits int `json:"difficulty_bits"`
		} `json:"pow"`
	}
	if err := json.Unmarshal(raw, &r); err != nil {
		return nil, fmt.Errorf("the server sent an unreadable challenge: %w", err)
	}
	exp, err := time.Parse(time.RFC3339, r.Expires)
	if err != nil {
		return nil, fmt.Errorf("the server sent an invalid challenge time: %w", err)
	}
	return &Challenge{ID: r.ID, Token: r.Token, ExpiresAt: exp, DifficultyBit: r.PoW.Bits}, nil
}

// Submit sends the contribution with a solved challenge.
func (c *Client) Submit(ctx context.Context, ch *Challenge, nonce string, doc *contracts.Contribution) (*Receipt, error) {
	body, err := json.Marshal(map[string]any{
		"challenge":    map[string]string{"id": ch.ID, "token": ch.Token, "pow_nonce": nonce},
		"contribution": doc,
	})
	if err != nil {
		return nil, err
	}
	if len(body) > contracts.MaxBodyBytes {
		return nil, fmt.Errorf("the document is %d bytes. The limit is %d", len(body), contracts.MaxBodyBytes)
	}
	raw, status, wait, err := c.do(ctx, "/api/v1/contributions", body)
	if err != nil {
		return nil, err
	}
	switch status {
	case http.StatusAccepted:
		if err := contracts.ValidateAPI("acceptedResponse", raw); err != nil {
			return nil, fmt.Errorf("the server sent an unexpected answer: %w", err)
		}
		var r struct {
			ID       string `json:"submission_id"`
			Received string `json:"received_at"`
			Country  string `json:"observed_country"`
			ASN      int    `json:"observed_asn"`
		}
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, err
		}
		at, _ := time.Parse(time.RFC3339, r.Received)
		return &Receipt{Accepted: true, SubmissionID: r.ID, ReceivedAt: at, ObservedCountry: r.Country, ObservedASN: r.ASN}, nil
	case http.StatusOK:
		if err := contracts.ValidateAPI("excludedResponse", raw); err != nil {
			return nil, fmt.Errorf("the server sent an unexpected answer: %w", err)
		}
		var r struct {
			Reason  string `json:"reason"`
			Country string `json:"observed_country"`
		}
		if err := json.Unmarshal(raw, &r); err != nil {
			return nil, err
		}
		return &Receipt{Reason: r.Reason, ObservedCountry: r.Country}, nil
	}
	return nil, apiError(status, raw, wait)
}

func (c *Client) post(ctx context.Context, path string, body []byte, want int, def string) ([]byte, error) {
	raw, status, wait, err := c.do(ctx, path, body)
	if err != nil {
		return nil, err
	}
	if status != want {
		return nil, apiError(status, raw, wait)
	}
	if err := contracts.ValidateAPI(def, raw); err != nil {
		return nil, fmt.Errorf("the server sent an unexpected answer: %w", err)
	}
	return raw, nil
}

func (c *Client) do(ctx context.Context, path string, body []byte) ([]byte, int, time.Duration, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base.String()+path, bytes.NewReader(body))
	if err != nil {
		return nil, 0, 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "nwrk/"+clientVersion(buildinfo.Get().Version))
	resp, err := c.http.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return nil, 0, 0, ctx.Err()
		}
		return nil, 0, 0, fmt.Errorf("could not reach %s: %w", c.base.Host, unwrap(err))
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, 0, 0, fmt.Errorf("reading the answer from %s failed: %w", c.base.Host, unwrap(err))
	}
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, 0, 0, fmt.Errorf("%s answered with a redirect. The client does not follow redirects", c.base.Host)
	}
	var wait time.Duration
	if secs, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && secs > 0 {
		wait = time.Duration(secs) * time.Second
	}
	return raw, resp.StatusCode, wait, nil
}

// unwrap removes the request URL from a transport error.
func unwrap(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return ue.Err
	}
	return err
}

func apiError(status int, raw []byte, wait time.Duration) error {
	e := &APIError{Status: status, Code: "server_error", Message: "the server answered with status " + strconv.Itoa(status)}
	if contracts.ValidateAPI("errorResponse", raw) == nil {
		var r struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(raw, &r) == nil {
			e.Code, e.Message = r.Error.Code, r.Error.Message
		}
	}
	e.RetryAfter = wait
	return e
}

// SolvePoW finds the nonce for a challenge. It stops when ctx ends.
func SolvePoW(ctx context.Context, ch *Challenge) (string, error) {
	for n := uint64(0); ; n++ {
		if n&0xfff == 0 && ctx.Err() != nil {
			return "", ctx.Err()
		}
		nonce := strconv.FormatUint(n, 10)
		if contracts.LeadingZeroBits(ch.ID, ch.Token, nonce) >= ch.DifficultyBit {
			return nonce, nil
		}
	}
}
