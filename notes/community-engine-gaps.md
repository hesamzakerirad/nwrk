# Community Engine Gaps

Result of the Phase 0.4 audit of `internal/measurement`. It lists what the community contribution feature can reuse and what it must add. Work items belong to Phase 3 of `../notes/execution-plan.md`. Contract items belong to Phase 1.

Audit date: 22 November 2026. Code version: working tree on top of `v0.4.0-dev`.

## Answers to the Phase 0 Questions

| Question | Answer |
|---|---|
| Can each layer use IPv4 or IPv6 on its own? | DNS: yes. `dns.System` asks A and AAAA separately (`ip4` and `ip6`). TCP and TLS: yes. They take one `netip.AddrPort`, so the caller picks the family. HTTP: not directly. `http.Get` takes a URL and resolves inside the transport. A caller can force a family with `Options.DialContext`. |
| Does DNS report the response code and the answer count? | Answer count: yes (`len(Answers)`). Response code: no for the system resolver. The OS API gives no code, so NXDOMAIN and an empty answer both become `dns.no_answer`. Only a chosen resolver gives a code. |
| Can TLS use a given SNI and report only the validation result? | Yes. `Handshake(ctx, serverName, addr, opts)` sets SNI and the verified name. `Result.Chain.Verified` is the validation result. Verification never turns off. |
| Can HTTP stop at a byte limit and report only status and time? | Partly. The body limit is the constant `MaxBody` (1 MiB). It is not an option. The status code and timings are in the result. |
| Is the failure code set small and stable? | Yes. `domain.ErrorCode` has `dns.*`, `tcp.*`, `tls.*`, `http.*` and `local.*` codes. The contract can reuse them, without `local.*`. |

## What the Engine Can Reuse

* Layer functions: `dns.System`, `tcp.Connect`, `tls.Handshake`, `http.Get`.
* Error classification in `errclass`, shared by all layers.
* Interface and route checks in `local`, including `GlobalIPv6`.
* Per-call deadlines through `context`. The runner sets 3 s for DNS and TCP, and 5 s for TLS and HTTP.

## Gaps

### G1. No runner for a profile

Nothing runs a list of endpoints with a concurrency limit of 4 to 6 and a total budget of 90 s. Add a runner in `internal/community`.

### G2. Local IPv6 absence looks like a failure

On a host with no global IPv6, every IPv6 attempt fails with `tcp.unreachable` or `local.no_route`. The result would count as a service failure. The runner must use `local` to detect missing global IPv6 and leave out all IPv6 measurements. A missing measurement is not a failed one.

Contract decision (Phase 1): the payload only holds a family when the host had a usable route for it.

### G3. Endpoints without AAAA records

Some services have no IPv6 address. For example `github.com` has no AAAA record. The DNS result for AAAA is `dns.no_answer`. That is not a failure of the service.

Contract decision (Phase 1): the catalogue lists the `families` each endpoint supports. The runner and the aggregation only count a family the endpoint supports.

### G4. DNS response code is missing for the system resolver

The system path cannot tell NXDOMAIN from an empty answer. The schema field `dns_rcode` must be optional and null here. Do not add a code that the OS did not give.

Decision for the aggregation spec (Phase 4): treat `dns.no_answer` from the system resolver as one outcome. Do not claim NXDOMAIN.

### G5. HTTP family pinning

`http.Get` has no family option. Use `Options.DialContext` with a wrapper that dials `tcp4` or `tcp6` and ignores the network name that Go passes.

Better: pin the HTTP dial to the address that the DNS step returned for that family. The four layers then describe one path. Without pinning, DNS round robin can make TCP and HTTP use different servers.

### G6. HTTP redirects cannot be turned off

`Options.MaxRedirects <= 0` means the default of 10. There is no way to ask for no redirect. The contract has `redirect_policy`.

Add an explicit policy: `none` (return the first response) and `follow` (current behavior). For V1 prefer endpoints that do not redirect, and use `none`. The status code in the payload is then the status of the first response.

### G7. HTTP body limit is fixed

`MaxBody` is 1 MiB. A `GET` can read that much per endpoint and family. Add `Options.MaxBody`. Prefer `HEAD` where the catalogue allows it. Record the limit in the profile.

### G8. Results hold data that must not leave the host

The engine result types carry fields that the contract forbids:

| Type | Fields that must be dropped |
|---|---|
| `domain.Measurement` target | `IP`, `Host` for the resolver, `Resolver.Servers` |
| `dns.Result` | `A`, `AAAA`, `Answers`, `CNAMEs`, `Queries[].Error.Message` |
| `tcp.Result` | `Address` |
| `tls.Result` | `Certificates`, `CipherSuite`, `Chain.Error` text |
| `http.Result` | `Headers`, `Hops[].URL`, error messages with addresses |

The sanitizer builds the payload from an allowlist, field by field. It must never marshal a `Measurement`. A test must fail if the sanitizer output has an IP address, a resolver address or a hop URL, whatever the input.

### G9. Error messages hold addresses

Messages such as `connection to <ip:port> was refused` contain addresses. The payload carries the error code only, never the message.

### G10. Separate layer steps cost more traffic

Four layer steps per endpoint and family make four connections. With 10 to 15 endpoints and two families the total stays small. Keep the profile limit of 15 endpoints. Check the total time in Phase 3.

### G11. Fragile string match for `dns.servfail`

`errclass.DNS` finds a SERVFAIL by the text `server misbehaving`. It works for the Go resolver. Other platforms can differ. Low risk for V1 because the system path maps most failures to `dns.transport`. Do not rely on `dns.servfail` in the aggregation spec.

## Status After Phase 3

| Gap | Status |
|---|---|
| G1 runner | Done: `internal/community/runner.go` |
| G2 missing IPv6 | Done: `local.Route` decides the families, and a missing family is left out |
| G3 no AAAA | Done: only the families in the profile are measured |
| G4 DNS response code | Done: the field is never set for the system resolver |
| G5 HTTP family pinning | Done: the HTTP dial uses the address that the DNS step returned |
| G6 redirects | Done: `http.Options.NoRedirect` |
| G7 body limit | Done: `http.Options.MaxBody`, set from `max_response_bytes` |
| G8 sanitizer | Done: `internal/community/payload.go` builds `contracts.Measurement` field by field, with a leak test |
| G9 error messages | Done: only the error code is used |
| G10 total time | Checked: a run of the 9 `ir-dev-v1` endpoints from a home network took about 2 seconds, and the budget is 90 seconds |
| G11 `dns.servfail` | Not used by the aggregation spec |

## Tasks for Later Phases

Phase 1 (contract):
* Make `dns_rcode` optional and nullable (G4).
* Add `families` to the endpoint catalogue (G3).
* Add `redirect_policy` values `none` and `follow`, and `max_response_bytes` (G6, G7).
* Say that a family is present only when the host had a route (G2).
* Use the engine error codes, without `local.*`, as `normalized_error` (G9).

Phase 3 (CLI):
* Add `internal/community` with the runner, family pinning and the allowlist sanitizer (G1, G2, G5, G8).
* Add `http.Options.MaxBody` and a no-redirect policy (G6, G7).
* Add the sanitizer leak test (G8).
