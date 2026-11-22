# Catalog Decisions

This file records why each endpoint is in a profile. Rules for approval are in section 7.3 of the build plan. A profile version never changes after release. To change an endpoint, add a new profile version and record the reason here.

## Evidence and Its Limits

Measured on 22 November 2026 from one Iranian network (one fixed line connection) with `curl`, over IPv4 and IPv6, with `HEAD` and with `GET`.

Not done yet, and required before the closed pilot:

* A check from at least four more Iranian networks, including two mobile carriers.
* A written confirmation of the operator for each endpoint, from the operator's own documentation.
* A second check a few weeks later, to see which endpoints are stable.

Treat every row as "reachable from one network on one day". It is not proof that the endpoint works everywhere.

## Common Rules

* Every endpoint uses HTTPS on port 443, with no authentication and no cookies.
* Every endpoint uses `HEAD`, so the client reads no response body (`max_response_bytes` is 0).
* Redirects are not followed (`redirect_policy` is `none`). Every endpoint answered without a redirect.
* A family is listed only if the hostname has a native AAAA record. This was checked against a public resolver. On the test network, some names without an AAAA record still answered over IPv6. That is network translation (DNS64 and NAT64), not a native path, so those endpoints list `ipv4` only.
* Prefer connectivity check files and `robots.txt` over home pages. They are small, stable and made for automated requests.

## Profile `ir-core-v1`

| Target | URL | Families | Result on 22 Nov 2026 | Notes |
|---|---|---|---|---|
| `google` | `www.google.com/generate_204` | ipv4, ipv6 | 204 | Google's connectivity check |
| `gstatic` | `www.gstatic.com/generate_204` | ipv4, ipv6 | 204 | Different host and edge from `google` |
| `cloudflare` | `www.cloudflare.com/robots.txt` | ipv4, ipv6 | 200 | |
| `mozilla` | `detectportal.firefox.com/success.txt` | ipv4, ipv6 | 200 | Firefox captive portal check |
| `apple` | `www.apple.com/library/test/success.html` | ipv4, ipv6 | 200 | Apple captive portal check |
| `example` | `example.com/` | ipv4, ipv6 | 200 | Reserved by IANA for documentation |
| `wikipedia` | `www.wikipedia.org/` | ipv4, ipv6 | 200 | |
| `digikala` | `www.digikala.com/robots.txt` | ipv4 | 200 | No native AAAA record |
| `aparat` | `www.aparat.com/robots.txt` | ipv4 | 200 | No native AAAA record |
| `divar` | `divar.ir/robots.txt` | ipv4 | 200 | No native AAAA record |

The domestic services match the anchors in the CLI `ir` preset.

## Profile `ir-dev-v1`

| Target | URL | Families | Result on 22 Nov 2026 | Notes |
|---|---|---|---|---|
| `github` | `github.com/robots.txt` | ipv4 | 200 | No native AAAA record |
| `go-proxy` | `proxy.golang.org/github.com/spf13/cobra/@v/v1.10.2.info` | ipv4, ipv6 | 200 | A released module version never changes |
| `npm` | `registry.npmjs.org/-/ping` | ipv4, ipv6 | 200 | |
| `pypi` | `pypi.org/simple/pip/` | ipv4, ipv6 | 200 | `HEAD` reads nothing. The page is large. |
| `docker-hub` | `registry-1.docker.io/v2/` | ipv4, ipv6 | **403** | See below |
| `crates-io` | `index.crates.io/config.json` | ipv4, ipv6 | 200 | |
| `debian` | `deb.debian.org/debian/dists/stable/InRelease` | ipv4, ipv6 | 200 | `stable` moves to a new release over time. The path stays valid. |
| `ubuntu` | `archive.ubuntu.com/ubuntu/dists/noble/InRelease` | ipv4, ipv6 | 200 | `noble` is supported until 2029. Review then. |
| `homebrew` | `formulae.brew.sh/api/formula/wget.json` | ipv4, ipv6 | 200 | |

### Docker Hub

The registry normally answers `GET /v2/` with 401 (authentication required). On the test network it answered 403. This is an HTTP response, so the dashboard must show it as a server refusal, and not as a DNS, TCP or TLS failure. The endpoint stays in the profile because this difference is what the project exists to show.

## Rejected Candidates

| Candidate | Reason |
|---|---|
| `www.msftconnecttest.com/connecttest.txt` | It is an HTTP only check host. HTTPS failed certificate verification on both families. |
| `www.microsoft.com/robots.txt` | Answered 403 to an automated request. The result would not describe reachability. |
| `www.cloudflare.com/cdn-cgi/trace` | `HEAD` returns 404, and `GET` returns the client address in the body. The body is never needed, so the endpoint is not used. |
| `api.github.com/zen` | Anonymous rate limits would turn many contributions into 403 responses. |
| `pypi.org/simple/` | The full index is tens of megabytes. |
| `https://example.com/` as the only reference | One host is not enough. Seven international references are used instead. |

## Differences From the Build Plan

* The plan lists a `timeout_ms` for each endpoint. The contract sets timeouts for each layer in the profile limits instead (DNS 3 s, TCP 3 s, TLS 5 s, HTTP 5 s). The layers have different limits, and one value for each endpoint cannot express that. The server migration must follow the contract.
* The plan lists 10 to 15 endpoints for each profile. `ir-core-v1` has 10. `ir-dev-v1` has 9, one for each developer service the plan names.
* Each endpoint has a `families` list. The plan did not have this field. It is needed because some services have no native IPv6, and a missing AAAA record must not count as a failure.
