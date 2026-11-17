# nwrk: Product & Engineering Specification

**Document status:** Working specification  
**Version:** 0.2  
**Product name:** nwrk  
**Executable name:** `nw`  
**Website:** https://nwrk.ir  
**Repository:** https://github.com/hesamzakerirad/nwrk  
**License:** MIT  
**Primary language:** Go  
**Product format:** Local-first, cross-platform command-line application  
**Target platforms:** Linux, macOS, and Windows (amd64 and arm64)  

The phased delivery plan lives in [ROADMAP.md](ROADMAP.md). Where this document and the roadmap disagree on timing, the roadmap wins.

---

## 1. Executive Summary

nwrk is a local-first, evidence-driven command-line toolkit for internet diagnostics, network security investigation, and network observability.

Its purpose is not simply to wrap common utilities such as `ping`, `dig`, `curl`, `traceroute`, and `openssl`. It should coordinate measurements, preserve their results, identify meaningful patterns, explain what the evidence supports, and recommend useful next investigations.

The product combines three related areas:

1. **Network health and troubleshooting**: determine whether a device or network can reach a destination, identify the failing layer, and inspect performance or configuration problems.
2. **Security and interference investigation**: identify suspicious DNS, TLS, HTTP, proxy, routing, and filtering behavior without overstating what an individual measurement proves.
3. **Observability**: repeat measurements, retain local history, compare results over time, and identify recurring or newly emerging failures.

The product is CLI-first by design. The first release should be a standalone Go executable that works without an account, server, database service, or cloud connection. Optional remote measurement integrations may be added later, but local diagnostics must remain useful without them.

### Product promise

> Run one command. Understand what happened, what evidence supports it, what might explain it, and what to investigate next.

### Core differentiator

The differentiator is the **diagnostic engine**: the ability to correlate observations from different network layers and produce traceable findings, ranked hypotheses, and practical next steps.

The product should not compete by merely offering the largest number of network tests. It should make the results of those tests easier to understand and act upon.

---

## 2. Product Vision and Positioning

### 2.1 Vision

Make network behavior understandable and diagnosable from the command line, from a simple connectivity problem to a complex investigation involving DNS, transport, TLS, HTTP, routing, and possible network interference.

### 2.2 Mission

Provide a trustworthy, portable, scriptable tool that turns network measurements into reproducible evidence and useful explanations.

### 2.3 Positioning

nwrk sits at the intersection of:

- General-purpose network diagnostics.
- Security and internet-interference investigation.
- Operational troubleshooting and lightweight observability.

It should not be positioned as a replacement for specialist platforms such as OONI Probe, RIPE Atlas, or Globalping. Those projects already provide important censorship measurements or distributed network measurement capabilities. nwrk should focus first on local investigation, evidence correlation, diagnostic reasoning, and practical workflows. Integrations with external measurement networks can provide additional context later.

### 2.3.1 Primary focus

The headline use case is diagnosing connectivity under DNS tampering, filtering, and unstable international links, as commonly experienced by users in Iran. In practice this means answering questions such as:

- Is the problem my local network, my ISP, domestic routing, or the international link?
- Does my system resolver return the same answers as a resolver I choose?
- Does the TLS connection fail only after the ClientHello, and only for certain server names?

The tool remains useful worldwide. Region-specific behavior is enabled through explicit region presets (`--region ir`), never through automatic geolocation.

### 2.4 Intended audiences

The first releases primarily serve technical users:

| Audience | Main need | Product experience |
|---|---|---|
| Developers | Understand why an application or API endpoint is unreachable | Fast diagnosis, clear errors, JSON output, exit codes |
| System administrators | Investigate network and infrastructure failures | Detailed measurements, configuration inspection, repeatable tests |
| Network engineers | Correlate behavior across DNS, transport, TLS, HTTP, and routes | Deep measurements, comparison, historical evidence |
| Security researchers | Investigate suspicious network behavior and possible interference | Transparent tests, evidence, caveats, exportable results |
| Support engineers | Produce reproducible reports for incidents and support cases | Guided diagnosis, concise summaries, shareable reports |
| Curious technical users | Understand their own internet connection | Friendly defaults and explanations without requiring specialist knowledge |

The product may eventually support non-technical users through guided interactive workflows, but the initial product is a CLI for technical users.

---

## 3. Product Principles

These principles should guide product design and code review.

1. **Local-first:** Core diagnostics must work without an account, backend, or network connection to a vendor service, except when testing an external destination.
2. **Privacy-first:** Do not upload measurement data automatically. Any external submission or third-party measurement must be explicit and clearly disclosed.
3. **Evidence before conclusions:** Findings must reference the measurements that support them.
4. **Honest uncertainty:** Distinguish observed facts from inferred causes. A timeout is not proof of a firewall; a TLS failure is not proof of censorship.
5. **Cross-platform:** Linux, macOS, and Windows are first-class targets. Platform-specific limitations must be reported rather than hidden.
6. **Scriptable:** Commands should support stable JSON output and documented exit codes.
7. **Safe by default:** Default tests should be non-invasive, bounded, and restricted to the target or configuration explicitly selected by the user.
8. **Reproducible:** Record relevant test parameters, timestamps, software version, and environment details so results can be interpreted later.
9. **Bounded execution:** Every network operation needs timeouts, resource limits, and cancellation support.
10. **Transparent operation:** Show what the tool is testing, where traffic is going, and what information is being stored or shared.
11. **Modular but not over-engineered:** Use clear package boundaries inside one Go application. Do not introduce microservices or a plugin framework before real requirements justify them.
12. **Useful without privilege:** Avoid requiring administrator/root privileges for the default diagnostic suite. Clearly identify tests that need elevated privileges or platform-specific capabilities.

---

## 4. Scope and Product Boundaries

### 4.1 Included product areas

- Local network configuration inspection.
- DNS resolution and resolver comparison.
- TCP connectivity tests.
- TLS handshake and certificate inspection.
- HTTP/HTTPS request diagnostics.
- Basic IPv4/IPv6 comparison.
- Regional reachability comparison (local, domestic, international) through explicit region presets.
- User-selectable DNS resolvers for every DNS-related command.
- Routing and path diagnostics in later releases.
- Network security indicators and interference investigation.
- Evidence-based diagnostic findings and recommendations.
- Local history and report export.
- Repeated local monitoring and comparisons in a later release.
- Optional integrations with external measurement networks after v1.0.

### 4.2 Explicit non-goals before v1.0

- A web dashboard or hosted SaaS platform.
- Desktop GUI or browser extension.
- Mobile application.
- Permanent background agent or system daemon.
- Packet capture or deep packet inspection.
- Malware detection or endpoint protection.
- Autonomous firewall, DNS, proxy, or routing configuration changes.
- Unbounded port scanning or discovery of unrelated hosts.
- VPN service or censorship circumvention client.
- A global probe network operated by the project.
- AI-generated diagnoses as the source of truth.
- Automatic geolocation of the user, or any lookup that reveals the user's location to a third party.
- User accounts, subscriptions, cloud synchronization, or a central database service.

These may be reconsidered only when the core CLI has demonstrated value and the relevant security, privacy, and maintenance costs are understood.

---

## 5. Product Experience

### 5.1 Default experience

The default experience should be understandable without memorizing networking utilities.

The primary workflows are:

nw doctor
nw doctor --region ir
nw diagnose example.com
nw diagnose example.com --profile deep
```

`doctor` checks the user's current network environment and common internet connectivity paths. With `--region`, it also separates local, domestic, and international reachability. `diagnose` investigates a specified destination and correlates measurements across relevant layers.

### 5.2 Diagnostic profiles

The initial profile model:

| Profile | Purpose | Typical tests |
|---|---|---|
| `quick` | Fast initial assessment | Local route availability, DNS, basic TCP connectivity |
| `standard` | Default destination diagnosis | DNS, TCP, TLS, HTTP, IPv4/IPv6 where applicable |
| `deep` | Extended investigation | Standard tests plus selected resolver comparisons, additional TLS/HTTP checks, and routing tests when supported |

The default should be `standard` for `diagnose` and a sensible bounded checklist for `doctor`.

Profiles must be configurable in a future release, but hard-coded, documented defaults are sufficient until v1.0.

### 5.3 Output modes

Every command should define its output behavior consistently:

- **Human output:** readable summaries, status indicators, explanations, and next steps.
- **JSON output:** structured, versioned data intended for scripts and other tools.
- **Quiet mode:** suppress nonessential output while preserving errors and exit status.
- **Verbose mode:** show additional measurement details and diagnostic reasoning.

Avoid making color the only carrier of meaning. Output must remain understandable in terminals without color and when redirected to files.

### 5.4 Interactive mode

An interactive terminal UI may be added after the main command workflows are stable. It should be a convenience layer over the same application and measurement services, not a separate diagnostic implementation.

---

## 6. Command Taxonomy

### 6.1 Core commands

Phases refer to [ROADMAP.md](ROADMAP.md).

| Command | Purpose | Phase |
|---|---|---|
| `nw version` | Print version and build information | P0 |
| `nw completion <shell>` | Generate shell completion scripts | P0 |
| `nw test dns <host>` | Run DNS measurements | P1 |
| `nw test tcp <host:port>` | Test TCP connectivity | P1 |
| `nw test tls <host>` | Inspect TLS negotiation and certificate validation | P1 |
| `nw test http <url>` | Inspect HTTP/HTTPS behavior | P1 |
| `nw diagnose <host-or-url>` | Run an orchestrated destination diagnosis | P2 |
| `nw doctor` | Inspect local network and general internet health | P3 |
| `nw network show` | Show a concise local network summary | P3 |
| `nw network interfaces` | List network interfaces and addresses | P3 |
| `nw network routes` | Inspect local routing table | P3 |
| `nw network dns-config` | Show configured resolvers | P3 |
| `nw network proxy` | Inspect relevant proxy settings | P3 |
| `nw config path` / `nw config show` | Show config file location and effective settings | P3 |
| `nw security inspect <host>` | Run security-oriented checks | P4 |
| `nw security interference <host>` | Investigate possible network interference | P4 |
| `nw path trace <host>` | Trace a route toward a destination | P4 |
| `nw path ping <host>` | Run controlled reachability/latency checks | P4 |
| `nw path mtu <host>` | Investigate path MTU behavior | P4 |
| `nw history list` | List local diagnostic runs | P5 |
| `nw history show <run-id>` | Show a stored run | P5 |
| `nw report export <run-id>` | Export a report | P5 |
| `nw watch <target>` | Repeat measurements locally | P7 |

### 6.2 Command examples

```bash

# General local network health check
nw doctor

# Separate local, domestic, and international failures
nw doctor --region ir

# Standard destination diagnosis
nw diagnose github.com

# Deeper investigation
nw diagnose github.com --profile deep

# Individual tests
nw test dns github.com
nw test tcp github.com:443
nw test tls github.com
nw test http https://github.com

# Compare the system resolver with resolvers you choose
nw test dns github.com --resolver 1.1.1.1 --resolver 10.0.0.53:5353

# Local configuration
nw network show
nw network dns-config

# Structured output
nw diagnose github.com --output json

# Export a previous report
nw report export <run-id> --format json --output report.json
```

### 6.3 Command design conventions

- Use consistent flags across commands: `--timeout`, `--output`, `--verbose`, `--quiet`, `--no-color`, and, where relevant, `--profile`, `--region`, and `--resolver`.
- Prefer explicit target syntax and validate hostnames, IP addresses, ports, and URLs before testing.
- Do not overload one command with unrelated behavior.
- Individual tests must be independently executable.
- The `diagnose` command orchestrates individual tests but does not duplicate their measurement logic.
- `doctor` focuses on the local environment; `diagnose` focuses on a specified destination.
- Document whether a command makes network requests, which destinations it contacts, and whether it requires privileges.

---

## 7. Diagnostic Capabilities

### 7.1 Local network inspection

Initial local inspection should identify, where supported:

- Active network interfaces.
- Interface addresses and address families.
- Default gateway and route availability.
- Configured DNS resolvers.
- Relevant proxy configuration and environment variables.
- Basic network availability indicators.

Do not collect unrelated host details. Avoid exposing private addresses in reports unless needed; offer redaction for exported reports.

### 7.2 DNS diagnostics

Initial capabilities (P1):

- Resolve A and AAAA records.
- Record resolver used where it can be determined.
- Record lookup duration.
- Preserve DNS response codes and structured errors.
- Distinguish no answer, NXDOMAIN, timeout, refused query, and transport failure.
- Support IPv4/IPv6 result separation.
- Optionally query an explicitly selected resolver for comparison.

Later capabilities:

- DNSSEC validation status.
- CNAME chain inspection.
- Comparison across system resolver and selected independent resolvers.
- DoT/DoH tests where explicitly configured.
- Detection of inconsistent or suspicious answers.

A differing DNS answer is an observation, not automatic proof of manipulation. Resolver location, split-horizon DNS, CDN responses, cache state, and geography can explain legitimate differences.
#### 7.2.1 Resolver selection

Every command that performs DNS lookups accepts a repeatable `--resolver` flag.

| Syntax | Transport | Phase |
|---|---|---|
| `host` or `host:port` | Plain DNS over UDP, with TCP fallback on truncation | P1 |
| `tcp://host[:port]` | Plain DNS over TCP | P1 |
| `tls://host[:port]` | DNS over TLS | P4 |
| `https://host/dns-query` | DNS over HTTPS | P4 |

The resolver list is taken from the first source that sets it, in this order:

1. `--resolver` flags.
2. The `NW_RESOLVERS` environment variable (comma-separated).
3. The `resolvers` key in the config file (from P3).
4. The resolvers of the selected region preset.

The system resolver is always measured as the baseline, so chosen resolvers are compared against it rather than silently replacing it.

### 7.3 TCP diagnostics

Initial capabilities (P1):

- Attempt a TCP connection to an explicit host and port.
- Record resolved destination address, address family, duration, and outcome.
- Distinguish timeout, connection refused, no route, resolution failure, and other operating-system errors where possible.
- Support bounded retries only when requested or defined by the diagnostic profile.

### 7.4 TLS diagnostics

Initial capabilities (P1):

- Establish a TLS connection with hostname verification enabled.
- Record handshake success or failure.
- Record negotiated TLS version and cipher suite when available.
- Inspect certificate subject, issuer, validity period, SANs, and chain verification result.
- Distinguish certificate validation errors from handshake/transport errors.
- Support an explicitly requested alternate TLS configuration only as an investigative test; do not silently disable certificate verification.

A failed handshake can have many causes, including incompatibility, server configuration, client configuration, proxy behavior, or network interference. The diagnostic engine must retain that uncertainty.

### 7.5 HTTP diagnostics

Initial capabilities (P1):

- Make a bounded HTTP/HTTPS request.
- Record status code and redirect chain.
- Record timing stages where measurable: DNS, connect, TLS, first byte, and total duration.
- Capture selected response headers useful for diagnostics.
- Classify timeout, redirect loop, protocol error, TLS error, and HTTP response separately.
- Avoid storing response bodies by default.
- Never collect or store authorization headers, cookies, or credentials in reports.

The request method and headers should be conservative defaults. Any non-GET method must be explicitly requested and documented.

### 7.6 IPv4 and IPv6 comparison

Where the operating system and destination allow it, compare IPv4 and IPv6 behavior independently. Report when one address family is unavailable or not applicable. Do not interpret a missing AAAA record as an IPv6 network failure.

### 7.7 Routing and path diagnostics (P4)

Potential capabilities:

- Traceroute using available platform mechanisms.
- TCP-based traceroute fallback where practical.
- Hop address and response timing.
- MTR-style repeated path sampling.
- Local route-table inspection.
- Path MTU investigation.

ICMP may be filtered, deprioritized, or rate-limited. Missing hop responses must not be presented as proof that a router is broken or traffic is blocked. Platform and privilege requirements must be explicit.
### 7.8 Region presets

`doctor` probes a fixed set of reference targets. Targets are defined in reviewed data files in the repository (`internal/regions/presets/*.toml`) and embedded in the binary.

- **`global` (default):** anycast public resolvers (for example 1.1.1.1, 8.8.8.8, 9.9.9.9) and a few large HTTPS endpoints that offer a lightweight check URL.
- **`ir`:** the global set plus domestic anchors (large, stable Iranian sites and domestic resolvers), so a report can state that domestic reachability works while international reachability fails.
- Presets are selected explicitly with `--region` or the config file. The tool never detects the user's country.
- Preset targets must be stable, neutral, and unrelated to circumvention services.
- Resolvers in a preset can be overridden as described in section 7.2.1.
- New regions are added through pull requests that document why each target was chosen.

---

## 8. Security and Internet-Interference Investigation

Security-oriented checks should be built on top of the same measurement engine.

### 8.1 Initial security areas

| Area | Indicators to investigate | Important caveat |
|---|---|---|
| DNS | Inconsistent answers, resolver changes, suspicious response patterns | Legitimate geographic and split-horizon differences exist |
| TLS | Unexpected handshake termination, certificate validation changes | Failures can be caused by configuration or compatibility |
| HTTP | Unexpected redirects, unusual status or response behavior | Applications and CDNs legitimately redirect or vary responses |
| Proxy | Unexpected or explicitly configured proxy behavior | Managed networks may intentionally enforce proxies |
| Routing | Route changes or reachability differences | Routing changes are common and not inherently malicious |
| Filtering | Repeated, destination-specific failures with comparative evidence | Local observations alone rarely establish attribution |

### 8.2 Evidence requirements

- Every security finding must reference one or more measurements.
- The report must distinguish direct observations from inferred patterns.
- Hypotheses should include supporting and contradicting evidence where available.
- Confidence should be qualitative initially (`low`, `medium`, `high`) and accompanied by an explanation.
- Avoid numerical confidence percentages until they can be calibrated against a meaningful validation dataset.
- The tool must state when there is insufficient evidence to reach a conclusion.

### 8.3 Interference investigation

The investigation workflow may compare:

- System resolver versus a user-selected resolver.
- IPv4 versus IPv6.
- Different destination endpoints when the user explicitly supplies them.
- Local behavior against an optional external measurement source.
- Results over time.

The tool should not automatically label an event as censorship, hijacking, surveillance, or attack based on a single timeout or mismatch.

### 8.4 Safe operation

- Test only the user-specified target or targets explicitly included in a profile.
- No broad port scanning in the default product.
- No exploit attempts, credential testing, or intrusive vulnerability scanning.
- Apply sensible concurrency, request-size, retry, and timeout limits.
- Make test destinations visible to the user.
- Do not bypass TLS validation silently.
- Do not change DNS, firewall, proxy, routing, or VPN configuration automatically.
### 8.5 Wording policy

Findings, rule identifiers, documentation, and the website use technical vocabulary only, for example `DNS_ANSWER_MISMATCH` or `TLS_RESET_AFTER_CLIENTHELLO`. Political terms are not used to label results, and the project does not ship circumvention features. This protects users who share reports and the maintainers who publish the tool, and it follows principle 4 (honest uncertainty).

---

## 9. Diagnostic Engine Design

The diagnostic engine is the intellectual core of the product and should be independently testable.

### 9.1 Separate measurements from interpretation

The architecture must distinguish:

1. **Measurement:** What did the tool observe?
2. **Finding:** What condition or anomaly was identified?
3. **Hypothesis:** What could explain the finding?
4. **Recommendation:** What should the user inspect or measure next?

For example:

- Measurement: DNS resolution succeeded; TCP connection succeeded; TLS handshake failed.
- Finding: TLS handshake failure occurred after TCP connection establishment.
- Hypotheses: TLS configuration incompatibility, proxy behavior, server-side failure, or network-level interference.
- Recommendation: Inspect the certificate and handshake error; repeat from a different network or compare with a known-good client if appropriate.

### 9.2 Orchestration and dependency graph

The orchestrator should understand dependencies between tests.

Example flow:

```text
Target validation
      |
      v
DNS resolution
      |
      +-- failure --> DNS findings and resolver investigation
      |
      v
Address selection
      |
      v
TCP connection
      |
      +-- failure --> transport/reachability findings
      |
      v
TLS handshake (HTTPS)
      |
      +-- failure --> TLS findings; HTTP request is skipped
      |
      v
HTTP request
      |
      v
Cross-measurement analysis
      |
      v
Findings, hypotheses, recommendations
```

The graph must support conditional tests, skipped tests, and independent tests. A skipped test must have an explicit reason, not appear as a successful test.

### 9.3 Rule engine

Start with deterministic, explicit rules rather than machine learning or an LLM.

Each rule should define:

- Stable rule identifier.
- Human-readable title and description.
- Required measurements.
- Detection conditions.
- Severity.
- Supporting evidence references.
- Known caveats and false-positive conditions.
- Suggested next test or action.
- Rule version.

Rule evaluation should be deterministic for the same normalized measurements and rule version.

### 9.4 Hypothesis ranking

The first version can rank hypotheses using transparent rule-based criteria. Do not present a ranking as calibrated probability.

For each hypothesis, store:

- Explanation.
- Supporting evidence.
- Contradicting evidence.
- Missing evidence.
- Qualitative confidence.
- Recommended next measurements.

### 9.5 No universal health score initially

Avoid a single overall score before v1.0. A single number can conceal a critical failure or imply more certainty than the evidence supports. Prefer clear per-layer status, severity, and explanation. A composite score may be considered later if its meaning can be defended and validated.

---

## 10. Core Domain Model and Data Contracts

Use a small set of versioned domain objects.

### 10.1 Core objects

| Object | Responsibility |
|---|---|
| `DiagnosticRun` | One complete diagnostic session, including target, profile, timing, and software version |
| `Measurement` | One test execution and its structured result |
| `Finding` | A detected condition or anomaly supported by measurements |
| `Hypothesis` | A possible explanation for one or more findings |
| `Recommendation` | A safe next step or additional measurement |

### 10.2 Required measurement metadata

A measurement should capture, where applicable:

- Stable measurement ID.
- Measurement type and implementation version.
- Start and end timestamps.
- Duration.
- Target host, URL, IP, and port as applicable.
- Address family.
- Resolver or network context when relevant.
- Status: success, failure, skipped, or inconclusive.
- Structured result fields.
- Structured error category and details.
- Test parameters and timeout.
- Data redaction metadata.

Avoid storing unnecessary personal or network-identifying information. Reports should support redaction of local addresses and sensitive environment information.

### 10.3 Example JSON report

Illustrative schema only; exact field names and types must be finalized before v0.1.

```json
{
  "schema_version": "1",
  "run": {
    "id": "run-001",
    "started_at": "2026-01-01T12:00:00Z",
    "target": "example.com",
    "profile": "standard",
    "tool_version": "0.1.0"
  },
  "measurements": [
    {
      "id": "m-001",
      "type": "dns",
      "status": "success",
      "duration_ms": 24,
      "result": {
        "a": ["203.0.113.10"],
        "aaaa": []
      }
    },
    {
      "id": "m-002",
      "type": "tcp",
      "status": "success",
      "duration_ms": 42,
      "result": {
        "address": "203.0.113.10:443"
      }
    },
    {
      "id": "m-003",
      "type": "tls",
      "status": "failure",
      "duration_ms": 120,
      "error": {
        "code": "handshake_failure",
        "message": "TLS handshake failed"
      }
    }
  ],
  "findings": [
    {
      "id": "f-001",
      "code": "TLS_HANDSHAKE_FAILURE",
      "severity": "warning",
      "measurement_ids": ["m-003"]
    }
  ]
}
```

The documentation must warn that example IP addresses and timestamps are illustrative.

### 10.4 Schema compatibility

- Include a `schema_version` in every exported report.
- Keep JSON field semantics stable within a major schema version.
- Add fields compatibly where possible.
- Document breaking changes.
- Keep machine-readable output independent from terminal presentation.

---

## 11. Technical Architecture

### 11.1 Technology choices

| Area | Choice | Notes |
|---|---|---|
| Language | Go | Current stable release; `go.mod` targets the oldest supported Go release |
| CLI framework | Cobra | Nested commands, flags, help, completion |
| Terminal styling | Plain ANSI escape codes | Color on by default when stdout is a terminal; off with `--no-color`, `NO_COLOR`, or non-terminal output |
| Networking | Go standard library first | Prefer standard library unless a specialized capability is needed |
| DNS library | `miekg/dns` | Needed to distinguish NXDOMAIN, REFUSED, and SERVFAIL and to query chosen resolvers directly |
| Logging | `log/slog` | Structured logs to stderr |
| Configuration | TOML | Small, documented key set |
| Local history | JSONL | Consider SQLite only when querying/filtering history needs it |
| Testing | Go testing | Unit, fixture-based integration, platform, and fuzz tests |
| Release automation | GoReleaser | Builds, archives, checksums, cosign keyless signatures |
| CI | GitHub Actions | Ubuntu, macOS, and Windows runners |
| Website | Hugo on GitHub Pages | English only, custom domain `nwrk.ir` |
| TUI | Bubble Tea, after v1.0 | Only after core commands and output contracts stabilize |

Do not add dependencies solely for convenience. Pin and review dependencies, track licenses, and prefer maintained projects.

### 11.2 High-level architecture

```text
+------------------------------------------------------+
|                    CLI Interface                     |
|            Cobra commands / flags / output           |
+----------------------------+-------------------------+
                             |
+----------------------------v-------------------------+
|                Application Orchestration              |
|          doctor / diagnose / test / watch             |
+----------------------------+-------------------------+
                             |
+----------------------------v-------------------------+
|                  Diagnostic Domain                    |
|     run / measurement / finding / hypothesis          |
+---------------+----------------------+---------------+
                |                      |
+---------------v----------+  +--------v---------------+
|    Measurement Engine    |  |     Platform Adapters  |
| DNS / TCP / TLS / HTTP   |  | interfaces / routes   |
| ICMP / routing (later)   |  | DNS config / proxies  |
+---------------+----------+  +------------------------+
                |
+---------------v--------------------------------------+
|               Diagnostic / Rule Engine                |
|       correlation / findings / hypotheses             |
+----------------------------+-------------------------+
                             |
+----------------------------v-------------------------+
|               Persistence and Reporting              |
|                JSONL / JSON / Markdown                |
+------------------------------------------------------+
```

### 11.3 Repository structure

```text
nwrk/
├── cmd/
│   └── nw/
│       └── main.go
├── internal/
│   ├── cli/              # Cobra commands and flag wiring only
│   ├── output/           # human and JSON renderers, color handling
│   ├── app/
│   │   ├── doctor/
│   │   ├── diagnose/
│   │   ├── test/
│   │   └── watch/
│   ├── domain/           # run, measurement, finding, hypothesis, recommendation
│   ├── target/           # host, URL and resolver parsing and validation
│   ├── fixtures/         # local DNS, TCP, TLS and HTTP servers for tests
│   ├── measurement/
│   │   ├── dns/
│   │   ├── tcp/
│   │   ├── tls/
│   │   ├── http/
│   │   └── path/
│   ├── platform/
│   │   ├── linux/
│   │   ├── darwin/
│   │   └── windows/
│   ├── diagnostics/
│   │   ├── engine/
│   │   └── rules/
│   ├── regions/
│   │   └── presets/      # global.toml, ir.toml (embedded)
│   ├── reporting/
│   ├── history/
│   └── config/
├── docs/                 # English reference docs
├── site/                 # Hugo site for nwrk.ir
│   └── static/
│       ├── CNAME
│       ├── install.sh
│       └── install.ps1
├── schema/               # JSON Schema of the report, published at /schema/
├── .github/
│   ├── workflows/        # ci.yml, release.yml, site.yml
│   └── ISSUE_TEMPLATE/
├── go.mod
├── go.sum
├── Makefile
├── .goreleaser.yaml
├── LICENSE               # MIT
├── README.md
├── CONTRIBUTING.md
├── SECURITY.md
└── PRINCIPLES.md
```

Create packages only when their responsibilities and dependencies are clear, not up front. Keep the domain independent of terminal formatting and OS-specific implementation details.

### 11.4 Dependency direction

- CLI depends on application services.
- Application services depend on domain interfaces and measurement interfaces.
- Measurement implementations return structured domain results.
- Diagnostic rules consume normalized measurements.
- Reporting serializes domain objects and must not perform measurements.
- Platform-specific packages implement narrow interfaces and should not leak OS-specific types into the domain.
- Domain packages must not import Cobra, terminal rendering libraries, or platform implementations.

### 11.5 Concurrency and cancellation

- Use `context.Context` for cancellation and deadlines.
- Run independent measurements concurrently only when their dependencies permit it.
- Define a maximum concurrency for each profile.
- Cancel dependent tests when prerequisites fail, unless a test is explicitly marked independent.
- Ensure command cancellation stops outstanding work and closes network resources.
- Avoid goroutine leaks and unbounded result channels.

---

## 12. Local Storage and Configuration

### 12.1 History storage (P5)

Use local JSONL files for measurement history initially.

Benefits:

- No database server.
- Easy inspection and backup.
- Simple export and migration.
- Low implementation overhead.

Locations, resolved with platform-aware directory lookup rather than hard-coded:

- Linux: `$XDG_STATE_HOME/nwrk/` or `~/.local/state/nwrk/` for history; `$XDG_CONFIG_HOME/nwrk/config.toml` for configuration.
- macOS: `~/Library/Application Support/nwrk/`.
- Windows: `%LOCALAPPDATA%\nwrk\`.

### 12.2 When to consider SQLite

Move to SQLite only when real usage requires efficient filtering, indexing, retention management, or larger local histories. The storage interface should make this migration possible without coupling the diagnostic engine to the storage implementation.

### 12.3 Configuration

The config file is TOML and arrives in P3. `nw config path` prints its location and `nw config show` prints the effective configuration together with the source of each value.

Initial keys (P3):

```toml
region = "ir"
resolvers = ["1.1.1.1", "tls://9.9.9.9"]
timeout = "5s"
color = "auto"   # auto | always | never
```

Keys added in P5: default profile, history retention, redaction preferences.

Precedence for every setting: command-line flag, then `NW_*` environment variable, then config file, then built-in default (or region preset, for resolvers).

Do not store passwords, tokens, or credentials in the config file.

---

## 13. Reporting and Exit Codes

### 13.1 Human-readable reports

A report should include:

1. Summary of the target and profile.
2. Overall diagnostic status without a misleading composite score.
3. Measurement-by-measurement results.
4. Findings with severity.
5. Supporting evidence.
6. Hypotheses and their uncertainty.
7. Recommended next steps.
8. Environment and version details relevant to reproducibility.
9. Privacy/redaction notes.

### 13.2 Export formats

- P1-P2: human-readable terminal output and JSON (`--output json`).
- P5: export of stored runs as JSON or Markdown, and redacted reports suitable for issue trackers or support requests.

### 13.3 Exit codes and output conventions

Exit codes follow the conventions of `ping`, `grep`, and `curl`:

| Code | Meaning |
|---:|---|
| `0` | Command completed and no actionable finding was detected |
| `1` | Command completed and the target has a problem (one or more actionable findings) |
| `2` | Usage error (invalid flag, target, or configuration) or the tool could not run the measurement |
| `130` | Interrupted by the user (SIGINT) |

A network failure of the target is a diagnostic result (`1`), not a tool error (`2`). The difference between a usage error and an execution error stays visible in stderr and in the JSON `error` object.

Output conventions:

- Results go to stdout; logs, progress, and errors go to stderr.
- JSON timestamps are RFC 3339 (ISO 8601) in UTC.
- Durations in JSON are integer milliseconds (`duration_ms`).
- Color follows the `NO_COLOR` convention and is never the only carrier of meaning.

---

## 14. First Public Release: v0.1.0

### 14.1 Objective

Prove that one command can coordinate useful network measurements, preserve structured evidence, and produce a defensible diagnosis.

### 14.2 Scope

v0.1.0 is the end of phase P2 in the roadmap. It deliberately ships one complete vertical slice.

| Feature | Requirement |
|---|---|
| Cross-platform executable | Linux, macOS, Windows on amd64 and arm64 |
| Install | `install.sh`, `install.ps1`, `go install`, manual download; checksums and cosign signatures |
| `nw diagnose <target>` | Standard destination investigation with dependency-aware orchestration |
| `nw test dns\|tcp\|tls\|http` | Independently runnable measurements |
| DNS | A/AAAA, timings, response codes, structured errors, `--resolver` |
| TCP | Host/port connectivity and structured error classification |
| TLS | Handshake, certificate validation, negotiated protocol details |
| HTTP | Bounded request, status, redirects, selected headers, timings |
| Diagnostic engine | First eight deterministic rules (see ROADMAP P2) |
| Findings, hypotheses, recommendations | Evidence references and qualitative confidence |
| JSON output | Versioned schema v1 |
| Exit codes | Section 13.3 |
| `nw version`, `nw completion` | Bash, Zsh, Fish, PowerShell |
| Website | nwrk.ir in English with install, quick start, and command reference |
| Project docs | README, CONTRIBUTING, SECURITY, PRINCIPLES, issue templates |

### 14.3 Deferred beyond v0.1.0

`doctor`, local network inspection, region presets, and the config file (P3); interference rules, encrypted DNS, path tracing, and MTU (P4); history, report export, and redaction (P5); package managers (P6); `watch` (P7); TUI and external measurement networks (after v1.0).

### 14.4 Acceptance criteria

- A user can install and run `nw` on every supported OS without a Go toolchain.
- `nw diagnose <target>` runs the standard measurement sequence and handles failures at each stage.
- Tests that cannot run are marked skipped or inconclusive with an explicit reason.
- Every finding references one or more measurements.
- The tool distinguishes an observation from a hypothesis.
- JSON output conforms to the documented schema.
- Exit codes follow section 13.3.
- Default operations do not upload measurements or change system configuration.
- All network operations have deadlines and resource limits.
- Unit and fixture-based integration tests cover success and failure paths.
- CI passes on Linux, macOS, and Windows.
- Documentation explains platform limitations and the meaning of findings in English.

---

## 15. Development Roadmap

The phase-by-phase plan, with scope and exit criteria, lives in [ROADMAP.md](ROADMAP.md). Versions describe capability milestones, not delivery dates.

| Phase | Release | Theme |
|---|---|---|
| P0 | v0.0.1 | Foundation: CLI skeleton, CI, releases, install scripts, website |
| P1 | v0.0.2 | Measurements: DNS, TCP, TLS, HTTP test commands and schema v1 |
| P2 | v0.1.0 | Diagnose: orchestration and first rules (first announced release) |
| P3 | v0.2.0 | Local and regional: `doctor`, network inspection, region presets, config file |
| P4 | v0.3.0 | Interference investigation, encrypted DNS, path diagnostics |
| P5 | v0.4.0 | History, report export, redaction |
| P6 | v0.5.0 | Package managers |
| P7 | v0.6.0 | Local observability (`watch`) |
| P8 | v1.0.0 | Stable contracts |

External measurement networks (Globalping, RIPE Atlas) and a TUI are deferred until after v1.0.

---

## 16. Testing and Quality Strategy

### 16.1 Unit tests

Test independently:

- Target parsing and validation.
- Error normalization.
- Measurement result models.
- Rule conditions.
- Hypothesis ranking.
- Report serialization.
- Exit-code mapping.
- Redaction behavior.

### 16.2 Integration tests

Use controlled local test servers and DNS fixtures to exercise:

- Successful DNS, TCP, TLS, and HTTP paths.
- NXDOMAIN and empty DNS answers.
- DNS timeouts and refused connections.
- TCP refusal and timeout.
- Invalid and expired certificates.
- TLS handshake errors.
- HTTP redirects, errors, and timeouts.
- Cancellation and deadline expiration.
- Partial diagnostic runs.

Do not make the test suite depend exclusively on public internet endpoints. Public endpoints can be used for optional smoke tests, not deterministic core tests.

### 16.3 Cross-platform tests

Validate behavior on Windows, macOS, and Linux. Platform adapters must have tests or fixtures for OS-specific output parsing and failure handling. Prefer native Go APIs over parsing human-readable command output whenever possible.

### 16.4 Fuzzing and robustness

Fuzz parsers and input boundaries, especially:

- Hostnames and URLs.
- IP/port parsing.
- DNS response parsing.
- Certificate metadata handling.
- Configuration loading.
- JSON report decoding where supported.

### 16.5 Performance and resource testing

Validate:

- Maximum concurrent measurements.
- Timeout behavior.
- Memory use under repeated runs.
- Graceful cancellation.
- No leaked goroutines or sockets.
- Bounded report and history growth.

---

## 17. Security, Privacy, and Trust

### 17.1 Data minimization

- Do not capture packet payloads.
- Do not store HTTP response bodies by default.
- Do not persist credentials, cookies, authorization headers, or private keys.
- Avoid collecting unnecessary machine identifiers.
- Provide redaction for local IP addresses, hostnames, and environment details in exported reports.

### 17.2 Network safety

- Respect explicit targets and ports.
- Use timeouts and rate limits.
- Bound redirects and response sizes.
- Do not recursively discover targets.
- Do not run exploit or credential tests.
- Do not modify host network settings.
- Clearly identify any third-party service contacted by an optional integration.

### 17.3 Security reporting

Security reports must explain limitations. A result can be `inconclusive`; this is preferable to a confident but unsupported conclusion.

### 17.4 Supply-chain security

- Pin dependencies through Go modules.
- Review dependency maintenance and licenses.
- Run dependency vulnerability checks in CI.
- Produce SHA-256 checksums and cosign keyless signatures (GitHub Actions OIDC) for every release.
- Consider SBOM generation as distribution matures.
- Publish a `SECURITY.md` with a responsible disclosure process.

---

## 18. Distribution, Website, and Documentation

### 18.1 Hosting

Everything is hosted on GitHub; the project runs no servers.

- Source, issues, and releases: GitHub.
- Binaries: GitHub Releases, built by GoReleaser.
- Website: GitHub Pages with the custom domain `nwrk.ir`, built from `site/` by a GitHub Actions workflow on every push to `main`.

GitHub downloads can be slow or unreliable from some networks, including in Iran. There is no binary mirror; the install scripts retry and, on failure, print the direct Release URL for manual download.

### 18.2 Installation

From P0:

```bash
curl -fsSL https://nwrk.ir/install.sh | sh
```

```powershell
irm https://nwrk.ir/install.ps1 | iex
```

```bash
go install github.com/hesamzakerirad/nwrk/cmd/nw@latest
```

The install scripts detect OS and architecture, download the archive from GitHub Releases, verify it against `checksums.txt`, and install `nw` into a user-writable directory without requiring root. Users who have cosign can also verify the signature; the docs show how.

From P6: Homebrew tap, Scoop bucket, WinGet, and AUR.

### 18.3 Release automation

GoReleaser builds six binaries (Linux, macOS, and Windows on amd64 and arm64), archives, `checksums.txt`, and cosign keyless signatures. A release is triggered by pushing a `v*` tag and runs only after CI passes.

### 18.4 Documentation and languages

- CLI output is English only.
- The website and documentation are English only.
- English docs in `docs/` are the source of truth.

Required documentation:

- `README.md`: overview, installation, first commands.
- `docs/commands.md`: complete command reference.
- `docs/diagnostics.md`: how diagnostic workflows operate.
- `docs/measurements.md`: details and limitations of each measurement.
- `docs/findings.md`: findings, confidence, caveats, and false positives.
- `docs/report-schema.md`: versioned JSON schema.
- `docs/privacy.md`: collection, storage, redaction, and external connections.
- `docs/platform-support.md`: OS differences and privileges.
- `docs/regions.md`: region presets and how to propose one.
- `CONTRIBUTING.md`, `SECURITY.md`, `PRINCIPLES.md`.

---

## 19. Ecosystem Strategy

The project learns from existing measurement ecosystems rather than rebuilding their infrastructure.

| Project | Strength | Relationship |
|---|---|---|
| OONI Probe | Internet interference measurements | Learn from measurement design; do not duplicate |
| Native tools (`dig`, `curl`, `traceroute`, `openssl`) | Mature protocol-specific diagnostics | Reference for expected behavior; do not merely wrap them |
| Globalping, RIPE Atlas | Distributed vantage points | Deferred until after v1.0: the APIs may be unreachable for the main audience and add API keys and data-sharing obligations |

The differentiator remains local evidence correlation and practical diagnosis.

---

## 20. Risks and Mitigations

| Risk | Why it matters | Mitigation |
|---|---|---|
| Overly broad scope | The project could become an unfinished collection of features | Protect each phase boundary and ship one complete diagnostic workflow |
| False security conclusions | Users may mistake an anomaly for proof of attack or censorship | Evidence references, caveats, inconclusive outcomes, rule validation |
| Cross-platform differences | Network APIs and privileges vary by operating system | Platform adapters, platform test matrix, transparent limitations |
| Unstable JSON contracts | Scripts may break between releases | Versioned schema and compatibility tests |
| Excessive dependencies | More maintenance and supply-chain risk | Prefer standard library and review each dependency |
| Performance and resource exhaustion | Diagnostics could hang or consume excessive resources | Context deadlines, bounded concurrency, request limits |
| Privacy leakage | Reports may reveal local addresses, destinations, or infrastructure | Local-first defaults, redaction, no automatic uploads |
| Reinventing existing platforms | Time spent duplicating mature measurement networks | Integrate external networks later; focus on local diagnosis and reasoning |
| Premature abstraction | Plugin systems and generic frameworks add complexity | Build only the abstractions needed by actual use cases |
| Maintainer and user safety | Results labeled with political terms could put maintainers or users at risk | Technical wording policy (section 8.5); no circumvention features |
| Unreliable GitHub access | Users may fail to download releases | Retrying install scripts, `go install`, manual download instructions in English |
| Single maintainer | Limited capacity | Small scope per phase; pull requests accepted from v0.1.0 |

---

## 21. Project Identity

| Item | Value |
|---|---|
| Product name | nwrk |
| Executable | `nw` |
| Website | https://nwrk.ir |
| Repository | https://github.com/hesamzakerirad/nwrk |
| Go module | `github.com/hesamzakerirad/nwrk` |
| State and config directory name | `nwrk` |
| License | MIT; inbound = outbound, no CLA |
| Maintainer | Single maintainer; pull requests accepted from v0.1.0 |

NW.js also installs a binary named `nw` through npm. The conflict is rare; the installation docs mention it.

---

## 22. Implementation Sequence

Implementation follows the phases in [ROADMAP.md](ROADMAP.md), starting with P0. Each phase is a vertical slice that ends in a tagged, installable release.

---

## 23. Definition of a Successful First Release

The first public release is successful when a developer or support engineer can run:

```bash
nw diagnose api.example.com
```

and receive:

- A reproducible set of DNS, TCP, TLS, and HTTP measurements.
- Clear identification of which stages succeeded, failed, or were skipped.
- Structured errors rather than opaque strings alone.
- Findings linked to supporting measurements.
- Explanations that distinguish observations from hypotheses.
- Safe, useful next investigative steps.
- A JSON report that scripts can consume.
- Local history that works without an account or hosted service.

The project should be judged first by the correctness and usefulness of this workflow, not by the number of commands, integrations, or protocols it supports.

---

## 24. Reference Projects and Technical Documentation

These resources are useful references, not mandatory dependencies or endorsements. Confirm current maintenance status and compatibility before adopting any library or integration.

### Go and CLI engineering

- [Go documentation](https://go.dev/doc/)
- [Go `net` package](https://pkg.go.dev/net)
- [Go `context` package](https://pkg.go.dev/context)
- [Go `log/slog` package](https://pkg.go.dev/log/slog)
- [Cobra CLI](https://github.com/spf13/cobra)
- [Lip Gloss](https://github.com/charmbracelet/lipgloss)
- [Bubble Tea](https://github.com/charmbracelet/bubbletea)
- [GoReleaser](https://goreleaser.com/)

### DNS and network measurements

- [miekg/dns](https://codeberg.org/miekg/dns)
- [OONI Probe Engine documentation](https://docs.ooni.org/probe-engine/)
- [Globalping documentation](https://globalping.io/docs) (after v1.0)
- [RIPE Atlas API documentation](https://atlas.ripe.net/docs/apis/rest-api-manual/introduction) (after v1.0)

### Release engineering and website

- [GoReleaser documentation](https://goreleaser.com/)
- [Sigstore cosign](https://docs.sigstore.dev/)
- [Hugo multilingual mode](https://gohugo.io/content-management/multilingual/)
- [GitHub Pages custom domains](https://docs.github.com/en/pages/configuring-a-custom-domain-for-your-github-pages-site)
- [NO_COLOR](https://no-color.org/)

---

## 25. Decisions Recorded

| Decision | Status |
|---|---|
| Product name | nwrk |
| Executable name | `nw` |
| Website | nwrk.ir on GitHub Pages, English |
| Repository | github.com/hesamzakerirad/nwrk |
| License | MIT, no CLA |
| Hosting | GitHub only (Pages, Releases, Actions); no servers, no binary mirror |
| Product direction | Diagnostics + interference investigation + observability |
| Primary focus | Connectivity under DNS tampering, filtering, and unstable international links |
| Wording | Technical vocabulary only; no circumvention features |
| Primary interface | CLI |
| Implementation language | Go |
| Architecture | Single modular Go application; no microservices |
| Execution model | Local-first; standalone executable |
| DNS library | miekg/dns |
| Terminal styling | Plain ANSI color, on by default for terminals; `--no-color` and `NO_COLOR` |
| CLI output language | English only |
| Documentation | Full English docs |
| Exit codes | 0 no findings, 1 findings, 2 usage or tool error, 130 interrupted |
| Resolvers | Repeatable `--resolver`; precedence flag > `NW_RESOLVERS` > config > preset; system resolver always measured |
| Region model | Explicit presets (`global` default, `ir`); no geolocation |
| Configuration | TOML, from P3 |
| Install | `install.sh`, `install.ps1`, `go install`, manual; package managers in P6 |
| Build targets | Linux, macOS, Windows on amd64 and arm64 |
| Release integrity | SHA-256 checksums and cosign keyless signatures |
| Release cadence | Every phase ends in a tagged release |
| First announced release | v0.1.0 (end of P2): `diagnose` and `test` commands |
| Default privacy model | No automatic measurement uploads |
| Storage | Local JSONL history, from P5 |
| External measurement networks | After v1.0 |
| Web, desktop, mobile apps, browser extension | Not planned |
| Contributions | Pull requests accepted from v0.1.0 |
