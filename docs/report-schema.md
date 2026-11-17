---
title: Report schema
description: The versioned JSON document printed by nw test --output json.
weight: 5
---

`nw test ... --output json` prints one JSON document on standard output. It is meant for scripts and for other tools, and it does not depend on how the terminal output looks.

The machine-readable definition is a JSON Schema: [report.v1.json](/schema/report.v1.json). Every document contains `"schema_version": "1"`.

## Compatibility promise

Within schema version 1, fields are never renamed, removed or given a different meaning. New fields can appear, so readers must ignore fields they do not know. A breaking change means a new `schema_version`, and is documented here.

## Shape

```json
{
  "schema_version": "1",
  "run": {
    "id": "run-1a2b3c4d5e6f",
    "started_at": "2026-01-01T12:00:00Z",
    "ended_at": "2026-01-01T12:00:01Z",
    "command": "test tcp",
    "target": "example.com:443",
    "tool_version": "0.0.2",
    "platform": { "os": "linux", "arch": "amd64" }
  },
  "measurements": [
    {
      "id": "m-001",
      "type": "dns",
      "version": "1",
      "status": "success",
      "started_at": "2026-01-01T12:00:00Z",
      "ended_at": "2026-01-01T12:00:00.024Z",
      "duration_ms": 24.1,
      "target": { "host": "example.com" },
      "resolver": { "kind": "system", "servers": ["192.0.2.53:53"] },
      "result": { "a": ["203.0.113.10"], "aaaa": [], "queries": [] }
    },
    {
      "id": "m-002",
      "type": "tcp",
      "version": "1",
      "status": "failure",
      "started_at": "2026-01-01T12:00:00.025Z",
      "ended_at": "2026-01-01T12:00:10.025Z",
      "duration_ms": 10000,
      "target": { "host": "example.com", "ip": "203.0.113.10", "port": 443, "family": "ipv4" },
      "error": { "code": "tcp.timeout", "message": "no answer from 203.0.113.10:443 before the deadline" }
    }
  ],
  "findings": [],
  "hypotheses": [],
  "recommendations": []
}
```

The addresses and times above are illustrative examples, not real measurements.

## Fields

**Report**: `schema_version`, `run`, and the lists `measurements`, `findings`, `hypotheses`, `recommendations`. The lists are always present and are arrays, never `null`. `nw test` leaves `findings`, `hypotheses` and `recommendations` empty; `nw diagnose` fills them, and adds `summary`.

**run**: `id`, `started_at`, `ended_at`, `command`, `target`, `tool_version`, `platform`, and `profile` when a profile was used.

**measurement**:

| Field | Meaning |
|---|---|
| `id` | `m-001`, `m-002`, ... in report order, stable within one report |
| `type` | `dns`, `tcp`, `tls`, `http`, or `local` (an inspection of this machine, from `nw doctor`) |
| `scope` | `local`, `domestic` or `international`, set by `nw doctor` |
| `version` | Version of the measurement implementation |
| `status` | `success`, `failure`, `skipped` or `inconclusive` |
| `started_at`, `ended_at`, `duration_ms` | When it ran and how long it took |
| `target` | Any of `host`, `url`, `ip`, `port`, `family` (`ipv4` or `ipv6`) |
| `resolver` | For DNS: `kind` (`system`, `udp` or `tcp`), `address`, and for the system resolver `servers` |
| `params` | The parameters of the test, such as `method` or `max_redirects` |
| `result` | Present on success, and on failures that left partial evidence. Its fields depend on `type`; see the schema |
| `error` | Present on failure: `code` (stable, see [Measurements](../measurements/)) and `message` (for people, may change) |
| `note` | Present on `skipped`: why it did not run |
| `redacted` | What was deliberately not collected, for example `response.set-cookie` |

Use `error.code` in scripts, never `error.message`.

**finding**: `id` (`f-001`, ordered by severity), `code` (the rule ID, stable), `rule_version`, `title`, `layer`, `severity` (`info`, `warning` or `error`), `summary`, `measurement_ids` (at least one; the evidence), and `caveats` (the known ways the rule can be wrong). `warning` and `error` are actionable and make `nw diagnose` exit `1`. See [Findings](../findings/).

**hypothesis**: `id`, `summary`, `finding_ids`, `confidence` (`low`, `medium` or `high`, a ranking and not a probability), and the lists `supporting`, `contradicting` and `missing`, each of `{text, measurement_ids}`, plus `next_measurements`. Hypotheses are ordered by confidence. A hypothesis is a possible explanation, never a verdict.

**recommendation**: `id`, `summary`, optional `command` (a `nw` command to run, where `<ip>` and `<url>` are placeholders), and `finding_ids`.

**summary** (`nw diagnose` only): `outcome` (`ok` or `problem`) and `layers`, a list of `{layer, status}` for `dns`, `tcp`, `tls` and `http`, with status `success`, `failure`, `partial`, `skipped` or `not_run`. There is deliberately no overall score.

**Probes.** Measurements made as evidence for the interference rules have `params.probe` (see [Measurements](../measurements/)). Their `result` follows the shape of their type, except two DNS probes that have their own shapes (`responses` for `multiple_responses`, and `signed`, `authenticated`, `cnames` for `dnssec`). The layer summary leaves probes out.

**run.command** is `test dns` and its siblings, `diagnose`, `doctor`, `security inspect` or `security interference`.

**resolver.kind** is `system`, `udp`, `tcp`, `tls` or `https`.

**run.profile** is `quick`, `standard` or `deep` for `nw diagnose`. **run.region** is the region preset for `nw doctor`.

**summary for `nw doctor`** also has `scopes`, a list of `{scope, status}` (`local` is `ok` or `problem`; the others are `reachable`, `partial`, `unreachable` or `not_checked`), and `verdict`: `healthy`, `local`, `domestic`, `international`, `upstream` or `partial`. See [Regions and presets](../regions/).

## Other documents

`nw network`, `nw config path`, `nw config show` and `nw path ping`, `trace` and `mtu` print their own small JSON documents with `--output json`. Each has a `schema_version` and follows the same compatibility promise; their fields are the ones shown in the human output.

## Exit status

The JSON document does not replace the exit status. For `nw test`: `0` all measurements succeeded, `1` at least one failed. For `nw diagnose`: `0` no actionable finding, `1` at least one. In both: `2` usage error, `130` interrupted. Errors that stop nw before any measurement, such as a bad flag, print `{"schema_version": "1", "error": {"kind", "message"}}` on standard error instead.
