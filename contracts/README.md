# Community Contribution Contract

This directory defines what `nw community contribute` sends, what the NWRK Status server accepts, and how the server turns results into public statistics. It is the single source of truth. The `nw` client embeds these files. The server copies them from a release tag and must pass the same fixtures.

Contract version: draft for `contracts-v1`. It is not tagged yet.

## Contents

| Path | Purpose |
|---|---|
| `schemas/community-contribution.v1.schema.json` | The sanitized document that the client uploads |
| `schemas/community-profile.v1.schema.json` | The format of a measurement profile |
| `schemas/community-api.v1.schema.json` | Challenge, submission and response messages |
| `schemas/community-public.v1.schema.json` | Messages of the public statistics endpoints |
| `aggregation/spec.md` | How rollups, windows, percentiles, the publication threshold and the states are computed |
| `aggregation/fixtures/` | Golden fixtures: rows in, expected rollups and window results out |
| `aggregation/aggregation.go` | Go reference implementation of the specification |
| `profiles/*.json` | Approved, immutable profiles: `ir-core-v1`, `ir-dev-v1` |
| `profiles/CHECKSUMS` | SHA-256 of each profile file |
| `openapi.yaml` | The contribution endpoints and the public read endpoints. It points to the schemas. |
| `fixtures/` | Valid and invalid documents and messages, with a manifest |
| `catalog-decisions.md` | Why each endpoint is in a profile |
| `contracts.go`, `pow.go` | Go validator and proof of work, used by the client and by tests |

## The Contribution Document

The document holds only these things:

* The client name and version.
* The profile ID and version.
* For each approved target ID: the layer (`dns`, `tcp`, `tls`, `http`), the address family, a normalized outcome, a duration in milliseconds, and for some layers a status code, a DNS response code, an answer count or a normalized error code.

It never holds addresses, hostnames, URLs, headers, certificates, cookies, resolver addresses or identifiers. Every object in the schema rejects unknown fields, so a new field cannot leak by accident. A test checks this.

Rules that the schema applies:

* A `failure` has an `error`. A `success` or a `response_received` has none.
* A DNS `success` has `answer_count`. Only DNS has `dns_rcode` and `answer_count`.
* An HTTP `response_received` has `status_code`. An HTTP failure has none. A status such as 403 or 451 is a response, not a failure.
* An error code starts with its layer: `dns.`, `tcp.`, `tls.` or `http.`. A TLS failure can also have a `tcp.` code, because the TCP connection can fail before TLS starts. No `local.` code is allowed.
* `dns_rcode` is optional. The operating system resolver does not report it.

Rules that need the profile (checked by `ValidateContribution` after the schema):

* The profile ID and version must be approved.
* Every target must be in that profile, once.
* A layer and family pair appears once for each target.
* A family must be one that the endpoint serves. A layer must be one that the endpoint uses.

A family appears in a document only if the host had a route for it. A missing measurement is not a failed one.

The body of a request must not exceed 65536 bytes. The largest valid fixture is about 11 KB.

## Profiles

A profile lists services and endpoints and the limits of one run. A published profile never changes. `contracts.Profiles()` checks each file against `profiles/CHECKSUMS` and fails if a byte changed. To change an endpoint:

1. Copy the profile to a new version. For example, set `"version": 2` in a new file `ir-dev-v1.v2.json`. Keep the profile ID.
2. Record the reason in `catalog-decisions.md`.
3. Add the new file to `profiles/CHECKSUMS` with `cd profiles && shasum -a 256 *.json > CHECKSUMS`.

The old version stays, because old clients still send it.

A `target_id` names one fixed endpoint in every profile. If an endpoint changes (hostname, path, method, families), use a new `target_id` for it. Stored results refer to the target ID. `contracts.Profiles()` and the server catalogue sync both refuse a changed endpoint with an old target ID.

## Challenge and Proof of Work

1. The client sends `POST /api/v1/contributions/challenge` with its version and the profile it wants.
2. The server answers with `challenge_id`, a one-time `token`, an expiry (five minutes) and the proof of work parameters.
3. The client finds a decimal `nonce` so that the SHA-256 hash of the ASCII text `<challenge_id>:<token>:<nonce>` has at least `difficulty_bits` leading zero bits. The nonce is a canonical decimal number: `0`, or digits with no leading zero.
4. The client sends `POST /api/v1/contributions` with `{ "challenge": { "id", "token", "pow_nonce" }, "contribution": { ... } }`.

The `contribution` value is the same document that `--dry-run` shows. A challenge works once. It stops simple replay and cheap floods. It does not prove that a measurement is real.

`fixtures/api/pow-vectors.json` has test vectors. Every implementation must produce the same bit counts and the same smallest nonce.

## Responses

* `202` with `status: accepted`: stored for aggregation. The answer has the submission ID and may include the observed country and network.
* `200` with `status: excluded`: the document is valid but outside the Iranian statistics. Nothing is stored.
* An error has `{ "error": { "code", "message", "details"? } }`. Error codes are in `community-api.v1.schema.json`. `ValidateContribution` returns the same codes that the server must return.

## Fixtures

`fixtures/manifest.json` lists every contribution fixture. For an invalid one it gives the stage (`schema` or `semantic`) and the API error code that must reject it. A test fails if a fixture file is not in the manifest. The server test suite must read the same manifest and give the same results.

A body that is too large is not a fixture file. Tests build it. The expected result is `payload_too_large`.

## Tests

```sh
make docker-test                       # all tests, in Docker
docker run --rm -v "$PWD":/src -w /src golang:1.26 go test ./contracts/
```

The tests check that the profiles match their checksums, that every schema object is closed, that no property name looks like forbidden data, that the error codes match the engine, that every fixture behaves as declared and that the proof of work vectors hold.

## Changing the Contract

* A new field, a new enum value or a new rule needs a new schema version, for example `community-contribution.v2`.
* Add a fixture for every new rule, and add it to the manifest.
* The server and the client pin a release tag of this directory.

## Aggregation

`aggregation/spec.md` is the public definition of every published number. The reference implementation in `aggregation/` and the server must give exactly the expected output for every file in `aggregation/fixtures/`. The fixtures were made with a second, independent implementation, so an error in one implementation shows up as a difference. A test also checks that every expected window result is valid against `schemas/community-public.v1.schema.json`.

The rules, in short: the server rounds each submission to an hour. It builds hourly rollups from the measurements, and every window is a sum of whole hourly rollups. A series (a service and a network) with fewer than 20 submissions in the window is published as `insufficient_data`, without rates or latencies. Latency percentiles come from a 16-bucket histogram of successful measurements, so they are approximate. The states say what the measurements show. They never claim a cause, and they never use the word censorship.
