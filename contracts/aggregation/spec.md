# Aggregation Specification, Version 1

This document says how NWRK Status turns stored measurement results into the numbers that it publishes. Anyone can read it and check the published numbers against it. The Go package in this directory is the reference implementation. The server must give the same output as the reference for every fixture in `fixtures/`.

Status: draft for the closed pilot. The constants in section 9 can change before the first public release. A change of any rule or constant after release needs a new version of this document and new fixtures.

## 1. Definitions

* A **measurement** is one result of one layer (`dns`, `tcp`, `tls` or `http`) for one address family (`ipv4` or `ipv6`) for one target. It comes from the contribution contract.
* A **submission** is one accepted contribution. A submission is not a person. One person can send many submissions. Never call a submission count a participant count.
* A **target** is one fixed endpoint, named by its `target_id`. In version 1 of the profiles, each service has exactly one target, so a service and its target have the same published identity.
* The **hour** of a measurement is the receipt time of its submission, in UTC, rounded down to the hour. The server stores the receipt time already rounded (see the threat model). All times in this document are UTC.
* The **ASN** of a measurement is the observed network of the submission. A submission with no known ASN has the ASN `0`. The ASN `0` is never published as a network. It counts in the country-wide numbers.
* A measurement is a **success** when it is `success` (layers `dns`, `tcp` and `tls`) or `response_received` (layer `http`). Any HTTP status code counts as a response. A measurement with the outcome `failure` is a **failure**.
* An **attempt** is a measurement, so `attempts = successes + failures`.

A layer after a failed layer does not run in the client. For this reason the HTTP attempts are fewer than the DNS attempts. Do not compare the attempts of two layers as if they were the same population.

## 2. Input Rows

The input of every computation is a list of rows. A row has these fields. The server reads them from its tables, and the fixtures write them in JSON.

| Field | Type | Meaning |
|---|---|---|
| `submission` | string | Identifier of the submission. Only used to count distinct submissions. |
| `hour` | string | The hour bucket, as `YYYY-MM-DDTHH:00:00Z`. |
| `target` | string | The `target_id`. |
| `asn` | integer or null | The observed ASN. `null` means unknown. |
| `layer` | string | `dns`, `tcp`, `tls` or `http`. |
| `family` | string | `ipv4` or `ipv6`. |
| `outcome` | string | `success`, `response_received` or `failure`. |
| `duration_ms` | integer | 0 to 60000. |
| `status_code` | integer, optional | HTTP status code, only for `http` with `response_received`. |
| `error` | string, optional | Normalized error code, only for `failure`. |

The computation does not check the rows. The server checks every contribution when it receives it.

## 3. Hourly Rollups

Group the rows by `(hour, target, asn, layer, family)`. The ASN `null` becomes `0`. For every group, make one row with these fields.

| Field | Meaning |
|---|---|
| `attempts` | Number of rows. |
| `successes` | Number of successes. |
| `failures` | Number of failures. |
| `status_counts` | Map from the status code, as a string, to the number of successes with that code. Only for `http`. An empty map for other layers. |
| `error_counts` | Map from the error code to the number of failures with that code. |
| `duration_count` | Number of successes. It equals `successes`. |
| `duration_sum_ms` | Sum of `duration_ms` over the successes. |
| `duration_min_ms` | Smallest `duration_ms` over the successes, or `null` if there is none. |
| `duration_max_ms` | Largest `duration_ms` over the successes, or `null` if there is none. |
| `histogram` | A list of 16 counts. See section 4. It counts the successes only. |

Durations of failures are never used in any statistic. A timeout has a duration of the timeout, and it would move the numbers.

Sort the rows by `hour`, `target`, `asn`, `layer`, `family`. Compare the strings by their bytes, and the ASN as a number.

### 3.1 Hourly Samples

Group the rows by `(hour, target, asn)`. The ASN `null` becomes `0`. For every group, make one row with the field `submissions`. It is the number of distinct `submission` values in the group. The sort order is `hour`, `target`, `asn`.

Every measurement of one submission is in one hour, so the number of submissions in a longer period is the sum of the hourly numbers. The sum is exact.

## 4. Histogram

The histogram has 16 buckets for the durations of successes. The upper limits, in milliseconds, are:

`10, 25, 50, 100, 200, 300, 500, 750, 1000, 1500, 2000, 3000, 5000, 10000, 30000, 60000`

A duration `d` goes in the first bucket where `d <= upper limit`. So 0 to 10 go in bucket 0, 11 to 25 in bucket 1, and 30001 to 60000 in bucket 15. The lower limit of bucket 0 is 0. The lower limit of every other bucket is the upper limit of the bucket before it.

## 5. Daily Rollups

A daily rollup has the same fields as an hourly rollup, with `day` (`YYYY-MM-DD`) in the place of `hour`. For every group `(day, target, asn, layer, family)`, add the hourly rollups of the 24 hours of the day:

* add `attempts`, `successes`, `failures`, `duration_count`, `duration_sum_ms`, every count in `status_counts` and `error_counts`, and every bucket of `histogram`;
* take the smallest `duration_min_ms` and the largest `duration_max_ms`, ignoring `null`;
* add `submissions` of the hourly samples in the same way. The daily samples have the fields `day`, `target`, `asn` and `submissions`.

The daily rollups are only a convenience for long histories. A window (section 6) is always computed from the hourly rollups. An hourly rollup that changes makes its day dirty, and the day is computed again from the hourly rollups. The computation never changes a rollup in place by adding to it.

## 6. Windows

A window is a number of whole hours that ends at `as_of`. The value `as_of` is an hour boundary, and the hour that starts at `as_of` is not part of the window. The window `W` covers the hours `[as_of - W, as_of)`.

| Name | Hours |
|---|---|
| `1h` | 1 |
| `6h` | 6 |
| `24h` | 24 |
| `7d` | 168 |
| `30d` | 720 |

The server uses the start of the current UTC hour as `as_of`. The current hour is not complete, so it is never part of a published window.

A **series** is `(target, asn)` for one ASN, or `(target, all)` for the country-wide series. The country-wide series adds all ASNs, including the ASN `0`.

### 6.1 Window Result

For a series and a window, add the hourly rollups and the hourly samples of the hours of the window. The result has these fields.

| Field | Meaning |
|---|---|
| `target`, `asn`, `window`, `from`, `to` | The request. `asn` is a number, or `"all"`. `from` is the start and `to` is `as_of`. |
| `submissions` | The sum of the hourly samples. |
| `threshold` | The publication threshold that was used. |
| `published` | `true` if `submissions >= threshold`. |
| `state` | The classification (section 8). |
| `layers` | Only if published. See below. |
| `completion_bp` | Only if published. See below. |
| `baseline` | Only if published. See section 8. |

For `layers`, make one entry for each of `dns`, `tcp`, `tls` and `http`. An entry has `attempts`, `successes`, `failures`, `success_bp`, `p50_ms`, `p95_ms` and `families`. The field `families` has the keys `ipv4` and `ipv6`. Each of them has `attempts`, `successes` and `success_bp`. The `http` entry also has `status_counts` and `error_counts`. All other entries have `error_counts`.

A series that has no row at all for a layer has `attempts` 0 in that layer. Then `success_bp`, `p50_ms` and `p95_ms` are `null`.

A series that is not published has no `layers`. It has only `submissions`, `threshold`, `published` and `state`. The server does not publish a rate, a latency or a status count for a series with too few submissions. Publishing `submissions` for it is allowed, because it only says how little data there is.

### 6.2 Rates

A rate is an integer in basis points (1/10000). For a numerator `n` and a denominator `m`:

`rate_bp = floor((n * 10000 + m / 2) / m)` with integer division, and `null` if `m` is 0.

This rounds half up. Do not use floating point for a rate.

* `success_bp` of a layer is `rate_bp(successes, attempts)`. For `http` it is the rate of responses, and it is not a rate of working pages.
* `completion_bp` is `rate_bp(http successes, dns attempts)`, over both families. It tells how many measurement chains reached an HTTP response. It is `null` if the DNS attempts are 0.

### 6.3 Percentiles

`p50_ms` and `p95_ms` come from the merged histogram of the successes of a layer in the window, all families together. Let `n` be the sum of the buckets. If `n` is 0, both are `null`.

For a percentile `p` (50 or 95), the rank is `rank = (p * n + 99) / 100` with integer division. It is the smallest integer that is at least `p * n / 100`. Walk the buckets from the first one and find the bucket where the running total first reaches `rank`. Let `before` be the running total before that bucket, `count` the count of that bucket, `lo` and `hi` its limits. Then, in tenths of a millisecond:

`tenths = lo * 10 + floor(((hi - lo) * 10 * (rank - before) * 2 + count) / (2 * count))`

The percentile is `tenths / 10`, written with one decimal digit. This is linear interpolation inside the bucket with the half rounded up. The value is an approximation, and its error is at most the width of the bucket. The published text must say so.

The result for the minimum and maximum of a window is not published. Only the hourly and daily rollups hold them.

### 6.2 Timelines

A timeline is a list of window results for successive end times, one hour apart, for one series. Point `i` of a timeline with `hours` points ends at `as_of - (hours - 1 - i)` hours and is computed as in section 6.1. The state of a point is the state of that result. A point below the threshold has the state `insufficient_data`. A timeline adds no rule of its own. An implementation must give the same state and submission count for a point as the history of the same series gives for the same end time.

## 7. Country-Wide Numbers

The country-wide series (`asn` is `"all"`) is the sum over all ASNs. It is weighted by the number of measurements. It is not the average of the rates of the networks, and it is not a survey of all Iranian internet users.

A country-wide result has two more fields: `networks_observed` is the number of ASNs, without `0`, that have at least one hourly sample in the window for the target, and `networks_published` is the number of those ASNs with `submissions >= threshold`.

## 8. Classification

The state of a published series is the first rule that matches, in this order. Use the rounded values of section 6.2. A rule that needs a value that is `null` does not match.

| Order | State | Rule |
|---|---|---|
| 1 | `insufficient_data` | `submissions < threshold`. |
| 2 | `network_failure_observed` | `completion_bp < COMPLETION_FAILURE_BP`. |
| 3 | `server_refusal_observed` | The `http` layer has `successes > 0`, and `refusal_bp >= REFUSAL_BP`. |
| 4 | `degraded_observations` | The baseline exists and one of the two conditions below holds. |
| 5 | `reachable_response_observed` | `completion_bp >= COMPLETION_REACHABLE_BP`. |
| 6 | `http_response_received` | None of the above. |

`refusal_bp` is `rate_bp(count of status 403 + count of status 451, http successes)`.

The **baseline** is the same series over the 168 hours before the start of the window: `[from - 168h, from)`. It exists when its `submissions >= threshold` and its `completion_bp` is not `null`. The `baseline` field of the result holds `submissions`, `completion_bp` and the HTTP `p95_ms` of the baseline. The baseline of a published series with no baseline has `"baseline": null`.

The conditions for `degraded_observations`:

* `baseline.completion_bp - completion_bp >= DEGRADED_DROP_BP`, or
* both `p95_ms` of the `http` layer values exist and `p95_ms >= DEGRADED_P95_FACTOR * baseline p95_ms`.

What the states do and do not say:

* A state describes what the measurements of the window show. It is not a statement about the cause.
* `network_failure_observed` does not mean censorship. A timeout, a DNS failure or a refused connection can have many causes, and the published text must say so.
* `server_refusal_observed` means that the endpoint answered with 403 or 451 for most responses. It is not a failure of DNS, TCP or TLS.
* The states never use the word censorship.

## 9. Constants

| Name | Value | Meaning |
|---|---|---|
| `THRESHOLD` | 20 | Smallest number of submissions for a published series. The server can change it by configuration. Every result holds the value that was used. |
| `DEFAULT_WINDOW` | `6h` | Window that the dashboard shows first. |
| `COMPLETION_REACHABLE_BP` | 9000 | At least 90 percent of the chains reach an HTTP response. |
| `COMPLETION_FAILURE_BP` | 5000 | Fewer than 50 percent of the chains reach an HTTP response. |
| `REFUSAL_BP` | 5000 | At least half of the HTTP responses are 403 or 451. |
| `DEGRADED_DROP_BP` | 2000 | The completion rate is at least 20 points lower than the baseline. |
| `DEGRADED_P95_FACTOR` | 2 | The HTTP 95th percentile is at least twice the baseline. |
| `BASELINE_HOURS` | 168 | Length of the baseline. |

The threshold is a publication rule. It does not mean that 20 independent people took part, and it is not an anonymity guarantee.

## 10. Properties That Every Implementation Must Keep

* **Order independence.** The result does not depend on the order of the input rows.
* **Rebuild equals increment.** Computing an hour again from its rows gives the same rollup as before. The computation replaces a rollup. It never adds to a stored rollup.
* **Window equals sum.** A window result is a function of the hourly rollups and the hourly samples only. It never needs the raw rows.
* **No other data.** A rollup holds no address, no submission identifier and no time finer than the hour.

## 11. Fixtures

The folder `fixtures/` has the files that every implementation must pass. `manifest.json` lists them. A fixture file has these fields:

* `description`: what the file checks.
* `config`: optional. `threshold` replaces the default.
* `rows`: the input rows (section 2).
* `expect.hourly`, `expect.samples`, `expect.daily`, `expect.daily_samples`: optional lists of the expected rows. A list that is present must match exactly, in order.
* `expect.windows`: optional list. Each item has a `request` with `target`, `asn`, `window` and `as_of`, and the expected `result` (section 6.1).

A test compares the parsed JSON values, so the order of the keys and the white space do not matter.
