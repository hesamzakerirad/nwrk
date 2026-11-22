---
title: Community Measurements
description: Share anonymous reachability results with NWRK Status. What nw measures, sends and stores, and how consent works.
weight: 12
---

`nw community` is the only part of nw that can send data. It is optional. It never runs in the background, and nothing is uploaded unless you run `nw community contribute` and agree after you see the result.

The results feed [NWRK Status](https://status.nwrk.ir), a public dashboard of which services are reachable from which networks in Iran.

## Commands

```sh
nw community info                      # what is measured, sent and stored. Sends nothing.
nw community contribute --dry-run      # measure and show the result. Never contacts the server.
nw community contribute                # measure, show the result, upload if you agree
```

### nw community info

Shows the services in the measurement profile and the text of the disclosure. It sends nothing over the network. Use `--profile` to read another profile. With `--output json` it prints the same information as JSON.

### nw community contribute

Runs the checks of a profile on your machine and shows the exact result. It uploads only if you agree.

| Flag | Meaning |
|---|---|
| `--profile` | Measurement profile. Default `ir-core-v1`. The profile fixes the services, the time limits and the total budget (90 seconds), so `--timeout` does not apply. |
| `--dry-run` | Measure and show the result. Never contacts the server. |
| `--payload-file <path>` | With `--dry-run`: write the exact message to a file, with mode `0600`. |
| `--api` | API address. Default `https://api.nwrk.ir`. The `NW_COMMUNITY_API` variable does the same. Plain `http` is accepted only for `localhost`. |

`--output json` works only with `--dry-run`, and prints the exact message. `--payload-file` works only with `--dry-run`.

## Consent

`contribute` asks two questions. Both default to no, and no flag answers them for you.

1. **Before it measures.** nw lists the services it will contact and shows the disclosure, then asks "Run these checks now?". If you do not answer yes, nothing is measured and nothing is sent.
2. **Before it uploads.** nw shows one line for each service and IP version, then asks "Upload these results?". Type `s` to see the exact message first. Any answer except `y` or `yes`, including end of input, means nothing is sent.

If the upload fails, nw says why. It keeps nothing: there is no queue and no retry. A rate limit answer says how long to wait.

## What Is Sent

For each service in the profile: the check type (DNS, TCP, TLS or HTTP), the IP version, success or failure, the time in milliseconds, and sometimes an HTTP status code, the DNS response code, the number of DNS answers or an error code. The message also holds the nw version and the profile name and version.

The message holds none of these:

* your public or local addresses
* your DNS resolver addresses
* the addresses of the services
* certificates, headers, cookies, response bodies or URLs
* your computer name, MAC address, location, or any device or installation ID

A service is measured over an IP version only if it has a record for that version and your machine has a route for it. A missing measurement is never counted as a failure.

## What the Server Stores

The server sees the address your connection comes from. It uses the address, in memory only, to look up the country and the network (ASN). It stores the country and the ASN with your results, and the time rounded to the hour. It does not store the address. Results from outside Iran are not stored.

The [privacy page](../privacy/) lists where the server is hosted and how long results are kept.

## Check It Yourself

Run `nw community contribute --dry-run --payload-file message.json`. The file holds the exact message that an upload would send. The message format and the checks that the server applies are in [`contracts/`](https://github.com/hesamzakerirad/nwrk/tree/main/contracts).
