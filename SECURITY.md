# Security policy

## Reporting a vulnerability

Please report vulnerabilities privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability**
(https://github.com/radestsam/nwrk/security/advisories/new). Do not open a public issue or pull request for a security problem.

Include what you found, how to reproduce it, the version (`nw version`) and your platform. We will acknowledge a report within a few days, keep you informed, and credit you in the release notes if you wish.

## What counts

nw runs on your machine and makes network requests you ask for. Problems we want to hear about include:

- A way to make nw send data you did not ask it to send, or to upload measurements anywhere.
- Recording of cookies, response bodies, authorization headers or credentials.
- Weakened certificate verification, or any path that skips it.
- Command or code execution from crafted input: a hostile target, DNS response, certificate, HTTP response or redirect.
- Unbounded resource use from a hostile peer (memory, time, redirects).
- A flaw in the install scripts or the release artifacts, including checksum or signature verification.

A diagnosis that is wrong or incomplete is a bug, not a vulnerability: use the bug report template.

## Supported versions

Until v1.0, only the latest release is supported.

## Verifying a download

Every release has `checksums.txt` and a cosign keyless signature. See the [install guide](docs/install.md#verify-a-download).
