# Contributing to nwrk

Thank you for helping. nw is a diagnosis tool, so the most valuable contributions are correct evidence and honest wording. Read [PRINCIPLES.md](PRINCIPLES.md) first; it is short.

## Ground rules

- **Measurements are separate from interpretation.** A measurement records what happened. Findings, hypotheses and recommendations are produced by rules from measurements, never the other way round.
- **Say what you do not know.** A hypothesis lists what supports it, what contradicts it and what was not checked. Confidence is `low`, `medium` or `high`, never a percentage.
- **Technical vocabulary only.** Findings, rule IDs, docs and the website describe what was observed (`TLS_HANDSHAKE_FAILURE_AFTER_TCP`), never who or why. Do not add circumvention features. See SPEC section 8.5.
- **Safe by default.** Nothing is uploaded, no system setting is changed, every network operation has a deadline and a size limit, and cookies, bodies and credentials are never recorded.
- **Tests use local fixtures.** Core tests never touch the public internet; use the servers in `internal/fixtures`.

## Support

nwrk is maintained on a best-effort basis. Expect a reply within a week.

## Setup

You need Go (the version in `go.mod`) and, for the site, [Hugo](https://gohugo.io/) extended.

```sh
make build     # bin/nw
make test      # go test -race ./...
make lint      # gofmt, go vet, staticcheck
make fuzz      # fuzz the input parsers briefly
make site      # build the website
```

## Adding or changing a rule

1. Write the rule in `internal/diagnostics/rules`: a stable ID, a version, the measurement types it requires, its caveats (the false-positive conditions), and what it concludes. Bump the version whenever its conditions or wording change.
2. Add **positive and negative** cases to `TestRules` in `rules_test.go`. A rule without both does not merge.
3. Document it in `docs/findings.md` with its false-positive conditions. A test checks that every rule ID appears there.
4. If you used the issue template "Rule false positive", link the issue.

## Pull requests

- Open an issue first for anything larger than a fix, so we can agree on the approach.
- Keep a pull request to one change. Update the docs in the same pull request:
- Add a line to the `Unreleased` section of [CHANGELOG.md](CHANGELOG.md) for any change a user can see.
- CI must pass on Linux, macOS and Windows.
- Commit messages say what changed and why, in the imperative ("Add TCP timeout rule").

## Docs

User docs live in `docs/` and are written in English.

## Reporting a security problem

Do not open a public issue. See [SECURITY.md](SECURITY.md).

## License

By contributing you agree that your contribution is licensed under the [MIT license](LICENSE).
