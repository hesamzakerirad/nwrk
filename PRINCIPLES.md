# Principles

These guide product design and code review. The full reasoning is in [docs/SPEC.md](docs/SPEC.md).

1. **Local-first.** Core diagnostics work without an account, backend or vendor service.
2. **Privacy-first.** Nothing is uploaded automatically. Anything external is explicit and disclosed.
3. **Evidence before conclusions.** Every finding points to the measurements behind it.
4. **Honest uncertainty.** Observations are kept apart from inferred causes. A timeout is not proof of a firewall, and a TLS failure is not proof of interference.
5. **Cross-platform.** Linux, macOS and Windows are first-class. Platform limits are reported, not hidden.
6. **Scriptable.** Stable JSON output and documented exit codes.
7. **Safe by default.** Tests are non-invasive, bounded, and limited to what the user selected.
8. **Reproducible.** Runs record parameters, timestamps and versions.
9. **Bounded.** Every network operation has a timeout, limits and cancellation.
10. **Transparent.** The tool shows what it tests and what it stores.
11. **Modular, not over-engineered.** One Go application with clear packages. No plugin framework before real requirements.
12. **No privileges needed.** The default suite runs unprivileged; tests that need more say so.

Technical vocabulary only: findings are named for what was measured, such as `DNS_ANSWER_MISMATCH`. nwrk does not ship circumvention features.
