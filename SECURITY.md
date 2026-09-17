# Security Policy

## Reporting a vulnerability

Report suspected vulnerabilities privately via
[GitHub security advisories](https://github.com/bigblue-r4/unicode-interference/security/advisories/new)
— do **not** open a public issue for anything exploitable. Coordinated
disclosure preferred; reporters are credited unless they ask otherwise.

## Supported versions

| Version | Supported |
|---------|-----------|
| 1.x | ✅ security fixes as patch releases |

## Threat model and scope

This library detects **script mixing** — non-Latin characters embedded in
otherwise-Latin text — using a forward/reverse interference pattern, and
reports where they sit. It is a *detector and a reporter*, not a sanitizer.

In scope as a security bug:

- A homoglyph in a script this crate claims to classify that produces no
  intrusion and no interference spike.
- A panic, hang, or unbounded allocation on any `&str` input.
- `rotate()` returning a mapping that is wrong for the documented script.

Explicitly out of scope:

- Semantic attacks in plain ASCII — nothing here reads meaning.
- Confusables **within** a single script (Latin `l`/`I`/`1`). The signal this
  crate uses is script *transition*; a same-script confusable produces no
  transition and is invisible to it by construction.
- Deciding what to do about a flagged string. Scores are advisory; blocking
  policy belongs to the caller.

**Do not use this crate as the only gate on untrusted input.** It answers one
narrow question. Pair it with a normalizer such as
[`deobfuscate`](https://crates.io/crates/deobfuscate) for encoding evasion, and
a semantic layer for everything neither of them sees.

## Assurance

| Property | Mechanism |
|----------|-----------|
| Behaviour pinned | 14 unit tests + one example, run on every push and PR (`.github/workflows/ci.yml`) |
| No lint regressions | `cargo clippy -- -D warnings` in CI |
| Supply-chain surface | **zero runtime dependencies** — the crate compiles against `core`/`std` only |

The zero-dependency property is the main security claim worth making about this
crate: there is no transitive tree to audit, and nothing to pull in at build
time beyond the toolchain.
