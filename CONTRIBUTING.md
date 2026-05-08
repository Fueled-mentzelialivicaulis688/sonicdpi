# Contributing to SonicDPI

By submitting a pull request you agree to license your contribution
under MIT OR Apache-2.0.

## Workflow

1. `cargo fmt --all` and `cargo clippy --all-targets -- -D warnings`
   must pass.
2. Add a test where it makes sense — `cargo test --workspace`.
3. For new strategies: also add a one-paragraph description to
   `docs/research-techniques-2026.md` and cite the source.
4. For new fake payloads under `crates/sonicdpi-engine/builtin/`:
   document how they were captured / generated. Real network captures
   from the contributor's own machine only — do not redistribute
   pcaps from third parties.

## Roadmap

Tracked as GitHub issues. The high-level milestones:

- **v0.2** — finish byte-rewriter (`Replace` / `InjectThenPass` actually emit packets).
- **v0.3** — macOS NetworkExtension backend with UDP support (Discord voice on Mac).
- **v0.4** — adaptive probing harness (auto-rotate ALT profiles).
- **v0.5** — minimal Tauri GUI for end-users.

## What we WILL accept

- New evasion strategies, with a clear reference to where they were
  documented (zapret discussion thread, ntc.party post, paper).
- Bug fixes, perf improvements, additional ISP/region profiles.
- Translations of the README.

## What we WON'T accept

- Anything that helps a censor identify SonicDPI traffic.
- Code copied from GPL projects (we are MIT/Apache-2.0; license drift
  is a hard no).
- Fake payloads that are obviously content-spoofed/fingerprintable
  (e.g., contain real user data or third-party PII).

## Reporting a regression on a real ISP

Open an issue with: country, ISP/AS number, date, profile used,
output of `sonicdpi run -vv` for the affected target, and what
"working" / "not working" looks like (page loads but slow vs hard
TLS reset vs voice connect timeout). Privacy: redact your own IPs.
