# CI architecture

CI runs on pull requests, on a schedule, and by hand (`workflow_dispatch`). Nothing runs on a push to `main`: a merged PR has already passed CI on its head (V2-1353). The org is on GitHub's Free plan, so every repo shares one pool of concurrent jobs, including a small number of macOS runners. That is why each piece of work runs once per PR.

## Pull requests

| Workflow | Job | What it runs |
| -- | -- | -- |
| `ci.yml` | Quick Checks | fmt; clippy `--all-features --all-targets`; clippy on the portable WebRTC profile; `cargo check` of lib/bins/examples; both WASM checks; licence headers |
| | Test Suite (Linux) | build; lib tests with all features and with no default features; WebRTC profile tests; every integration test target (`--test '*'`); doc tests |
| | Tests (windows-latest), Tests (macos-latest) | default features: lib tests and the `quick` and `auto_binding_integration` targets. macOS also builds `x86_64-apple-darwin` |
| | MSRV (1.95.0) | `cargo check` with all features and with no default features |
| | CI Gate | fails unless every job above succeeded |
| `pr-checks.yml` | linear-link, pr-template | the required status checks (see CLAUDE.md, "Pull requests") |
| | self-test | tests for `check_pr.py` |
| `coverage.yml` | Coverage | `cargo llvm-cov --lib`; HTML report artifact; warns below the threshold, doesn't gate |
| `security.yml` | Vulnerability Scan (`cargo audit`), Policy Check (`cargo deny`), SBOM, Security Report, Dependency Review, Security Gate | only when `Cargo.toml` or `Cargo.lock` changes |

`claude.yml` runs only when someone mentions `@claude`.

## Scheduled and manual

| Workflow | When | What |
| -- | -- | -- |
| `security.yml` | daily 02:00 UTC | `cargo audit` and `cargo deny`; advisories change without the tree changing |
| `platforms.yml` | Mondays 02:00 UTC | the full matrix: Linux stable/beta/MSRV, aarch64 Linux (cross), x86_64 and aarch64 macOS, Windows. Dispatch can pick `minimal` |
| `tests.yml` | Mondays 04:00 UTC | extended property tests (1024 cases, release build) |
| `platforms-exotic.yml` | Fridays 03:21 UTC | FreeBSD, NetBSD, Solaris, illumos, Android, feature powerset |
| `benchmarks.yml` | Sundays 00:00 UTC | criterion benchmarks |

## Releases

`release.yml` runs on a `v*` tag: validate the tag against `Cargo.toml`, generate the changelog (git-cliff), build the 7 release targets, publish the crate, create the GitHub release. It doesn't re-run the test suite (V2-1353).

## Adding a check

- **A new PR check is a step or job in `ci.yml` that feeds `CI Gate`**, not a new workflow. A separate workflow compiles the crate again and takes another runner, and nothing gates on it.
- **A check must be able to fail.** Don't add `continue-on-error`, `|| true`, or `|| echo` to a check. If a result is advisory, say so in the job name and leave it out of `CI Gate`.
- **Run multi-line steps under bash on Windows.** A multi-line `pwsh` step only fails if its last command fails.
- **Skip a test in CI only with a linked ticket**, and remove the skip when the ticket closes.
