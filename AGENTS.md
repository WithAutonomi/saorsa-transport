# AGENTS.md

This is the single development guide for all coding agents working in this repository. `CLAUDE.md` and `GEMINI.md` import it; add new guidance here, not there.

## Project Overview

saorsa-transport is a Rust QUIC transport for peer-to-peer networks, built for the Autonomi ecosystem. It adds native QUIC NAT traversal (hole punching coordinated over existing connections), address discovery, MASQUE relay fallback and pure post-quantum authentication. The core QUIC state machines and the `high_level` async API began as a fork of Quinn but are now this project's own code.

### Repository independence

**saorsa-transport is an independent project, not a Quinn fork for contributions.**

- **NEVER** create PRs to quinn-rs/quinn.
- **NEVER** push to any quinn-rs repository.
- **NEVER** add quinn-rs/quinn as an upstream remote.
- This repository is github.com/WithAutonomi/saorsa-transport (standalone). GitHub may still show it as a fork (legacy); we do not contribute back to Quinn. See [ADR-010](docs/adr/ADR-010-repository-ownership.md).

## Design Principles

Each decision links to the ADR that records why. The index is `docs/adr/README.md`.

- **Symmetric P2P** ([ADR-004](docs/adr/ADR-004-symmetric-p2p-architecture.md)): every node is the same type and both connects and accepts. There are no client, server or bootstrap roles; initial peers are `known_peers`.
- **Pure post-quantum crypto, raw public keys, no X.509** ([ADR-003](docs/adr/ADR-003-pure-post-quantum-cryptography.md), spec `docs/rfcs/saorsa-transport-pqc-authentication.md`): ML-KEM-768 key exchange and ML-DSA-65 identity keys. The peer ID is 32 bytes: BLAKE3 over the ASCII prefix `AUTONOMI_PEER_ID_V2:` followed by the ML-DSA-65 public key (`fingerprint_public_key` in `src/crypto/raw_public_keys/pqc.rs`). Code points (`src/crypto/pqc/cipher_suites.rs`): ML-KEM-768 is TLS group `0x0201`, ML-DSA-65 is signature scheme `0x0905`. The design intent is no hybrids and no classical fallback, but be aware the current provider (`src/crypto/pqc/pqc_crypto_provider.rs`) still accepts hybrid ML-KEM groups such as `0x11EC` (X25519MLKEM768) as transitional, with a unit test asserting that. Do not rely on it, and do not add new classical or hybrid paths.
- **Native QUIC NAT traversal** ([ADR-005](docs/adr/ADR-005-native-quic-nat-traversal.md)): implements `draft-seemann-quic-nat-traversal-02` with address discovery per `draft-ietf-quic-address-discovery-00`, using QUIC extension frames and transport parameters between connected peers. The QUIC NAT traversal uses no STUN, ICE or TURN. The separate WebRTC Direct transport for browsers ([ADR-015](docs/adr/ADR-015-direct-browser-webrtc.md), feature `webrtc-direct`) is a different path and is not part of this rule.
- **MASQUE relay fallback** when hole punching fails: [ADR-006](docs/adr/ADR-006-masque-relay-fallback.md), [ADR-009](docs/adr/ADR-009-masque-relay-data-plane.md), [ADR-011](docs/adr/ADR-011-stable-relay-port-reservations.md), [ADR-013](docs/adr/ADR-013-relay-tunnel-teardown-ordering.md).
- **Dual-stack / universal connectivity** ([ADR-008](docs/adr/ADR-008-universal-connectivity-architecture.md)): IPv4 and IPv6, with connection attempts and path choice handled by `connection_strategy`, `happy_eyeballs`, `path_selection`.
- **Local-only HostKey** ([ADR-007](docs/adr/ADR-007-local-only-hostkey.md)): the host key encrypts local state only and is never a network identity.
- **`LinkTransport` abstraction** ([ADR-001](docs/adr/ADR-001-link-transport-abstraction.md)): the trait that overlay networks such as saorsa-core build on.
- Keep-alive and congestion behaviour: ADR-012, ADR-014, ADR-016, ADR-018 (all in `docs/adr/`).

## Architecture

The authoritative module map is the crate-level doc comment in `src/lib.rs` (section "Module map"); read it rather than a copy here, and keep it current when you add modules. In short:

- Entry points: `src/node.rs` (zero-config `Node`) and `src/p2p_endpoint.rs` with `src/unified_config.rs` (`P2pEndpoint` / `P2pConfig`, full control).
- QUIC core: `src/endpoint.rs`, `src/connection/`, `src/frame.rs`, `src/transport_parameters.rs`, with the async API in `src/high_level/`.
- NAT traversal: `src/nat_traversal_api.rs` (`NatTraversalEndpoint`), `src/nat_traversal/`, `src/candidate_discovery.rs`, `src/discovery/`.
- Relays: `src/masque/`, `src/relay/`. Crypto and identity: `src/crypto/`, `src/trust/`, `src/host_identity/`.
- Other transports: `src/transport/`, `src/constrained/`, `src/connection_router.rs`, `src/webrtc/`.
- Wire format of the NAT traversal and address discovery extensions (transport parameters, frame IDs): `docs/architecture/PROTOCOL_EXTENSIONS.md`. Treat it as the reference for frame layouts; do not copy frame IDs into other docs.
- The workspace also contains `saorsa-transport-workspace-hack` (a cargo-hakari crate, config in `.config/hakari.toml`); do not hand-edit it.

## Common Commands

These mirror `.github/workflows/ci.yml` (the PR gate). Run the relevant ones before pushing. Default features are `native`, `platform-verifier`, `network-discovery`, `upnp`; other features in `Cargo.toml` include `ble`, `webrtc`, `webrtc-direct`, `log`, `trace`, `trace-full`, `property_testing`, `fuzzing`. Linux builds with `--all-features` need `libdbus-1-dev` and `pkg-config` (for `ble`).

```bash
# Format, lint and docs (CI uses -D warnings)
cargo fmt --all -- --check
cargo clippy --all-features --all-targets -- -D warnings
cargo clippy -p saorsa-transport --lib --no-default-features --features webrtc -- -D warnings
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps --locked --all-features

# Compile checks
cargo check --lib --bins --examples
cargo check --lib --no-default-features --target wasm32-unknown-unknown
cargo check -p saorsa-transport --lib --no-default-features --features webrtc --target wasm32-unknown-unknown

# Tests (Linux CI profile)
cargo test --lib --all-features -- --test-threads=2
cargo test --lib --no-default-features -- --test-threads=2
cargo test -p saorsa-transport --lib --no-default-features --features webrtc webrtc::
cargo test --all-features --test '*' -- --test-threads=2
cargo test --doc

# Windows/macOS CI runs default features only
cargo test --lib -- --test-threads=2
cargo test --test quick -- --test-threads=2
cargo test --test auto_binding_integration -- --test-threads=2

# MSRV (CI uses the rust-version from Cargo.toml)
cargo check --all-features && cargo check --no-default-features
```

- Use `cargo test`, not nextest: CI uses `cargo test`, and the repo has no nextest config (`.config/` only holds `hakari.toml`).
- Integration test targets are the files in `tests/`; the declared `[[test]]` targets in `Cargo.toml` are `quick` (`tests/quick/`), `long` (`tests/long/`) and `property_tests` (`tests/property_tests/`). Run one with `cargo test --test <name>`. Long-running tests are `#[ignore]`d (for example in `tests/long/`); run them with `cargo test --test long -- --ignored`. Files named `*.disabled` and the `tests/disabled/`, `examples/disabled/`, `benches/disabled/` directories are not built.
- Benchmarks are the `[[bench]]` targets in `Cargo.toml` (`benches/`), e.g. `cargo bench --bench relay_queue`.
- Examples (in `examples/`, run with `cargo run --example <name>`): `simple_p2p`, `simple_chat`, `simple_transfer`, `port_configuration`, `ml_kem_usage`, `pqc_config_demo`, `pqc_verification`, `throughput_test`, `trace_demo`, `verify_quic_endpoints`, `test_network_discovery_simple`, `ble_chat` (needs `--features ble`).
- Scripts in `scripts/`: `security-validation.sh`, `pqc-security-validation.sh`, `pqc-release-validation.sh`, `bump-version.sh`, `terraform-env.sh`.
- Slower suites (extended property tests, full platform matrix, security audit, coverage) run in `tests.yml`, `platforms.yml`, `platforms-exotic.yml`, `security.yml`, `coverage.yml`; see `.github/CI_ARCHITECTURE.md`.

## Key Conventions

- **MSRV and edition:** see `rust-version` and `edition` in `Cargo.toml`; do not hard-code versions in docs or workflows.
- **No `unwrap()` / `expect()` in production code.** `Cargo.toml` `[lints.clippy]` sets `unwrap_used` and `expect_used` to deny; `clippy.toml` allows them in tests. Propagate errors with `?`. Library errors are typed enums (for example `EndpointError` in `src/p2p_endpoint.rs`, `SaorsaTransportError` in `src/error_handling.rs`), generally derived with `thiserror`.
- **Format and lint clean:** `cargo fmt --all` and clippy with `-D warnings` must pass (see Common Commands). `src/lib.rs` already allows many clippy lints crate-wide; do not add more blanket `#![allow]`s, prefer a narrow local `#[allow]` with a reason.
- **Document public APIs:** `src/lib.rs` enables `warn(missing_docs)` and `warn(dead_code)`; remove unused code rather than silencing the warning.
- **Doc examples must compile.** `cargo test --doc` runs in CI, and the README's code is compiled as a doctest too. Use `no_run` (with hidden `# ` setup lines) for examples that need a network, and `text` for pseudo-code or diagrams. Don't use `ignore` without a written reason: ignored examples are how the old docs drifted. Intra-doc links must resolve (`cargo doc` runs with `-D warnings`). Link items in feature-gated modules by full `crate::` path.
- **Licence header:** every tracked `.rs` file must open with the MIT OR Apache-2.0 header within its first 15 lines (CI checks this); copy it from an existing file.
- **Logging:** use `tracing` macros, not `println!`, in library code.
- **Wasm:** CI checks only the `--no-default-features` library and the `webrtc` profile on `wasm32-unknown-unknown`; the `native` stack is gated behind `cfg(feature = "native")`. Keep those checks green when touching feature gates.
- **Commits:** Conventional Commits (`feat(nat): ...`, `fix(frame): ...`); `cliff.toml` configures git-cliff.
- **Changelog:** `CHANGELOG.md` follows Keep a Changelog with an `[Unreleased]` section; record user-visible and breaking changes there.
- **Specs live in `docs/rfcs/`:** `rfc9000.txt`, `draft-seemann-quic-nat-traversal-02.txt`, `draft-ietf-quic-address-discovery-00.txt`, `draft-seemann-masque-connect-udp-ecn-01.txt`, `fips-203-ml-kem.pdf`, `fips-204-ml-dsa.pdf`, `saorsa-transport-pqc-authentication.md` (our authentication spec), plus TLS/PQC drafts (`draft-ietf-tls-mlkem-04.txt`, `draft-ietf-tls-ecdhe-mlkem-00.txt`, `draft-ietf-tls-hybrid-design-12.txt`/`-14.txt`, `draft-ietf-lamps-kyber-certificates-10.txt`, `draft-ietf-lamps-dilithium-certificates-11.txt`, `draft-reddy-uta-pqc-app-07.txt`) and `nist-sp-800-56c-rev2.pdf`. The wire format actually implemented is `docs/architecture/PROTOCOL_EXTENSIONS.md`; where it and a draft disagree, it describes our behaviour.

### Debugging

`RUST_LOG` targets are module paths under the `saorsa_transport` crate (only `pub` modules are useful as filters; private ones like `congestion` and `token` inherit the crate target). Examples:

```bash
RUST_LOG=saorsa_transport::nat_traversal_api=debug cargo test --test nat_traversal_api_tests -- --nocapture
RUST_LOG=saorsa_transport::connection=trace cargo test --lib connection:: -- --nocapture
RUST_LOG=saorsa_transport::crypto=debug cargo test --test pqc_basic_integration -- --nocapture
RUST_LOG=debug cargo run --example simple_p2p
```

Other useful `pub` targets: `nat_traversal`, `candidate_discovery`, `p2p_endpoint`, `masque`, `relay`, `discovery`, `high_level`, `trust`.

## Pull requests: fill the template

When you open a pull request, you MUST use `.github/PULL_REQUEST_TEMPLATE.md` as
the PR body and fill it in completely — do not open a PR with an empty or ad-hoc
description.

- **Fill every field.** Leave nothing blank; if a value isn't determinable, ask
  before opening the PR.
- **Link the Linear issue with a closing magic word** — write `Closes V2-123` in
  the `## Linear issue` section, one line per issue. Any of Linear's closing
  words works, in any tense (`close` / `fix` / `resolve` / `complete` /
  `implement`, plus their `-s`, `-d` and `-ing` forms), and the key may be a
  `linear.app` issue URL. A bare `V2-123` does **not** link the PR at all, and
  the linking-only words (`ref`, `part of`, `towards`, `relates to`) attach it
  without driving the Merged transition — CI rejects both. An issue key in the
  branch name or PR title also links, but write the closing form anyway; it is
  what moves the issue to Merged when the PR lands on `main`.
- **Check exactly one Risk tier box and exactly one Semver impact box.** Propose
  them from the change; a human confirms them at review.
- An **ADR link is required for Tier 2/3**.

CI enforces the Linear link and the template fields (`linear-link` and
`pr-template` status checks); a PR that omits them fails its checks.
Release-promotion PRs — a `chore(release):` title from an `rc-*` head branch —
are exempt from both checks (they are mechanical version-bump PRs generated by
the release process). Dependabot PRs — opened by `dependabot[bot]` — are exempt
too; if you do real work on top of one, open it as your own PR instead.
