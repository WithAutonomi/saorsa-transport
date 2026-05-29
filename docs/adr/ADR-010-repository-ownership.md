# ADR-010: Repository Ownership under WithAutonomi

## Status

Accepted (2026-05-29)

## Context

`saorsa-transport` began under Saorsa Labs as a reusable transport crate for Saorsa networking work. It is now operationally coupled to Autonomi v2: most Autonomi releases touch either `saorsa-core`, `saorsa-transport`, or both, and the transport crate is part of the WithAutonomi dependency and release surface.

Leaving the repository under `saorsa-labs` made organisation-level monitoring noisy because Autonomi release activity appeared alongside x0x and foundation work.

## Decision

Host `saorsa-transport` in the `WithAutonomi` GitHub organisation. The repository remains named `saorsa-transport`, but its location reflects Autonomi v2 release ownership and monitoring responsibility.

The ownership boundary is:

- `WithAutonomi`: Autonomi-specific implementation crates and crates that participate in the Autonomi release train.
- `saorsa-labs`: x0x repositories and foundation/shared crates such as generic crypto or messaging primitives unless their release ownership changes.

GitHub redirects from the previous location are expected to remain in place, but repository metadata, documentation, CI links, and release references should use `https://github.com/WithAutonomi/saorsa-transport`.

## Consequences

### Benefits

- Autonomi v2 monitoring can track transport changes together with the `ant-*` repositories.
- x0x and foundation monitoring is less noisy.
- Release ownership is clearer for maintainers and external contributors.
- Repository metadata and badges point at the canonical organisation.

### Trade-offs

- Existing local clones may need their `origin` URL updated.
- Any external automation that hard-codes the previous URL must be updated.

### Neutral

- The crate name does not change.
- The transport API and protocol decisions are unchanged.
- GitHub redirects should preserve most existing links during the transition.

## Alternatives Considered

1. **Keep the repository in `saorsa-labs`**
   - Rejected because operational activity would continue to blur x0x/foundation monitoring with Autonomi v2 release work.

2. **Rename the crate/repository to remove the `saorsa-` prefix**
   - Rejected because the crate name is already established and the move is about ownership/operations, not API or brand churn.

## References

- Canonical repository: <https://github.com/WithAutonomi/saorsa-transport>
- Related core crate: <https://github.com/WithAutonomi/saorsa-core>
