# ADR-011: Stable Relay Port Reservations (Authenticated, Leased)

## Status

Proposed (2026-06-24)

## Context

### The problem: relay reconnects mint permanent dead addresses

Each MASQUE relay session binds a fresh OS-assigned UDP port. In
`src/masque/relay_server.rs` the relay binds `SocketAddr::new(UNSPECIFIED, 0)`,
reads back the kernel-assigned port via `local_addr().port()`, and advertises
`SocketAddr::new(public_ip, bound_port)` to the relayed peer, which then
publishes it into the DHT.

Sessions are tracked only by session id and **client socket address**
(`client_to_session: HashMap<SocketAddr, u64>`). There is no peer-identity map
and no reservation concept. When a session ends, `close_session` removes the
maps and **drops the `Arc<UdpSocket>`**, freeing the port forever.

Production analysis of file uploads showed relayed peers' sessions die and
re-establish constantly — one peer produced **13 sessions (13 distinct ports)
in a single day to the same relay**. Because each reconnect gets a brand-new
address, every previously-advertised `relay_ip:port` is orphaned the instant the
session drops and never becomes valid again. The owner only heals the DHT when
it eventually re-advertises and that propagates (tens of minutes to hours).
Churny peers therefore leave a growing trail of permanently-dead addresses in
FIND_NODE — a major contributor to the observed **~25% dead-record fraction**
and **~53% relay-dial-failure rate**.

### Why a stable port helps at the source

If a reconnecting peer is handed **the same `relay_ip:port`** it had before,
every DHT entry already pointing at that peer self-heals the moment it
reconnects — no re-advertise, no propagation wait, no orphan. This attacks the
dead-record problem at the source (stops minting orphans) rather than mopping up
after it client-side. We operate roughly **half of the network's relays**, so it
can be deployed on our own nodes unilaterally and measured.

### Why it is not a simple port-allocator tweak

A naive "reuse the last port for this peer" allocator is unsafe. Adversarial
review requires that identity binding, handover, replay, DoS, lease, and privacy
semantics all be specified first. The relay did not even have the relayed peer's
authenticated identity in scope at allocation time: the QUIC connection is
PQC-authenticated (ML-KEM-768 + ML-DSA-65) and the peer's public key is
extractable via `connection.peer_identity()`, but that identity was dropped
before `handle_connect_request` ran — which received only `client_addr`. Any
peer id in `ConnectUdpRequest` payload would be untrusted and spoofable.

## Decision

Introduce an **authenticated, leased, identity-keyed relay-port reservation**,
applied unconditionally for authenticated relayed peers, with structured INFO
logs as a metrics substitute (the node has no metrics system, and only INFO/WARN
reach the log pipeline). `reservation_ttl` and `max_reservations` are plain
tuning numbers on the relay config (like `max_sessions`), not feature toggles.

### 1. Authenticated identity source

The relayed peer's authenticated identity is derived once per connection as the
canonical `AUTONOMI_PEER_ID_V2` fingerprint — BLAKE3 over the ML-DSA-65 public
key from `connection.peer_identity()` (`authenticated_peer_fingerprint`). It is
threaded into `handle_connect_request` and stored on `RelaySession`. A peer id
supplied in request payload is **never** used.

### 2. Leased reservation, retained socket (Option A)

`MasqueRelayServer` holds `reservations: RwLock<HashMap<RelayPeerId, Reservation>>`
where `Reservation { port, udp_socket: Arc<UdpSocket>, upnp, released_at }`.

When an authenticated peer's session ends, instead of dropping the socket we
**move the bound `UdpSocket` (and its UPnP mapping) into the reservation**
(`released_at = now`). Because we keep the socket bound for the lease, the port
**cannot be reassigned to anyone else** — reuse is conflict-free. The
reservation is bounded by:

- `reservation_ttl` (default 10 min) — lease lifetime after session loss;
- `max_reservations` (default 1024) — an LRU cap; the least-recently-released
  reservation is evicted (and its port freed) when the cap is reached.

Expiry is **lazy + LRU-bounded** (no background sweeper): a reconnecting peer
discards its own over-TTL reservation on reclaim, vanished peers are reclaimed by
the LRU cap, and `cleanup_expired_reservations()` is exposed for a future
maintenance tick or tests. This matches the existing dial-failure-cache pattern
and avoids new startup wiring (the relay server has no periodic task today).

### 3. Safe reconnect / handover

On an incoming CONNECT from authenticated peer `P`, `handle_connect_request`:

- Acquires a **per-identity mutex stripe** (bounded; indexed by the fingerprint)
  and holds it across the handover, the capacity/duplicate checks, the reclaim,
  and the session insert — so concurrent CONNECTs from the same identity are
  serialized and never leave two live sessions for one identity.
- **Retires any live session `P` already holds, before the capacity/duplicate
  checks**, so an authenticated reconnect is not rejected with `503`/`409`.
  `close_session` **cancels and awaits** that session's stream-forwarding loop —
  the loop aborts its reader/writer tasks and releases the socket before the
  call returns — so no orphaned data plane survives the handover and the port can
  be leased and immediately reclaimed by the reconnect (**same** port). The
  common path (`P` disconnected, its loop ended and leased the port, then `P`
  reconnects) reclaims the same port the same way.
- Takes the reservation only if it is **fresh** (within `reservation_ttl`) and
  its socket matches the client's **IP family**; otherwise discards it and binds
  a fresh port.

Socket exclusivity is enforced two ways: the loop aborts and awaits its forwarding
tasks on its own exit, and `close_session` cancels and awaits a still-live loop
before the socket can be leased/reclaimed — so old and new sessions never share a
socket. The connection handler also forwards the **exact** session id returned by
`handle_connect_request` (not a later client-address lookup), and a loop claims its
session id, so one session never gets two forwarding loops.

### 4. Fallback path

Any miss — no authenticated identity, no/stale/mismatched reservation, feature
disabled — falls through to the original random `UNSPECIFIED:0` bind. Relay
acquisition is never wedged on "must have the previous port". Because Option A
holds the socket for the lease, a bind **conflict** cannot arise on the reuse
path (it is the failure mode of the rejected Option B, where only the port
number is remembered and re-bound).

### 5. DHT freshness preserved

No change to the publish path. The owner's `PublishAddressSet` remains
authoritative and sequence-ordered (monotonic `seq`, `last_publish_seqs`
newer-wins, FIND_NODE "newest seq beats XOR-closer stale report"). Relay-loss
still triggers direct-only/updated republish, and relayer-eligibility / K-closest
checks still apply. Stable ports simply make the already-published address valid
again on reconnect.

### 6. Companion client failure-cache adjustment (saorsa-core)

The client `DialFailureCache` is keyed by socket address with a 30-minute TTL and
clears only on a successful dial. With random ports a recovered peer dodges the
cache (new port = new key); with **stable** ports the recovered `relay_ip:port`
is the *same* key and would stay suppressed for up to 30 minutes — blunting the
self-heal. Therefore, when a **higher-`seq`** `PublishAddressSet` is *applied*
for a peer, saorsa-core clears the dial-failure entries for that peer's
newly-published socket addresses (`clear_dial_failures_for_published`), so a
self-healed address is re-admitted immediately. Shipped as a separate saorsa-core
commit; it runs in both the node and the `ant` client.

### 7. Logs as metrics

All reservation lines share a stable `component = "relay_reservation"` with an
`event` field and carry the peer fingerprint (short hex) and port. They are
tiered by level to keep **production** log volume low while leaving full detail
for a **testnet** run, because the node forwards only INFO/WARN to the log
pipeline (Elasticsearch) and the per-event lines fire once per relay-session
lifecycle:

- **DEBUG (per-event detail, testnet):** `reclaim_hit`, `reclaim_miss`,
  `reservation_created`, `reservation_expired`. Enabled on a testnet via
  `RUST_LOG=saorsa_transport::masque=debug`; off production ES entirely.
- **INFO (production signal):**
  - `event = "summary"` — a rate-limited "gauge" line
    (`RELAY_RESERVATION_SUMMARY_INTERVAL_MS`, default 5 min) carrying cumulative
    `hits / misses / created / expired / evicted` and the current
    `active_reservations`. Emitted opportunistically from the CONNECT path (no
    background task), so a busy relay reports ~once per interval and an idle one
    not at all. This is enough to confirm on production that reuse is happening
    (hits climbing) and to watch the pool size.
  - `reservation_evicted` — kept at INFO because it is rare and signals that
    `max_reservations` is being hit (the cap may be too low).

There is no `bind_conflict` event — Option A makes reuse conflict-free (see §4).

## Consequences

### Benefits
- Existing DHT records pointing at a reconnecting peer self-heal immediately — no
  re-advertise, no propagation wait, no orphan trail. Targets the dead-record /
  dial-failure rate at source.
- Deployable unilaterally on the relays we operate (~50%). Validation is a
  binary A/B — the current release (no reservations) as baseline vs the new
  build as treatment — since the behaviour is unconditional rather than toggled.
- Fewer distinct relay addresses per peer over time collapses the "13 ports/day"
  pattern toward one, which also makes the client IP-tier suppressor (V2-463)
  less likely to mis-trip.

### Costs / trade-offs
- Each idle reservation holds an open UDP socket + fd until TTL/eviction —
  bounded by `max_reservations` (LRU) and `reservation_ttl`. Expiry is lazy, so
  in the worst case up to `max_reservations` idle sockets are held until the cap
  forces eviction.
- Added state and lock discipline on the relay connect/close paths; the handover
  logic must be correct (covered by unit tests).
- **Privacy:** a stable port links "this port ⇄ this peer" at the relay across
  reconnects for the lease window. The peer↔relay-address mapping is already
  public in the DHT, so the added linkability is bounded to the lease window; the
  TTL caps it. Accepted, documented.
- A first rollout needs both the relay binary (nodes) and, for the cache-clear
  benefit, the saorsa-core change in the client binary.

### Security semantics (adversarial review)
- **Identity binding:** reservation key is the authenticated ML-DSA fingerprint
  from the QUIC connection; payload identity is never trusted.
- **Handover:** authenticated same-identity reconnect retires the old session and
  reuses the port under lock; a different identity can never reuse another peer's
  port (different key).
- **Replay:** a replayed CONNECT cannot authenticate as `P` without `P`'s ML-DSA
  key (the QUIC handshake binds it); the port is only ever handed to a live
  authenticated connection.
- **DoS:** one reservation per identity (reconnects reuse, they do not multiply);
  total bounded by `max_reservations` LRU + TTL; idle reservations evicted under
  pressure; fd/memory bounded. An attacker minting many identities is capped by
  the LRU and gains nothing per-port.
- **Lease:** bounded TTL after session loss; no permanent reservation; in-memory
  only, **not** persisted across relay restart (a restart yields fresh random
  ports and the seq mechanism heals the DHT normally).
- **Privacy:** as above — bounded by the lease window, accepted.

## Alternatives Considered

- **Naive "reuse last port" allocator.** Rejected: no identity binding →
  spoofable; no lease/DoS bounds; review-blocked.
- **Option B — remember only the port number, rebind on reconnect.** Simpler
  state (no idle socket held) but the port can be reassigned between sessions,
  producing bind conflicts and reclaim misses. Documented as the fallback shape
  but not implemented; Option A (hold the socket) is conflict-free.
- **Client-side eviction only (drop dead relay records faster).** Mops up after
  the fact rather than stopping orphan creation; complementary, not a substitute.
  The companion cache-clear (§6) is a minimal, targeted version of this.
- **Persisting reservations across relay restart.** Rejected: violates "no
  permanent reservation," adds replay/ownership complexity; the seq mechanism
  already heals post-restart.
- **A background maintenance sweeper for prompt expiry + a periodic gauge.**
  Deferred: the relay server has no maintenance tick today (session cleanup is
  likewise unscheduled). Lazy + LRU expiry is sufficient and self-contained; a
  sweeper can be added later at the `RelayManager` keepalive tick.
- **Building a real metrics subsystem.** Out of scope; structured INFO logs are
  sufficient for validation given the log pipeline.

## References

- Implementation (branch `feat-consistent_relay_port`): `src/masque/relay_server.rs`
  (`authenticated_peer_fingerprint` via `nat_traversal_api.rs`, `Reservation`,
  `lease_reservation`, `reclaim_reservation`, `cleanup_expired_reservations`),
  `src/masque/relay_session.rs` (`RelayPeerId`, `peer_id`).
- Identity: `src/nat_traversal_api.rs` (`authenticated_peer_fingerprint`,
  `extract_public_key_from_connection`), `src/crypto/raw_public_keys/pqc.rs`
  (`fingerprint_public_key`, `extract_public_key_from_spki`).
- Companion: saorsa-core `src/dht_network_manager.rs`
  (`clear_dial_failures_for_published`, `PublishAddressSet` handler,
  `DialFailureCache`); prior work V2-463 (relay-IP tier).
- Related ADRs: ADR-006 (MASQUE relay fallback), ADR-009 (relay data plane).
