# ADR-017: End Pending DTLS Handshakes When Closing a WebRTC Direct Association

## Status

Proposed

## Context

A WebRTC Direct listener answers as the DTLS server ([ADR-015](ADR-015-direct-browser-webrtc.md)).
Once ICE connects, the peer connection's operation queue runs
`start_transports`, which calls `RTCDtlsTransport::start`, which waits in
`DTLSConn::new` for the browser's ClientHello. While it waits, a reader task
reads the DTLS endpoint of the ICE mux with no deadline and a writer task
waits for outgoing records. Until the browser's second ClientHello (the one
answering HelloVerifyRequest), the server has nothing to retransmit, so a
browser that stops sending never makes the handshake fail: it re-arms a
one-second retransmit timer for as long as the reader lives.

Closing the peer connection does not end that wait in webrtc 0.14:

- `RTCDtlsTransport::stop` closes only an established DTLS connection, and
  there is none until the handshake completes.
- `RTCIceTransport::stop` calls `Mux::close`, which removes the mux endpoints
  but never closes their buffers, so the reader stays blocked.
- `Operations::close` only signals the queue's worker, which is still inside
  `start_transports`.

So every browser that connects ICE and stops before its second ClientHello
leaves three tasks behind for the life of the process: the operation-queue
worker, still running the handshake, and the handshake's reader and writer.
They hold the peer connection's internals (DTLS and ICE transports, media
engine, interceptors), about 62 KiB, and the handshake wakes once a second.
webrtc 0.17.2 and upstream's `v0.17.x` branch have the same code. The
reference-cycle fix in webrtc-rs #909 is unrelated: it targets the 0.21
rewrite, and only connections with media tracks.

The evidence points to this as the main cause of the slow memory growth seen
across the production fleet. The fleet logged between 340,000 and 850,000
inbound WebRTC attempts a day this week, and only about 3% reach `connected`.
In the sampled failing ones, ICE connects within about 100 ms, the peer
connection stays `connecting`, and the 10-second setup deadline closes it. On
ant-node 0.22.0, among services with RSS readings at both ends of the window
and no detected reset, an OLS fit of per-service RSS growth against those
attempts gives 68.6 KiB per attempt (r² 0.88, 759 services, 10 October 06:00 to
12 October 15:00 UTC, 57 hours) and 67.1 KiB per attempt (r² 0.70, 731
services, 13 October 00:00 to 15 October 00:00 UTC, 48 hours); the fitted
attempt term accounts for 65% and 74% of those services' total RSS growth in
the two windows. In a local harness, the listener runs in its own process while
eight clients each connect through their own STUN-only relay. The listener
keeps 61.9 KiB and three tasks per attempt, linearly over 160 attempts, with
nothing released afterwards. Successful sessions, and attempts that never
connect ICE, keep nothing.

## Decision

**Before closing an inbound peer connection whose DTLS transport is still
`Connecting`, deliver a DTLS close_notify to its handshake through ICE.**
Teardown writes a plaintext close_notify alert record (epoch 0, sequence number
2^48 - 1) into the association's ICE connection as if it came from the
browser's address. ICE passes it to the mux, the mux to the DTLS endpoint, and
the reader treats it like any close_notify: it stops reading, so the handshake
fails and `start_transports` returns. Teardown waits up to one second for the
transport to leave `Connecting`, then calls `close` as before. The record is
best effort: if writing it fails, or the transport is still `Connecting` after
one second, teardown calls `close` anyway and the handshake can stay pending
as it did before this change.

**If the DTLS transport is still `New`, teardown stops it first.**
`prepare_transport` only starts a handshake from `New`, so ICE connecting while
the peer connection closes can no longer start one that nothing would end. A
start that had already passed that check gets the close_notify if teardown
sees `Connecting` when it reads the state again (see Consequences for when it
does not). Because webrtc reports a peer connection with ICE connected and
DTLS closed as `Connected`, the listener's diagnostics now count a connection
as successful only once its DTLS handshake has completed (the transport has
stored the remote certificate), so ICE connecting during such a close is not
recorded as a success.

The three inbound teardown paths go through this step: the setup deadline,
`WebRtcDirectConnection::close`, and dropping an association without closing
it. Each runs while ICE still delivers packets, before `close` stops it. Listener
shutdown is the exception: `WebRtcDirectListener::close` closes every ICE
connection first, so a handshake still pending then stays pending until the
process exits. ant-node closes its listener only when the node stops.

The record's sequence number is the last one DTLS allows. A browser's handshake
records count up from zero, so the replay window accepts it.

## Consequences

- An abandoned handshake releases its tasks and peer connection when the
  association closes, instead of never, once the close_notify reaches it within
  the one-second wait.
- One narrow window remains: a start that passes its `New` check just before
  teardown stops the transport, and whose `Connecting` teardown does not see
  on its next read, because it is published after that read or overwritten by
  the stop's `Closed`. The start only takes a few uncontended locks between its
  check and that publish, and it needs ICE to connect at that same instant.
- The reader answers the close_notify with its own, so the listener sends one
  15-byte datagram toward the browser when it closes an association whose DTLS
  transport is `Connecting`. A transport still in `New` sends nothing.
- Teardown of such an association waits for the handshake to end: 12 to 19 ms
  in local browser runs, at most one second. If the close_notify cannot be
  written, or the handshake outlives that second, the close goes ahead and the
  handshake stays pending, as before this change.
- Associations with a completed handshake close as before. One whose DTLS
  never started is stopped before the peer connection closes, which ends the
  same way. No wire-format, API or configuration change, and no change to
  outbound dials, whose DTLS client sends and retransmits flights and fails on
  its own. The listener's diagnostics count an inbound connection as successful
  only once it has a stored remote certificate.
- Nodes need the new build and a restart; there is nothing to coordinate with
  browsers.

## Alternatives Considered

**Upgrade webrtc.** No release fixes this: 0.17.2 has the same code, and the
0.21 rewrite is a different API that ant-node and the browser profile do not
use.

**Patch webrtc.** Closing endpoint buffers in `Mux::close` alone would turn the
blocked read into a busy loop, because the DTLS reader retries every read error
except an alert. A fork needs both changes, plus a `[patch]` in every binary
that depends on this crate. Worth proposing upstream, but not a fix the fleet
can take this week.

**Send the alert after `close`.** By then the mux read loop has stopped, so
nothing reaches the endpoint.

**Answer as DTLS client.** The listener would then drive the handshake and
fail on its own, but it changes the browser profile.

## References

- `src/webrtc/direct.rs`: `close_inbound_peer`, `DTLS_CLOSE_NOTIFY`,
  `create_inbound_connection` (setup deadline), `AssociationOwner`,
  `WebRtcDirectConnection::close`
- webrtc 0.14.0: `dtls_transport/mod.rs` (`start`, `stop`), `mux/mod.rs`
  (`Mux::close`), `peer_connection/operation/mod.rs` (`Operations::close`);
  dtls 0.13.0: `conn/mod.rs` (`DTLSConn::new`, `read_and_buffer`)
- Tests: `close_on_accept_releases_dtls_transport`,
  `close_releases_pending_dtls_handshake`,
  `drop_releases_pending_dtls_handshake`,
  `setup_deadline_releases_pending_dtls_handshake` (a native client behind a
  relay that drops DTLS) and
  `close_notify_record_decodes_as_a_plaintext_close_notify`
