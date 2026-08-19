# ADR-013: Relay Tunnel Teardown Ordering and Failure Classification

## Status

Proposed (2026-08-19)

## Context

A proactive relay allocation owns two coupled resources: a MASQUE tunnel
(`MasqueRelaySocket` and its reader, writer and keepalive tasks) and a second
Quinn endpoint that uses that tunnel as its `AsyncUdpSocket`. The endpoint's
inbound path exists only for as long as the tunnel does.

saorsa-core gates relay publication behind a canary quorum, so an allocation may
be prepared and then discarded without ever being published, and PR #131 made
that discard deterministic by aborting and joining the tunnel tasks. Between
them, relay teardown went from a rare event to a routine one: 1,773 teardowns
across 73 hosts in the 48 h after the 0.36.0 rollout, tracking node restarts.

That exposed two defects in the teardown path (V2-986), both invisible while
teardown was rare.

### 1. Ordering

`teardown` closed the endpoint, then destroyed the tunnel, then waited for the
endpoint to drain. `Endpoint::close` only *queues* a `ConnectionEvent::Close` per
connection; the frames still have to travel out through the tunnel. Destroying
the tunnel first removed the transport those frames needed. The connection driver
then handled the queued `Close`, immediately hit channel EOF because
`EndpointDriver::drop` had cleared `connections.senders`, and exited with
"endpoint driver future was dropped" *before* `drive_transmit`. The close frame
was built and never sent, and the peer was left to time out. The connection's
local close reason was overwritten by the internal transport error for the same
reason.

The `wait_idle` that followed was measuring nothing: it defines idle as an empty
sender map, which is exactly the map the dying driver had just cleared.

### 2. Classification

`MasqueRelaySocket::poll_recv` reported the recv channel closing as
`io::ErrorKind::BrokenPipe`, with no way to tell "the relay stream broke" from
"we aborted the reader task on purpose". Quinn treats a `poll_recv` error as a
socket failure: `EndpointDriver` resolves to `Err`, which is logged at ERROR and
whose `Drop` sets `driver_lost` and clears the connection senders instead of
letting the endpoint retire through its refcount-reaches-zero path. Every
requested teardown therefore produced
`ERROR ... I/O error: relay recv stream closed`: 2,338 occurrences in 48 h across
73 hosts, roughly 100x the previous rate.

Unexpected tunnel loss produces the identical line, so the message alone cannot
classify the fleet's occurrences; correlation with relay lifecycle logs puts at
least 56% of them on the requested-teardown path.

## Decision

**A teardown we requested is not a transport failure, and the endpoint drains
before the tunnel is dismantled.**

`ProactiveRelay::teardown` becomes `close` → bounded 1 s `wait_idle` →
`tunnel.shutdown()` → release the relay session. The reorder is what lets the
queued CONNECTION_CLOSE frames leave, and it makes `wait_idle` measure a real
drain.

`RelayTunnelControl` carries a `TunnelCause` of `Live`, `Failed` or
`ShutdownRequested` in an `AtomicU8` shared with the `MasqueRelaySocket` it owns,
settled by compare-exchange so the **first** transition out of `Live` wins.
`poll_recv`, on a closed recv channel with nothing buffered, returns
`Poll::Pending` for `ShutdownRequested` and the existing `BrokenPipe` otherwise.
The tunnel-death watcher likewise stays quiet for a requested teardown.

First-cause rather than a "shutdown was called" flag is load-bearing: cleanup
routinely arrives *after* a tunnel has broken, so last-writer-wins would let it
reclassify the failure that triggered it as intentional. For the same reason the
relay health monitor gets its own abort path
(`abort_unhealthy_proactive_relay`), which marks the tunnel failed before tearing
it down. Without that, `is_relay_healthy` can condemn a relay from the state of
the *outer* relay session while the tunnel's own cause is still `Live`, and the
teardown would settle `ShutdownRequested` first.

That verdict now names the relay it was reached about
(`unhealthy_published_relay`). Asking whether the relay is healthy and then
asking separately which relay is published are two awaits, and a replacement can
publish between them, in which case the monitor would tear down the healthy
replacement on the strength of a verdict about its predecessor.

Parking `poll_recv` does not strand the endpoint driver. Nothing can arrive on a
torn-down tunnel, and the driver keeps its other wake sources: the endpoint-event
channel, a connection's `Drained` event, and the explicit wake
`EndpointRef::drop` issues at refcount zero. So it still completes with `Ok(())`
once the endpoint is dropped.

One consequence has to be handled. The driver crashing was what released a
connection parked waiting for send capacity; it no longer crashes, so
`abort_tasks` wakes `send_capacity_freed` itself, and `TunnelPoller` consults a
`writer_stopped` flag alongside the channel state. Both halves are needed:
`JoinHandle::abort` is asynchronous, so the channel is typically still open when
that wake arrives, and a poller that looked only at the channel would see it full
and open, consume the notification, re-park, and never be woken again. Whenever
the poller answers "writable", `enqueue_outbound` must not answer `WouldBlock`,
because Quinn retries that immediately and without yielding. So a full queue
whose writer has stopped drops the datagram instead.

`writer_stopped` is tracked independently of the cause because the relay's two
stream halves are independent: a peer that resets only its server-to-client half
ends the tunnel while the writer remains able to flush what is queued. It is
recorded by a `WriterExit` guard held by the writer future, so it is set on every
path that ends the writer, including an abort that lands before the future's
first poll.

The cause, the writer state and both `Notify`s live in one `TunnelState` that the
control, the socket and the tunnel tasks all hold strongly. Reaching back through
a `Weak<RelayTunnelControl>` would not do: the dial-through path in
`p2p_endpoint` drops its control as soon as the dial completes, while the socket
and its tasks live on, and a writer that could not record its exit there would
leave a parked poller waiting forever.

## Consequences

### Benefits

- A requested teardown no longer produces an endpoint-driver I/O ERROR;
  unrequested tunnel loss still does.
- Peers reached through a discarded relay address get a real opportunity to
  receive CONNECTION_CLOSE and fail fast, instead of waiting out an idle timeout.
- The relay endpoint retires through the same path as any other endpoint, so
  `wait_idle` measures a real drain.
- Relay churn stays observable on the `info!` lifecycle logs that describe it
  accurately ("Proactive relay allocation prepared" / "Proactive relay torn
  down").

### Trade-offs

- Teardown may spend up to its 1 s drain budget before it begins releasing the
  relay server's capacity slot, since it is `shutdown()` closing the tunnel
  streams that lets the server observe the release. `NatTraversalEndpoint::shutdown`
  inherits the same bound before it closes ordinary connections.
- CONNECTION_CLOSE delivery is improved, not guaranteed. `Endpoint::close` uses
  `try_send` and drops the close event if a connection mailbox is full;
  `wait_idle` waits for Quinn's connection map to empty rather than for the
  MASQUE send queue to flush; `shutdown()` aborts the writer regardless of what
  is still queued; and Quinn does not consider a locally closed connection
  drained until `3 × PTO`, which 1 s need not cover.
- A connection whose close event was dropped is now left to its 30 s idle timeout
  rather than killed outright by the driver crash.
- A requested teardown no longer produces a transport-level receive signal. This
  is deliberate, and is why the change is paired with tests asserting that
  unrequested tunnel loss still fails `poll_recv`, is still logged, and is not
  reclassified by cleanup arriving afterwards.
- `ProactiveRelay::drop`, the forced-cleanup fallback that already logs a
  warning, cannot await. It still closes and calls `shutdown_now()` without
  draining. That path is reached only when an allocation is dropped without going
  through `teardown`, which is what the existing warning is for.
- A tunnel that breaks on its own between `close()` and `shutdown()` settles as
  `Failed`, so `poll_recv` reports it. Correct, but it means the log line can
  still appear during an otherwise orderly teardown.

### Risks

- If some future caller shuts a tunnel down and keeps using its endpoint, that
  endpoint goes quiet instead of erroring. `TunnelCause` is reachable only
  through `RelayTunnelControl`, whose callers are the relay lifecycle paths in
  `nat_traversal_api`, so the blast radius is bounded to code that already
  intends the socket to be dead.

## Alternatives Considered

- **Downgrade the log line at the driver.** Rejected: the log site is generic
  code shared by every endpoint, and it would suppress genuine `BrokenPipe`
  failures from ordinary UDP sockets too.
- **Return `Poll::Ready(Ok(0))` instead of parking.** Rejected: `poll_socket`
  re-polls immediately, records no work, and self-schedules, so it spins.
- **Reuse `is_transient_recv_error`.** Rejected for the same reason: that
  classifier makes `poll_socket` `continue`.
- **Fix only the ordering.** Rejected: the endpoint still holds live references
  (the accept loop's, and `ProactiveRelay`'s own) when the tunnel is finally
  destroyed, so the driver would still observe the socket disappear and still
  fail.
- **A boolean "shutdown was requested" flag.** Rejected: cleanup arriving after a
  failure would silence it. Hence first-cause `TunnelCause`.
- **Classify `try_send` errors too.** Rejected: `ConnectionDriver` already treats
  every non-`WouldBlock` send error as ordinary packet loss (rate-limited
  `warn!`, datagram dropped, driver untouched), so there is no fatal path to
  spare.

## References

- Linear V2-986: "relay recv stream closed" transport errors up ~100x fleet-wide
- PR #131: identity-scoped relay publication. Introduced `RelayTunnelControl` and
  deterministic teardown, first released in 0.36.0.
- saorsa-core ADR-016: canary-gated proactive relays
- `src/masque/relay_socket.rs`: `RelayTunnelControl`, `TunnelCause`,
  `WriterExit`, `MasqueRelaySocket::poll_recv`
- `src/nat_traversal_api.rs`: `ProactiveRelay::teardown`,
  `abort_unhealthy_proactive_relay`
- `src/high_level/endpoint.rs`: `EndpointDriver::poll`, `State::drive_recv`,
  `EndpointRef::drop`
