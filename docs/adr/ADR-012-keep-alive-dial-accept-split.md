# ADR-012: Keep-Alive on the Dialling Side Only

## Status

Proposed

## Context

We wanted to cut wasted egress. A node in this network holds many connections
that sit idle most of the time, and it was paying far more to keep them open
than the job requires.

A QUIC keep-alive is a small packet sent on an otherwise silent connection so
that neither end times it out. Two things were wrong with ours.

**Both ends were configured to send them.** That does not mean two exchanges per
interval: any traffic resets both timers, so the shorter interval sets the pace
and the longer one rarely fires. The cost is one exchange per *shorter* interval.

**The accepting end's interval was not its own setting.** It read
`NatTraversalTimeouts::retry_interval`, the cadence for retrying NAT traversal —
an unrelated concern that happens to live in the same struct. In production that
made it 2 s, so the fleet's idle cadence was set by a NAT-retry knob nobody had
chosen for the purpose, and tuning NAT retries would have silently changed idle
bandwidth.

Together those cost **29.8 B/s per connection endpoint**, continuously, on an
idle 25-node testnet.

## Decision

Send keep-alives from the dialling side only, at a fixed 10 s:

```rust
// dialling side
transport_config.keep_alive_interval(Some(DIAL_KEEP_ALIVE_INTERVAL)); // 10 s
// accepting side
transport_config.keep_alive_interval(None);
```

`retry_interval` is no longer read by the keep-alive path at all.

**One side is enough.** The accepting end answers every keep-alive, so both idle
timers reset and each end still puts a packet on the wire once per interval.
That outgoing packet is also what keeps each end's NAT mapping alive, since
RFC 4787 mappings are refreshed by outbound traffic.

**Every connection has exactly one dialling end**, so this cannot leave a
connection with no keep-alive. Outbound `connect()`, hole punching and both
relay paths dial with the client config; simultaneous open makes two ordinary
client/server connections and deduplication picks one; migration keeps the
config the connection already had.

**The interval is the only real lever.** Because the shorter timer always
dominated, disabling one side saves nothing by itself — the saving comes from
10 s replacing an effective 2 s.

**Not configurable, deliberately.** A keep-alive interval is a property of the
network the fleet runs on, not a per-operator preference, and nobody can be
expected to know what to set it to. The coupling to `retry_interval` is an
example of what a settable value already cost us. Hard-coding means the value is
reviewed once, here, with its reasoning attached to it.

**Why 10 s and not longer.** The binding constraint is NAT mapping lifetime, not
the QUIC idle timeout. RFC 4787 requires mappings to survive two minutes, but
20–30 s middleboxes are reported in the field, and home routers and
carrier-grade NAT are where those live. If a mapping lapses, the keep-alive is
dropped at the peer's NAT *before* it can provoke the ACK that would have
refreshed it, so the connection cannot recover itself and needs a reconnect.
10 s is also below RFC 8085 §3.5's 15 s floor for general-Internet keep-alives —
a deliberate departure for a node whose reachability depends on those mappings.

## Consequences

**Idle egress falls 79.5%**, from 29.8 to 6.1 B/s per connection endpoint.
Measured two ways with no shared code path — a 25-node testnet (79.51%) and
in-process connection pairs (79.58%) — agreeing to 0.07 percentage points.
Figures are wire-equivalent: measured UDP payload plus an assumed 28 B IPv4+UDP
header per datagram.

**The saving is not linear in rollout.** A patched node dialling an un-upgraded
node saves *nothing* (measured 0%): the un-upgraded accepter keeps pinging at
its own 2 s cadence, and the shorter timer wins. The full saving arrives only
when both ends of a connection are upgraded, so plan the upgrade per connection
pair rather than expecting a proportional gain.

**No API or wire change.** No public type changes, so no semver break. No frame
or transport-parameter change either; the cadence is a local choice and never
negotiated, so patched and un-upgraded nodes interoperate in both directions.

**The accepting side stops taking RTT samples on idle connections.** An RTT
sample needs an ACK covering a locally-sent ack-eliciting packet, and ACK-only
responses do not produce one, so its PTO estimate can go stale on an otherwise
silent connection. Any application traffic restores sampling at once.

**Loss margin shrinks.** A lost keep-alive arms PTO rather than waiting for the
next one, so survivable consecutive loss depends on the path's PTO — roughly
seven outbound losses near a 1 s PTO, three near 5 s. Computed estimates; no
local path exercised loss, and every run recorded `lost_packets = 0`.

**Idle connections are cheaper to pin.** A conforming peer now needs one packet
before 30 s rather than an answer every ~2 s — roughly 15x fewer
attacker-originated packets, by packet-rate arithmetic rather than measurement.
Not a new capability: any authenticated packet already reset the idle timer, so
a peer willing to ignore the old PINGs could always have done this. Connection
caps are the mitigation, and `P2pConfig::max_connections` not being enforced at
the QUIC accept layer is a pre-existing gap this ADR does not address.

**Rollback is a dependency pin and a rolling restart.** There is no
configuration to change, by design. Existing connections keep the transport
config they were created with, so a revert takes effect on reconnect. No
durable wire, crypto or persisted state is involved, and mixed versions
interoperate, so the rollback need not be atomic.

### Not validated locally

Every measurement is loopback: **no NAT and no packet loss**, which is precisely
what the interval is chosen against. Two further caveats: the gap between
keep-alives is the interval **plus one round trip**, because the timer re-arms
on receive as well as send; and no jitter is applied, which RFC 8085 recommends.

Watch after rollout, comparing consumer and cellular nodes against a datacentre
control over at least seven days:

| signal | why |
|---|---|
| connection lifetime p10/p50, and the fraction closing at 30–45 s | a mode near 30 s is the NAT-timeout signature |
| reconnect rate and handshake bytes per node-hour | reconnects eat the saving; one costs ~165 s of it |
| `fail_timeout` audit outcomes | a dead connection reads as an unanswered audit and costs trust score |
| per-node UDP egress | confirms the saving is real off loopback |

Production does not record the first two today, which is worth fixing before
this reaches a large share of the fleet. If the lifetime signature appears,
shorten the interval rather than reverting. 5 s is the obvious step and still
removes the second timer, though note it is not a return to the old behaviour:
the previous *effective* cadence was the accepting side's 2 s, so only 2 s
reproduces it exactly. Any other regression means revert and diagnose.

## Alternatives Considered

**Make the interval configurable.** Rejected. A keep-alive interval is a
property of the network, not a per-operator preference; nobody can be expected
to know what to set it to, and the accidental coupling to `retry_interval` shows
what a settable value already cost. It also adds a knob that has to be
documented, validated, plumbed through consumers and reasoned about at every
layer, to express a value that should have exactly one correct setting.

**Dialling side only, but at the existing 2 s.** Saves nothing. The shorter
timer already dominated, so the effective cadence would be unchanged — it just
moves which side emits it.

**15 s.** Measured better still (86.5%), but leaves roughly half the headroom
against a short-timeout middlebox, and the failure does not degrade gracefully.
Given the network is meant to run on home connections, 10 s is the right side of
that trade to be wrong on.

**Disable the dialling side instead.** Symmetric in egress, worse operationally:
the dialling side is the one that knows it wants the connection kept open.

**Raise `max_idle_timeout` to 60 s.** Would restore margin against the idle
timeout at zero egress cost, but does nothing for NAT mapping lifetime, which is
the actual constraint — and it doubles how long a silent peer pins resources.
