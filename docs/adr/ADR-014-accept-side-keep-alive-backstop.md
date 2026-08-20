# ADR-014: Accept-Side Keep-Alive Backstop

## Status

Proposed

Amends [ADR-012](ADR-012-keep-alive-dial-accept-split.md), which is otherwise
unchanged: the dialling side still drives the cadence at 10 s and still supplies
the traffic that refreshes NAT mappings.

## Context

ADR-012 moved keep-alives to the dialling side only and took idle egress down
78% on a 990-node testnet. It also left the accepting side with no timer of any
kind, and that turns out to cost more than the reasoning there allowed for.

A QUIC connection closes silently once it has received nothing for
`max_idle_timeout`, 30 s here. What a connection can absorb before that happens
is not set by the loss *rate* — it is set by how long it can be totally silent.
The interesting failure is therefore a short outage rather than a percentage of
lost datagrams: a stretch where nothing arrives at all, which is what receive
buffer saturation on a loaded node looks like from the far end.

Measured against a recurring bidirectional outage, on a path with 40 ms RTT and
1.5% background loss, three connections per outage length. The outage recurs
every 90 s inside a 300 s window, so each connection meets it three times, and
its phase relative to the keep-alive timers is not controlled — the connections
in a group start together, so a group shares a phase and the thresholds below
are the behaviour at the phases sampled rather than a worst case. Loss is a
deterministic function of each socket's datagram ordinal, so the arms meet the
same pattern.

| Outage | both sides on a timer | dialling side only |
|---:|---:|---:|
| 13 s | 0/3 died | 0/3 died |
| 15 s | 0/3 | 0/3 |
| **17 s** | **0/3** | **3/3** |
| 21 s | 0/3 | 3/3 |
| 25 s | 0/3 | 3/3 |
| 29 s | 3/3 | 3/3 |

**The survivable outage fell from about 28 s to about 16 s** at the sampled
phases. A stall between those two figures took the connection down where it
previously rode through, at every length tested in that range. Two effects
compound, and the second is the larger:

1. With a 10 s cadence the connection is already about 5 s into its silence when
   the outage begins, against about 1 s at ADR-012's effective 2 s baseline.
2. **Recovery afterwards is slower.** Only the dialling side probes, and its
   probe timer backs off exponentially, so the first packet after a stall can be
   roughly 10 s late. With a timer on both sides the accepting side probes on
   its own and its timer re-arms on every send, so it does not inherit that
   backoff.

Uniform loss does not appear to produce this at fleet rates: at 1.5% neither
arrangement lost a connection across twenty idle windows, and losing every
opportunity in a 30 s window works out on the order of 1 in 10^11. That is an
estimate from the packet arithmetic rather than a measured bound, and it says
nothing about correlated loss, which is what the outage model above stands in
for.

This also fits where the effect was seen. Brief total stalls are a load
phenomenon — the fleet logged 61.5M receive-buffer overflow errors per hour
under load against 2,115 when idle — and the connection-lifecycle change
reported after ADR-012 shipped appeared only in the loaded phase.

## Decision

Give the accepting side a keep-alive again, as a backstop rather than a cadence:

```rust
// accepting side
transport_config.keep_alive_interval(Some(ACCEPT_KEEP_ALIVE_BACKSTOP)); // 25 s
// dialling side, unchanged from ADR-012
transport_config.keep_alive_interval(Some(DIAL_KEEP_ALIVE_INTERVAL)); // 10 s
```

**It restores the margin across the range tested.** With the backstop,
connections survived the 17 s, 21 s and 25 s outages that killed every
connection without it, matching the pre-ADR-012 arrangement at every length
sampled. At 29 s both arrangements lose connections, as expected against a 30 s
idle timeout.

**It is expected to add no measurable steady-state egress.** The keep-alive timer re-arms on
every packet received as well as sent (`connection/mod.rs` on authenticated
receive, `connection/packet_builder.rs` on send), and the dialling peer pings
every 10 s, so on a healthy connection the backstop has no room to fire. That is
asserted on a lossless loopback path by `tests/keep_alive_asymmetry.rs`, which
requires the accepting side to emit no keep-alive across a 40 s idle window. It
is not a proof for the fleet: the real gap between received packets is the
cadence plus a round trip, and a degraded-but-live connection that loses pings
can stretch it further. The expectation is that ADR-012's measured 78%
idle-egress reduction survives essentially intact, and per-node idle egress
after rollout is the number that confirms it.

**Why 25 s.** The value is bounded from both directions.

Below, by the cost: too low and it fires in ordinary operation. Restoring the
outage margin does not need a small value — 5 s was measured alongside 25 s and
behaved identically at every length — because what restores the margin is having
a timer at all, not how often it runs. So the interval is free to sit well clear
of the 10 s cadence, and should.

Above, by two costs.

The first is the timer service margin. `handle_timeout` services timers in
`Timer::VALUES` order and `Idle` is ordered before `KeepAlive`, so if the
connection driver is not polled for the gap between the two deadlines, the idle
timeout is processed first and the connection closes without the backstop being
sent. 5 s is the nominal difference between the constants and the most that gap
can be; the real separation can be smaller, because sending re-arms the
keep-alive timer while the idle timer is only re-armed by the first
ack-eliciting send after a receive. Driver stalls are a load phenomenon and load
is the condition this ADR is about, so the margin is worth stating plainly.

The second is dead-peer retention. The backstop PING is ack-eliciting, so the
first one sent after a peer goes quiet re-arms the idle timer, and a peer that
disappears is retained for roughly the backstop plus the idle timeout — about
55 s, against 30 s with no timer on this side and about 32 s under the 2 s
arrangement that preceded ADR-012. Later probes do not extend it further, since
only the first ack-eliciting send after a receive resets the idle timer. This is
inherent to having a backstop at all, and a lower value would shorten it. It
matters more than it otherwise would because `P2pConfig::max_connections` is not
enforced at the QUIC accept layer, a pre-existing gap ADR-012 also noted.

25 s therefore favours not reintroducing the idle-egress cost, which is the
whole point of the arrangement it protects, and pays for that on the other two.
If the fleet shows either — connections closing without the backstop under load,
or dead-peer retention pressing on connection capacity — a lower value inside
the measured range is the lighter response than removing the backstop.

## Consequences

**Idle egress is expected to be unchanged in steady state**, by the argument
above and by `tests/keep_alive_asymmetry.rs`, which asserts the accepting side
emits zero keep-alives across a 40 s idle window while the dialling peer pings.
That test runs on a lossless loopback path, so it establishes the mechanism
rather than the fleet result; per-node idle egress after rollout is what
confirms it.

**The accepting side takes RTT samples again** once the backstop fires, which
ADR-012 noted it had stopped doing. That consequence is narrowed rather than
removed: on a healthy connection the backstop does not fire, so the estimate
still goes stale there. Measurement found no cost either way — after idling past
the timeout, the accepting side's estimate read within a few milliseconds of the
true path RTT, because a stale estimate on a stable path is a correct one.

**No API or wire change.** The interval is a crate-private constant, and the
cadence is a local choice that is never negotiated, so patched and un-upgraded
nodes interoperate in both directions.

**A disappeared peer is retained for longer**, roughly 55 s rather than 30 s,
for the reason given under the interval choice above. On a node holding many
mostly-idle connections this raises the steady-state count of connections whose
peer is already gone.

**Rollback is a dependency pin and a rolling restart**, as with ADR-012.
Existing connections keep the transport config they were created with, so a
revert takes effect on reconnect and need not be atomic.

### Not validated here

The measurements above come from an in-process harness with an injected one-way
delay and drop pattern, not from a testnet, and that harness is not checked in
here — it carries a dev-dependency and an impairment layer out of proportion to
this change. Three limits follow.

The harness had to be made trustworthy before any of its numbers were: applying
the delay with one task per datagram reorders datagrams, and QUIC declares a
packet lost once three later ones are acknowledged, so a first attempt
manufactured roughly twelve times more loss than it injected and produced large
but entirely artificial differences between the arms. Delivery is now strictly
FIFO and every run reports declared losses over injected drops, which must read
1.0. Any repeat of this measurement should report that ratio too.

Sample size is three connections per outage length, at a single phase each, so
the thresholds locate a step rather than measure a distribution. The step itself
is unambiguous — 0/3 against 3/3, at three consecutive lengths, reproduced
across two runs — but the exact boundary is bracketed, not pinned.

What remains unmeasured is how often stalls long enough to matter — the tested
lengths sat between about 16 s and about 28 s — actually occur on the fleet. This ADR shows the margin was lost and that the backstop restores
it; it does not establish how often that margin was being called upon. Watch
connection lifetimes and reconnect rate under load after rollout, which is the
signal ADR-012 already asked for and production does not yet record.

## Alternatives Considered

**Leave it as ADR-012 shipped it.** Rejected. The lost margin is real and
reproducible, and restoring it is expected to add no measurable egress.

**A tighter backstop, 5 s.** Measured, and no better across the whole outage
range. It gives up headroom against the dialling cadence for nothing.

**Shorten the dialling interval instead.** Would narrow the first of the two
effects and none of the second, since recovery would still wait on one side's
backing-off probe timer, and it would give back a proportional share of the
idle-egress saving.

**Raise `max_idle_timeout`.** Would widen the survivable outage on both
arrangements, but it is a different decision with its own cost — a silent peer
pins resources for longer, which the backstop already adds to — and it does not
address the asymmetry this ADR is about.
