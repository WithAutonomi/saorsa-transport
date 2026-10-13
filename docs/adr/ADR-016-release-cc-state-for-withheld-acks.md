# ADR-016: Release Congestion-Control State for Packets Whose ACK Is Withheld

## Status

Proposed

## Context

When a peer's address changes, `Connection::migrate` moves the connection to a
new path and validates it with a PATH_CHALLENGE. Until the PATH_RESPONSE
arrives, `on_packet_acked` withholds ACKs from the congestion controller, so
that late ACKs from the old path cannot skew the new path's estimates. That
rule comes from Quinn, whose controllers keep no per-packet state, so a
withheld ACK cost nothing.

BBRv2, the default controller since v0.33.0, does keep per-packet state: the
adapter's set of unacked packets and the bandwidth sampler's per-packet map.
Every ack-eliciting packet gets an entry when it is sent, and only `on_ack`,
`on_packet_lost`, `on_packet_abandoned` or `on_packet_neutered` release it. A
withheld ACK called none of them, so its packet stayed tracked for as long as
that path's controller lived: after a successful migration, until the
connection closed. It then counted as the oldest unacked packet, and since the
sampler map only drops entries from the front, every ack-eliciting packet sent
afterwards kept an entry too.

When a connection migrates while sending, BBRv2 starts fresh on the new path,
and a single ack-eliciting packet sent there whose ACK is processed before the
PATH_RESPONSE is enough to pin it. The packet carrying the PATH_CHALLENGE is a likely one:
when the peer sends its ACK and its PATH_RESPONSE in one packet, it writes the
ACK frame first. Every migration in the local tests pinned the controller this
way.

This matches a production incident: nine services sending heavily, mostly as
relays, to peers behind one NAT'd address started retaining memory within the
same half hour, kept 10-15% of the bytes they sent there, and grew by 1.7-7.2
GiB within hours; the one with a kernel log on record was killed for running
out of memory. Production does not log path migrations, so the trigger is
inferred from that signature. A local NAT-rebind reproduction
kept 16.9% of the bytes sent after the rebind, and a heap profile placed 112
of 121 MiB of live heap in the sampler map.

A related gap exists when validation fails. Migration parks the previous
path's controller, still tracking the packets that were in flight at that
moment. That snapshot does not grow, since nothing is sent through a parked
controller, but the `PathValidation` timer can restore it, and its stale
entries would then pin it the same way. (Its count of bytes in flight is stale
too, but `on_end_acks` already resets that from the connection's count on the
next ACK.)

## Decision

1. **Neuter a packet whose ACK is withheld.** While the path is being
   validated, `on_packet_acked` calls `on_packet_neutered` for each
   ack-eliciting packet instead of skipping the controller. The controller
   drops its state for the packet and takes no sample from the ACK, without
   touching its count of bytes in flight, so its congestion response during
   validation is unchanged. (That count must stay put because the packet may
   predate the current path's controller, which never counted it.)
2. **Resync from the connection after every ACK frame that acknowledges
   something new.** The connection already knows exactly which packets are
   outstanding. Once `on_end_acks` has flushed the batch, it passes the
   controller the sample packet number of the oldest one
   (`Controller::on_least_unacked`). BBRv2 drops whatever it still tracks
   below that and trims its sampler map. This does for per-packet state what
   `on_end_acks` already does for the byte count: it covers a restored path
   from the first ACK there that acknowledges something new, and any future
   path that resolves a packet without telling the controller.

## Consequences

- A resolved packet can no longer pin the active path's sampler map: after
  each ACK frame that acknowledges new packets, the map is trimmed up to the
  connection's oldest outstanding packet, whatever migrations the connection
  has been through. A parked previous path keeps at most the snapshot it had
  at migration, as before.
- No wire, API or configuration change, and no change to BBRv2's ACK
  sampling or its in-flight byte accounting. The other controllers keep no
  per-packet state and ignore both calls.
- The resync costs a handful of lookups per ACK frame when nothing is stale:
  the first entry of each packet space's sent-packet map, of BBRv2's unacked
  set and of its sampler map.
- Nodes need the new build and a restart; there is nothing to coordinate with
  peers.

## Alternatives Considered

**Stop withholding ACKs during validation.** Would change how BBRv2 reacts to
every migration, which is what the rule exists to prevent, to fix a bookkeeping
problem.

**Cap the sampler map at a fixed size.** A small cap drops state for packets
that really are in flight on a large bandwidth-delay product, and a large one
only limits stale retention rather than removing it. The connection's
outstanding set already gives the exact point to trim to.

**Carry BBRv2 state across migration.** Unrelated to the leak: the withheld
ACKs would still pin a cloned controller the same way.

## References

- `src/connection/mod.rs`: `on_packet_acked`, `on_ack_received`,
  `least_unacked_sample_pn`, `migrate`, the `Timer::PathValidation` handler
  (which restores the previous path)
- `src/congestion.rs`: `Controller::on_packet_neutered`,
  `Controller::on_least_unacked`
- `src/congestion/bbr2/adapter.rs`: `Bbr2Adapter::on_least_unacked`
- Tests: `src/connection/migration_congestion_tests.rs` (a real migration
  mid-transfer through a rebinding UDP proxy) and
  `src/congestion/bbr2/smoke_tests.rs`
