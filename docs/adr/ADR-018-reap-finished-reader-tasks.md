# ADR-018: Reap Finished QUIC Reader Tasks

## Status

Proposed

## Context

`P2pEndpoint` gives every QUIC connection a reader task that accepts the
connection's unidirectional streams and forwards their data to the endpoint's
channel. The accept path, the connect paths and the hole-punch forwarder all
spawn these readers into one `JoinSet`, `reader_tasks`, and keep an
`AbortHandle` per address so that a later reader or a disconnect can stop the
earlier one.

A reader ends when its connection closes or when it is aborted, and its future
is then dropped, releasing the connection and its buffers. The task itself is
not released: a `JoinSet` keeps each finished task allocated until it is
joined or the set is dropped, and nothing joined `reader_tasks`. Shutdown
calls `abort_all`, which aborts but does not join. So every connection an
endpoint ever had kept its reader's task allocation until the endpoint was
dropped, which for a node is when the process exits. The set replaced a
`HashMap` of join handles that disconnects cleaned up, in v0.21.0.

A 91-hour heaptrack trace of ant-node 0.22.0 shows it: 4.84 MB still
allocated at exit from `spawn_reader_task` on the accept path, over 9,461
allocations. That is about 512 bytes per allocation, the size of one reader's
task in a local build, so the trace fits every reader that node ever spawned
there still being allocated, not only those of the connections it had open
when it stopped. The connect paths add their own share.
It is a small leak, about half a KiB per connection, but it grows for the life
of the process.

## Decision

Spawn every reader through `spawn_reader`, which first joins the readers in
the set that have already finished, then spawns the new one. A reader that
panicked is logged at warn as it is joined; one that was aborted is not, since
aborting is how disconnects and replacement readers stop it.

## Consequences

- `reader_tasks` holds the live readers plus those that finished since the
  previous spawn, instead of one entry for every connection ever made. An
  endpoint that stops making connections keeps the readers that finished
  after its last spawn until it is dropped, which is bounded by how many
  connections it had open at once.
- Joining a finished task costs a pop from the set's list of finished tasks,
  under the lock the spawn already takes.
- Reader panics were invisible; they are now logged when joined.
- No wire, API or configuration change. Nodes need the new build and a
  restart.

## Alternatives Considered

**Also join from the reader-exit handler or the stale-connection reaper.**
This would free the readers that finish after the last spawn sooner, but an
endpoint making no new connections holds at most as many of those as it had
connections open at once, so the extra joining points would not change the
bound.

**Spawn readers with `tokio::spawn` and drop the `JoinSet`.** Finished tasks
would be freed at once, but dropping the endpoint would no longer abort its
readers, and shutdown would have to rely on every live reader still having an
entry in `reader_handles`.

## References

- `src/p2p_endpoint.rs`: `spawn_reader`, `P2pEndpoint::spawn_reader_task`,
  `P2pEndpoint::spawn_incoming_connection_forwarder`, `run_quic_reader_task`,
  `P2pEndpoint::shutdown`
- Test: `p2p_endpoint::tests::test_finished_reader_tasks_do_not_accumulate`
