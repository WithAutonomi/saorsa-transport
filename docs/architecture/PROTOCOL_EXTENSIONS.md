# saorsa-transport Wire Reference: QUIC Extensions

This document specifies the QUIC transport parameters and extension frames that saorsa-transport puts on the wire for NAT traversal and address discovery. It is normative for peer implementations: a compatible peer must produce and accept what is described here.

It describes the code at commit 84b9097e, including behaviour that is probably unintended; those cases are listed under "Known issues". It is based on `draft-seemann-quic-nat-traversal-02` and `draft-ietf-quic-address-discovery-00` (copies in `docs/rfcs/`), with the deviations listed below. Where this document and a draft disagree, this document describes what saorsa-transport does.

Conventions: `(i)` is a QUIC variable-length integer (RFC 9000 section 16); `(n)` is n bits; all fixed-width integers and ports are big-endian.

## Transport parameters

These are ordinary QUIC transport parameters, carried in the TLS transport-parameters extension.

| ID | Name | Value encoding | Who may send |
|---|---|---|---|
| `0x3d7e9f0bca12fea6` | nat_traversal | Empty (length 0) = "ClientSupport". Non-empty = one varint, the concurrency limit = "ServerSupport". | Either endpoint may send either form (symmetric P2P). |
| `0x3d7e9f0bca12fea8` | rfc_nat_traversal (saorsa-specific, not in the draft) | Empty (length 0). Any non-empty value is Malformed. | Either endpoint. Sent whenever NAT traversal is configured. |
| `0x9f81a176` | address_discovery | One varint: `0` = send only, `1` = receive only, `2` = send and receive. | Either endpoint. |
| `0x50C0` | pqc_algorithms | Length 1, then one byte bitfield: bit 0 = ML-KEM-768, bit 1 = ML-DSA-65, bits 2-7 reserved (sent as 0). | Either endpoint. The ID is in the experimental range; not IANA-assigned. |

Validation:
- Each of these parameters may appear at most once; a duplicate is Malformed.
- nat_traversal: a concurrency limit of 0 is IllegalValue on either side. A limit above 100 is IllegalValue only when the receiver is the accepting (server) side of the connection; the dialling side accepts any non-zero value.
- address_discovery: any value other than 0, 1, 2 is Malformed.
- pqc_algorithms: a length other than 1 is Malformed.
- Senders must write the length as the exact encoded size of the value. The decoder does not check that the length of nat_traversal (ServerSupport) or address_discovery matches the varint it reads (see Known issues).

Negotiation:
- NAT traversal is active on a connection only if the local endpoint has it configured, the peer sent nat_traversal, and at least one of the two sent ServerSupport. If both sent ClientSupport, it is not active. The concurrency limit is validated as above but has no further effect on the wire.
- The RFC frame format (below) is used for sending only if the local endpoint has NAT traversal configured and the peer sent rfc_nat_traversal. Otherwise the legacy format is used for sending.
- A node sends OBSERVED_ADDRESS once the peer has sent address_discovery, whatever its value, unless the application has disabled address discovery. The node's own address_discovery value and the 0/1/2 modes are not consulted when sending or receiving (see Known issues).

## Frame types

Frame types are encoded as varints. All of them are larger than 16383 and smaller than 2^30, so each takes 4 bytes on the wire. Each frame that carries an address has one type for IPv4 and one for IPv6, as listed below. Take the address family from this table, not from the type's parity: for ADD_ADDRESS, PUNCH_ME_NOW and OBSERVED_ADDRESS the IPv4 type is even, but for TRY_CONNECT_TO and TRY_CONNECT_TO_RESPONSE it is odd.

| Frame | IPv4 | IPv6 |
|---|---|---|
| ADD_ADDRESS | `0x3d7e90` | `0x3d7e91` |
| PUNCH_ME_NOW | `0x3d7e92` | `0x3d7e93` |
| REMOVE_ADDRESS | `0x3d7e94` (one type, no address) | |
| TRY_CONNECT_TO | `0x3d7e95` | `0x3d7e96` |
| TRY_CONNECT_TO_RESPONSE | `0x3d7e97` | `0x3d7e98` |
| OBSERVED_ADDRESS | `0x9f81a6` | `0x9f81a7` |

The authoritative IDs are the `FrameType` constants in `src/frame.rs`.

These frames are only valid in 1-RTT packets. Received in an Initial, Handshake or 0-RTT packet, any of them is a PROTOCOL_VIOLATION. Senders must not put them in 0-RTT packets.

## Frame layouts

IPv4 address = 4 bytes, IPv6 address = 16 bytes, followed by a 16-bit port. In the RFC format (and all frames other than legacy ADD_ADDRESS and PUNCH_ME_NOW) the address family is given by the frame type alone; there is no version byte.

### ADD_ADDRESS

RFC format (identical to the draft):

```
ADD_ADDRESS Frame {
  Type (i) = 0x3d7e90 / 0x3d7e91,
  Sequence Number (i),
  IP Address (32 or 128),
  Port (16),
}
```

Legacy format:

```
ADD_ADDRESS Frame {
  Type (i) = 0x3d7e90 / 0x3d7e91,
  Sequence Number (i),
  Priority (i),
  IP Version (8) = 4 or 6,
  IP Address (32 or 128),
  Port (16),
  [ Flow Info (32), Scope Id (32) ]   // IPv6 only
}
```

In the RFC format no priority is sent; the receiver computes a local priority from the address. Local candidates are numbered from sequence number 1.

### PUNCH_ME_NOW

RFC format:

```
PUNCH_ME_NOW Frame {
  Type (i) = 0x3d7e92 / 0x3d7e93,
  Round (i),
  Paired With Sequence Number (i),
  IP Address (32 or 128),
  Port (16),
  Has Target Peer Id (8) = 0 or 1,      // saorsa extension
  [ Target Peer Id (256) ],             // present iff the flag is 1
}
```

Legacy format: as above, but with `IP Version (8)` before the address and `Flow Info (32), Scope Id (32)` after the port for IPv6, then the same trailer. The trailer is always written by the sender; the draft has no trailer. A flag value other than 0 or 1 is a decode error.

IP Address and Port are the address the receiver should punch towards, normally the sender's own external address. A frame sent directly rather than relayed may carry the unspecified address and port 0. Target Peer Id identifies the peer a coordinator should relay the frame to (see Coordination).

### REMOVE_ADDRESS

Same in both formats:

```
REMOVE_ADDRESS Frame {
  Type (i) = 0x3d7e94,
  Sequence Number (i),
}
```

### OBSERVED_ADDRESS

Identical to the draft:

```
OBSERVED_ADDRESS Frame {
  Type (i) = 0x9f81a6 / 0x9f81a7,
  Sequence Number (i),
  IP Address (32 or 128),
  Port (16),
}
```

A connection sends one OBSERVED_ADDRESS, with sequence number 0, reporting the peer's address on the primary path.

### TRY_CONNECT_TO and TRY_CONNECT_TO_RESPONSE

Not in either draft. Decoded and validated on receive; never sent (see Known issues).

```
TRY_CONNECT_TO Frame {
  Type (i) = 0x3d7e95 / 0x3d7e96,
  Request Id (i),
  IP Address (32 or 128),
  Port (16),
  Timeout Ms (16),
}

TRY_CONNECT_TO_RESPONSE Frame {
  Type (i) = 0x3d7e97 / 0x3d7e98,
  Request Id (i),
  Success (8) = 1 on success, otherwise 0,
  Error Code (8),                      // written as 0 on success
  Source IP Address (32 or 128),
  Source Port (16),
}
```

Error codes: 0 Timeout, 1 ConnectionRefused, 2 NetworkUnreachable, 3 HostUnreachable, 4 RateLimited, 5 InvalidAddress, 255 InternalError. Any other received value is treated as InternalError. The error code is ignored when Success is non-zero.

### Format selection

A sender uses the RFC format for ADD_ADDRESS and PUNCH_ME_NOW only when the peer advertised rfc_nat_traversal (see Negotiation); otherwise it uses the legacy format. A receiver always tries the RFC layout first and falls back to the legacy layout only if that fails. In practice only the RFC format can be received reliably (see Known issues). All other frames have a single format.

## Receive rules

- ADD_ADDRESS, PUNCH_ME_NOW, REMOVE_ADDRESS received when NAT traversal is not active on the connection: PROTOCOL_VIOLATION. TRY_CONNECT_TO and TRY_CONNECT_TO_RESPONSE do not require NAT traversal.
- OBSERVED_ADDRESS received on a connection where the peer did not send address_discovery, or where the application has disabled address discovery: PROTOCOL_VIOLATION.
- The draft's direction rules (ADD_ADDRESS and REMOVE_ADDRESS server-to-client only, PUNCH_ME_NOW client-to-server only) are not enforced; any peer may send any of them.
- ADD_ADDRESS is checked in this order:
  1. An address whose IP equals the IP of the peer's current path is silently dropped. IPv4-mapped IPv6 addresses are normalized first.
  2. Silently dropped: more than 20 candidates from this peer in 60 seconds (every attempt counts, including rejected ones), or the receiver is under resource pressure.
  3. Silently dropped: port 0 or below 1024; unspecified, broadcast, multicast or documentation IPv4 addresses; loopback unless allowed locally; multicast or unspecified IPv6 addresses; addresses made of one repeated octet or segment.
  4. If 50 remote candidates are already held: PROTOCOL_VIOLATION. This check comes before the duplicate check, so a duplicate sent to a full table also closes the connection.
  5. An address already held under another sequence number is silently dropped. A known sequence number with a new address replaces the old one.
- REMOVE_ADDRESS for an unknown sequence number is ignored.
- OBSERVED_ADDRESS with a sequence number less than or equal to the highest already received is ignored (tracked per path; only path 0 is used today).
- TRY_CONNECT_TO is validated (a loopback target is refused unless loopback is allowed locally, and an unspecified target is refused), but no response is ever put on the wire.

## Coordination (PUNCH_ME_NOW relay)

Every connection with NAT traversal active can act as a coordinator. A relayed hole punch works like this:

1. The initiator sends PUNCH_ME_NOW to a connected peer, the coordinator, with the trailer flag 1, Target Peer Id set to the peer it wants to reach, its own external address, and Paired With Sequence Number 0.
2. The coordinator validates the frame and silently ignores it if it fails. It is rejected for: rate limits (300 coordination requests per 60 s), the address checks above, a round above 1,000,000, a paired sequence number above 10,000, or a target equal to the sender.
3. The coordinator finds a connection to the target by Target Peer Id. It first looks for a connection registered under that id, then compares it with each connection's address-derived 32-byte id: byte 0 = 4 or 6, then the IP octets, then the port, zero-padded. Peer ids are registered by the embedding application through `P2pEndpoint::register_connection_peer_id`; this crate does not derive them. The relayed punches this crate sends itself use the address-derived id.
4. The coordinator forwards the frame to the target with the trailer flag 0, keeping Round, Paired With Sequence Number and address. If it has no connection to the target, nothing is sent and the initiator is not told.
5. The target (flag 0) checks the round. A round of 0, or one more than 100 away from its own current round, is a PROTOCOL_VIOLATION on the connection to the coordinator. Otherwise it starts sending hole-punch packets to the address in the frame.

A frame with the flag set to 1 is always handled as a request to coordinate, never as one addressed to the receiver.

## Deviations from the drafts

1. Two wire formats for ADD_ADDRESS and PUNCH_ME_NOW (RFC and legacy), selected per connection by the saorsa-specific rfc_nat_traversal parameter.
2. PUNCH_ME_NOW carries a trailer (`Has Target Peer Id`, optional 32-byte id) that the draft does not have. A draft-conformant PUNCH_ME_NOW without the trailer is accepted only if it is the last frame in the packet or is followed by a PADDING (0x00) byte. Otherwise the next byte is read as the trailer flag and decoding usually fails.
3. No client/server asymmetry: either endpoint may send either form of the nat_traversal parameter and any NAT traversal frame. Two ClientSupport endpoints do not enable NAT traversal.
4. The concurrency limit is capped at 100 on the accepting side (the draft allows any value above 0), and is not otherwise used.
5. Candidate pairing and prioritization run on both sides, not only on the client.
6. Additional frames TRY_CONNECT_TO and TRY_CONNECT_TO_RESPONSE, and the additional parameters rfc_nat_traversal and pqc_algorithms.
7. ADD_ADDRESS from the peer's own IP, from low ports, or from reserved addresses is dropped, and more than 50 candidates closes the connection.
8. One OBSERVED_ADDRESS per connection; the address_discovery modes are not honoured.
9. PUNCH_ME_NOW relay through a coordinator, identified by Target Peer Id.

## Known issues

All tracked in V2-1823.

- **Legacy-format frames can't be received reliably.** The receiver tries the RFC decoder first and, on error, runs the legacy decoder on the same buffer without rewinding. Worse, a legacy ADD_ADDRESS always parses "successfully" as RFC.
  - Example: the legacy IPv4 ADD_ADDRESS body (after the type) `01 40 64 04 c0 00 02 01 12 34` means sequence 1, priority 100, version 4, 192.0.2.1:4660.
  - The RFC decoder reads sequence 1, address 64.100.4.192, port 2, and leaves `01 12 34` to be parsed as further frames.
  - A legacy PUNCH_ME_NOW parses as RFC only when the byte that lands in the flag position is 0 or 1. Otherwise decoding fails with FRAME_ENCODING_ERROR.
- **A relayed PUNCH_ME_NOW with round 0 closes the target's connection to the coordinator.** The coordinator accepts and forwards round 0, but the target treats it as a PROTOCOL_VIOLATION.
- **A duplicate ADD_ADDRESS sent to a full candidate table closes the connection**, because the cap is checked before the duplicate check.
- **The address_discovery modes are parsed and then ignored.** send only, receive only, and send and receive all behave the same. The rate limiter for OBSERVED_ADDRESS (10 per second) and its bootstrap-mode variants never take effect, because only one frame is ever sent.
- **The negotiated nat_traversal concurrency limit is computed but not used**, and the 100 cap is checked only on the accepting side.
- **The decoder doesn't check the parameter length** for nat_traversal (ServerSupport) and address_discovery. A wrong length makes it read the value from the bytes of the next parameter.
- **TRY_CONNECT_TO and TRY_CONNECT_TO_RESPONSE are never sent.** No send path encodes them, the response queue is filled but never drained, and the endpoint handler for a received request is a TODO. Peers must not rely on them.
- **`src/nat_traversal/frames.rs` defines `FRAME_TYPE_PUNCH_ME_NOW = 0x3d7e91` and `FRAME_TYPE_REMOVE_ADDRESS = 0x3d7e92`, which are wrong.** That module is a separate multi-transport codec whose `encode_with_type` is not called on the packet path. Use the IDs in `src/frame.rs`.

## Source of truth

- `src/frame.rs`: frame type IDs, the frame decoder, `ObservedAddress`.
- `src/frame/nat_traversal_unified.rs`: ADD_ADDRESS, PUNCH_ME_NOW, REMOVE_ADDRESS and TRY_CONNECT_TO(_RESPONSE) encode/decode; format selection.
- `src/transport_parameters.rs`: parameter IDs, encoding, validation.
- `src/connection/mod.rs`: frame send and receive handling, the per-space frame rules, format and capability negotiation, address discovery.
- `src/connection/nat_traversal.rs`: candidate validation and limits, coordinator and round checks.
- `src/endpoint.rs` and `src/shared.rs`: relaying PUNCH_ME_NOW to the target and the address-derived peer id.
- `docs/rfcs/draft-seemann-quic-nat-traversal-02.txt`, `docs/rfcs/draft-ietf-quic-address-discovery-00.txt`.
- ADRs: `docs/adr/ADR-004`, `ADR-005`, `ADR-008`.
