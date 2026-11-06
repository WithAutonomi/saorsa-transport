// Copyright 2026 Saorsa Labs Ltd.
// SPDX-License-Identifier: MIT OR Apache-2.0

//! Plain STUN Binding answers on the WebRTC Direct socket.
//!
//! WebRTC connections between two clients need each client to learn the
//! public address it sends from (its "server reflexive" candidate). A node
//! can tell it: a client's ICE agent sends a plain Binding request (no ICE
//! credentials) to the node's WebRTC Direct port, and the node answers with
//! XOR-MAPPED-ADDRESS (RFC 8489).
//!
//! The answer is a few bytes larger than the request (32 bytes for a 20-byte
//! IPv4 request, 44 for IPv6), unlike the other replies this socket sends to a
//! source before admitting it: admission challenges and refusals never exceed
//! the request that drew them. An unauthenticated UDP request can carry a
//! forged source, so answers are kept from being a useful reflector (RFC 8489
//! §16.1.2) three ways:
//!
//! - they go only to sources the application allows (for example, addresses
//!   that recently reached it over an authenticated connection, so a victim's
//!   address is allowed only where the victim itself has been);
//! - each source, an IPv4 address or an IPv6 /64, gets at most
//!   [`PER_SOURCE_PER_SECOND`] answers a second, after a burst of
//!   [`PER_SOURCE_BURST`];
//! - the socket sends at most [`GLOBAL_PER_SECOND`] answers a second in all,
//!   after a burst of [`GLOBAL_BURST`], spent only on requests the first two
//!   allow, so one source cannot use up the others' share.
//!
//! Every check runs on the raw bytes, without allocating, and the answer is
//! built only once both limits grant it, so requests refused cost the
//! socket's receive loop little. A plain request refused is consumed here
//! rather than passed on to the connection handling that shares the socket.
//! With no policy set, plain requests are left to that handling, which drops
//! them, as before.

use parking_lot::{Mutex, RwLock};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};
use stun::agent::TransactionId;
use stun::attributes::{ATTR_FINGERPRINT, ATTR_USERNAME};
use stun::fingerprint::{FINGERPRINT, fingerprint_value};
use stun::message::{BINDING_SUCCESS, Message, Setter};
use stun::xoraddr::XorMappedAddress;

use super::super::source_ip_bucket;

/// Decides which source addresses get an answer to a plain Binding request.
///
/// It is called on the socket's receive loop for each plain request, before
/// the rate limits, so it must be cheap and must not block.
pub type PlainBindingPolicy = Arc<dyn Fn(IpAddr) -> bool + Send + Sync>;

/// Answers one source may get per second, on average.
const PER_SOURCE_PER_SECOND: f64 = 10.0;
/// Answers one source may get in a burst. An ICE agent gathering from a few
/// interfaces sends a handful, retransmitted a few times.
const PER_SOURCE_BURST: f64 = 20.0;
/// Answers the socket sends per second, to all sources, on average.
const GLOBAL_PER_SECOND: f64 = 2000.0;
/// Answers the socket sends in a burst, to all sources.
const GLOBAL_BURST: f64 = 4000.0;
/// Sources remembered for rate limiting.
const MAX_TRACKED_SOURCES: usize = 4096;
/// How often a full source map may be swept for sources to forget.
const SWEEP_INTERVAL: Duration = Duration::from_secs(1);
/// A Binding request from an ICE agent is small; anything larger is not one.
const MAX_REQUEST_BYTES: usize = 548;
/// The STUN header: type, length, magic cookie, transaction id.
const HEADER_BYTES: usize = 20;
/// An attribute's type and length.
const ATTRIBUTE_HEADER_BYTES: usize = 4;
/// The FINGERPRINT attribute, header and CRC.
const FINGERPRINT_BYTES: usize = ATTRIBUTE_HEADER_BYTES + 4;
const BINDING_REQUEST_TYPE: u16 = 0x0001;
const MAGIC_COOKIE: [u8; 4] = [0x21, 0x12, 0xa4, 0x42];

/// What the socket does with a packet.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum PlainVerdict {
    /// Not a plain Binding request this listener answers: handle it as usual.
    NotPlain,
    /// A plain Binding request refused: drop it.
    Drop,
    /// A plain Binding request answered: send this.
    Reply(Vec<u8>),
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

impl Bucket {
    fn full(burst: f64, now: Instant) -> Self {
        Self {
            tokens: burst,
            last: now,
        }
    }

    fn refill(&mut self, now: Instant, per_second: f64, burst: f64) {
        let elapsed = now.saturating_duration_since(self.last).as_secs_f64();
        self.tokens = (self.tokens + elapsed * per_second).min(burst);
        // An earlier `now` adds nothing and must not move `last` back, or
        // the time since `last` would be credited twice.
        self.last = self.last.max(now);
    }
}

#[derive(Default)]
struct Limits {
    global: Option<Bucket>,
    sources: HashMap<IpAddr, Bucket>,
    /// When the full source map was last swept for refilled buckets.
    swept: Option<Instant>,
}

impl Limits {
    /// Takes one answer from `key`'s bucket and the socket's, or, if either
    /// has none to give, from neither: a request refused by one limit costs
    /// nothing from the other, and a source is remembered only once answered.
    fn grant(&mut self, key: IpAddr, now: Instant) -> bool {
        let global = self
            .global
            .get_or_insert_with(|| Bucket::full(GLOBAL_BURST, now));
        global.refill(now, GLOBAL_PER_SECOND, GLOBAL_BURST);
        if global.tokens < 1.0 {
            return false;
        }
        if !self.sources.contains_key(&key) && self.sources.len() >= MAX_TRACKED_SOURCES {
            // Forget sources whose bucket has refilled: they are as good as
            // new. At most once a second, so a stream of new sources while the
            // map is full costs a lookup each, not a sweep each.
            let due = self
                .swept
                .is_none_or(|swept| now.saturating_duration_since(swept) >= SWEEP_INTERVAL);
            if due {
                self.swept = Some(now);
                self.sources.retain(|_, bucket| {
                    bucket.refill(now, PER_SOURCE_PER_SECOND, PER_SOURCE_BURST);
                    bucket.tokens < PER_SOURCE_BURST
                });
            }
            if self.sources.len() >= MAX_TRACKED_SOURCES {
                return false;
            }
        }
        let source = self
            .sources
            .entry(key)
            .or_insert_with(|| Bucket::full(PER_SOURCE_BURST, now));
        source.refill(now, PER_SOURCE_PER_SECOND, PER_SOURCE_BURST);
        if source.tokens < 1.0 {
            return false;
        }
        source.tokens -= 1.0;
        global.tokens -= 1.0;
        true
    }
}

/// The policy and rate limits for plain Binding answers.
#[derive(Default)]
pub(super) struct PlainBinding {
    policy: RwLock<Option<PlainBindingPolicy>>,
    limits: Mutex<Limits>,
}

impl PlainBinding {
    pub(super) fn set_policy(&self, policy: Option<PlainBindingPolicy>) {
        *self.policy.write() = policy;
    }

    /// What to do with `packet` from `source`.
    pub(super) fn verdict(&self, packet: &[u8], source: SocketAddr) -> PlainVerdict {
        self.verdict_at(packet, source, Instant::now)
    }

    /// [`Self::verdict`], reading the time from `now` only for a request the
    /// limits are asked about, so other packets cost no clock read.
    fn verdict_at(
        &self,
        packet: &[u8],
        source: SocketAddr,
        now: impl FnOnce() -> Instant,
    ) -> PlainVerdict {
        let Some(request) = PlainRequest::read(packet) else {
            return PlainVerdict::NotPlain;
        };
        let Some(policy) = self.policy.read().clone() else {
            return PlainVerdict::NotPlain;
        };
        // The limits count only requests that would be answered: requests the
        // policy or the FINGERPRINT check refuses cost the other sources
        // nothing, and take no place among the tracked sources.
        let ip = source.ip().to_canonical();
        if !policy(ip) || !request.fingerprint_matches(packet) {
            return PlainVerdict::Drop;
        }
        let now = now();
        if !self.limits.lock().grant(source_ip_bucket(ip), now) {
            return PlainVerdict::Drop;
        }
        request
            .answer(source)
            .map_or(PlainVerdict::Drop, PlainVerdict::Reply)
    }
}

/// A plain Binding request, read from its bytes: what its answer needs.
struct PlainRequest {
    transaction_id: [u8; 12],
    /// Where its FINGERPRINT attribute starts, if it has one.
    fingerprint_at: Option<usize>,
}

/// The big-endian `u16` at `at` in `bytes`.
fn read_u16(bytes: &[u8], at: usize) -> Option<u16> {
    bytes
        .get(at..at.checked_add(2)?)
        .and_then(|field| <[u8; 2]>::try_from(field).ok())
        .map(u16::from_be_bytes)
}

impl PlainRequest {
    /// `packet` as a plain Binding request, from its bytes alone and without
    /// allocating: a well-framed STUN Binding request of plausible size with
    /// no USERNAME (an ICE connectivity check carries one) and no
    /// comprehension-required attribute (RFC 8489 §14; ICE agents asking a
    /// STUN server send none). Its FINGERPRINT, if any, is checked
    /// separately, by [`Self::fingerprint_matches`].
    ///
    /// A request with a comprehension-required attribute is left alone rather
    /// than answered with `420 Unknown Attribute` (RFC 8489 §6.3.1): this
    /// socket is not a general STUN server, no ICE agent sends one, and an
    /// error answer would be one more reply a forged source could draw from
    /// the node.
    fn read(packet: &[u8]) -> Option<Self> {
        if packet.len() < HEADER_BYTES || packet.len() > MAX_REQUEST_BYTES {
            return None;
        }
        let (header, mut attributes) = packet.split_at_checked(HEADER_BYTES)?;
        if read_u16(header, 0) != Some(BINDING_REQUEST_TYPE)
            || header.get(4..8) != Some(&MAGIC_COOKIE[..])
        {
            return None;
        }
        if read_u16(header, 2).map(usize::from) != Some(attributes.len())
            || attributes.len() % 4 != 0
        {
            return None;
        }
        let transaction_id = header
            .get(8..HEADER_BYTES)
            .and_then(|id| <[u8; 12]>::try_from(id).ok())?;
        let mut at = HEADER_BYTES;
        let mut fingerprint_at = None;
        while !attributes.is_empty() {
            let (head, rest) = attributes.split_at_checked(ATTRIBUTE_HEADER_BYTES)?;
            let kind = read_u16(head, 0)?;
            let length = read_u16(head, 2)?;
            if kind == ATTR_USERNAME.0 || kind < 0x8000 {
                return None;
            }
            if kind == ATTR_FINGERPRINT.0 && fingerprint_at.is_none() {
                fingerprint_at = Some(at);
            }
            let padded = (usize::from(length) + 3) & !3;
            let (_, after) = rest.split_at_checked(padded)?;
            at += ATTRIBUTE_HEADER_BYTES + padded;
            attributes = after;
        }
        Some(Self {
            transaction_id,
            fingerprint_at,
        })
    }

    /// Whether the request's FINGERPRINT, if it has one, is its last
    /// attribute and matches `packet` (RFC 8489 §14.7).
    fn fingerprint_matches(&self, packet: &[u8]) -> bool {
        let Some(at) = self.fingerprint_at else {
            return true;
        };
        if at.checked_add(FINGERPRINT_BYTES) != Some(packet.len())
            || read_u16(packet, at + 2) != Some(4)
        {
            return false;
        }
        let covered = packet.get(..at);
        let value = packet
            .get(at + ATTRIBUTE_HEADER_BYTES..)
            .and_then(|value| <[u8; 4]>::try_from(value).ok())
            .map(u32::from_be_bytes);
        matches!((covered, value), (Some(covered), Some(value)) if value == fingerprint_value(covered))
    }

    /// The Binding success response telling `source` its address, with a
    /// FINGERPRINT if the request had one.
    fn answer(&self, source: SocketAddr) -> Option<Vec<u8>> {
        let mapped = XorMappedAddress {
            ip: source.ip().to_canonical(),
            port: source.port(),
        };
        let mut response = Message::new();
        let mut setters: Vec<Box<dyn Setter>> = vec![
            Box::new(TransactionId(self.transaction_id)),
            Box::new(BINDING_SUCCESS),
            Box::new(mapped),
        ];
        if self.fingerprint_at.is_some() {
            setters.push(Box::new(FINGERPRINT));
        }
        response.build(&setters).ok()?;
        Some(response.raw)
    }
}

/// The Binding success response for a plain Binding request, or `None` if
/// `packet` is not one or its FINGERPRINT does not match.
#[cfg(test)]
fn plain_binding_response(packet: &[u8], source: SocketAddr) -> Option<Vec<u8>> {
    let request = PlainRequest::read(packet)?;
    request
        .fingerprint_matches(packet)
        .then(|| request.answer(source))
        .flatten()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::webrtc::direct::{WebRtcCertificate, WebRtcDirectListener};
    use anyhow::{Context, Result};
    use std::net::{Ipv4Addr, Ipv6Addr};
    use stun::attributes::{ATTR_SOFTWARE, AttrType};
    use stun::message::{BINDING_REQUEST, Getter};
    use stun::textattrs::{Software, Username};
    use tokio::net::UdpSocket;
    use tokio::time::timeout;

    impl PlainBinding {
        /// [`PlainBinding::verdict`] at `now`.
        fn at(&self, packet: &[u8], source: SocketAddr, now: Instant) -> PlainVerdict {
            self.verdict_at(packet, source, || now)
        }
    }

    fn request(extra: Vec<Box<dyn Setter>>) -> Result<Vec<u8>> {
        let mut message = Message::new();
        let mut setters: Vec<Box<dyn Setter>> =
            vec![Box::new(TransactionId::new()), Box::new(BINDING_REQUEST)];
        setters.extend(extra);
        message.build(&setters)?;
        Ok(message.raw)
    }

    /// A request whose FINGERPRINT does not match its bytes.
    fn broken_fingerprint(extra: Vec<Box<dyn Setter>>) -> Result<Vec<u8>> {
        let mut extra = extra;
        extra.push(Box::new(FINGERPRINT));
        let mut broken = request(extra)?;
        let last = broken.last_mut().context("empty request")?;
        *last ^= 1;
        Ok(broken)
    }

    fn mapped(reply: &[u8]) -> Result<SocketAddr> {
        let mut message = Message::new();
        message.unmarshal_binary(reply)?;
        assert_eq!(message.typ, BINDING_SUCCESS);
        let mut address = XorMappedAddress::default();
        address.get_from(&message)?;
        Ok(SocketAddr::new(address.ip, address.port))
    }

    fn answer(packet: &[u8], source: SocketAddr) -> Result<Vec<u8>> {
        plain_binding_response(packet, source).context("no answer")
    }

    fn allowing_all() -> PlainBinding {
        let binding = PlainBinding::default();
        binding.set_policy(Some(Arc::new(|_| true)));
        binding
    }

    fn replied(verdict: &PlainVerdict) -> bool {
        matches!(verdict, PlainVerdict::Reply(_))
    }

    fn v4_source(base: u32, n: u32) -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::from(base + n)), 40000)
    }

    /// Whether `reply` answers `request`'s transaction.
    fn same_transaction(request: &[u8], reply: &[u8]) -> bool {
        request.get(8..HEADER_BYTES).is_some()
            && request.get(8..HEADER_BYTES) == reply.get(8..HEADER_BYTES)
    }

    #[test]
    fn a_plain_request_learns_its_source_address() -> Result<()> {
        let source: SocketAddr = "198.51.100.7:40000".parse()?;
        let packet = request(Vec::new())?;
        let reply = answer(&packet, source)?;
        assert_eq!(mapped(&reply)?, source);
        assert!(same_transaction(&packet, &reply));
        // An IPv4-mapped IPv6 source is answered as the IPv4 address it is.
        let v4_mapped: SocketAddr = "[::ffff:198.51.100.7]:40000".parse()?;
        let reply = answer(&request(Vec::new())?, v4_mapped)?;
        assert_eq!(mapped(&reply)?, source);
        Ok(())
    }

    #[test]
    fn a_fingerprint_is_checked_and_returned() -> Result<()> {
        let source: SocketAddr = "198.51.100.7:40000".parse()?;
        let with = request(vec![
            Box::new(Software::new(ATTR_SOFTWARE, "test".into())),
            Box::new(FINGERPRINT),
        ])?;
        let reply = answer(&with, source)?;
        let mut message = Message::new();
        message.unmarshal_binary(&reply)?;
        assert!(FINGERPRINT.check(&message).is_ok());
        let broken =
            broken_fingerprint(vec![Box::new(Software::new(ATTR_SOFTWARE, "test".into()))])?;
        assert!(plain_binding_response(&broken, source).is_none());
        // A request whose FINGERPRINT does not match is dropped.
        let binding = allowing_all();
        let now = Instant::now();
        assert_eq!(binding.at(&broken, source, now), PlainVerdict::Drop);
        Ok(())
    }

    #[test]
    fn connectivity_checks_and_other_packets_are_left_alone() -> Result<()> {
        let source: SocketAddr = "198.51.100.7:40000".parse()?;
        let binding = allowing_all();
        let now = Instant::now();
        let check = request(vec![Box::new(Username::new(ATTR_USERNAME, "a:b".into()))])?;
        assert!(plain_binding_response(&check, source).is_none());
        assert_eq!(binding.at(&check, source, now), PlainVerdict::NotPlain);
        let mut required = Message::new();
        required.build(&[Box::new(TransactionId::new()), Box::new(BINDING_REQUEST)])?;
        required.add(AttrType(0x0003), &[0, 0, 0, 6]);
        assert!(plain_binding_response(&required.raw, source).is_none());
        assert_eq!(
            binding.at(&required.raw, source, now),
            PlainVerdict::NotPlain
        );
        let not_stun = b"not stun at all, but long enough";
        assert_eq!(binding.at(not_stun, source, now), PlainVerdict::NotPlain);
        // A header that claims more attributes than the packet holds.
        let mut short = request(Vec::new())?;
        let length = short.get_mut(3).context("short request")?;
        *length = 8;
        assert_eq!(binding.at(&short, source, now), PlainVerdict::NotPlain);
        Ok(())
    }

    #[test]
    fn only_allowed_sources_are_answered_each_within_its_rate() -> Result<()> {
        let binding = PlainBinding::default();
        let allowed: SocketAddr = "198.51.100.7:40000".parse()?;
        let other: SocketAddr = "198.51.100.8:40000".parse()?;
        let packet = request(Vec::new())?;
        let now = Instant::now();
        // No policy: left to the usual handling, which drops it.
        assert_eq!(binding.at(&packet, allowed, now), PlainVerdict::NotPlain);
        let allowed_ip = allowed.ip();
        binding.set_policy(Some(Arc::new(move |ip| ip == allowed_ip)));
        // Refused, and consumed here.
        assert_eq!(binding.at(&packet, other, now), PlainVerdict::Drop);
        let answered = (0..30)
            .filter(|_| replied(&binding.at(&packet, allowed, now)))
            .count();
        assert_eq!(answered, 20);
        let later = now + Duration::from_secs(1);
        assert!(replied(&binding.at(&packet, allowed, later)));
        Ok(())
    }

    #[test]
    fn one_ipv6_network_shares_one_rate() -> Result<()> {
        let binding = allowing_all();
        let packet = request(Vec::new())?;
        let now = Instant::now();
        let answered = (0..30u16)
            .filter(|host| {
                let source = SocketAddr::new(
                    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, *host)),
                    40000,
                );
                replied(&binding.at(&packet, source, now))
            })
            .count();
        assert_eq!(answered, 20);
        Ok(())
    }

    #[test]
    fn requests_with_a_bad_fingerprint_cost_others_nothing() -> Result<()> {
        let binding = allowing_all();
        let now = Instant::now();
        let broken = broken_fingerprint(Vec::new())?;
        for n in 0..5000u32 {
            let _ = binding.at(&broken, v4_source(0x0a00_0000, n % 4000), now);
        }
        let other: SocketAddr = "198.51.100.8:40000".parse()?;
        assert!(replied(&binding.at(&request(Vec::new())?, other, now)));
        Ok(())
    }

    #[test]
    fn requests_with_a_bad_fingerprint_take_no_place_among_sources() -> Result<()> {
        let binding = allowing_all();
        let now = Instant::now();
        let broken = broken_fingerprint(Vec::new())?;
        for n in 0..(MAX_TRACKED_SOURCES as u32 + 100) {
            let _ = binding.at(&broken, v4_source(0x0d00_0000, n), now);
        }
        assert!(binding.limits.lock().sources.is_empty());
        let other: SocketAddr = "198.51.100.8:40000".parse()?;
        assert!(replied(&binding.at(&request(Vec::new())?, other, now)));
        Ok(())
    }

    #[test]
    fn a_full_source_map_is_swept_at_most_once_a_second() -> Result<()> {
        let binding = allowing_all();
        let packet = request(Vec::new())?;
        let start = Instant::now();
        // Fill the map with sources that have used tokens, so none can go,
        // in two rounds a moment apart, as the socket's own burst is smaller.
        let now = start + Duration::from_millis(50);
        for n in 0..(MAX_TRACKED_SOURCES as u32) {
            let at = if n < 4000 { start } else { now };
            assert!(replied(&binding.at(&packet, v4_source(0x0b00_0000, n), at)));
        }
        let newcomer = |n: u32| v4_source(0x0c00_0000, n);
        // The first newcomer sweeps (and finds nothing to forget).
        assert_eq!(binding.at(&packet, newcomer(0), now), PlainVerdict::Drop);
        assert_eq!(binding.limits.lock().swept, Some(now));
        // By the next newcomer, 50 ms on, the first round's buckets have
        // refilled and a sweep would forget them, but none is due yet.
        let soon = now + Duration::from_millis(50);
        assert_eq!(binding.at(&packet, newcomer(1), soon), PlainVerdict::Drop);
        assert_eq!(binding.limits.lock().swept, Some(now));
        // A second on, the next sweep is due and makes room.
        let due = now + SWEEP_INTERVAL;
        assert!(replied(&binding.at(&packet, newcomer(2), due)));
        assert_eq!(binding.limits.lock().swept, Some(due));
        Ok(())
    }

    #[test]
    fn an_earlier_time_credits_no_answer_twice() -> Result<()> {
        let binding = allowing_all();
        let packet = request(Vec::new())?;
        let source: SocketAddr = "198.51.100.7:40000".parse()?;
        let start = Instant::now();
        let later = start + Duration::from_secs(1);
        let answered = (0..30)
            .filter(|_| replied(&binding.at(&packet, source, later)))
            .count();
        assert_eq!(answered, 20);
        // A reading from before `later` adds nothing, and the second before
        // `later` is not credited again when the clock returns to it.
        assert_eq!(binding.at(&packet, source, start), PlainVerdict::Drop);
        assert_eq!(binding.at(&packet, source, later), PlainVerdict::Drop);
        Ok(())
    }

    #[test]
    fn one_source_over_its_rate_leaves_the_others_their_answers() -> Result<()> {
        let binding = allowing_all();
        let packet = request(Vec::new())?;
        let now = Instant::now();
        let flooder: SocketAddr = "198.51.100.7:40000".parse()?;
        for _ in 0..10_000 {
            let _ = binding.at(&packet, flooder, now);
        }
        let other: SocketAddr = "198.51.100.8:40000".parse()?;
        assert!(replied(&binding.at(&packet, other, now)));
        Ok(())
    }

    #[test]
    fn the_socket_sends_only_so_many_answers_at_once() -> Result<()> {
        let binding = allowing_all();
        let packet = request(Vec::new())?;
        let now = Instant::now();
        let answered = (0..4010u32)
            .filter(|n| replied(&binding.at(&packet, v4_source(0x0a00_0000, *n), now)))
            .count();
        assert_eq!(answered, 4000);
        Ok(())
    }

    #[test]
    fn a_request_the_socket_cannot_answer_costs_its_source_nothing() -> Result<()> {
        let binding = allowing_all();
        let packet = request(Vec::new())?;
        let now = Instant::now();
        for n in 0..4000u32 {
            let _ = binding.at(&packet, v4_source(0x0a00_0000, n), now);
        }
        // The socket's burst is spent: a newcomer is refused, and neither
        // spends its own tokens nor takes a place among the sources.
        let newcomer: SocketAddr = "198.51.100.9:40000".parse()?;
        for _ in 0..50 {
            assert_eq!(binding.at(&packet, newcomer, now), PlainVerdict::Drop);
        }
        let key = source_ip_bucket(newcomer.ip());
        assert!(!binding.limits.lock().sources.contains_key(&key));
        // Once the socket has answers again, the newcomer has its whole burst.
        let later = now + Duration::from_secs(1);
        let answered = (0..30)
            .filter(|_| replied(&binding.at(&packet, newcomer, later)))
            .count();
        assert_eq!(answered, 20);
        Ok(())
    }

    #[test]
    fn a_fingerprint_must_be_the_last_attribute() -> Result<()> {
        let source: SocketAddr = "198.51.100.7:40000".parse()?;
        // A FINGERPRINT whose CRC matches the bytes before it, followed by one
        // more attribute: refused for its place alone.
        let mut message = Message::new();
        message.build(&[Box::new(TransactionId::new()), Box::new(BINDING_REQUEST)])?;
        message.add(ATTR_FINGERPRINT, &[0; 4]);
        message.add(ATTR_SOFTWARE, b"late");
        let mut packet = message.raw;
        let crc = fingerprint_value(packet.get(..HEADER_BYTES).context("short request")?);
        let value = packet
            .get_mut(HEADER_BYTES + ATTRIBUTE_HEADER_BYTES..HEADER_BYTES + FINGERPRINT_BYTES)
            .and_then(|value| <&mut [u8; 4]>::try_from(value).ok())
            .context("short request")?;
        *value = crc.to_be_bytes();
        let read = PlainRequest::read(&packet).context("not a plain request")?;
        assert_eq!(read.fingerprint_at, Some(HEADER_BYTES));
        assert!(plain_binding_response(&packet, source).is_none());
        let binding = allowing_all();
        assert_eq!(
            binding.at(&packet, source, Instant::now()),
            PlainVerdict::Drop
        );
        Ok(())
    }

    #[test]
    fn the_raw_reading_agrees_with_the_stun_parser() -> Result<()> {
        let with = request(vec![
            Box::new(Software::new(ATTR_SOFTWARE, "agent".into())),
            Box::new(FINGERPRINT),
        ])?;
        let mut parsed = Message::new();
        parsed.unmarshal_binary(&with)?;
        let read = PlainRequest::read(&with).context("not a plain request")?;
        assert_eq!(read.transaction_id, parsed.transaction_id.0);
        assert!(read.fingerprint_matches(&with));
        assert!(FINGERPRINT.check(&parsed).is_ok());
        Ok(())
    }

    /// Whether `client` hears nothing for a moment.
    async fn silent(client: &UdpSocket) -> bool {
        let mut buffer = [0u8; 1500];
        timeout(Duration::from_millis(300), client.recv_from(&mut buffer))
            .await
            .is_err()
    }

    // The listener's own socket answers only the sources its policy allows,
    // with the address each request came from.
    #[tokio::test]
    async fn the_listener_answers_allowed_sources_with_their_address() -> Result<()> {
        let certificate = WebRtcCertificate::generate()?;
        let listener = WebRtcDirectListener::bind("127.0.0.1:0".parse()?, certificate).await?;
        let target = listener.local_addr();
        let client = UdpSocket::bind("127.0.0.1:0").await?;
        let source = client.local_addr()?;
        let packet = request(Vec::new())?;

        // No policy: dropped, as before.
        client.send_to(&packet, target).await?;
        assert!(silent(&client).await);

        let allowed = source.ip();
        listener.set_plain_binding_policy(Some(Arc::new(move |ip| ip == allowed)));
        client.send_to(&packet, target).await?;
        let mut buffer = [0u8; 1500];
        let (length, from) =
            timeout(Duration::from_secs(5), client.recv_from(&mut buffer)).await??;
        assert_eq!(from, target);
        let reply = buffer.get(..length).context("reply longer than buffer")?;
        assert_eq!(mapped(reply)?, source);
        assert!(same_transaction(&packet, reply));

        // A source the policy refuses gets nothing.
        listener.set_plain_binding_policy(Some(Arc::new(|_| false)));
        client.send_to(&packet, target).await?;
        assert!(silent(&client).await);
        Ok(())
    }
}
