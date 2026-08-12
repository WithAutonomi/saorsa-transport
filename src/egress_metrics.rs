// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! TEMPORARY process-wide QUIC egress attribution counters.
//!
//! Gated behind the `egress-metrics` feature, which is never enabled for
//! release builds. Exists so the keep-alive A/B harness can attribute a
//! measured byte delta to specific frame types instead of extrapolating from
//! a socket-level total.
//!
//! Counters are process-global rather than per-connection because the harness
//! runs a whole testnet inside one process and wants the fleet aggregate; the
//! per-connection view is still available via `ConnectionStats::egress`.

use std::sync::atomic::{AtomicU64, Ordering};

macro_rules! define {
    ($($name:ident),* $(,)?) => {
        $(pub(crate) static $name: AtomicU64 = AtomicU64::new(0);)*
    };
}

define!(
    UDP_TX_BYTES,
    UDP_TX_DATAGRAMS,
    UDP_RX_BYTES,
    UDP_RX_DATAGRAMS,
    PING_TX,
    ACK_ONLY_BYTES_TX,
    ACK_ONLY_PACKETS_TX,
    HANDSHAKE_BYTES_TX,
    HANDSHAKE_PACKETS_TX,
    STREAM_PAYLOAD_BYTES_TX,
    LOST_BYTES,
    LOST_PACKETS,
    IDLE_TIMEOUT_CLOSES,
);

/// A point-in-time read of the process-wide egress counters.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Snapshot {
    /// Total UDP payload bytes transmitted.
    pub udp_tx_bytes: u64,
    /// Total UDP datagrams transmitted.
    pub udp_tx_datagrams: u64,
    /// Total UDP payload bytes received.
    pub udp_rx_bytes: u64,
    /// Total UDP datagrams received.
    pub udp_rx_datagrams: u64,
    /// PING frames transmitted (keep-alive and MTU probes).
    pub ping_tx: u64,
    /// Bytes in transmitted packets that carried only ACK frames.
    pub ack_only_bytes_tx: u64,
    /// Transmitted packets that carried only ACK frames.
    pub ack_only_packets_tx: u64,
    /// Bytes transmitted in the Initial and Handshake packet number spaces.
    pub handshake_bytes_tx: u64,
    /// Packets transmitted in the Initial and Handshake packet number spaces.
    pub handshake_packets_tx: u64,
    /// STREAM frame payload bytes transmitted, retransmissions included.
    pub stream_payload_bytes_tx: u64,
    /// Bytes in packets declared lost by loss detection.
    pub lost_bytes: u64,
    /// Packets declared lost by loss detection.
    pub lost_packets: u64,
    /// Connections killed by the QUIC idle timeout.
    pub idle_timeout_closes: u64,
}

/// Read every counter.
#[must_use]
pub fn snapshot() -> Snapshot {
    Snapshot {
        udp_tx_bytes: UDP_TX_BYTES.load(Ordering::Relaxed),
        udp_tx_datagrams: UDP_TX_DATAGRAMS.load(Ordering::Relaxed),
        udp_rx_bytes: UDP_RX_BYTES.load(Ordering::Relaxed),
        udp_rx_datagrams: UDP_RX_DATAGRAMS.load(Ordering::Relaxed),
        ping_tx: PING_TX.load(Ordering::Relaxed),
        ack_only_bytes_tx: ACK_ONLY_BYTES_TX.load(Ordering::Relaxed),
        ack_only_packets_tx: ACK_ONLY_PACKETS_TX.load(Ordering::Relaxed),
        handshake_bytes_tx: HANDSHAKE_BYTES_TX.load(Ordering::Relaxed),
        handshake_packets_tx: HANDSHAKE_PACKETS_TX.load(Ordering::Relaxed),
        stream_payload_bytes_tx: STREAM_PAYLOAD_BYTES_TX.load(Ordering::Relaxed),
        lost_bytes: LOST_BYTES.load(Ordering::Relaxed),
        lost_packets: LOST_PACKETS.load(Ordering::Relaxed),
        idle_timeout_closes: IDLE_TIMEOUT_CLOSES.load(Ordering::Relaxed),
    }
}

impl Snapshot {
    /// Field-wise difference `self - earlier`, saturating at zero.
    #[must_use]
    pub fn since(&self, earlier: &Self) -> Self {
        Self {
            udp_tx_bytes: self.udp_tx_bytes.saturating_sub(earlier.udp_tx_bytes),
            udp_tx_datagrams: self
                .udp_tx_datagrams
                .saturating_sub(earlier.udp_tx_datagrams),
            udp_rx_bytes: self.udp_rx_bytes.saturating_sub(earlier.udp_rx_bytes),
            udp_rx_datagrams: self
                .udp_rx_datagrams
                .saturating_sub(earlier.udp_rx_datagrams),
            ping_tx: self.ping_tx.saturating_sub(earlier.ping_tx),
            ack_only_bytes_tx: self
                .ack_only_bytes_tx
                .saturating_sub(earlier.ack_only_bytes_tx),
            ack_only_packets_tx: self
                .ack_only_packets_tx
                .saturating_sub(earlier.ack_only_packets_tx),
            handshake_bytes_tx: self
                .handshake_bytes_tx
                .saturating_sub(earlier.handshake_bytes_tx),
            handshake_packets_tx: self
                .handshake_packets_tx
                .saturating_sub(earlier.handshake_packets_tx),
            stream_payload_bytes_tx: self
                .stream_payload_bytes_tx
                .saturating_sub(earlier.stream_payload_bytes_tx),
            lost_bytes: self.lost_bytes.saturating_sub(earlier.lost_bytes),
            lost_packets: self.lost_packets.saturating_sub(earlier.lost_packets),
            idle_timeout_closes: self
                .idle_timeout_closes
                .saturating_sub(earlier.idle_timeout_closes),
        }
    }

    /// Render as `key=value` pairs for a single log line.
    #[must_use]
    pub fn to_kv(&self) -> String {
        format!(
            "udp_tx_bytes={} udp_tx_datagrams={} udp_rx_bytes={} udp_rx_datagrams={} \
             ping_tx={} ack_only_bytes_tx={} ack_only_packets_tx={} handshake_bytes_tx={} \
             handshake_packets_tx={} stream_payload_bytes_tx={} lost_bytes={} lost_packets={} idle_timeout_closes={}",
            self.udp_tx_bytes,
            self.udp_tx_datagrams,
            self.udp_rx_bytes,
            self.udp_rx_datagrams,
            self.ping_tx,
            self.ack_only_bytes_tx,
            self.ack_only_packets_tx,
            self.handshake_bytes_tx,
            self.handshake_packets_tx,
            self.stream_payload_bytes_tx,
            self.lost_bytes,
            self.lost_packets,
            self.idle_timeout_closes,
        )
    }
}

#[inline]
pub(crate) fn add(counter: &AtomicU64, value: u64) {
    counter.fetch_add(value, Ordering::Relaxed);
}
