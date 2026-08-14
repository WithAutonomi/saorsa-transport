// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Configurable timeouts for NAT traversal operations

use crate::Duration;
use serde::{Deserialize, Serialize};

/// Configuration for NAT traversal timeouts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NatTraversalTimeouts {
    /// Timeout for hole punching coordination
    pub coordination_timeout: Duration,

    /// Overall timeout for establishing a connection through NAT
    pub connection_establishment_timeout: Duration,

    /// Timeout for individual probe attempts
    pub probe_timeout: Duration,

    /// Interval between retry attempts
    pub retry_interval: Duration,

    /// Timeout for bootstrap node queries
    pub bootstrap_query_timeout: Duration,

    /// Time to wait for path migration to complete
    pub migration_timeout: Duration,

    /// Time to wait for session state transitions
    pub session_timeout: Duration,
}

/// QUIC keep-alive interval for connections this node dials.
///
/// Only the dialling side sends keep-alives. One side is enough: a keep-alive
/// is ack-eliciting, so the peer answers it, both idle timers reset, and each
/// side puts a packet on the wire once per interval — which is also what
/// refreshes a NAT mapping for that five-tuple.
///
/// 10 s rather than the 5 s + 2 s pair it replaces. Because any traffic resets
/// both timers, the old arrangement ran at whichever interval was shorter, so
/// the effective cadence was the accepting side's 2 s and the interval is the
/// only real lever on idle egress. Measured on a 25-node testnet, moving to
/// 10 s takes idle egress from 29.8 to 6.1 B/s per connection endpoint.
///
/// The constraint on going further is NAT mapping lifetime, not the QUIC idle
/// timeout: RFC 4787 requires two minutes but 20-30 s middleboxes are reported
/// in the field, and if a mapping lapses the keep-alive is dropped before it
/// can provoke the ACK that would have refreshed it. 10 s is deliberately below
/// RFC 8085's 15 s floor for general-Internet keep-alives, for that reason.
pub(crate) const DIAL_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(10);

/// `max_idle_timeout` applied to every QUIC connection this crate creates.
///
/// Named here so the two endpoint configuration sites cannot drift apart, and
/// so the keep-alive above has something to be read against.
///
/// Crate-private on purpose: these are internal wiring values, not API. The
/// integration test asserts the literals it expects rather than importing
/// these, so a wrong constant fails the test instead of moving it.
pub(crate) const QUIC_MAX_IDLE_TIMEOUT_MS: u32 = 30_000;

impl Default for NatTraversalTimeouts {
    fn default() -> Self {
        Self {
            coordination_timeout: Duration::from_secs(10),
            connection_establishment_timeout: Duration::from_secs(30),
            probe_timeout: Duration::from_secs(5),
            retry_interval: Duration::from_secs(1),
            bootstrap_query_timeout: Duration::from_secs(5),
            migration_timeout: Duration::from_secs(60),
            session_timeout: Duration::from_secs(5),
        }
    }
}

impl NatTraversalTimeouts {
    /// Create timeouts optimized for fast local networks
    pub fn fast() -> Self {
        Self {
            coordination_timeout: Duration::from_secs(5),
            connection_establishment_timeout: Duration::from_secs(15),
            probe_timeout: Duration::from_secs(2),
            retry_interval: Duration::from_millis(500),
            bootstrap_query_timeout: Duration::from_secs(2),
            migration_timeout: Duration::from_secs(30),
            session_timeout: Duration::from_secs(2),
        }
    }

    /// Create timeouts optimized for slow or unreliable networks
    pub fn conservative() -> Self {
        Self {
            coordination_timeout: Duration::from_secs(20),
            connection_establishment_timeout: Duration::from_secs(60),
            probe_timeout: Duration::from_secs(10),
            retry_interval: Duration::from_secs(2),
            bootstrap_query_timeout: Duration::from_secs(10),
            migration_timeout: Duration::from_secs(120),
            session_timeout: Duration::from_secs(10),
        }
    }
}

/// Configuration for discovery operation timeouts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryTimeouts {
    /// Total timeout for the entire discovery process
    pub total_timeout: Duration,

    /// Timeout for scanning local network interfaces
    pub local_scan_timeout: Duration,

    /// Time to cache network interface information
    pub interface_cache_ttl: Duration,

    /// Time to cache server reflexive addresses
    pub server_reflexive_cache_ttl: Duration,

    /// Interval between health checks for bootstrap nodes
    pub health_check_interval: Duration,
}

impl Default for DiscoveryTimeouts {
    fn default() -> Self {
        Self {
            total_timeout: Duration::from_secs(30),
            local_scan_timeout: Duration::from_secs(2),
            interface_cache_ttl: Duration::from_secs(60),
            server_reflexive_cache_ttl: Duration::from_secs(300),
            health_check_interval: Duration::from_secs(30),
        }
    }
}

/// Configuration for relay-related timeouts
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayTimeouts {
    /// Timeout for relay request operations
    pub request_timeout: Duration,

    /// Interval between retry attempts
    pub retry_interval: Duration,

    /// Time window for rate limiting
    pub rate_limit_window: Duration,
}

impl Default for RelayTimeouts {
    fn default() -> Self {
        Self {
            request_timeout: Duration::from_secs(30),
            retry_interval: Duration::from_millis(500),
            rate_limit_window: Duration::from_secs(60),
        }
    }
}

/// Master timeout configuration
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TimeoutConfig {
    /// NAT traversal timeouts
    pub nat_traversal: NatTraversalTimeouts,

    /// Discovery timeouts
    pub discovery: DiscoveryTimeouts,

    /// Relay timeouts
    pub relay: RelayTimeouts,
}

impl TimeoutConfig {
    /// Create a configuration optimized for fast networks
    pub fn fast() -> Self {
        Self {
            nat_traversal: NatTraversalTimeouts::fast(),
            discovery: DiscoveryTimeouts::default(),
            relay: RelayTimeouts::default(),
        }
    }

    /// Create a configuration optimized for slow networks
    pub fn conservative() -> Self {
        Self {
            nat_traversal: NatTraversalTimeouts::conservative(),
            discovery: DiscoveryTimeouts::default(),
            relay: RelayTimeouts::default(),
        }
    }
}
