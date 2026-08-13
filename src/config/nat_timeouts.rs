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

    /// QUIC keep-alive interval applied to connections this node *dials*.
    ///
    /// This is deliberately independent of [`Self::retry_interval`]: the NAT
    /// retry cadence and the idle keep-alive cadence solve different problems
    /// and previously shared one value, which pinned the keep-alive to the
    /// retry interval and made idle connections far more expensive than they
    /// need to be.
    ///
    /// `None` disables keep-alive on dialled connections. Must stay below the
    /// 30 s `max_idle_timeout` used for QUIC connections, and in practice well
    /// below it so a single lost keep-alive does not race the idle timer.
    #[serde(default = "default_dial_keep_alive_interval")]
    pub dial_keep_alive_interval: Option<Duration>,

    /// QUIC keep-alive interval applied to connections this node *accepts*.
    ///
    /// `None` (the default) disables keep-alive on the accepting side. Only one
    /// side of a connection needs keep-alive enabled for the connection to be
    /// preserved, and the dialling side already provides it via
    /// [`Self::dial_keep_alive_interval`]. The accepting side still emits an
    /// ACK in response to each incoming keep-alive, so both directions still
    /// see traffic at the dial cadence.
    #[serde(default = "default_accept_keep_alive_interval")]
    pub accept_keep_alive_interval: Option<Duration>,
}

/// Default keep-alive interval for dialled connections (10 s).
///
/// Tracks the shipped default on `fix/keepalive-dial-accept-split` so the A/B
/// harness measures the cadence that actually ships. The rationale for 10 s
/// over 15 s is NAT mapping headroom; see ADR-012 on that branch.
fn default_dial_keep_alive_interval() -> Option<Duration> {
    Some(Duration::from_secs(10))
}

/// Default keep-alive interval for accepted connections (disabled).
fn default_accept_keep_alive_interval() -> Option<Duration> {
    None
}

/// `max_idle_timeout` applied to every QUIC connection this crate creates,
/// in milliseconds.
///
/// Keep-alive intervals are only meaningful relative to this value, so the two
/// live together and [`NatTraversalTimeouts::validate_keep_alive`] enforces the
/// relationship. Changing it here changes it at both endpoint configuration
/// sites in `nat_traversal_api`.
pub const QUIC_MAX_IDLE_TIMEOUT_MS: u32 = 30_000;

/// [`QUIC_MAX_IDLE_TIMEOUT_MS`] as a [`Duration`].
pub const QUIC_MAX_IDLE_TIMEOUT: Duration = Duration::from_millis(QUIC_MAX_IDLE_TIMEOUT_MS as u64);

/// Largest keep-alive interval that still leaves room for one lost keep-alive
/// to be recovered before the peer's idle timer expires: half the idle timeout.
pub const MAX_USABLE_KEEP_ALIVE: Duration =
    Duration::from_millis((QUIC_MAX_IDLE_TIMEOUT_MS / 2) as u64);

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
            dial_keep_alive_interval: default_dial_keep_alive_interval(),
            accept_keep_alive_interval: default_accept_keep_alive_interval(),
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
            dial_keep_alive_interval: default_dial_keep_alive_interval(),
            accept_keep_alive_interval: default_accept_keep_alive_interval(),
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
            dial_keep_alive_interval: default_dial_keep_alive_interval(),
            accept_keep_alive_interval: default_accept_keep_alive_interval(),
        }
    }

    /// Reject keep-alive settings that cannot work.
    ///
    /// These fields are deserialized from operator-supplied configuration, so
    /// the invariants the defaults satisfy have to be enforced for arbitrary
    /// values too:
    ///
    /// - a zero interval re-arms the keep-alive timer at the current instant
    ///   every time it fires, which is a PING/CPU busy loop;
    /// - an interval at or above [`MAX_USABLE_KEEP_ALIVE`] leaves no room to
    ///   recover a lost keep-alive before the peer's idle timer expires, and at
    ///   or above [`QUIC_MAX_IDLE_TIMEOUT`] the connection is guaranteed to
    ///   idle out between keep-alives;
    /// - disabling both sides means nothing holds an idle connection open.
    pub fn validate_keep_alive(&self) -> Result<(), String> {
        for (name, value) in [
            ("dial_keep_alive_interval", self.dial_keep_alive_interval),
            (
                "accept_keep_alive_interval",
                self.accept_keep_alive_interval,
            ),
        ] {
            let Some(interval) = value else { continue };
            if interval.is_zero() {
                return Err(format!(
                    "{name} must not be zero: it would spin the keep-alive timer"
                ));
            }
            if interval > MAX_USABLE_KEEP_ALIVE {
                return Err(format!(
                    "{name} ({interval:?}) must be at most {MAX_USABLE_KEEP_ALIVE:?}, \
                     half the {QUIC_MAX_IDLE_TIMEOUT:?} max_idle_timeout, so a lost \
                     keep-alive can be recovered before the peer times the connection out"
                ));
            }
        }
        if self.dial_keep_alive_interval.is_none() && self.accept_keep_alive_interval.is_none() {
            return Err(
                "at least one of dial_keep_alive_interval or accept_keep_alive_interval must be \
                 set, or idle connections will be closed at the idle timeout"
                    .to_string(),
            );
        }
        Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A config persisted before the keep-alive fields existed must still load.
    /// `NatTraversalTimeouts` derives `Deserialize` with no container-level
    /// `#[serde(default)]`, so without per-field defaults every stored config
    /// would fail to parse after the upgrade.
    #[test]
    fn deserializes_config_written_before_the_keep_alive_fields() {
        let legacy = r#"{
            "coordination_timeout": {"secs": 10, "nanos": 0},
            "connection_establishment_timeout": {"secs": 30, "nanos": 0},
            "probe_timeout": {"secs": 5, "nanos": 0},
            "retry_interval": {"secs": 1, "nanos": 0},
            "bootstrap_query_timeout": {"secs": 5, "nanos": 0},
            "migration_timeout": {"secs": 60, "nanos": 0},
            "session_timeout": {"secs": 5, "nanos": 0}
        }"#;
        let parsed: NatTraversalTimeouts =
            serde_json::from_str(legacy).expect("legacy config must still deserialize");
        assert_eq!(parsed.retry_interval, Duration::from_secs(1));
        assert_eq!(
            parsed.dial_keep_alive_interval,
            Some(Duration::from_secs(15))
        );
        assert_eq!(parsed.accept_keep_alive_interval, None);
    }

    /// The keep-alive must stay clear of the 30 s `max_idle_timeout` applied to
    /// every QUIC connection, or a connection can idle out between keep-alives.
    #[test]
    fn dial_keep_alive_stays_below_the_idle_timeout() {
        const MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
        for timeouts in [
            NatTraversalTimeouts::default(),
            NatTraversalTimeouts::fast(),
            NatTraversalTimeouts::conservative(),
        ] {
            let dial = timeouts
                .dial_keep_alive_interval
                .expect("dial keep-alive must be set: it is the only one left");
            assert!(
                dial < MAX_IDLE_TIMEOUT,
                "dial keep-alive {dial:?} must be below the {MAX_IDLE_TIMEOUT:?} idle timeout"
            );
        }
    }

    #[test]
    fn rejects_unusable_keep_alive_settings() {
        let base = NatTraversalTimeouts::default();
        base.validate_keep_alive().expect("defaults must validate");

        // Zero would re-arm the timer at `now` on every fire.
        let mut zero = base.clone();
        zero.dial_keep_alive_interval = Some(Duration::ZERO);
        assert!(zero.validate_keep_alive().is_err(), "zero dial interval");
        let mut zero_accept = base.clone();
        zero_accept.accept_keep_alive_interval = Some(Duration::ZERO);
        assert!(
            zero_accept.validate_keep_alive().is_err(),
            "zero accept interval"
        );

        // At or beyond half the idle timeout there is no room to recover a
        // lost keep-alive; at or beyond the idle timeout it cannot work at all.
        let mut too_long = base.clone();
        too_long.dial_keep_alive_interval = Some(MAX_USABLE_KEEP_ALIVE + Duration::from_millis(1));
        assert!(too_long.validate_keep_alive().is_err(), "interval too long");
        let mut past_idle = base.clone();
        past_idle.dial_keep_alive_interval = Some(QUIC_MAX_IDLE_TIMEOUT);
        assert!(past_idle.validate_keep_alive().is_err(), "interval >= idle");

        // Both sides off means nothing holds an idle connection open.
        let mut both_off = base.clone();
        both_off.dial_keep_alive_interval = None;
        both_off.accept_keep_alive_interval = None;
        assert!(both_off.validate_keep_alive().is_err(), "both disabled");

        // Either side alone is fine.
        let mut accept_only = base.clone();
        accept_only.dial_keep_alive_interval = None;
        accept_only.accept_keep_alive_interval = Some(Duration::from_secs(10));
        accept_only
            .validate_keep_alive()
            .expect("accept-only is a valid configuration");
    }

    /// The shipped default must sit exactly on the boundary the validator
    /// allows, so that lowering the idle timeout without revisiting the
    /// keep-alive fails a test rather than shipping.
    #[test]
    fn default_dial_interval_is_within_the_usable_bound() {
        let dial = NatTraversalTimeouts::default()
            .dial_keep_alive_interval
            .expect("dial keep-alive must be set");
        assert!(dial <= MAX_USABLE_KEEP_ALIVE);
        assert!(dial < QUIC_MAX_IDLE_TIMEOUT);
    }

    /// Round-tripping must preserve the new fields, not silently reset them.
    #[test]
    fn keep_alive_fields_round_trip() {
        let mut timeouts = NatTraversalTimeouts::conservative();
        timeouts.dial_keep_alive_interval = Some(Duration::from_secs(9));
        timeouts.accept_keep_alive_interval = Some(Duration::from_secs(21));
        let encoded = serde_json::to_string(&timeouts).expect("serialize");
        let decoded: NatTraversalTimeouts = serde_json::from_str(&encoded).expect("deserialize");
        assert_eq!(
            decoded.dial_keep_alive_interval,
            Some(Duration::from_secs(9))
        );
        assert_eq!(
            decoded.accept_keep_alive_interval,
            Some(Duration::from_secs(21))
        );
    }
}
