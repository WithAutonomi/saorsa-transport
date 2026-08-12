//! Transport-level A/B for the dial/accept keep-alive split.
//!
//! Measures idle per-connection-endpoint egress directly at the QUIC layer,
//! with frame attribution, across the four cadence combinations that matter:
//! baseline (both un-upgraded), patched (both upgraded), and the two mixed
//! cases. Complements the ant-node testnet arm, which supplies realistic
//! connection counts, workload and churn but a noisier byte signal.
//!
//! ```bash
//! cargo test --features egress-metrics --test keepalive_egress_ab \
//!   -- --nocapture --test-threads=1
//! ```
//!
//! Knobs (env): `KA_IDLE_SECS` (default 90), `KA_PAIRS` (default 4).

#![cfg(feature = "egress-experiment")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::cast_precision_loss)]

use saorsa_transport::config::nat_timeouts::TimeoutConfig;
use saorsa_transport::egress_metrics;
use saorsa_transport::{NatConfig, P2pConfig, P2pEndpoint, PqcConfig};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant};

/// Pre-change wiring: dial hardcoded to 5 s, accept pinned to `retry_interval`
/// (2 s under `conservative_timeouts()`, which is what saorsa-core selects).
const BASELINE_DIAL: Option<Duration> = Some(Duration::from_secs(5));
const BASELINE_ACCEPT: Option<Duration> = Some(Duration::from_secs(2));

/// Post-change wiring.
const PATCHED_DIAL: Option<Duration> = Some(Duration::from_secs(15));
const PATCHED_ACCEPT: Option<Duration> = None;

/// IPv4 + UDP header bytes, added per datagram to turn QUIC payload bytes into
/// on-the-wire bytes. The counters see payload only.
const WIRE_OVERHEAD_PER_DATAGRAM: f64 = 28.0;

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn config(
    known_peers: Vec<SocketAddr>,
    dial: Option<Duration>,
    accept: Option<Duration>,
) -> P2pConfig {
    let mut timeouts = TimeoutConfig::conservative();
    timeouts.nat_traversal.dial_keep_alive_interval = dial;
    timeouts.nat_traversal.accept_keep_alive_interval = accept;
    P2pConfig::builder()
        .bind_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .known_peers(known_peers)
        .timeouts(timeouts)
        .nat(NatConfig {
            allow_loopback: true,
            enable_relay_fallback: false,
            ..Default::default()
        })
        .pqc(PqcConfig::default())
        .build()
        .expect("build config")
}

struct ArmResult {
    name: &'static str,
    connections: usize,
    idle_secs: f64,
    delta: egress_metrics::Snapshot,
    /// Connections still open, checked individually at the end of the window.
    alive_after: usize,
}

impl ArmResult {
    /// Egress bytes per second per connection *endpoint*. The counters are
    /// process-global and both ends of every pair live in this process, so the
    /// denominator is `2 * connections`.
    fn payload_bytes_per_conn_endpoint_sec(&self) -> f64 {
        self.delta.udp_tx_bytes as f64 / (2.0 * self.connections as f64) / self.idle_secs
    }

    fn wire_bytes_per_conn_endpoint_sec(&self) -> f64 {
        let wire = self.delta.udp_tx_bytes as f64
            + self.delta.udp_tx_datagrams as f64 * WIRE_OVERHEAD_PER_DATAGRAM;
        wire / (2.0 * self.connections as f64) / self.idle_secs
    }

    fn datagrams_per_conn_endpoint_sec(&self) -> f64 {
        self.delta.udp_tx_datagrams as f64 / (2.0 * self.connections as f64) / self.idle_secs
    }

    fn report(&self) {
        println!(
            "KA-ARM arm={} connections={} idle_secs={:.1} \
             payload_Bps_per_conn_endpoint={:.3} wire_Bps_per_conn_endpoint={:.3} \
             datagrams_per_conn_endpoint_s={:.4} pings={} alive_after={}/{} {}",
            self.name,
            self.connections,
            self.idle_secs,
            self.payload_bytes_per_conn_endpoint_sec(),
            self.wire_bytes_per_conn_endpoint_sec(),
            self.datagrams_per_conn_endpoint_sec(),
            self.delta.ping_tx,
            self.alive_after,
            self.connections,
            self.delta.to_kv(),
        );
    }
}

/// Bring up `pairs` dialer/accepter pairs with the given cadences, let the
/// handshake and NAT-traversal chatter settle, then measure a quiet window.
async fn run_arm(
    name: &'static str,
    dial: Option<Duration>,
    accept: Option<Duration>,
    pairs: usize,
    idle: Duration,
) -> ArmResult {
    let mut accepters = Vec::with_capacity(pairs);
    let mut dialers = Vec::with_capacity(pairs);
    let mut addrs = Vec::with_capacity(pairs);

    for _ in 0..pairs {
        let accepter = P2pEndpoint::new(config(vec![], dial, accept))
            .await
            .expect("accepter");
        let addr = accepter.local_addr().expect("accepter addr");
        let dialer = P2pEndpoint::new(config(vec![addr], dial, accept))
            .await
            .expect("dialer");
        tokio::time::timeout(Duration::from_secs(20), dialer.connect(addr))
            .await
            .expect("connect timeout")
            .expect("connect");
        addrs.push(addr);
        accepters.push(accepter);
        dialers.push(dialer);
    }

    // Settle: handshake, address discovery and any NAT-traversal frames must
    // finish before the quiet window opens, or they land in the delta.
    tokio::time::sleep(Duration::from_secs(10)).await;

    let before = egress_metrics::snapshot();
    let started = Instant::now();
    tokio::time::sleep(idle).await;
    let elapsed = started.elapsed().as_secs_f64();
    let delta = egress_metrics::snapshot().since(&before);

    // Liveness, per connection, before anything is torn down. Counting bytes
    // cannot show this: a dead connection simply stops contributing, which
    // looks like a saving. `close_reason()` is `Some` once a connection has
    // been closed for any reason, including an idle timeout.
    let mut alive = 0usize;
    for (dialer, addr) in dialers.iter().zip(addrs.iter()) {
        let still_up = match dialer.get_quic_connection(addr).await {
            Ok(Some(conn)) => conn.close_reason().is_none(),
            _ => false,
        };
        if still_up {
            alive += 1;
        }
    }

    for endpoint in dialers.into_iter().chain(accepters) {
        let _ = tokio::time::timeout(Duration::from_secs(3), endpoint.shutdown()).await;
    }
    // Let teardown traffic drain so it does not bleed into the next arm.
    tokio::time::sleep(Duration::from_secs(3)).await;

    ArmResult {
        name,
        connections: pairs,
        idle_secs: elapsed,
        delta,
        alive_after: alive,
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn idle_keepalive_egress_by_arm() {
    let idle = Duration::from_secs(env_u64("KA_IDLE_SECS", 90));
    let pairs = env_u64("KA_PAIRS", 4) as usize;

    let baseline = run_arm("baseline", BASELINE_DIAL, BASELINE_ACCEPT, pairs, idle).await;
    baseline.report();

    let patched = run_arm("patched", PATCHED_DIAL, PATCHED_ACCEPT, pairs, idle).await;
    patched.report();

    // Mixed: a patched dialer against an un-upgraded accepter. The accepter
    // still pings at its own cadence, so the pair keeps the old rate.
    let mixed_old_accepter = run_arm(
        "mixed_patched_dial_baseline_accept",
        PATCHED_DIAL,
        BASELINE_ACCEPT,
        pairs,
        idle,
    )
    .await;
    mixed_old_accepter.report();

    // Mixed: an un-upgraded dialer against a patched accepter. Only the
    // dialer's 5 s keep-alive remains.
    let mixed_old_dialer = run_arm(
        "mixed_baseline_dial_patched_accept",
        BASELINE_DIAL,
        PATCHED_ACCEPT,
        pairs,
        idle,
    )
    .await;
    mixed_old_dialer.report();

    let base = baseline.wire_bytes_per_conn_endpoint_sec();
    let post = patched.wire_bytes_per_conn_endpoint_sec();
    let reduction = 100.0 * (1.0 - post / base);
    println!(
        "KA-SUMMARY baseline_wire_Bps={base:.3} patched_wire_Bps={post:.3} \
         reduction_pct={reduction:.2} \
         mixed_old_accept_wire_Bps={:.3} mixed_old_dial_wire_Bps={:.3}",
        mixed_old_accepter.wire_bytes_per_conn_endpoint_sec(),
        mixed_old_dialer.wire_bytes_per_conn_endpoint_sec(),
    );

    // Every connection in every arm must still be open. Byte counts cannot
    // show this on their own: a connection that dies stops sending, which
    // reads as a saving rather than a fault.
    for arm in [&baseline, &patched, &mixed_old_accepter, &mixed_old_dialer] {
        assert_eq!(
            arm.alive_after, arm.connections,
            "arm {}: only {}/{} connections survived the idle window",
            arm.name, arm.alive_after, arm.connections
        );
    }
}

/// Long-idle soak: hold connections open across many keep-alive cycles and
/// check none of them dies. The 15 s dial keep-alive sits at exactly half the
/// 30 s `max_idle_timeout`, so this is the margin the design actually depends
/// on. Any closure shows up as handshake bytes (a reconnect) or as the
/// connection count dropping.
///
/// ```bash
/// KA_SOAK=1 KA_SOAK_SECS=1800 cargo test --features egress-metrics \
///   --test keepalive_egress_ab soak -- --nocapture
/// ```
#[tokio::test(flavor = "multi_thread")]
async fn patched_keepalive_soak() {
    if std::env::var("KA_SOAK").ok().as_deref() != Some("1") {
        eprintln!("KA-SOAK skipped (set KA_SOAK=1 to run)");
        return;
    }
    let secs = env_u64("KA_SOAK_SECS", 1800);
    let pairs = env_u64("KA_PAIRS", 4) as usize;

    let result = run_arm(
        "soak_patched",
        PATCHED_DIAL,
        PATCHED_ACCEPT,
        pairs,
        Duration::from_secs(secs),
    )
    .await;
    result.report();

    let cycles = secs as f64 / 15.0;
    println!(
        "KA-SOAK secs={secs} pairs={pairs} keepalive_cycles_per_conn={cycles:.0} \
         handshake_bytes={} handshake_packets={} lost_bytes={} lost_packets={} \
         pings={} expected_pings={:.0}",
        result.delta.handshake_bytes_tx,
        result.delta.handshake_packets_tx,
        result.delta.lost_bytes,
        result.delta.lost_packets,
        result.delta.ping_tx,
        cycles * pairs as f64,
    );

    assert_eq!(
        result.alive_after, pairs,
        "only {}/{pairs} connections survived the soak",
        result.alive_after
    );
    assert_eq!(
        result.delta.handshake_bytes_tx, 0,
        "a connection reconnected during the soak: the keep-alive did not hold it open"
    );
    // Every dialler pings once per interval for the whole window. A connection
    // that died late would still pass a loose bound, so require the full count
    // (one interval of slack for where the window boundary falls).
    let expected = cycles * pairs as f64;
    assert!(
        result.delta.ping_tx as f64 >= expected - pairs as f64,
        "expected {expected:.0} keep-alive pings, saw {}: connections stopped pinging",
        result.delta.ping_tx
    );
}
