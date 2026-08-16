// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Only the dialling side keep-alives, and that is enough to hold a connection.
//!
//! Two in-process endpoints are connected and left idle for longer than the
//! 30 s `max_idle_timeout`. Everything is read from the dialling side's
//! `ConnectionStats`, which sees both halves of the question: `frame_tx.ping`
//! is what this node sent and `frame_rx.ping` is what the peer sent, so the
//! accepting side's silence is observed on the wire rather than inferred.
//!
//! `frame_tx.ping` is not a keep-alive counter in general — it also counts
//! DPLPMTUD probes, PTO probes and path validation. None of those should fire
//! here after the settle: the MTU search finishes in a few loopback round trips
//! and does not re-probe for 600 s, PTO needs loss, and path validation needs a
//! migration. That is an argument rather than a proof, so the test checks the
//! *spacing* of the PINGs too, which a stray probe would not match.
//!
//! This is loopback: no NAT, no loss, one connection. It shows the mechanism
//! works on an ideal path. It says nothing about NAT mapping expiry, which is
//! what actually bounds how long the interval can be.

#![allow(clippy::expect_used)]

use saorsa_transport::{NatConfig, P2pConfig, P2pEndpoint, PqcConfig};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

/// The cadence and idle timeout the transport is expected to use. Written as
/// literals rather than imported from the crate, so that changing the constant
/// fails this test instead of silently moving what it asserts.
const EXPECTED_KEEP_ALIVE: Duration = Duration::from_secs(10);
const EXPECTED_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Long enough for the handshake, PQC key exchange, address discovery and the
/// MTU search to finish, so none of them lands inside the window.
const SETTLE: Duration = Duration::from_secs(8);

/// Idle window: past the idle timeout, so a connection nothing is keeping alive
/// is guaranteed to be gone by the end of it.
const IDLE_WINDOW: Duration = Duration::from_secs(40);

const _: () = assert!(
    IDLE_WINDOW.as_millis() > EXPECTED_IDLE_TIMEOUT.as_millis(),
    "the window must exceed the idle timeout or this proves nothing"
);

fn config(known_peers: Vec<SocketAddr>) -> P2pConfig {
    P2pConfig::builder()
        .bind_addr(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .known_peers(known_peers)
        .nat(NatConfig {
            allow_loopback: true,
            enable_relay_fallback: false,
            ..Default::default()
        })
        .pqc(PqcConfig::default())
        .build()
        .expect("build test config")
}

#[tokio::test(flavor = "multi_thread")]
async fn only_the_dialling_side_keep_alives_and_the_connection_survives() {
    let accepter = P2pEndpoint::new(config(vec![]))
        .await
        .expect("accepter endpoint");
    let peer = accepter.local_addr().expect("accepter address");
    let dialer = P2pEndpoint::new(config(vec![peer]))
        .await
        .expect("dialer endpoint");
    tokio::time::timeout(Duration::from_secs(20), dialer.connect(peer))
        .await
        .expect("connect did not time out")
        .expect("connect succeeded");

    // `(pings sent, pings received, acks received)` from the dialler's view.
    let counters = || async {
        match dialer.get_quic_connection(&peer).await {
            Ok(Some(conn)) => {
                let s = conn.stats();
                (s.frame_tx.ping, s.frame_rx.ping, s.frame_rx.acks)
            }
            other => panic!("no live connection to {peer} ({other:?})"),
        }
    };

    tokio::time::sleep(SETTLE).await;
    let (sent_before, received_before, acks_before) = counters().await;

    // Sample across the window so the PINGs can be timed, not just counted.
    let started = tokio::time::Instant::now();
    let mut ping_times = Vec::new();
    let mut seen = sent_before;
    while started.elapsed() < IDLE_WINDOW {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let (sent_now, _, _) = counters().await;
        for _ in seen..sent_now {
            ping_times.push(started.elapsed());
        }
        seen = sent_now;
    }
    let (sent_after, received_after, acks_after) = counters().await;
    for _ in seen..sent_after {
        ping_times.push(started.elapsed());
    }

    let pings_sent = sent_after - sent_before;
    let pings_received = received_after - received_before;
    let acks_received = acks_after - acks_before;
    let report = format!("sent={pings_sent} received={pings_received} acks={acks_received}");

    assert_eq!(
        pings_received, 0,
        "the accepting side must send no keep-alive of its own: {report}"
    );
    assert!(
        acks_received > 0,
        "the accepting side must answer — its ACKs are the outbound packets that \
         refresh its NAT mapping in the reverse direction: {report}"
    );

    // At a 10 s cadence a 40 s window holds three or four, depending on where
    // the window opens relative to the timer.
    let expected = IDLE_WINDOW.as_secs() / EXPECTED_KEEP_ALIVE.as_secs();
    assert!(
        (expected - 1..=expected + 1).contains(&pings_sent),
        "expected about {expected} keep-alives over {IDLE_WINDOW:?} at a \
         {EXPECTED_KEEP_ALIVE:?} cadence: {report}"
    );
    assert_eq!(
        ping_times.len() as u64,
        pings_sent,
        "every counted PING must be timed, or the spacing check below skips it"
    );

    // Counting alone would let an unrelated PING — an MTU or PTO probe — stand
    // in for a keep-alive that never fired, since those cluster near other
    // traffic rather than arriving on a cadence. So require the gaps to be at
    // least half the interval.
    //
    // Deliberately one-sided: these timestamps are when the sampler *observed*
    // a counter change, so a busy machine can only stretch a gap, never shrink
    // one. An upper bound would flake; a lower bound cannot.
    let minimum_gap = EXPECTED_KEEP_ALIVE / 2;
    for pair in ping_times.windows(2) {
        if let [earlier, later] = pair {
            let gap = later.saturating_sub(*earlier);
            assert!(
                gap >= minimum_gap,
                "PINGs {gap:?} apart, closer than the {minimum_gap:?} floor for a \
                 {EXPECTED_KEEP_ALIVE:?} cadence — something other than the keep-alive \
                 is emitting them: {report}"
            );
        }
    }

    // `close_reason()` would only say the local driver has not processed a close
    // yet, so instead require the far side to still be answering. This shows the
    // peer is alive and reachable; it is not proof that this particular payload
    // was delivered, since ACK counters do not identify what they acknowledge.
    dialer
        .send(&peer, b"post-idle liveness probe")
        .await
        .expect("an idle-but-alive connection must still accept a send");
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let acks_at_send = counters().await.2;
    loop {
        if counters().await.2 > acks_at_send {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the peer did not acknowledge data sent after a {IDLE_WINDOW:?} idle window"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let _ = tokio::time::timeout(Duration::from_secs(3), dialer.shutdown()).await;
    let _ = tokio::time::timeout(Duration::from_secs(3), accepter.shutdown()).await;
}
