//! Portable Saorsa WebRTC Direct profile and application wire contract.
//!
//! WebRTC requests are split across ordered SCTP messages. A fixed deadline is
//! appropriate for headers and small control requests, but not for a full
//! [`MAX_BROWSER_RECORD_BYTES`] body competing with other replica uploads. Both
//! sides use this module so the sender never waits longer than the receiver is
//! willing to accept the same frame.

use fips204::{
    ml_dsa_65,
    traits::{SerDes as _, Verifier as _},
};
use std::time::Duration;

mod payment;
mod session;
mod wire;
pub use payment::*;
pub use session::{
    PQ_CLIENT_HELLO_BYTES, PQ_ENCRYPTED_OVERHEAD_BYTES, PQ_FRAME_PREFIX_BYTES,
    PQ_SERVER_ACCEPT_BYTES, PqClientHandshake, PqSession, PqSessionError, accept_pq_session,
    decode_pq_frame, encode_pq_frame, pq_frame_length,
};
pub use wire::*;

/// Verify an ML-DSA-65 signature, returning `false` for malformed input.
#[must_use]
pub fn verify_ml_dsa_65(
    public_key: &[u8],
    signature: &[u8],
    message: &[u8],
    context: &[u8],
) -> bool {
    let Ok(public_key) = <[u8; ml_dsa_65::PK_LEN]>::try_from(public_key) else {
        return false;
    };
    let Ok(signature) = <[u8; ml_dsa_65::SIG_LEN]>::try_from(signature) else {
        return false;
    };
    let Ok(public_key) = ml_dsa_65::PublicKey::try_from_bytes(public_key) else {
        return false;
    };
    public_key.verify(message, &signature, context)
}

/// Time allowed for a header-only WebRTC Direct request.
pub const WEBRTC_TRANSFER_BASE_TIMEOUT: Duration = Duration::from_secs(10);

/// Slowest sustained per-DataChannel frame rate accommodated by the protocol.
///
/// Uploads deliberately fan out to several peers. A conservative per-channel
/// floor keeps those parallel streams viable on ordinary residential uplinks.
pub const WEBRTC_MIN_TRANSFER_RATE_BYTES_PER_SEC: u64 = 32 * 1024;

/// Upper bound for one complete WebRTC Direct request or response transfer.
pub const WEBRTC_TRANSFER_MAX_TIMEOUT: Duration = Duration::from_secs(180);

/// Return the transfer deadline for a frame containing `frame_bytes` bytes.
///
/// The fixed base covers connection scheduling and latency. Transfer time is
/// added at [`WEBRTC_MIN_TRANSFER_RATE_BYTES_PER_SEC`] and clamped so a
/// permanently stalled channel is still discarded.
#[must_use]
pub fn transfer_timeout(frame_bytes: usize) -> Duration {
    let frame_bytes = u64::try_from(frame_bytes).unwrap_or(u64::MAX);
    let transfer_seconds = frame_bytes.div_ceil(WEBRTC_MIN_TRANSFER_RATE_BYTES_PER_SEC);
    WEBRTC_TRANSFER_BASE_TIMEOUT
        .saturating_add(Duration::from_secs(transfer_seconds))
        .min(WEBRTC_TRANSFER_MAX_TIMEOUT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transfer_timeout_scales_with_body_size() {
        assert_eq!(transfer_timeout(0), Duration::from_secs(10));
        assert_eq!(transfer_timeout(32 * 1024), Duration::from_secs(11));
        assert_eq!(
            transfer_timeout(MAX_BROWSER_RECORD_BYTES),
            Duration::from_secs(138)
        );
        assert_eq!(
            transfer_timeout(MAX_BROWSER_RECORD_BYTES + 1),
            Duration::from_secs(139)
        );
    }

    #[test]
    fn transfer_timeout_is_capped() {
        assert_eq!(transfer_timeout(usize::MAX), WEBRTC_TRANSFER_MAX_TIMEOUT);
    }
}
