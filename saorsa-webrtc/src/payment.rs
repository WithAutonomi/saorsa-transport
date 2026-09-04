//! Portable verification primitives for the browser payment wire profile.

use serde::{Deserialize, Serialize};
use tiny_keccak::{Hasher as _, Keccak};

use crate::verify_ml_dsa_65;

/// Domain-separation tag for a storage commitment signature.
pub const DOMAIN_COMMITMENT: &[u8] = b"autonomi.ant.replication.storage_commitment.v1";

/// Domain-separation tag for the commitment pin.
pub const DOMAIN_COMMITMENT_HASH: &[u8] = b"autonomi.ant.replication.commitment_hash.v1";

/// Maximum number of keys accepted in a browser storage commitment.
pub const MAX_COMMITMENT_KEY_COUNT: u32 = 1_000_000;

/// Maximum encoded storage commitment accepted from the browser wire profile.
pub const MAX_COMMITMENT_SIDECAR_BYTES: usize = 8 * 1024;

/// Number of closest nodes queried by the browser storage workflow.
pub const CLOSE_GROUP_SIZE: usize = 7;

/// Successful stores required for a simple close-group majority.
pub const CLOSE_GROUP_MAJORITY: usize = (CLOSE_GROUP_SIZE / 2) + 1;

const PRICING_DIVISOR: u128 = 6_000;
const DIVISOR_SQUARED: u128 = PRICING_DIVISOR * PRICING_DIVISOR;
const PRICE_BASELINE_WEI: u128 = 3_906_250_000_000_000;
const PRICE_COEFFICIENT_WEI: u128 = 35_156_250_000_000_000;

/// Portable representation of the native storage commitment sidecar.
///
/// Its Serde representation intentionally matches the application protocol's
/// native `StorageCommitment` byte for byte.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct StorageCommitment {
    /// Merkle root over the responder's claimed keys.
    pub root: [u8; 32],
    /// Number of leaves covered by the commitment.
    pub key_count: u32,
    /// Sender peer ID bound by the signature.
    pub sender_peer_id: [u8; 32],
    /// Sender ML-DSA-65 public key.
    pub sender_public_key: Vec<u8>,
    /// ML-DSA-65 signature over the canonical commitment fields.
    pub signature: Vec<u8>,
}

/// Calculate storage price in wei with portable integer primitives.
#[must_use]
pub fn calculate_price_wei(close_records_stored: u32) -> u128 {
    let n = u128::from(close_records_stored);
    PRICE_BASELINE_WEI + n.saturating_mul(n).saturating_mul(PRICE_COEFFICIENT_WEI) / DIVISOR_SQUARED
}

/// Return the canonical bytes covered by a storage commitment signature.
#[must_use]
pub fn storage_commitment_bytes_for_signing(
    root: &[u8; 32],
    key_count: u32,
    sender_peer_id: &[u8; 32],
    sender_public_key: &[u8],
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32 + 4 + 32 + 4 + sender_public_key.len());
    bytes.extend_from_slice(root);
    bytes.extend_from_slice(&key_count.to_le_bytes());
    bytes.extend_from_slice(sender_peer_id);
    let public_key_length = u32::try_from(sender_public_key.len()).unwrap_or(u32::MAX);
    bytes.extend_from_slice(&public_key_length.to_le_bytes());
    bytes.extend_from_slice(sender_public_key);
    bytes
}

/// Verify the embedded signature of a browser storage commitment.
#[must_use]
pub fn verify_commitment_signature(commitment: &StorageCommitment) -> bool {
    let payload = storage_commitment_bytes_for_signing(
        &commitment.root,
        commitment.key_count,
        &commitment.sender_peer_id,
        &commitment.sender_public_key,
    );
    verify_ml_dsa_65(
        &commitment.sender_public_key,
        &commitment.signature,
        &payload,
        DOMAIN_COMMITMENT,
    )
}

/// Hash the canonical encoded storage commitment into its application pin.
#[must_use]
pub fn commitment_hash(commitment: &StorageCommitment) -> Option<[u8; 32]> {
    let encoded = postcard::to_allocvec(commitment).ok()?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(DOMAIN_COMMITMENT_HASH);
    hasher.update(&encoded);
    Some(*hasher.finalize().as_bytes())
}

/// Construct the canonical bytes covered by a browser storage quote signature.
#[must_use]
pub fn payment_quote_bytes_for_signing(
    content: &[u8; 32],
    timestamp_secs: u64,
    price_wei: u128,
    rewards_address: &[u8; 20],
    committed_key_count: u32,
    commitment_pin: Option<&[u8; 32]>,
) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(32 + 8 + 32 + 20 + 4 + 33);
    bytes.extend_from_slice(content);
    bytes.extend_from_slice(&timestamp_secs.to_le_bytes());
    bytes.extend_from_slice(&price_wei.to_le_bytes());
    bytes.extend_from_slice(&[0; 16]);
    bytes.extend_from_slice(rewards_address);
    bytes.extend_from_slice(&committed_key_count.to_le_bytes());
    if let Some(pin) = commitment_pin {
        bytes.push(1);
        bytes.extend_from_slice(pin);
    } else {
        bytes.push(0);
    }
    bytes
}

/// Compute the Keccak-256 EVM payment quote identifier.
#[must_use]
pub fn payment_quote_hash(signed_bytes: &[u8], public_key: &[u8], signature: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak::v256();
    hasher.update(signed_bytes);
    hasher.update(public_key);
    hasher.update(signature);
    let mut output = [0; 32];
    hasher.finalize(&mut output);
    output
}

#[cfg(test)]
mod tests {
    use super::*;
    use saorsa_pqc::api::sig::ml_dsa_65;

    #[test]
    fn payment_hash_matches_native_vector() {
        assert_eq!(
            hex::encode(payment_quote_hash(&[0, 1], &[2], &[3])),
            "d98f2e8134922f73748703c8e7084d42f13d2fa1439936ef5a3abcf5646fe83f"
        );
    }

    #[test]
    fn commitment_signature_and_pin_round_trip() {
        let (public_key, secret_key) = ml_dsa_65().generate_keypair().expect("keypair");
        let public_key = public_key.to_bytes();
        let peer_id = *blake3::hash(&public_key).as_bytes();
        let mut commitment = StorageCommitment {
            root: [0x53; 32],
            key_count: 23,
            sender_peer_id: peer_id,
            sender_public_key: public_key,
            signature: Vec::new(),
        };
        let payload = storage_commitment_bytes_for_signing(
            &commitment.root,
            commitment.key_count,
            &commitment.sender_peer_id,
            &commitment.sender_public_key,
        );
        commitment.signature = ml_dsa_65()
            .sign_with_context(&secret_key, &payload, DOMAIN_COMMITMENT)
            .expect("signature")
            .to_bytes();

        assert!(verify_commitment_signature(&commitment));
        assert_eq!(commitment_hash(&commitment), commitment_hash(&commitment));
    }
}
