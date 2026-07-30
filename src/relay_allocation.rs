// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Cryptographic proof that a relay issued a specific allocation.

use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};
use thiserror::Error;

use crate::crypto::pqc::MlDsaOperations;
use crate::crypto::pqc::ml_dsa::MlDsa65;
use crate::crypto::pqc::types::{MlDsaPublicKey, MlDsaSecretKey, MlDsaSignature};
use crate::crypto::raw_public_keys::pqc::fingerprint_public_key;

const RECEIPT_VERSION: u8 = 1;
const RECEIPT_DOMAIN: &[u8] = b"SAORSA_RELAY_ALLOCATION_V1";
const RECEIPT_LIFETIME_SECS: u64 = 24 * 60 * 60;

/// A relay-signed binding between an authenticated client and one allocation.
///
/// Witnesses must validate this receipt before attempting a canary dial. This
/// prevents a requester from turning the canary service into an arbitrary
/// reflected dial primitive.
#[derive(Clone, Serialize, Deserialize)]
pub struct RelayAllocationReceipt {
    version: u8,
    target_peer_id: [u8; 32],
    relayer_peer_id: [u8; 32],
    relay_addr: SocketAddr,
    allocation_id: u64,
    expires_at_unix_secs: u64,
    relayer_public_key: Vec<u8>,
    signature: Vec<u8>,
}

impl std::fmt::Debug for RelayAllocationReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RelayAllocationReceipt")
            .field("version", &self.version)
            .field("target_peer_id", &hex::encode(self.target_peer_id))
            .field("relayer_peer_id", &hex::encode(self.relayer_peer_id))
            .field("relay_addr", &self.relay_addr)
            .field("allocation_id", &self.allocation_id)
            .field("expires_at_unix_secs", &self.expires_at_unix_secs)
            .finish_non_exhaustive()
    }
}

impl PartialEq for RelayAllocationReceipt {
    fn eq(&self, other: &Self) -> bool {
        self.version == other.version
            && self.target_peer_id == other.target_peer_id
            && self.relayer_peer_id == other.relayer_peer_id
            && self.relay_addr == other.relay_addr
            && self.allocation_id == other.allocation_id
            && self.expires_at_unix_secs == other.expires_at_unix_secs
            && self.relayer_public_key == other.relayer_public_key
            && self.signature == other.signature
    }
}

impl Eq for RelayAllocationReceipt {}

/// Why a relay-allocation receipt could not be issued or verified.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RelayAllocationReceiptError {
    /// The receipt uses an unsupported wire version.
    #[error("unsupported relay allocation receipt version {0}")]
    UnsupportedVersion(u8),
    /// The receipt is not bound to the requesting peer.
    #[error("relay allocation receipt target does not match requester")]
    TargetMismatch,
    /// The receipt is not signed by the claimed relayer.
    #[error("relay allocation receipt relayer does not match claim")]
    RelayerMismatch,
    /// The receipt is for a different relay allocation address.
    #[error("relay allocation receipt address does not match request")]
    AddressMismatch,
    /// The receipt has expired.
    #[error("relay allocation receipt expired")]
    Expired,
    /// The local clock could not be represented as Unix time.
    #[error("system clock is before the Unix epoch")]
    InvalidClock,
    /// The embedded ML-DSA material is malformed.
    #[error("relay allocation receipt contains invalid ML-DSA material")]
    InvalidCryptoMaterial,
    /// The receipt wire representation is malformed.
    #[error("relay allocation receipt encoding is invalid")]
    InvalidEncoding,
    /// The ML-DSA signature is invalid.
    #[error("relay allocation receipt signature is invalid")]
    InvalidSignature,
    /// Signing failed.
    #[error("failed to sign relay allocation receipt")]
    SigningFailed,
}

impl RelayAllocationReceipt {
    /// Issue a receipt for an allocation made to an authenticated client.
    pub fn issue(
        relayer_public_key: &MlDsaPublicKey,
        relayer_secret_key: &MlDsaSecretKey,
        target_peer_id: [u8; 32],
        relay_addr: SocketAddr,
        allocation_id: u64,
    ) -> Result<Self, RelayAllocationReceiptError> {
        let now = unix_time_secs(SystemTime::now())?;
        let relayer_peer_id = fingerprint_public_key(relayer_public_key);
        let mut receipt = Self {
            version: RECEIPT_VERSION,
            target_peer_id,
            relayer_peer_id,
            relay_addr,
            allocation_id,
            expires_at_unix_secs: now.saturating_add(RECEIPT_LIFETIME_SECS),
            relayer_public_key: relayer_public_key.as_bytes().to_vec(),
            signature: Vec::new(),
        };
        let signature = MlDsa65::new()
            .sign(relayer_secret_key, &receipt.signing_message())
            .map_err(|_| RelayAllocationReceiptError::SigningFailed)?;
        receipt.signature = signature.as_bytes().to_vec();
        Ok(receipt)
    }

    /// Validate the receipt and all bindings supplied by a canary requester.
    pub fn verify(
        &self,
        target_peer_id: [u8; 32],
        relayer_peer_id: [u8; 32],
        relay_addr: SocketAddr,
        now: SystemTime,
    ) -> Result<(), RelayAllocationReceiptError> {
        if self.version != RECEIPT_VERSION {
            return Err(RelayAllocationReceiptError::UnsupportedVersion(
                self.version,
            ));
        }
        if self.target_peer_id != target_peer_id {
            return Err(RelayAllocationReceiptError::TargetMismatch);
        }
        if self.relayer_peer_id != relayer_peer_id {
            return Err(RelayAllocationReceiptError::RelayerMismatch);
        }
        if self.relay_addr != relay_addr {
            return Err(RelayAllocationReceiptError::AddressMismatch);
        }
        if unix_time_secs(now)? >= self.expires_at_unix_secs {
            return Err(RelayAllocationReceiptError::Expired);
        }

        let public_key = MlDsaPublicKey::from_bytes(&self.relayer_public_key)
            .map_err(|_| RelayAllocationReceiptError::InvalidCryptoMaterial)?;
        if fingerprint_public_key(&public_key) != self.relayer_peer_id {
            return Err(RelayAllocationReceiptError::RelayerMismatch);
        }
        let signature = MlDsaSignature::from_bytes(&self.signature)
            .map_err(|_| RelayAllocationReceiptError::InvalidCryptoMaterial)?;
        match MlDsa65::new().verify(&public_key, &self.signing_message(), &signature) {
            Ok(true) => Ok(()),
            Ok(false) => Err(RelayAllocationReceiptError::InvalidSignature),
            Err(_) => Err(RelayAllocationReceiptError::InvalidCryptoMaterial),
        }
    }

    /// Authenticated client fingerprint bound into this receipt.
    pub fn target_peer_id(&self) -> [u8; 32] {
        self.target_peer_id
    }

    /// Authenticated relay fingerprint bound into this receipt.
    pub fn relayer_peer_id(&self) -> [u8; 32] {
        self.relayer_peer_id
    }

    /// Public allocation address bound into this receipt.
    pub fn relay_addr(&self) -> SocketAddr {
        self.relay_addr
    }

    pub(crate) fn encode(&self) -> Vec<u8> {
        let mut encoded = Vec::with_capacity(
            1 + 32
                + 32
                + 1
                + 16
                + 2
                + 8
                + 8
                + 2
                + self.relayer_public_key.len()
                + 2
                + self.signature.len(),
        );
        encoded.push(self.version);
        encoded.extend_from_slice(&self.target_peer_id);
        encoded.extend_from_slice(&self.relayer_peer_id);
        match self.relay_addr.ip() {
            IpAddr::V4(ip) => {
                encoded.push(4);
                encoded.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                encoded.push(6);
                encoded.extend_from_slice(&ip.octets());
            }
        }
        encoded.extend_from_slice(&self.relay_addr.port().to_be_bytes());
        encoded.extend_from_slice(&self.allocation_id.to_be_bytes());
        encoded.extend_from_slice(&self.expires_at_unix_secs.to_be_bytes());
        encoded.extend_from_slice(&(self.relayer_public_key.len() as u16).to_be_bytes());
        encoded.extend_from_slice(&self.relayer_public_key);
        encoded.extend_from_slice(&(self.signature.len() as u16).to_be_bytes());
        encoded.extend_from_slice(&self.signature);
        encoded
    }

    pub(crate) fn decode(mut encoded: &[u8]) -> Result<Self, RelayAllocationReceiptError> {
        fn take<'a>(
            encoded: &mut &'a [u8],
            length: usize,
        ) -> Result<&'a [u8], RelayAllocationReceiptError> {
            if encoded.len() < length {
                return Err(RelayAllocationReceiptError::InvalidEncoding);
            }
            let (value, remainder) = encoded.split_at(length);
            *encoded = remainder;
            Ok(value)
        }

        let version = take(&mut encoded, 1)?[0];
        let target_peer_id = take(&mut encoded, 32)?
            .try_into()
            .map_err(|_| RelayAllocationReceiptError::InvalidEncoding)?;
        let relayer_peer_id = take(&mut encoded, 32)?
            .try_into()
            .map_err(|_| RelayAllocationReceiptError::InvalidEncoding)?;
        let ip = match take(&mut encoded, 1)?[0] {
            4 => {
                let octets: [u8; 4] = take(&mut encoded, 4)?
                    .try_into()
                    .map_err(|_| RelayAllocationReceiptError::InvalidEncoding)?;
                IpAddr::V4(std::net::Ipv4Addr::from(octets))
            }
            6 => {
                let octets: [u8; 16] = take(&mut encoded, 16)?
                    .try_into()
                    .map_err(|_| RelayAllocationReceiptError::InvalidEncoding)?;
                IpAddr::V6(std::net::Ipv6Addr::from(octets))
            }
            _ => return Err(RelayAllocationReceiptError::InvalidEncoding),
        };
        let port = u16::from_be_bytes(
            take(&mut encoded, 2)?
                .try_into()
                .map_err(|_| RelayAllocationReceiptError::InvalidEncoding)?,
        );
        let allocation_id = u64::from_be_bytes(
            take(&mut encoded, 8)?
                .try_into()
                .map_err(|_| RelayAllocationReceiptError::InvalidEncoding)?,
        );
        let expires_at_unix_secs = u64::from_be_bytes(
            take(&mut encoded, 8)?
                .try_into()
                .map_err(|_| RelayAllocationReceiptError::InvalidEncoding)?,
        );
        let public_key_len = u16::from_be_bytes(
            take(&mut encoded, 2)?
                .try_into()
                .map_err(|_| RelayAllocationReceiptError::InvalidEncoding)?,
        ) as usize;
        let relayer_public_key = take(&mut encoded, public_key_len)?.to_vec();
        let signature_len = u16::from_be_bytes(
            take(&mut encoded, 2)?
                .try_into()
                .map_err(|_| RelayAllocationReceiptError::InvalidEncoding)?,
        ) as usize;
        let signature = take(&mut encoded, signature_len)?.to_vec();
        if !encoded.is_empty() {
            return Err(RelayAllocationReceiptError::InvalidEncoding);
        }

        Ok(Self {
            version,
            target_peer_id,
            relayer_peer_id,
            relay_addr: SocketAddr::new(ip, port),
            allocation_id,
            expires_at_unix_secs,
            relayer_public_key,
            signature,
        })
    }

    fn signing_message(&self) -> Vec<u8> {
        let mut message = Vec::with_capacity(RECEIPT_DOMAIN.len() + 100);
        message.extend_from_slice(RECEIPT_DOMAIN);
        message.push(self.version);
        message.extend_from_slice(&self.target_peer_id);
        message.extend_from_slice(&self.relayer_peer_id);
        match self.relay_addr.ip() {
            IpAddr::V4(ip) => {
                message.push(4);
                message.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                message.push(6);
                message.extend_from_slice(&ip.octets());
            }
        }
        message.extend_from_slice(&self.relay_addr.port().to_be_bytes());
        message.extend_from_slice(&self.allocation_id.to_be_bytes());
        message.extend_from_slice(&self.expires_at_unix_secs.to_be_bytes());
        message
    }
}

fn unix_time_secs(time: SystemTime) -> Result<u64, RelayAllocationReceiptError> {
    time.duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| RelayAllocationReceiptError::InvalidClock)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::raw_public_keys::pqc::generate_ml_dsa_keypair;
    use std::net::{Ipv4Addr, SocketAddrV4};

    #[test]
    fn receipt_verifies_only_for_exact_binding() {
        let (public_key, secret_key) = generate_ml_dsa_keypair().expect("keypair");
        let relayer = fingerprint_public_key(&public_key);
        let target = [7; 32];
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12_345));
        let receipt = RelayAllocationReceipt::issue(&public_key, &secret_key, target, addr, 42)
            .expect("receipt");

        assert!(
            receipt
                .verify(target, relayer, addr, SystemTime::now())
                .is_ok()
        );
        assert_eq!(
            receipt.verify([8; 32], relayer, addr, SystemTime::now()),
            Err(RelayAllocationReceiptError::TargetMismatch)
        );
        assert_eq!(
            receipt.verify(target, [9; 32], addr, SystemTime::now()),
            Err(RelayAllocationReceiptError::RelayerMismatch)
        );
    }

    #[test]
    fn tampering_invalidates_signature() {
        let (public_key, secret_key) = generate_ml_dsa_keypair().expect("keypair");
        let relayer = fingerprint_public_key(&public_key);
        let target = [7; 32];
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12_345));
        let mut receipt = RelayAllocationReceipt::issue(&public_key, &secret_key, target, addr, 42)
            .expect("receipt");
        receipt.allocation_id += 1;

        assert_eq!(
            receipt.verify(target, relayer, addr, SystemTime::now()),
            Err(RelayAllocationReceiptError::InvalidSignature)
        );
    }

    #[test]
    fn receipt_expires_at_its_signed_deadline() {
        let (public_key, secret_key) = generate_ml_dsa_keypair().expect("keypair");
        let relayer = fingerprint_public_key(&public_key);
        let target = [7; 32];
        let addr = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 12_345));
        let receipt = RelayAllocationReceipt::issue(&public_key, &secret_key, target, addr, 42)
            .expect("receipt");
        let deadline = UNIX_EPOCH + std::time::Duration::from_secs(receipt.expires_at_unix_secs);

        assert_eq!(
            receipt.verify(target, relayer, addr, deadline),
            Err(RelayAllocationReceiptError::Expired)
        );
    }
}
