// Copyright 2026 Saorsa Labs Ltd.
// SPDX-License-Identifier: GPL-3.0-only

//! Bounded STUN reachability probes; these do not authenticate peer identity.
use super::{IncomingAssociation, parse_profile_credentials, stun_ice_credentials};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use stun::agent::TransactionId;
use stun::attributes::{ATTR_ICE_CONTROLLED, ATTR_PRIORITY, ATTR_USERNAME};
use stun::fingerprint::FINGERPRINT;
use stun::integrity::MessageIntegrity;
use stun::message::{BINDING_REQUEST, BINDING_SUCCESS, Message, Setter};
use stun::textattrs::Username;
use tokio::time::Instant;

const PROBE_LIFETIME: Duration = Duration::from_secs(2);
const MAX_PROBES: usize = 256;
const MAX_PROBES_PER_IP: usize = 4;

struct Probe {
    association: IncomingAssociation,
    transaction: TransactionId,
    expires: Instant,
}

#[derive(Default)]
pub(super) struct Admission {
    probes: HashMap<SocketAddr, Probe>,
}

pub(super) enum Decision {
    Ignore,
    Challenge(Vec<u8>),
    Admit(IncomingAssociation),
}

impl Admission {
    pub(super) fn expects_response(&self, packet: &[u8], source: SocketAddr) -> bool {
        let Some(probe) = self.probes.get(&source) else {
            return false;
        };
        let mut message = Message::new();
        message.unmarshal_binary(packet).is_ok()
            && message.typ == BINDING_SUCCESS
            && message.transaction_id == probe.transaction
    }

    pub(super) fn expire(&mut self, now: Instant) {
        self.probes.retain(|_, probe| probe.expires > now);
    }

    pub(super) fn receive(&mut self, packet: &[u8], source: SocketAddr, now: Instant) -> Decision {
        self.expire(now);
        let mut message = Message::new();
        if message.unmarshal_binary(packet).is_err() || FINGERPRINT.check(&message).is_err() {
            return Decision::Ignore;
        }
        if message.typ == BINDING_SUCCESS {
            let Some(probe) = self.probes.get(&source) else {
                return Decision::Ignore;
            };
            if message.transaction_id != probe.transaction
                || MessageIntegrity::new_short_term_integrity(probe.association.client_pwd.clone())
                    .check(&mut message)
                    .is_err()
            {
                return Decision::Ignore;
            }
            return self
                .probes
                .remove(&source)
                .map_or(Decision::Ignore, |probe| Decision::Admit(probe.association));
        }
        if message.typ != BINDING_REQUEST {
            return Decision::Ignore;
        }
        let Some((server, client)) = stun_ice_credentials(packet) else {
            return Decision::Ignore;
        };
        let Some(credentials) = parse_profile_credentials(&server, &client) else {
            return Decision::Ignore;
        };
        if MessageIntegrity::new_short_term_integrity(server.clone())
            .check(&mut message)
            .is_err()
        {
            return Decision::Ignore;
        }
        // Do not refresh or reflect retransmissions indefinitely. A fresh probe
        // is allowed only after expiry; spoofed sources cannot allocate RTC state.
        if self.probes.contains_key(&source)
            || self.probes.len() >= MAX_PROBES
            || self
                .probes
                .keys()
                .filter(|addr| addr.ip().to_canonical() == source.ip().to_canonical())
                .count()
                >= MAX_PROBES_PER_IP
        {
            return Decision::Ignore;
        }
        let transaction = TransactionId::new();
        let mut challenge = Message::new();
        if challenge
            .build(&[
                Box::new(transaction),
                Box::new(BINDING_REQUEST),
                Box::new(Username::new(ATTR_USERNAME, format!("{client}:{server}"))),
            ])
            .is_err()
        {
            return Decision::Ignore;
        }
        challenge.add(ATTR_ICE_CONTROLLED, &0u64.to_be_bytes());
        challenge.add(ATTR_PRIORITY, &1u32.to_be_bytes());
        if MessageIntegrity::new_short_term_integrity(credentials.client_pwd.clone())
            .add_to(&mut challenge)
            .is_err()
            || FINGERPRINT.add_to(&mut challenge).is_err()
            || challenge.raw.len() > packet.len()
        {
            return Decision::Ignore;
        }
        self.probes.insert(
            source,
            Probe {
                association: IncomingAssociation {
                    remote_addr: source,
                    server_ufrag: server,
                    client_ufrag: client,
                    client_pwd: credentials.client_pwd,
                },
                transaction,
                expires: now + PROBE_LIFETIME,
            },
        );
        Decision::Challenge(challenge.raw)
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use stun::attributes::ATTR_ICE_CONTROLLING;
    use stun::xoraddr::XorMappedAddress;

    pub(in crate::webrtc::direct) fn request(password: &str) -> Vec<u8> {
        let mut message = Message::new();
        let server = format!("{}{}", super::super::ICE_CREDENTIAL_PREFIX_V2, password);
        message
            .build(&[
                Box::new(TransactionId::new()),
                Box::new(BINDING_REQUEST),
                Box::new(Username::new(
                    ATTR_USERNAME,
                    format!("{server}:browserClientUfrag"),
                )),
            ])
            .unwrap();
        message.add(ATTR_ICE_CONTROLLING, &1u64.to_be_bytes());
        message.add(ATTR_PRIORITY, &1u32.to_be_bytes());
        MessageIntegrity::new_short_term_integrity(server)
            .add_to(&mut message)
            .unwrap();
        FINGERPRINT.add_to(&mut message).unwrap();
        message.raw
    }

    pub(in crate::webrtc::direct) fn response(
        challenge: &[u8],
        password: &str,
        source: SocketAddr,
    ) -> Vec<u8> {
        let mut incoming = Message::new();
        incoming.unmarshal_binary(challenge).unwrap();
        let mut response = Message::new();
        response
            .build(&[
                Box::new(incoming.transaction_id),
                Box::new(BINDING_SUCCESS),
                Box::new(XorMappedAddress {
                    ip: source.ip(),
                    port: source.port(),
                }),
                Box::new(MessageIntegrity::new_short_term_integrity(
                    password.to_string(),
                )),
                Box::new(FINGERPRINT),
            ])
            .unwrap();
        response.raw
    }

    #[test]
    fn only_an_unexpired_response_from_the_challenged_address_admits() {
        let mut admission = Admission::default();
        let source = "127.0.0.1:5000".parse().unwrap();
        let other = "127.0.0.2:5000".parse().unwrap();
        let now = Instant::now();
        let password = "browserPassword0123456789";
        let original = request(password);
        let Decision::Challenge(challenge) = admission.receive(&original, source, now) else {
            panic!("expected challenge")
        };
        assert!(challenge.len() <= original.len());
        let valid = response(&challenge, password, source);
        assert!(matches!(
            admission.receive(&valid, other, now),
            Decision::Ignore
        ));
        let wrong = response(&challenge, "wrong password", source);
        assert!(matches!(
            admission.receive(&wrong, source, now),
            Decision::Ignore
        ));
        let mut wrong_id = Message::new();
        wrong_id
            .build(&[Box::new(TransactionId::new()), Box::new(BINDING_REQUEST)])
            .unwrap();
        assert!(matches!(
            admission.receive(&response(&wrong_id.raw, password, source), source, now),
            Decision::Ignore
        ));
        assert!(matches!(
            admission.receive(&valid, source, now),
            Decision::Admit(_)
        ));
        assert!(matches!(
            admission.receive(&valid, source, now),
            Decision::Ignore
        ));
        assert!(matches!(
            admission.receive(&original, source, now),
            Decision::Challenge(_)
        ));
        assert!(matches!(
            admission.receive(&valid, source, now + PROBE_LIFETIME),
            Decision::Ignore
        ));
        assert!(admission.probes.is_empty());
    }

    #[test]
    fn malformed_or_unsigned_stun_allocates_nothing() {
        let mut admission = Admission::default();
        let source = "127.0.0.1:5000".parse().unwrap();
        let original = request("browserPassword0123456789");
        // Include every truncation and a corrupt fingerprint.
        for end in 0..original.len() {
            assert!(matches!(
                admission.receive(&original[..end], source, Instant::now()),
                Decision::Ignore
            ));
        }
        let mut corrupt = original;
        let last = corrupt.len() - 1;
        corrupt[last] ^= 1;
        assert!(matches!(
            admission.receive(&corrupt, source, Instant::now()),
            Decision::Ignore
        ));
        assert!(admission.probes.is_empty());
    }

    #[test]
    fn probes_are_bounded_per_ip_globally_and_expire_without_refresh() {
        let mut admission = Admission::default();
        let now = Instant::now();
        let packet = request("browserPassword0123456789");
        for port in 1..=MAX_PROBES_PER_IP {
            let source = SocketAddr::from(([127, 0, 0, 1], port as u16));
            assert!(matches!(
                admission.receive(&packet, source, now),
                Decision::Challenge(_)
            ));
        }
        assert!(matches!(
            admission.receive(&packet, "127.0.0.1:9999".parse().unwrap(), now),
            Decision::Ignore
        ));
        for index in 1..=MAX_PROBES {
            let source =
                SocketAddr::from(([10, 0, (index / 256) as u8, (index % 256) as u8], 5000));
            let _ = admission.receive(&packet, source, now);
        }
        assert_eq!(admission.probes.len(), MAX_PROBES);
        admission.expire(now + PROBE_LIFETIME);
        assert!(admission.probes.is_empty());
    }
}
