// Copyright 2024 Saorsa Labs Ltd.
//
// This Saorsa Network Software is licensed under the General Public License (GPL), version 3.
// Please see the file LICENSE-GPL, or visit <http://www.gnu.org/licenses/> for the full text.
//
// Full details available at https://saorsalabs.com/licenses

//! Saorsa's signaling-free WebRTC Direct transport.
//!
//! This module deliberately exposes no libp2p types or wire protocols. It uses
//! WebRTC ICE-lite, DTLS, SCTP, and reliable ordered DataChannels directly.
//! A browser learns the listener's literal IP address, UDP port, and pinned
//! certificate hash from a bootstrap record, so no DNS or signaling service is
//! required.
//!
//! The browser creates an SDP offer with a random credential prefixed by
//! [`ICE_CREDENTIAL_PREFIX`] and synthesizes the listener's SDP answer from the
//! bootstrap endpoint. The listener learns that credential and the browser's
//! observed address from the first STUN binding request, then constructs the
//! corresponding peer connection locally.

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::RwLock;
use rand::distributions::{Alphanumeric, DistString};
use std::collections::HashMap;
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use stun::attributes::ATTR_USERNAME;
use stun::message::{Message as StunMessage, is_message as is_stun_message};
use thiserror::Error;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc, watch};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use webrtc::api::setting_engine::SettingEngine;
use webrtc::api::{APIBuilder, interceptor_registry::register_default_interceptors};
use webrtc::data::data_channel::DataChannel;
use webrtc::data_channel::RTCDataChannel;
use webrtc::dtls::extension::extension_use_srtp::SrtpProtectionProfile;
use webrtc::dtls_transport::dtls_role::DTLSRole;
use webrtc::ice::network_type::NetworkType;
use webrtc::ice::udp_mux::{UDPMux, UDPMuxConn, UDPMuxConnParams, UDPMuxWriter};
use webrtc::ice::udp_network::UDPNetwork;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::peer_connection::certificate::RTCCertificate;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::util::{Conn, Error as WebRtcUtilError};
use webrtc_rcgen::{KeyPair, PKCS_ECDSA_P256_SHA256};

use crate::transport::WebRtcDirectAddr;

/// Prefix identifying the first version of the Saorsa WebRTC Direct profile.
pub const ICE_CREDENTIAL_PREFIX: &str = "saorsa+webrtc+v1/";

/// Maximum binary message size supported by this transport profile.
///
/// Large application frames must be split into messages no larger than this
/// value. The DataChannel itself remains reliable and ordered.
pub const MAX_DATA_CHANNEL_MESSAGE_SIZE: usize = 16 * 1024;

const MAX_PENDING_ASSOCIATIONS: usize = 256;

/// Errors produced by the WebRTC Direct transport.
#[derive(Debug, Error)]
pub enum WebRtcDirectError {
    /// The listener or its underlying channel has closed.
    #[error("WebRTC Direct transport is closed")]
    Closed,
    /// A socket operation failed.
    #[error("WebRTC Direct socket error: {0}")]
    Io(#[from] std::io::Error),
    /// A certificate could not be generated, loaded, or inspected.
    #[error("WebRTC Direct certificate error: {0}")]
    Certificate(String),
    /// WebRTC session setup or DataChannel I/O failed.
    #[error("WebRTC Direct session error: {0}")]
    Session(String),
    /// A DataChannel message violated the Saorsa transport profile.
    #[error("WebRTC Direct protocol error: {0}")]
    Protocol(String),
}

/// Persistent P-256 certificate used to authenticate a WebRTC Direct listener.
#[derive(Clone, Debug, PartialEq)]
pub struct WebRtcCertificate {
    inner: RTCCertificate,
}

impl WebRtcCertificate {
    /// Generate a new P-256 certificate accepted by current web browsers.
    pub fn generate() -> Result<Self, WebRtcDirectError> {
        ensure_crypto_provider();
        let key_pair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
            .map_err(|error| WebRtcDirectError::Certificate(error.to_string()))?;
        let inner = RTCCertificate::from_key_pair(key_pair)
            .map_err(|error| WebRtcDirectError::Certificate(error.to_string()))?;
        Ok(Self { inner })
    }

    /// Load a certificate and private key from WebRTC's persistent PEM form.
    pub fn from_pem(pem: &str) -> Result<Self, WebRtcDirectError> {
        ensure_crypto_provider();
        let inner = RTCCertificate::from_pem(pem)
            .map_err(|error| WebRtcDirectError::Certificate(error.to_string()))?;
        Ok(Self { inner })
    }

    /// Serialize the certificate and private key for persistent storage.
    pub fn serialize_pem(&self) -> String {
        self.inner.serialize_pem()
    }

    /// Return the SHA-256 digest browsers pin through the endpoint certhash.
    pub fn sha256_digest(&self) -> Result<[u8; 32], WebRtcDirectError> {
        let fingerprint = self
            .inner
            .get_fingerprints()
            .into_iter()
            .find(|fingerprint| fingerprint.algorithm.eq_ignore_ascii_case("sha-256"))
            .ok_or_else(|| {
                WebRtcDirectError::Certificate(
                    "certificate does not contain a SHA-256 fingerprint".to_string(),
                )
            })?;
        let bytes = hex::decode(fingerprint.value.replace(':', ""))
            .map_err(|error| WebRtcDirectError::Certificate(error.to_string()))?;
        bytes.try_into().map_err(|bytes: Vec<u8>| {
            WebRtcDirectError::Certificate(format!(
                "SHA-256 fingerprint has {} bytes instead of 32",
                bytes.len()
            ))
        })
    }
}

fn ensure_crypto_provider() {
    // saorsa-transport's native QUIC stack uses aws-lc-rs. Installation is a
    // process-wide one-time choice; an already-installed provider is valid.
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// A signaling-free WebRTC listener bound to one UDP socket.
pub struct WebRtcDirectListener {
    local_addr: SocketAddr,
    certificate: WebRtcCertificate,
    mux: Arc<DirectUdpMux>,
    incoming: mpsc::Receiver<IncomingAssociation>,
    driver: JoinHandle<()>,
}

impl WebRtcDirectListener {
    /// Bind a listener using a persistent certificate.
    pub async fn bind(
        bind_addr: SocketAddr,
        certificate: WebRtcCertificate,
    ) -> Result<Self, WebRtcDirectError> {
        let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
        let local_addr = socket.local_addr()?;
        let (incoming_tx, incoming) = mpsc::channel(MAX_PENDING_ASSOCIATIONS);
        let mux = DirectUdpMux::new(Arc::clone(&socket), local_addr, incoming_tx);
        let driver_mux = Arc::clone(&mux);
        let driver = tokio::spawn(async move {
            driver_mux.run(socket).await;
        });
        Ok(Self {
            local_addr,
            certificate,
            mux,
            incoming,
            driver,
        })
    }

    /// Return the bound UDP socket address.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Return the listener certificate.
    pub fn certificate(&self) -> &WebRtcCertificate {
        &self.certificate
    }

    /// Accept the next browser association discovered through STUN.
    pub async fn accept(&mut self) -> Result<WebRtcDirectConnection, WebRtcDirectError> {
        let association = self
            .incoming
            .recv()
            .await
            .ok_or(WebRtcDirectError::Closed)?;
        let result = create_inbound_connection(
            association.remote_addr,
            &association.ice_credential,
            Arc::clone(&self.mux),
            &self.certificate,
        )
        .await;
        if result.is_err() {
            self.mux
                .release_pending(association.remote_addr, &association.ice_credential);
        }
        result
    }

    /// Stop accepting connections and release the shared UDP mux.
    pub async fn close(&self) -> Result<(), WebRtcDirectError> {
        self.mux
            .close()
            .await
            .map_err(|error| WebRtcDirectError::Session(error.to_string()))
    }
}

impl Drop for WebRtcDirectListener {
    fn drop(&mut self) {
        self.mux.shutdown.cancel();
        self.driver.abort();
    }
}

/// One browser WebRTC association that can carry application DataChannels.
pub struct WebRtcDirectConnection {
    remote_addr: SocketAddr,
    peer_connection: Arc<RTCPeerConnection>,
    incoming: mpsc::Receiver<WebRtcDataChannel>,
    closed: watch::Receiver<bool>,
}

impl WebRtcDirectConnection {
    /// Return the browser's observed UDP address.
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Accept the next reliable ordered DataChannel opened by the browser.
    pub async fn accept_data_channel(&mut self) -> Result<WebRtcDataChannel, WebRtcDirectError> {
        loop {
            tokio::select! {
                channel = self.incoming.recv() => {
                    return channel.ok_or(WebRtcDirectError::Closed);
                }
                changed = self.closed.changed() => {
                    if changed.is_err() || *self.closed.borrow() {
                        return Err(WebRtcDirectError::Closed);
                    }
                }
            }
        }
    }

    /// Close the WebRTC association.
    pub async fn close(&self) -> Result<(), WebRtcDirectError> {
        self.peer_connection
            .close()
            .await
            .map_err(|error| WebRtcDirectError::Session(error.to_string()))
    }
}

/// Native diagnostic client for the Saorsa WebRTC Direct wire profile.
///
/// Browser applications use `RTCPeerConnection` directly. This type exists so
/// native integration tests and troubleshooting tools can verify listeners
/// through the same ICE-lite, DTLS, SCTP, and DataChannel path.
pub struct WebRtcDirectClient {
    local_addr: SocketAddr,
    peer_connection: Arc<RTCPeerConnection>,
    channel: WebRtcDataChannel,
    mux: Arc<DirectUdpMux>,
    driver: JoinHandle<()>,
}

impl WebRtcDirectClient {
    /// Dial a pinned direct endpoint and open one reliable ordered DataChannel.
    pub async fn dial(
        endpoint: &WebRtcDirectAddr,
        data_channel_label: &str,
    ) -> Result<Self, WebRtcDirectError> {
        if data_channel_label.is_empty() {
            return Err(WebRtcDirectError::Protocol(
                "DataChannel label must not be empty".to_string(),
            ));
        }
        let bind_addr = match endpoint.ip() {
            IpAddr::V4(_) => SocketAddr::from(([0, 0, 0, 0], 0)),
            IpAddr::V6(_) => SocketAddr::from(([0_u16; 8], 0)),
        };
        let socket = Arc::new(UdpSocket::bind(bind_addr).await?);
        let local_addr = socket.local_addr()?;
        let (unused_incoming, incoming) = mpsc::channel(1);
        drop(incoming);
        let mux = DirectUdpMux::new(Arc::clone(&socket), local_addr, unused_incoming);
        let driver_mux = Arc::clone(&mux);
        let driver = tokio::spawn(async move {
            driver_mux.run(socket).await;
        });

        let result =
            create_outbound_client(endpoint, data_channel_label, local_addr, Arc::clone(&mux))
                .await;
        match result {
            Ok((peer_connection, channel)) => Ok(Self {
                local_addr,
                peer_connection,
                channel,
                mux,
                driver,
            }),
            Err(error) => {
                mux.shutdown.cancel();
                driver.abort();
                Err(error)
            }
        }
    }

    /// Return the local UDP address used for this association.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Return the open application DataChannel.
    pub fn data_channel(&self) -> &WebRtcDataChannel {
        &self.channel
    }

    /// Close the DataChannel, peer connection, and UDP mux.
    pub async fn close(&self) -> Result<(), WebRtcDirectError> {
        self.channel.close().await?;
        self.peer_connection
            .close()
            .await
            .map_err(|error| WebRtcDirectError::Session(error.to_string()))?;
        self.mux
            .close()
            .await
            .map_err(|error| WebRtcDirectError::Session(error.to_string()))
    }
}

impl Drop for WebRtcDirectClient {
    fn drop(&mut self) {
        self.mux.shutdown.cancel();
        self.driver.abort();
    }
}

/// A reliable ordered WebRTC DataChannel carrying binary application messages.
#[derive(Clone)]
pub struct WebRtcDataChannel {
    inner: Arc<DataChannel>,
    label: String,
    id: u16,
}

impl WebRtcDataChannel {
    /// Return the application label chosen by the browser.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Return the SCTP stream identifier.
    pub fn id(&self) -> u16 {
        self.id
    }

    /// Receive one binary DataChannel message.
    ///
    /// An empty vector means the browser closed or reset the channel.
    pub async fn receive(&self) -> Result<Vec<u8>, WebRtcDirectError> {
        let mut buffer = vec![0_u8; MAX_DATA_CHANNEL_MESSAGE_SIZE];
        let (length, is_string) = self
            .inner
            .read_data_channel(&mut buffer)
            .await
            .map_err(|error| WebRtcDirectError::Session(error.to_string()))?;
        if is_string {
            return Err(WebRtcDirectError::Protocol(
                "text DataChannel messages are not supported".to_string(),
            ));
        }
        buffer.truncate(length);
        Ok(buffer)
    }

    /// Send one binary DataChannel message.
    pub async fn send(&self, message: &[u8]) -> Result<(), WebRtcDirectError> {
        if message.len() > MAX_DATA_CHANNEL_MESSAGE_SIZE {
            return Err(WebRtcDirectError::Protocol(format!(
                "message has {} bytes; maximum is {MAX_DATA_CHANNEL_MESSAGE_SIZE}",
                message.len()
            )));
        }
        let written = self
            .inner
            .write(&Bytes::copy_from_slice(message))
            .await
            .map_err(|error| WebRtcDirectError::Session(error.to_string()))?;
        if written != message.len() {
            return Err(WebRtcDirectError::Session(format!(
                "DataChannel wrote {written} of {} bytes",
                message.len()
            )));
        }
        Ok(())
    }

    /// Close this DataChannel.
    pub async fn close(&self) -> Result<(), WebRtcDirectError> {
        self.inner
            .close()
            .await
            .map_err(|error| WebRtcDirectError::Session(error.to_string()))
    }
}

async fn create_inbound_connection(
    remote_addr: SocketAddr,
    ice_credential: &str,
    udp_mux: Arc<DirectUdpMux>,
    certificate: &WebRtcCertificate,
) -> Result<WebRtcDirectConnection, WebRtcDirectError> {
    if !is_valid_ice_credential(ice_credential) {
        return Err(WebRtcDirectError::Protocol(
            "invalid Saorsa ICE credential".to_string(),
        ));
    }

    let mut settings = SettingEngine::default();
    settings.set_lite(true);
    settings.disable_certificate_fingerprint_verification(true);
    settings
        .set_answering_dtls_role(DTLSRole::Server)
        .map_err(|error| WebRtcDirectError::Session(error.to_string()))?;
    settings.set_ice_credentials(ice_credential.to_string(), ice_credential.to_string());
    settings.set_udp_network(UDPNetwork::Muxed(udp_mux as Arc<dyn UDPMux + Send + Sync>));
    settings.detach_data_channels();
    settings.set_srtp_protection_profiles(vec![
        SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm,
        SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
        SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_32,
    ]);
    settings.set_network_types(vec![match remote_addr {
        SocketAddr::V4(_) => NetworkType::Udp4,
        SocketAddr::V6(_) => NetworkType::Udp6,
    }]);
    let first_ip = AtomicBool::new(true);
    settings.set_ip_filter(Box::new(move |_| first_ip.swap(false, Ordering::Relaxed)));

    let mut media_engine = webrtc::api::media_engine::MediaEngine::default();
    media_engine
        .register_default_codecs()
        .map_err(|error| WebRtcDirectError::Session(error.to_string()))?;
    let registry = register_default_interceptors(Registry::new(), &mut media_engine)
        .map_err(|error| WebRtcDirectError::Session(error.to_string()))?;
    let api = APIBuilder::new()
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .with_setting_engine(settings)
        .build();
    let peer_connection = Arc::new(
        api.new_peer_connection(RTCConfiguration {
            certificates: vec![certificate.inner.clone()],
            ..RTCConfiguration::default()
        })
        .await
        .map_err(|error| WebRtcDirectError::Session(error.to_string()))?,
    );

    let (incoming_tx, incoming) = mpsc::channel(16);
    register_data_channel_handler(&peer_connection, incoming_tx);
    let (closed_tx, closed) = watch::channel(false);
    peer_connection.on_peer_connection_state_change(Box::new(move |state| {
        let closed_tx = closed_tx.clone();
        Box::pin(async move {
            use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
            if matches!(
                state,
                RTCPeerConnectionState::Failed
                    | RTCPeerConnectionState::Disconnected
                    | RTCPeerConnectionState::Closed
            ) {
                let _ = closed_tx.send(true);
            }
        })
    }));

    let offer = RTCSessionDescription::offer(client_offer(remote_addr, ice_credential))
        .map_err(|error| WebRtcDirectError::Session(error.to_string()))?;
    peer_connection
        .set_remote_description(offer)
        .await
        .map_err(|error| WebRtcDirectError::Session(error.to_string()))?;
    let answer = peer_connection
        .create_answer(None)
        .await
        .map_err(|error| WebRtcDirectError::Session(error.to_string()))?;
    peer_connection
        .set_local_description(answer)
        .await
        .map_err(|error| WebRtcDirectError::Session(error.to_string()))?;

    Ok(WebRtcDirectConnection {
        remote_addr,
        peer_connection,
        incoming,
        closed,
    })
}

async fn create_outbound_client(
    endpoint: &WebRtcDirectAddr,
    data_channel_label: &str,
    local_addr: SocketAddr,
    udp_mux: Arc<DirectUdpMux>,
) -> Result<(Arc<RTCPeerConnection>, WebRtcDataChannel), WebRtcDirectError> {
    let ice_credential = format!(
        "{ICE_CREDENTIAL_PREFIX}{}",
        Alphanumeric.sample_string(&mut rand::thread_rng(), 32)
    );
    let client_certificate = WebRtcCertificate::generate()?;
    let mut settings = SettingEngine::default();
    settings.set_ice_credentials(ice_credential.clone(), ice_credential.clone());
    settings.set_udp_network(UDPNetwork::Muxed(udp_mux as Arc<dyn UDPMux + Send + Sync>));
    settings.detach_data_channels();
    settings.set_srtp_protection_profiles(vec![
        SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm,
        SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_80,
        SrtpProtectionProfile::Srtp_Aes128_Cm_Hmac_Sha1_32,
    ]);
    settings.set_network_types(vec![match endpoint.socket_addr() {
        SocketAddr::V4(_) => NetworkType::Udp4,
        SocketAddr::V6(_) => NetworkType::Udp6,
    }]);
    let first_ip = AtomicBool::new(true);
    settings.set_ip_filter(Box::new(move |_| first_ip.swap(false, Ordering::Relaxed)));

    let peer_connection = Arc::new(
        APIBuilder::new()
            .with_setting_engine(settings)
            .build()
            .new_peer_connection(RTCConfiguration {
                certificates: vec![client_certificate.inner],
                ..RTCConfiguration::default()
            })
            .await
            .map_err(|error| WebRtcDirectError::Session(error.to_string()))?,
    );
    let rtc_channel = peer_connection
        .create_data_channel(data_channel_label, None)
        .await
        .map_err(|error| WebRtcDirectError::Session(error.to_string()))?;
    let (channel_tx, mut channel_rx) = mpsc::channel(1);
    let label = data_channel_label.to_string();
    let channel_id = rtc_channel.id();
    let open_channel = Arc::clone(&rtc_channel);
    rtc_channel.on_open(Box::new(move || {
        let open_channel = Arc::clone(&open_channel);
        let channel_tx = channel_tx.clone();
        let label = label.clone();
        Box::pin(async move {
            match open_channel.detach().await {
                Ok(inner) => {
                    let _ = channel_tx
                        .send(WebRtcDataChannel {
                            inner,
                            label,
                            id: channel_id,
                        })
                        .await;
                }
                Err(error) => {
                    tracing::debug!(%error, "failed to detach outbound WebRTC DataChannel");
                }
            }
        })
    }));

    let offer = peer_connection
        .create_offer(None)
        .await
        .map_err(|error| WebRtcDirectError::Session(error.to_string()))?;
    peer_connection
        .set_local_description(offer)
        .await
        .map_err(|error| WebRtcDirectError::Session(error.to_string()))?;
    let answer = RTCSessionDescription::answer(server_answer(
        endpoint.socket_addr(),
        endpoint.certificate_hash().as_bytes(),
        &ice_credential,
    ))
    .map_err(|error| WebRtcDirectError::Session(error.to_string()))?;
    peer_connection
        .set_remote_description(answer)
        .await
        .map_err(|error| WebRtcDirectError::Session(error.to_string()))?;
    let channel = tokio::time::timeout(std::time::Duration::from_secs(10), channel_rx.recv())
        .await
        .map_err(|_| WebRtcDirectError::Session("DataChannel opening timed out".to_string()))?
        .ok_or_else(|| {
            WebRtcDirectError::Session("DataChannel closed before opening".to_string())
        })?;
    tracing::debug!(%local_addr, remote = %endpoint.socket_addr(), "WebRTC Direct dial completed");
    Ok((peer_connection, channel))
}

fn register_data_channel_handler(
    peer_connection: &RTCPeerConnection,
    incoming: mpsc::Sender<WebRtcDataChannel>,
) {
    peer_connection.on_data_channel(Box::new(move |channel: Arc<RTCDataChannel>| {
        let incoming = incoming.clone();
        Box::pin(async move {
            if !channel.ordered() || channel.max_retransmits().is_some() {
                channel.close().await.ok();
                return;
            }
            let label = channel.label().to_string();
            let id = channel.id();
            let open_channel = Arc::clone(&channel);
            channel.on_open(Box::new(move || {
                let incoming = incoming.clone();
                let open_channel = Arc::clone(&open_channel);
                let label = label.clone();
                Box::pin(async move {
                    match open_channel.detach().await {
                        Ok(inner) => {
                            let channel = WebRtcDataChannel { inner, label, id };
                            if let Err(error) = incoming.try_send(channel) {
                                let channel = error.into_inner();
                                channel.close().await.ok();
                            }
                        }
                        Err(error) => {
                            tracing::debug!(%error, id, "failed to detach WebRTC DataChannel");
                        }
                    }
                })
            }));
        })
    }));
}

fn client_offer(remote_addr: SocketAddr, ice_credential: &str) -> String {
    let (ip_version, ip) = match remote_addr.ip() {
        IpAddr::V4(ip) => ("IP4", ip.to_string()),
        IpAddr::V6(ip) => ("IP6", ip.to_string()),
    };
    format!(
        "v=0\n\
o=- 0 0 IN {ip_version} {ip}\n\
s=-\n\
c=IN {ip_version} {ip}\n\
t=0 0\n\
m=application {} UDP/DTLS/SCTP webrtc-datachannel\n\
a=mid:0\n\
a=ice-options:ice2\n\
a=ice-ufrag:{ice_credential}\n\
a=ice-pwd:{ice_credential}\n\
a=fingerprint:sha-256 FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF:FF\n\
a=setup:actpass\n\
a=sctp-port:5000\n\
a=max-message-size:{MAX_DATA_CHANNEL_MESSAGE_SIZE}\n",
        remote_addr.port()
    )
}

fn server_answer(
    remote_addr: SocketAddr,
    certificate_hash: &[u8; 32],
    ice_credential: &str,
) -> String {
    let (ip_version, ip) = match remote_addr.ip() {
        IpAddr::V4(ip) => ("IP4", ip.to_string()),
        IpAddr::V6(ip) => ("IP6", ip.to_string()),
    };
    let fingerprint = certificate_hash
        .iter()
        .map(|byte| format!("{byte:02X}"))
        .collect::<Vec<_>>()
        .join(":");
    format!(
        "v=0\n\
o=- 0 0 IN {ip_version} {ip}\n\
s=-\n\
t=0 0\n\
a=ice-lite\n\
m=application {} UDP/DTLS/SCTP webrtc-datachannel\n\
c=IN {ip_version} {ip}\n\
a=mid:0\n\
a=ice-options:ice2\n\
a=ice-ufrag:{ice_credential}\n\
a=ice-pwd:{ice_credential}\n\
a=fingerprint:sha-256 {fingerprint}\n\
a=setup:passive\n\
a=sctp-port:5000\n\
a=max-message-size:{MAX_DATA_CHANNEL_MESSAGE_SIZE}\n\
a=candidate:1467250027 1 UDP 1467250027 {ip} {} typ host\n\
a=end-of-candidates\n",
        remote_addr.port(),
        remote_addr.port()
    )
}

fn is_valid_ice_credential(credential: &str) -> bool {
    credential.starts_with(ICE_CREDENTIAL_PREFIX)
        && (22..=256).contains(&credential.len())
        && credential
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'/'))
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct IncomingAssociation {
    remote_addr: SocketAddr,
    ice_credential: String,
}

struct DirectUdpMux {
    local_addr: SocketAddr,
    conns: Mutex<HashMap<String, UDPMuxConn>>,
    address_map: RwLock<HashMap<SocketAddr, UDPMuxConn>>,
    pending: RwLock<HashMap<String, SocketAddr>>,
    incoming: mpsc::Sender<IncomingAssociation>,
    socket: Weak<UdpSocket>,
    shutdown: CancellationToken,
    closed: AtomicBool,
}

impl DirectUdpMux {
    fn new(
        socket: Arc<UdpSocket>,
        local_addr: SocketAddr,
        incoming: mpsc::Sender<IncomingAssociation>,
    ) -> Arc<Self> {
        Arc::new(Self {
            local_addr,
            conns: Mutex::new(HashMap::new()),
            address_map: RwLock::new(HashMap::new()),
            pending: RwLock::new(HashMap::new()),
            incoming,
            socket: Arc::downgrade(&socket),
            shutdown: CancellationToken::new(),
            closed: AtomicBool::new(false),
        })
    }

    async fn run(self: Arc<Self>, socket: Arc<UdpSocket>) {
        let mut buffer = [0_u8; MAX_DATA_CHANNEL_MESSAGE_SIZE];
        loop {
            let received = tokio::select! {
                () = self.shutdown.cancelled() => break,
                received = socket.recv_from(&mut buffer) => received,
            };
            let (length, remote_addr) = match received {
                Ok(received) => received,
                Err(error) if error.kind() == ErrorKind::ConnectionReset => continue,
                Err(error) => {
                    tracing::warn!(%error, "WebRTC Direct UDP listener failed");
                    break;
                }
            };
            let packet = &buffer[..length];
            let connection = self.connection_for_packet(packet, remote_addr).await;
            if let Some(connection) = connection {
                if let Err(error) = connection.write_packet(packet, remote_addr).await {
                    tracing::debug!(%error, %remote_addr, "failed to route WebRTC UDP packet");
                }
                continue;
            }

            let Some(ice_credential) = remote_ice_credential(packet) else {
                continue;
            };
            if !is_valid_ice_credential(&ice_credential) {
                tracing::debug!(%remote_addr, "ignored invalid WebRTC Direct ICE credential");
                continue;
            }
            let association = IncomingAssociation {
                remote_addr,
                ice_credential,
            };
            {
                let mut pending = self.pending.write();
                if pending.contains_key(&association.ice_credential) {
                    continue;
                }
                pending.insert(association.ice_credential.clone(), association.remote_addr);
            }
            if let Err(error) = self.incoming.try_send(association.clone()) {
                self.pending.write().remove(&association.ice_credential);
                tracing::debug!(%remote_addr, %error, "WebRTC Direct accept queue is full");
            }
        }
    }

    async fn connection_for_packet(
        &self,
        packet: &[u8],
        remote_addr: SocketAddr,
    ) -> Option<UDPMuxConn> {
        // A browser may reuse the same UDP source port for a replacement peer
        // connection. Binding requests carry the new association's local ICE
        // credential, so it must take precedence over a stale address mapping.
        // Binding responses do not carry USERNAME and therefore continue to use
        // the source-address mapping registered when the ICE agent sent its
        // request. DTLS and SCTP packets use that mapping as well.
        if let Some(local_credential) = local_ice_credential(packet) {
            return self.conns.lock().await.get(&local_credential).cloned();
        }
        self.address_map.read().get(&remote_addr).cloned()
    }

    fn release_pending(&self, remote_addr: SocketAddr, ice_credential: &str) {
        let removed = self.pending.write().remove(ice_credential);
        if removed.is_some_and(|pending_addr| pending_addr != remote_addr) {
            tracing::debug!(%remote_addr, %ice_credential, "released WebRTC association from a replacement candidate address");
        }
    }
}

#[async_trait]
impl UDPMux for DirectUdpMux {
    async fn close(&self) -> Result<(), WebRtcUtilError> {
        if self.closed.swap(true, Ordering::AcqRel) {
            return Ok(());
        }
        self.shutdown.cancel();
        let connections = std::mem::take(&mut *self.conns.lock().await);
        for (_, connection) in connections {
            connection.close();
        }
        self.address_map.write().clear();
        self.pending.write().clear();
        Ok(())
    }

    async fn get_conn(
        self: Arc<Self>,
        ice_credential: &str,
    ) -> Result<Arc<dyn Conn + Send + Sync>, WebRtcUtilError> {
        if self.closed.load(Ordering::Acquire) {
            return Err(WebRtcUtilError::ErrUseClosedNetworkConn);
        }
        let mut connections = self.conns.lock().await;
        if let Some(connection) = connections.get(ice_credential) {
            return Ok(Arc::new(connection.clone()));
        }
        let writer: Arc<dyn UDPMuxWriter + Send + Sync> = self.clone();
        let connection = UDPMuxConn::new(UDPMuxConnParams {
            local_addr: self.local_addr,
            key: ice_credential.to_string(),
            udp_mux: Arc::downgrade(&writer),
        });
        let mut closed = connection.close_rx();
        let mux = Arc::clone(&self);
        let credential = ice_credential.to_string();
        tokio::spawn(async move {
            let _ = closed.changed().await;
            mux.remove_conn_by_ufrag(&credential).await;
        });
        connections.insert(ice_credential.to_string(), connection.clone());
        Ok(Arc::new(connection))
    }

    async fn remove_conn_by_ufrag(&self, ice_credential: &str) {
        let removed = self.conns.lock().await.remove(ice_credential);
        if let Some(connection) = removed {
            let mut addresses = self.address_map.write();
            for address in connection.get_addresses() {
                addresses.remove(&address);
            }
        }
    }
}

#[async_trait]
impl UDPMuxWriter for DirectUdpMux {
    async fn register_conn_for_address(&self, connection: &UDPMuxConn, addr: SocketAddr) {
        let key = connection.key();
        self.address_map
            .write()
            .entry(addr)
            .and_modify(|current| {
                if current.key() != key {
                    current.remove_address(&addr);
                    *current = connection.clone();
                }
            })
            .or_insert_with(|| connection.clone());
        self.pending.write().remove(connection.key());
    }

    async fn send_to(&self, packet: &[u8], target: &SocketAddr) -> Result<usize, WebRtcUtilError> {
        let socket = self
            .socket
            .upgrade()
            .ok_or(WebRtcUtilError::ErrUseClosedNetworkConn)?;
        socket
            .send_to(packet, target)
            .await
            .map_err(|error| WebRtcUtilError::Io(error.into()))
    }
}

fn local_ice_credential(packet: &[u8]) -> Option<String> {
    stun_ice_credentials(packet).map(|(local, _)| local)
}

fn remote_ice_credential(packet: &[u8]) -> Option<String> {
    stun_ice_credentials(packet).map(|(_, remote)| remote)
}

fn stun_ice_credentials(packet: &[u8]) -> Option<(String, String)> {
    if !is_stun_message(packet) {
        return None;
    }
    let mut message = StunMessage::new();
    message.unmarshal_binary(packet).ok()?;
    let (attribute, found) = message.attributes.get(ATTR_USERNAME);
    if !found {
        return None;
    }
    let username = String::from_utf8(attribute.value).ok()?;
    let (local, remote) = username.split_once(':')?;
    Some((local.to_string(), remote.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use stun::agent::TransactionId;
    use stun::message::{BINDING_REQUEST, BINDING_SUCCESS};
    use stun::textattrs::Username;

    #[test]
    fn validates_only_saorsa_profile_credentials() {
        assert!(is_valid_ice_credential(
            "saorsa+webrtc+v1/0123456789abcdefghijklmnopqrstuv"
        ));
        assert!(!is_valid_ice_credential(
            "libp2p+webrtc+v1/0123456789abcdefghijklmnopqrstuv"
        ));
        assert!(!is_valid_ice_credential("saorsa+webrtc+v1/too-short"));
        assert!(!is_valid_ice_credential(
            "saorsa+webrtc+v1/invalid_underscore_character"
        ));
    }

    #[test]
    fn generated_certificate_round_trips_and_has_sha256_pin() {
        let certificate = WebRtcCertificate::generate().unwrap();
        let digest = certificate.sha256_digest().unwrap();
        assert_ne!(digest, [0_u8; 32]);

        let loaded = WebRtcCertificate::from_pem(&certificate.serialize_pem()).unwrap();
        assert_eq!(loaded.sha256_digest().unwrap(), digest);
    }

    #[test]
    fn client_offer_contains_observed_address_and_saorsa_credential() {
        let address: SocketAddr = "192.0.2.4:49152".parse().unwrap();
        let credential = "saorsa+webrtc+v1/0123456789abcdefghijklmnopqrstuv";
        let offer = client_offer(address, credential);
        assert!(offer.contains("m=application 49152 UDP/DTLS/SCTP webrtc-datachannel"));
        assert!(offer.contains("c=IN IP4 192.0.2.4"));
        assert!(offer.contains(&format!("a=ice-ufrag:{credential}")));
        assert!(RTCSessionDescription::offer(offer).is_ok());
    }

    #[tokio::test]
    async fn binding_request_credential_overrides_stale_source_address_mapping() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let local_addr = socket.local_addr().unwrap();
        let (incoming, _) = mpsc::channel(1);
        let mux = DirectUdpMux::new(socket, local_addr, incoming);
        let remote_addr: SocketAddr = "127.0.0.1:49152".parse().unwrap();
        let old_credential = "saorsa+webrtc+v1/oldoldoldoldoldoldoldoldoldold12";
        let new_credential = "saorsa+webrtc+v1/newnewnewnewnewnewnewnewnewnew12";

        let writer: Arc<dyn UDPMuxWriter + Send + Sync> = mux.clone();
        let old_connection = UDPMuxConn::new(UDPMuxConnParams {
            local_addr,
            key: old_credential.to_string(),
            udp_mux: Arc::downgrade(&writer),
        });
        let new_connection = UDPMuxConn::new(UDPMuxConnParams {
            local_addr,
            key: new_credential.to_string(),
            udp_mux: Arc::downgrade(&writer),
        });
        mux.conns
            .lock()
            .await
            .insert(new_credential.to_string(), new_connection);
        mux.address_map
            .write()
            .insert(remote_addr, old_connection.clone());

        let mut request = StunMessage::new();
        request
            .build(&[
                Box::new(BINDING_REQUEST),
                Box::new(TransactionId::new()),
                Box::new(Username::new(
                    ATTR_USERNAME,
                    format!("{new_credential}:browser"),
                )),
            ])
            .unwrap();
        let routed = mux
            .connection_for_packet(&request.raw, remote_addr)
            .await
            .unwrap();
        assert_eq!(routed.key(), new_credential);

        let mut unknown_request = StunMessage::new();
        unknown_request
            .build(&[
                Box::new(BINDING_REQUEST),
                Box::new(TransactionId::new()),
                Box::new(Username::new(
                    ATTR_USERNAME,
                    "saorsa+webrtc+v1/unknownunknownunknownunknown12:browser".to_string(),
                )),
            ])
            .unwrap();
        assert!(
            mux.connection_for_packet(&unknown_request.raw, remote_addr)
                .await
                .is_none()
        );

        let mut response = StunMessage::new();
        response
            .build(&[Box::new(BINDING_SUCCESS), Box::new(TransactionId::new())])
            .unwrap();
        let routed = mux
            .connection_for_packet(&response.raw, remote_addr)
            .await
            .unwrap();
        assert_eq!(routed.key(), old_credential);
    }
}
