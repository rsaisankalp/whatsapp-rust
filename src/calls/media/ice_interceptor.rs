//! Relay UDP connection for WhatsApp WebRTC transport.
//!
//! WhatsApp Web uses a real RTCPeerConnection with manipulated SDP that sets
//! ice-ufrag to the relay auth_token and ice-pwd to the relay_key. The browser's
//! ICE stack sends STUN Binding Requests with proper credentials to the relay,
//! and the relay responds with valid STUN Binding Responses (including
//! MESSAGE-INTEGRITY). ICE succeeds naturally, then DTLS and SCTP follow.
//!
//! This module provides a simple UDP socket wrapper implementing webrtc-rs's
//! `Conn` trait so it can be used with `UDPMuxDefault`. All packets are
//! forwarded directly to/from the relay — no interception or spoofing.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use log::{debug, info, trace, warn};
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc};
use webrtc::util;

/// Result of a pre-ICE STUN Bind or TURN Allocate with subscriptions.
#[derive(Debug, Clone)]
pub struct PreIceBindResult {
    /// Whether the bind/allocate succeeded.
    pub success: bool,
    /// Mapped address from the response (our public address as seen by relay).
    pub mapped_address: Option<SocketAddr>,
    /// Raw response bytes for further inspection.
    pub response_bytes: Vec<u8>,
}

/// Classify a packet by its first byte for logging.
fn packet_type(buf: &[u8]) -> &'static str {
    match buf.first() {
        Some(0..=3) => "STUN",
        Some(20..=63) => "DTLS",
        _ => "OTHER",
    }
}

/// DTLS content type from first byte (only valid when packet_type is "DTLS").
fn dtls_content_type(b: u8) -> &'static str {
    match b {
        20 => "ChangeCipherSpec",
        21 => "Alert",
        22 => "Handshake",
        23 => "ApplicationData",
        25 => "Heartbeat",
        _ => "Unknown",
    }
}

/// A UDP connection to a WhatsApp relay server.
///
/// Implements the `Conn` trait from webrtc-util so it can be used
/// with `UDPMuxDefault` for WebRTC transport. All packets are
/// forwarded directly — the relay handles STUN authentication
/// using the credentials from the manipulated SDP.
pub struct RelayUdpConn {
    /// The underlying UDP socket.
    socket: Arc<UdpSocket>,
    /// Remote address (relay server).
    remote_addr: SocketAddr,
    /// Local address.
    local_addr: SocketAddr,
    /// Whether connection is closed.
    closed: Arc<Mutex<bool>>,
    /// Packet counters for summary logging.
    sent_count: AtomicU64,
    recv_count: AtomicU64,
    /// Optional interceptor: receives copies of incoming non-DTLS packets
    /// (STUN responses and SRTP/RTP) for application-level processing.
    interceptor_tx: Option<mpsc::Sender<Vec<u8>>>,
}

impl RelayUdpConn {
    /// Create a new UDP connection to a relay server.
    pub async fn new(relay_addr: SocketAddr) -> io::Result<Self> {
        let bind_addr = if relay_addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };

        let socket = UdpSocket::bind(bind_addr).await?;
        let local_addr = socket.local_addr()?;

        info!(
            "Relay UDP: {} -> {} (direct pass-through)",
            local_addr, relay_addr
        );

        Ok(Self {
            socket: Arc::new(socket),
            remote_addr: relay_addr,
            local_addr,
            closed: Arc::new(Mutex::new(false)),
            sent_count: AtomicU64::new(0),
            recv_count: AtomicU64::new(0),
            interceptor_tx: None,
        })
    }

    /// Get the local address.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Get the remote (relay) address.
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Get a reference to the underlying socket (for pre-flight checks before UDPMux takes over).
    pub fn socket(&self) -> &UdpSocket {
        &self.socket
    }

    /// Get a clone of the underlying socket Arc.
    /// Call this BEFORE passing to UDPMux to keep a shared reference.
    pub fn socket_arc(&self) -> Arc<UdpSocket> {
        self.socket.clone()
    }

    /// Set an interceptor channel that receives copies of non-DTLS incoming packets.
    /// STUN responses (first byte 0-3) and RTP/SRTP packets (first byte 128-191)
    /// are forwarded to this channel for application-level processing.
    pub fn set_interceptor(&mut self, tx: mpsc::Sender<Vec<u8>>) {
        self.interceptor_tx = Some(tx);
    }

    /// Send a bare STUN Binding Request to test relay reachability.
    /// This should be called BEFORE the conn is passed to UDPMux.
    /// Returns Ok(Some(response_bytes)) if relay responds, Ok(None) if timeout.
    pub async fn probe_relay(&self) -> io::Result<Option<Vec<u8>>> {
        // Minimal STUN Binding Request: 20-byte header, no attributes
        let mut probe = [0u8; 20];
        probe[0] = 0x00;
        probe[1] = 0x01; // Binding Request (0x0001)
        // probe[2..4] = 0x0000 (Message Length = 0)
        probe[4] = 0x21;
        probe[5] = 0x12;
        probe[6] = 0xA4;
        probe[7] = 0x42; // Magic Cookie
        // Transaction ID (bytes 8-19) - use nanosecond timestamp
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64;
        probe[8..16].copy_from_slice(&ts.to_be_bytes());
        // probe[16..20] stay as zeros

        let sent = self.socket.send_to(&probe, self.remote_addr).await?;
        info!(
            "Relay probe: sent bare STUN Binding Request ({} bytes) to {}",
            sent, self.remote_addr
        );

        let mut buf = [0u8; 1500];
        match tokio::time::timeout(Duration::from_secs(2), self.socket.recv_from(&mut buf)).await {
            Ok(Ok((len, from))) => {
                info!(
                    "Relay probe: RESPONSE {} bytes from {} (first 20: {:02x?})",
                    len,
                    from,
                    &buf[..len.min(20)]
                );
                Ok(Some(buf[..len].to_vec()))
            }
            Ok(Err(e)) => {
                warn!("Relay probe: recv error: {}", e);
                Err(e)
            }
            Err(_) => {
                warn!(
                    "Relay probe: NO RESPONSE within 2s from {} — relay may be unreachable or ignoring unauthenticated STUN",
                    self.remote_addr
                );
                Ok(None)
            }
        }
    }

    /// Send STUN Binding Requests with subscription attributes BEFORE the WebRTC
    /// ICE agent takes over. Tries multiple auth strategies:
    ///
    /// 1. No auth + subscriptions (relay responds to unauthenticated STUN)
    /// 2. USERNAME only (no MESSAGE-INTEGRITY) + subscriptions
    /// 3. Full ICE auth (USERNAME:dummy + MESSAGE-INTEGRITY) + subscriptions
    ///
    /// Must be called BEFORE UDPMux takes ownership of this connection.
    pub async fn pre_ice_bind_with_subscriptions(
        &self,
        auth_token: &[u8],
        relay_key: &[u8],
        sender_subs: &[u8],
        receiver_subs: &[u8],
    ) -> io::Result<PreIceBindResult> {
        use super::stun::StunMessage;

        info!(
            "Pre-ICE subscription bind to {} (auth_token={} bytes, sender_subs={} bytes, receiver_subs={} bytes)",
            self.remote_addr,
            auth_token.len(),
            sender_subs.len(),
            receiver_subs.len(),
        );

        // Strategy 1: No auth, just subscription attributes
        // The relay responds to bare STUN, so it might accept subscriptions without auth
        {
            let mut txn_id = [0u8; 12];
            rand::RngCore::fill_bytes(&mut rand::rng(), &mut txn_id);

            let mut bind = StunMessage::binding_request(txn_id)
                .with_priority(None); // No ICE priority for simple bind

            if !sender_subs.is_empty() {
                bind = bind.with_sender_subscriptions(sender_subs.to_vec());
            }
            if !receiver_subs.is_empty() {
                bind = bind.with_receiver_subscription(receiver_subs.to_vec());
            }

            let bind_data = bind.encode();
            info!(
                "Pre-ICE strategy 1 (no auth + subs): {} bytes, txn={:02x?}",
                bind_data.len(), &txn_id[..4]
            );

            if let Some(result) = self.send_and_wait_stun(&bind_data, &txn_id, "strategy1-noauth").await? {
                if result.success {
                    info!("Pre-ICE strategy 1 (no auth) SUCCEEDED!");
                    return Ok(result);
                }
            }
        }

        // Strategy 2: USERNAME only (no MESSAGE-INTEGRITY) + subscriptions
        {
            let mut txn_id = [0u8; 12];
            rand::RngCore::fill_bytes(&mut rand::rng(), &mut txn_id);

            let mut bind = StunMessage::binding_request(txn_id)
                .with_username(auth_token)
                .with_priority(None);

            if !sender_subs.is_empty() {
                bind = bind.with_sender_subscriptions(sender_subs.to_vec());
            }
            if !receiver_subs.is_empty() {
                bind = bind.with_receiver_subscription(receiver_subs.to_vec());
            }

            let bind_data = bind.encode();
            info!(
                "Pre-ICE strategy 2 (username + subs, no integrity): {} bytes, txn={:02x?}",
                bind_data.len(), &txn_id[..4]
            );

            if let Some(result) = self.send_and_wait_stun(&bind_data, &txn_id, "strategy2-username").await? {
                if result.success {
                    info!("Pre-ICE strategy 2 (username only) SUCCEEDED!");
                    return Ok(result);
                }
            }
        }

        // Strategy 3: Full auth (USERNAME + MESSAGE-INTEGRITY) + subscriptions
        {
            let mut txn_id = [0u8; 12];
            rand::RngCore::fill_bytes(&mut rand::rng(), &mut txn_id);

            let mut bind = StunMessage::binding_request(txn_id)
                .with_username(auth_token)
                .with_integrity_key(relay_key);

            if !sender_subs.is_empty() {
                bind = bind.with_sender_subscriptions(sender_subs.to_vec());
            }
            if !receiver_subs.is_empty() {
                bind = bind.with_receiver_subscription(receiver_subs.to_vec());
            }

            let bind_data = bind.encode();
            info!(
                "Pre-ICE strategy 3 (full auth + subs): {} bytes, txn={:02x?}",
                bind_data.len(), &txn_id[..4]
            );

            if let Some(result) = self.send_and_wait_stun(&bind_data, &txn_id, "strategy3-fullauth").await? {
                if result.success {
                    info!("Pre-ICE strategy 3 (full auth) SUCCEEDED!");
                    return Ok(result);
                }
            }
        }

        // Strategy 4: USERNAME with ICE format (ufrag:dummy) + MESSAGE-INTEGRITY + subscriptions
        // ICE uses USERNAME = remote_ufrag:local_ufrag format
        {
            let mut txn_id = [0u8; 12];
            rand::RngCore::fill_bytes(&mut rand::rng(), &mut txn_id);

            // Build ICE-style username: auth_token:wabot
            let ice_username = {
                let mut u = auth_token.to_vec();
                u.extend_from_slice(b":wabot");
                u
            };

            let mut bind = StunMessage::binding_request(txn_id)
                .with_username(&ice_username)
                .with_integrity_key(relay_key);

            if !sender_subs.is_empty() {
                bind = bind.with_sender_subscriptions(sender_subs.to_vec());
            }
            if !receiver_subs.is_empty() {
                bind = bind.with_receiver_subscription(receiver_subs.to_vec());
            }

            let bind_data = bind.encode();
            info!(
                "Pre-ICE strategy 4 (ICE-format username + subs): {} bytes, txn={:02x?}",
                bind_data.len(), &txn_id[..4]
            );

            if let Some(result) = self.send_and_wait_stun(&bind_data, &txn_id, "strategy4-iceformat").await? {
                if result.success {
                    info!("Pre-ICE strategy 4 (ICE format) SUCCEEDED!");
                    return Ok(result);
                }
            }
        }

        warn!("Pre-ICE STUN Bind: all 4 strategies failed for {}", self.remote_addr);
        Ok(PreIceBindResult {
            success: false,
            mapped_address: None,
            response_bytes: Vec::new(),
        })
    }

    /// Helper: send a STUN message and wait for a matching response.
    /// Returns Some(result) if we got any response, None on timeout.
    async fn send_and_wait_stun(
        &self,
        data: &[u8],
        txn_id: &[u8; 12],
        label: &str,
    ) -> io::Result<Option<PreIceBindResult>> {
        use super::stun::StunMessage;

        let sent = self.socket.send_to(data, self.remote_addr).await?;
        info!("Pre-ICE {}: sent {} bytes to {}", label, sent, self.remote_addr);

        let mut buf = [0u8; 1500];
        match tokio::time::timeout(Duration::from_millis(2500), self.socket.recv_from(&mut buf)).await {
            Ok(Ok((len, from))) => {
                info!(
                    "Pre-ICE {}: received {} bytes from {} (first20={:02x?})",
                    label, len, from, &buf[..len.min(20)]
                );

                if let Ok(response) = StunMessage::decode(&buf[..len]) {
                    for attr in &response.attributes {
                        info!("Pre-ICE {} response attr: {:?}", label, attr);
                    }

                    if response.transaction_id == *txn_id {
                        if response.is_success() {
                            let mapped = response.mapped_address();
                            info!("Pre-ICE {} SUCCESS! mapped={:?}", label, mapped);
                            return Ok(Some(PreIceBindResult {
                                success: true,
                                mapped_address: mapped,
                                response_bytes: buf[..len].to_vec(),
                            }));
                        } else if response.is_error() {
                            let (code, reason) = response.error_code().unwrap_or((0, "unknown"));
                            warn!("Pre-ICE {} ERROR: code={}, reason='{}'", label, code, reason);
                            return Ok(Some(PreIceBindResult {
                                success: false,
                                mapped_address: None,
                                response_bytes: buf[..len].to_vec(),
                            }));
                        }
                    } else {
                        info!(
                            "Pre-ICE {}: txn mismatch (expected {:02x?}, got {:02x?})",
                            label, &txn_id[..4], &response.transaction_id[..4]
                        );
                        // Got a response but wrong txn - return as failure with data
                        return Ok(Some(PreIceBindResult {
                            success: false,
                            mapped_address: None,
                            response_bytes: buf[..len].to_vec(),
                        }));
                    }
                } else {
                    info!("Pre-ICE {}: non-STUN response ({} bytes)", label, len);
                    return Ok(Some(PreIceBindResult {
                        success: false,
                        mapped_address: None,
                        response_bytes: buf[..len].to_vec(),
                    }));
                }
            }
            Ok(Err(e)) => {
                warn!("Pre-ICE {}: recv error: {}", label, e);
            }
            Err(_) => {
                info!("Pre-ICE {}: timeout (2.5s)", label);
            }
        }

        Ok(None)
    }

    /// Send a TURN Allocate Request with subscription attributes before ICE.
    /// Some WhatsApp relay configs require TURN Allocate instead of STUN Bind
    /// for subscription registration.
    pub async fn pre_ice_allocate_with_subscriptions(
        &self,
        auth_token: &[u8],
        relay_key: &[u8],
        sender_subs: &[u8],
        receiver_subs: &[u8],
    ) -> io::Result<PreIceBindResult> {
        use super::stun::StunMessage;

        let mut txn_id = [0u8; 12];
        {
            use rand::RngCore;
            rand::rng().fill_bytes(&mut txn_id);
        }

        let mut alloc = StunMessage::allocate_request(txn_id)
            .with_username(auth_token)
            .with_integrity_key(relay_key);

        if !sender_subs.is_empty() {
            alloc = alloc.with_sender_subscriptions(sender_subs.to_vec());
        }
        if !receiver_subs.is_empty() {
            alloc = alloc.with_receiver_subscription(receiver_subs.to_vec());
        }

        let alloc_data = alloc.encode();
        info!(
            "Pre-ICE TURN Allocate: sending {} bytes to {} (txn={:02x?})",
            alloc_data.len(),
            self.remote_addr,
            &txn_id[..4],
        );

        let max_attempts = 3;
        for attempt in 1..=max_attempts {
            let sent = self.socket.send_to(&alloc_data, self.remote_addr).await?;
            info!(
                "Pre-ICE Allocate attempt {}/{}: sent {} bytes",
                attempt, max_attempts, sent
            );

            let mut buf = [0u8; 1500];
            match tokio::time::timeout(
                Duration::from_secs(3),
                self.socket.recv_from(&mut buf),
            )
            .await
            {
                Ok(Ok((len, from))) => {
                    info!(
                        "Pre-ICE Allocate: received {} bytes from {} (first20={:02x?})",
                        len, from, &buf[..len.min(20)]
                    );

                    if let Ok(response) = StunMessage::decode(&buf[..len]) {
                        for attr in &response.attributes {
                            info!("Pre-ICE Allocate response attr: {:?}", attr);
                        }

                        if response.transaction_id == txn_id {
                            if response.is_success() {
                                let mapped = response.mapped_address();
                                let relayed = response.relayed_address();
                                let lifetime = response.lifetime();
                                info!(
                                    "Pre-ICE TURN Allocate SUCCESS! mapped={:?}, relayed={:?}, lifetime={:?}s",
                                    mapped, relayed, lifetime
                                );
                                return Ok(PreIceBindResult {
                                    success: true,
                                    mapped_address: mapped,
                                    response_bytes: buf[..len].to_vec(),
                                });
                            } else if response.is_error() {
                                let (code, reason) =
                                    response.error_code().unwrap_or((0, "unknown"));
                                warn!(
                                    "Pre-ICE Allocate ERROR: code={}, reason='{}'",
                                    code, reason
                                );
                                // 401 with realm/nonce = challenge-response needed
                                if code == 401 {
                                    if let (Some(realm), Some(nonce)) =
                                        (response.realm(), response.nonce())
                                    {
                                        info!(
                                            "Pre-ICE Allocate got 401 challenge: realm='{}', nonce={} bytes. Retrying with realm/nonce.",
                                            realm, nonce.len()
                                        );
                                        let mut retry_txn = [0u8; 12];
                                        rand::RngCore::fill_bytes(
                                            &mut rand::rng(),
                                            &mut retry_txn,
                                        );
                                        let mut retry = StunMessage::allocate_request(retry_txn)
                                            .with_username(auth_token)
                                            .with_integrity_key(relay_key)
                                            .with_realm(realm)
                                            .with_nonce(nonce.to_vec());
                                        if !sender_subs.is_empty() {
                                            retry = retry.with_sender_subscriptions(
                                                sender_subs.to_vec(),
                                            );
                                        }
                                        if !receiver_subs.is_empty() {
                                            retry = retry.with_receiver_subscription(
                                                receiver_subs.to_vec(),
                                            );
                                        }
                                        let retry_data = retry.encode();
                                        let _ = self
                                            .socket
                                            .send_to(&retry_data, self.remote_addr)
                                            .await?;
                                        // Continue to next recv iteration to get challenge response
                                        continue;
                                    }
                                }
                                if code == 403 {
                                    return Ok(PreIceBindResult {
                                        success: false,
                                        mapped_address: None,
                                        response_bytes: buf[..len].to_vec(),
                                    });
                                }
                            }
                        }
                    }
                }
                Ok(Err(e)) => {
                    warn!("Pre-ICE Allocate attempt {}: recv error: {}", attempt, e);
                }
                Err(_) => {
                    info!(
                        "Pre-ICE Allocate attempt {}/{}: timeout (3s)",
                        attempt, max_attempts
                    );
                }
            }
        }

        warn!("Pre-ICE TURN Allocate: no success after {} attempts", max_attempts);
        Ok(PreIceBindResult {
            success: false,
            mapped_address: None,
            response_bytes: Vec::new(),
        })
    }

    fn log_send(&self, buf: &[u8]) {
        let n = self.sent_count.fetch_add(1, Ordering::Relaxed) + 1;
        let ptype = packet_type(buf);
        if ptype == "DTLS" {
            info!(
                "Relay TX #{}: {} {} ({} bytes) -> {}",
                n,
                ptype,
                dtls_content_type(buf[0]),
                buf.len(),
                self.remote_addr
            );
        } else if ptype == "STUN" {
            // Log STUN packets with first bytes at debug level for diagnostics
            debug!(
                "Relay TX #{}: STUN ({} bytes) -> {} | header: {:02x?}",
                n,
                buf.len(),
                self.remote_addr,
                &buf[..buf.len().min(20)]
            );
        } else {
            debug!(
                "Relay TX #{}: {} ({} bytes) -> {}",
                n,
                ptype,
                buf.len(),
                self.remote_addr
            );
        }
        trace!(
            "Relay TX #{} full first 40 bytes: {:02x?}",
            n,
            &buf[..buf.len().min(40)]
        );
    }

    fn log_recv(&self, buf: &[u8], from: SocketAddr) {
        let n = self.recv_count.fetch_add(1, Ordering::Relaxed) + 1;
        let ptype = packet_type(buf);
        if ptype == "DTLS" {
            info!(
                "Relay RX #{}: {} {} ({} bytes) <- {}",
                n,
                ptype,
                dtls_content_type(buf[0]),
                buf.len(),
                from
            );
        } else {
            debug!(
                "Relay RX #{}: {} ({} bytes) <- {}",
                n,
                ptype,
                buf.len(),
                from
            );
        }
        trace!(
            "Relay RX #{} first 20 bytes: {:02x?}",
            n,
            &buf[..buf.len().min(20)]
        );
    }
}

#[async_trait]
impl util::Conn for RelayUdpConn {
    async fn connect(&self, addr: SocketAddr) -> util::Result<()> {
        debug!("Relay UDP: connect({}) - no-op for UDP", addr);
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> util::Result<usize> {
        let (len, from) = self.socket.recv_from(buf).await?;
        self.log_recv(&buf[..len], from);

        // Intercept non-DTLS packets (STUN responses and RTP/SRTP)
        if let Some(ref tx) = self.interceptor_tx {
            let first = buf.get(0).copied().unwrap_or(0);
            // STUN (0-3) or RTP/SRTP (128-191) — skip DTLS (20-63) which WebRTC handles
            if first <= 3 || first >= 128 {
                let _ = tx.try_send(buf[..len].to_vec());
            }
        }

        Ok(len)
    }

    async fn recv_from(&self, buf: &mut [u8]) -> util::Result<(usize, SocketAddr)> {
        let (len, from) = self.socket.recv_from(buf).await?;
        self.log_recv(&buf[..len], from);

        // Intercept non-DTLS packets (STUN responses and RTP/SRTP)
        if let Some(ref tx) = self.interceptor_tx {
            let first = buf.get(0).copied().unwrap_or(0);
            if first <= 3 || first >= 128 {
                let _ = tx.try_send(buf[..len].to_vec());
            }
        }

        Ok((len, from))
    }

    async fn send(&self, buf: &[u8]) -> util::Result<usize> {
        self.log_send(buf);
        let sent = self.socket.send_to(buf, self.remote_addr).await?;
        Ok(sent)
    }

    async fn send_to(&self, buf: &[u8], target: SocketAddr) -> util::Result<usize> {
        self.log_send(buf);
        let sent = self.socket.send_to(buf, target).await?;
        Ok(sent)
    }

    fn local_addr(&self) -> util::Result<SocketAddr> {
        Ok(self.local_addr)
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        Some(self.remote_addr)
    }

    async fn close(&self) -> util::Result<()> {
        let sent = self.sent_count.load(Ordering::Relaxed);
        let recv = self.recv_count.load(Ordering::Relaxed);
        info!(
            "Relay UDP closed: {} -> {} (sent={}, recv={})",
            self.local_addr, self.remote_addr, sent, recv
        );
        *self.closed.lock().await = true;
        Ok(())
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}
