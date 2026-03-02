use base64::Engine;
use chrono::{Local, Utc};
use log::{debug, error, info, warn};
use opus::{Application as OpusApplication, Channels as OpusChannels, Encoder as OpusEncoder};
use prost::Message as _;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::io::Cursor;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, mpsc};
use wacore::download::{Downloadable, MediaType};
use wacore::iq::spec::IqSpec;
use wacore::iq::usync::{ContactInfoSpec, DeviceListSpec};
use wacore::messages::MessageUtils;
use wacore::net::{HttpClient, HttpRequest};
use wacore::proto_helpers::MessageExt;
use wacore::types::call::CallId;
use wacore::types::events::Event;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::Jid;
use wacore_binary::node::{Node, NodeContent};
use waproto::whatsapp as wa;
use whatsapp_rust::bot::{Bot, MessageContext};
use whatsapp_rust::calls::media::{
    RtpSession, SRTP_AUTH_TAG_LEN, SrtpSession, StunMessage, StunMessageType,
    create_app_data_sender_subscriptions, create_audio_sender_subscriptions,
    create_audio_sender_subscriptions_with_jid,
    create_combined_sender_subscriptions, create_combined_receiver_subscription,
};
use whatsapp_rust::calls::{
    AcceptAudioParams, CallManager, CallOptions, CallStanzaBuilder, EncType, SignalingType,
    SrtpKeyingMaterial,
};
use whatsapp_rust::client::Client;
use whatsapp_rust::pair_code::PairCodeOptions;
use whatsapp_rust::store::SqliteStore;
use whatsapp_rust::upload::UploadResponse;
use whatsapp_rust_tokio_transport::TokioWebSocketTransportFactory;
use whatsapp_rust_ureq_http_client::UreqHttpClient;

const PING_TRIGGER: &str = "🦀ping";
const MEDIA_PING_TRIGGER: &str = "ping";
const PONG_TEXT: &str = "🏓 Pong!";
const MEDIA_PONG_TEXT: &str = "pong";
const REACTION_EMOJI: &str = "🏓";

#[derive(Clone, Debug)]
struct CallAutomationConfig {
    enabled: bool,
    auto_accept: bool,
    api_endpoint: Option<String>,
    api_key: Option<String>,
    batch_frames: usize,
    flush_interval: Duration,
    recv_timeout: Duration,
    ping_interval: Duration,
    connect_retries: usize,
    connect_retry_delay: Duration,
    echo_when_no_api: bool,
    auto_dial_target: Option<String>,
    auto_dial_video: bool,
    auto_dial_delay: Duration,
    sample_audio_on_connect: bool,
    sample_audio_duration_ms: u64,
    sample_audio_frequency_hz: f32,
    srtp_offset_scan: bool,
    packet_signature_debug_count: usize,
}

impl CallAutomationConfig {
    fn from_env() -> Self {
        Self {
            enabled: env_bool("WHATSAPP_CALL_AUTOMATION_ENABLED", true),
            auto_accept: env_bool("WHATSAPP_CALL_AUTO_ACCEPT", true),
            api_endpoint: std::env::var("WHATSAPP_VOICE_BOT_API").ok(),
            api_key: std::env::var("WHATSAPP_VOICE_BOT_API_KEY").ok(),
            batch_frames: env_usize("WHATSAPP_VOICE_BATCH_FRAMES", 50),
            flush_interval: Duration::from_millis(env_u64("WHATSAPP_VOICE_FLUSH_MS", 1200)),
            recv_timeout: Duration::from_millis(env_u64("WHATSAPP_VOICE_RECV_TIMEOUT_MS", 100)),
            ping_interval: Duration::from_secs(env_u64("WHATSAPP_VOICE_PING_INTERVAL_SECS", 5)),
            connect_retries: env_usize("WHATSAPP_CALL_CONNECT_RETRIES", 5),
            connect_retry_delay: Duration::from_millis(env_u64(
                "WHATSAPP_CALL_CONNECT_RETRY_DELAY_MS",
                500,
            )),
            echo_when_no_api: env_bool("WHATSAPP_CALL_ECHO_FALLBACK", true),
            auto_dial_target: std::env::var("WHATSAPP_TEST_CALL_TO").ok(),
            auto_dial_video: env_bool("WHATSAPP_TEST_CALL_VIDEO", false),
            auto_dial_delay: Duration::from_secs(env_u64("WHATSAPP_TEST_CALL_DELAY_SECS", 10)),
            sample_audio_on_connect: env_bool("WHATSAPP_CALL_SAMPLE_AUDIO", true),
            sample_audio_duration_ms: env_u64("WHATSAPP_CALL_SAMPLE_AUDIO_DURATION_MS", 2000),
            sample_audio_frequency_hz: env_f32("WHATSAPP_CALL_SAMPLE_AUDIO_FREQ_HZ", 440.0),
            srtp_offset_scan: env_bool("WHATSAPP_CALL_SRTP_OFFSET_SCAN", true),
            packet_signature_debug_count: env_usize("WHATSAPP_CALL_PACKET_DEBUG_COUNT", 32),
        }
    }
}

#[derive(Clone, Default)]
struct CallAutomationRegistry {
    sessions: Arc<Mutex<HashMap<String, Arc<CallAutomationSession>>>>,
}

struct CallAutomationSession {
    stop: Arc<AtomicBool>,
}

impl CallAutomationRegistry {
    async fn reserve(&self, call_id: &str) -> bool {
        let mut sessions = self.sessions.lock().await;
        if sessions.contains_key(call_id) {
            return false;
        }

        sessions.insert(
            call_id.to_string(),
            Arc::new(CallAutomationSession {
                stop: Arc::new(AtomicBool::new(false)),
            }),
        );
        true
    }

    async fn replace(&self, call_id: &str, session: Arc<CallAutomationSession>) {
        self.sessions
            .lock()
            .await
            .insert(call_id.to_string(), session);
    }

    async fn stop(&self, call_id: &str) {
        if let Some(session) = self.sessions.lock().await.remove(call_id) {
            session.stop.store(true, Ordering::Relaxed);
            info!("Stopped automation session for call {}", call_id);
        }
    }
}

#[derive(Debug, Serialize)]
struct VoiceBotApiRequest {
    call_id: String,
    sequence: u64,
    codec: &'static str,
    sample_rate: u32,
    opus_frames_b64: Vec<String>,
}

#[derive(Debug, Deserialize, Default)]
struct VoiceBotApiResponse {
    transcript: Option<String>,
    reply_text: Option<String>,
    reply_opus_b64: Option<String>,
    reply_opus_frames_b64: Option<Vec<String>>,
}

// Usage:
//   cargo run                                      # QR code pairing only
//   cargo run -- --phone 15551234567               # Pair code + QR code (concurrent)
//   cargo run -- -p 15551234567                    # Short form
//   cargo run -- -p 15551234567 --code MYCODE12    # Custom 8-char pair code
//   cargo run -- -p 15551234567 -c MYCODE12        # Short form
fn main() {
    let args: Vec<String> = std::env::args().collect();
    let phone_number = parse_arg(&args, "--phone", "-p");
    let custom_code = parse_arg(&args, "--code", "-c");

    if let Some(ref phone) = phone_number {
        eprintln!("Phone number provided: {}", phone);
        if let Some(ref code) = custom_code {
            eprintln!("Custom pair code: {}", code);
        }
        eprintln!("Will use pair code authentication (concurrent with QR)");
    }

    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info"))
        .format(|buf, record| {
            use std::io::Write;
            writeln!(
                buf,
                "{} [{:<5}] [{}] - {}",
                Local::now().format("%H:%M:%S"),
                record.level(),
                record.target(),
                record.args()
            )
        })
        .init();

    let call_automation_config = CallAutomationConfig::from_env();
    let call_automation_registry = CallAutomationRegistry::default();
    info!("Call automation config: {:?}", call_automation_config);

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("Failed to build tokio runtime");

    rt.block_on(async {
        let backend = match SqliteStore::new("whatsapp.db").await {
            Ok(store) => Arc::new(store),
            Err(e) => {
                error!("Failed to create SQLite backend: {}", e);
                return;
            }
        };
        info!("SQLite backend initialized successfully.");

        let transport_factory = TokioWebSocketTransportFactory::new();
        let http_client = UreqHttpClient::new();

        let mut builder = Bot::builder()
            .with_backend(backend)
            .with_transport_factory(transport_factory)
            .with_http_client(http_client);

        if let Some(phone) = phone_number {
            builder = builder.with_pair_code(PairCodeOptions {
                phone_number: phone,
                custom_code,
                ..Default::default()
            });
        }

        let automation_cfg = call_automation_config.clone();
        let automation_registry = call_automation_registry.clone();
        let dial_triggered = Arc::new(AtomicBool::new(false));

        let mut bot = builder
            .on_event(move |event, client| {
                let automation_cfg = automation_cfg.clone();
                let automation_registry = automation_registry.clone();
                let dial_triggered = dial_triggered.clone();
                async move {
                    match event {
                        Event::PairingQrCode { code, timeout } => {
                            info!("----------------------------------------");
                            info!(
                                "QR code received (valid for {} seconds):",
                                timeout.as_secs()
                            );
                            info!("\n{}\n", code);
                            info!("----------------------------------------");
                        }
                        Event::PairingCode { code, timeout } => {
                            info!("========================================");
                            info!("PAIR CODE (valid for {} seconds):", timeout.as_secs());
                            info!("Enter this code on your phone:");
                            info!("WhatsApp > Linked Devices > Link a Device");
                            info!("> Link with phone number instead");
                            info!("");
                            info!("    >>> {} <<<", code);
                            info!("");
                            info!("========================================");
                        }
                        Event::Message(msg, info) => {
                            let ctx = MessageContext {
                                message: msg,
                                info,
                                client,
                            };

                            if let Some(media_ping_request) = get_pingable_media(&ctx.message) {
                                handle_media_ping(&ctx, media_ping_request).await;
                            }

                            if let Some(text) = ctx.message.text_content()
                                && text == PING_TRIGGER
                            {
                                info!("Received text ping, sending pong...");

                                let message_key = wa::MessageKey {
                                    remote_jid: Some(ctx.info.source.chat.to_string()),
                                    id: Some(ctx.info.id.clone()),
                                    from_me: Some(ctx.info.source.is_from_me),
                                    participant: if ctx.info.source.is_group {
                                        Some(ctx.info.source.sender.to_string())
                                    } else {
                                        None
                                    },
                                };

                                let reaction_message = wa::message::ReactionMessage {
                                    key: Some(message_key),
                                    text: Some(REACTION_EMOJI.to_string()),
                                    sender_timestamp_ms: Some(Utc::now().timestamp_millis()),
                                    ..Default::default()
                                };

                                let final_message_to_send = wa::Message {
                                    reaction_message: Some(reaction_message),
                                    ..Default::default()
                                };

                                if let Err(e) = ctx.send_message(final_message_to_send).await {
                                    error!("Failed to send reaction: {}", e);
                                }

                                let start = Instant::now();
                                let context_info = ctx.build_quote_context();
                                let reply_message = wa::Message {
                                    extended_text_message: Some(Box::new(
                                        wa::message::ExtendedTextMessage {
                                            text: Some(PONG_TEXT.to_string()),
                                            context_info: Some(Box::new(context_info.clone())),
                                            ..Default::default()
                                        },
                                    )),
                                    ..Default::default()
                                };

                                let sent_msg_id = match ctx.send_message(reply_message).await {
                                    Ok(id) => id,
                                    Err(e) => {
                                        error!("Failed to send initial pong message: {}", e);
                                        return;
                                    }
                                };

                                let duration = start.elapsed();
                                let duration_str = format!("{:.2?}", duration);

                                info!(
                                    "Send took {}. Editing message {}...",
                                    duration_str, &sent_msg_id
                                );

                                let updated_content = wa::Message {
                                    extended_text_message: Some(Box::new(
                                        wa::message::ExtendedTextMessage {
                                            text: Some(format!("{}\n`{}`", PONG_TEXT, duration_str)),
                                            context_info: Some(Box::new(context_info)),
                                            ..Default::default()
                                        },
                                    )),
                                    ..Default::default()
                                };

                                if let Err(e) =
                                    ctx.edit_message(sent_msg_id.clone(), updated_content).await
                                {
                                    error!("Failed to edit message {}: {}", sent_msg_id, e);
                                } else {
                                    info!("Successfully sent edit for message {}.", sent_msg_id);
                                }
                            }
                        }
                        Event::Connected(_) => {
                            info!("✅ Bot connected successfully!");

                            if let Some(target) = automation_cfg.auto_dial_target.clone()
                                && !dial_triggered.swap(true, Ordering::AcqRel)
                            {
                                let is_video = automation_cfg.auto_dial_video;
                                let dial_delay = automation_cfg.auto_dial_delay;
                                let outbound_cfg = automation_cfg.clone();
                                tokio::spawn(async move {
                                    info!(
                                        "Waiting {:?} before auto-dialing {}",
                                        dial_delay, target
                                    );
                                    tokio::time::sleep(dial_delay).await;
                                    let recipient_jid = match resolve_call_target_jid(&client, &target).await {
                                        Ok(jid) => jid,
                                        Err(e) => {
                                            error!("Failed to resolve dial target {}: {}", target, e);
                                            return;
                                        }
                                    };

                                    if env_bool("WHATSAPP_CALL_SEND_WARMUP", false) {
                                        let warmup_text = std::env::var("WHATSAPP_CALL_WARMUP_TEXT")
                                            .ok()
                                            .filter(|v| !v.trim().is_empty())
                                            .unwrap_or_else(|| "call warmup".to_string());
                                        let warmup_wait_ms =
                                            env_u64("WHATSAPP_CALL_WARMUP_WAIT_MS", 1200);
                                        let warmup_message = wa::Message {
                                            conversation: Some(warmup_text.clone()),
                                            ..Default::default()
                                        };
                                        match client
                                            .send_message(recipient_jid.clone(), warmup_message)
                                            .await
                                        {
                                            Ok(msg_id) => info!(
                                                "Sent warmup message {} before calling {}",
                                                msg_id, recipient_jid
                                            ),
                                            Err(e) => warn!(
                                                "Failed to send warmup message to {}: {}",
                                                recipient_jid, e
                                            ),
                                        }
                                        info!(
                                            "Waiting {}ms after warmup before placing call to {}",
                                            warmup_wait_ms, recipient_jid
                                        );
                                        tokio::time::sleep(Duration::from_millis(warmup_wait_ms))
                                            .await;
                                    }

                                    match start_outgoing_call_with_jid(
                                        client.clone(),
                                        recipient_jid,
                                        is_video,
                                    )
                                    .await
                                    {
                                        Ok(call_id) => {
                                            info!(
                                                "Started {} test call {} to {}",
                                                if is_video { "video" } else { "audio" },
                                                call_id,
                                                target
                                            );
                                            if outbound_cfg.enabled {
                                                info!(
                                                    "Outbound call {} placed; waiting for remote accept before starting automation",
                                                    call_id
                                                );
                                            }
                                        }
                                        Err(e) => {
                                            error!("Failed to start test call to {}: {}", target, e);
                                        }
                                    }
                                });
                            }
                        }
                        Event::Receipt(receipt) => {
                            info!(
                                "Got receipt for message(s) {:?}, type: {:?}",
                                receipt.message_ids, receipt.r#type
                            );
                        }
                        Event::LoggedOut(_) => {
                            error!("❌ Bot was logged out!");
                        }
                        Event::CallOffer(offer) => {
                            info!(
                                "📞 Incoming {} call from {} (call_id: {})",
                                if offer.media_type == wacore::types::call::CallMediaType::Video {
                                    "video"
                                } else {
                                    "audio"
                                },
                                offer.meta.from,
                                offer.meta.call_id
                            );

                            if offer.is_offline {
                                info!("Skipping offline call {}", offer.meta.call_id);
                                return;
                            }

                            if !automation_cfg.enabled || !automation_cfg.auto_accept {
                                info!(
                                    "Call automation disabled or auto-accept off for {}",
                                    offer.meta.call_id
                                );
                                return;
                            }

                            let call_id = CallId::new(&offer.meta.call_id);
                            if let Err(e) =
                                auto_accept_call(client.clone(), &call_id, &automation_cfg).await
                            {
                                warn!("Auto-accept failed for {}: {}", call_id, e);
                                return;
                            }

                            if let Err(e) = start_call_automation(
                                client,
                                call_id,
                                automation_cfg,
                                automation_registry,
                            )
                            .await
                            {
                                warn!("Failed to start call automation: {}", e);
                            }
                        }
                        Event::CallAccepted(accepted) => {
                            info!("📞 Call {} accepted by remote", accepted.meta.call_id);

                            if !automation_cfg.enabled {
                                return;
                            }

                            let call_id = CallId::new(&accepted.meta.call_id);
                            if let Err(e) = start_call_automation(
                                client,
                                call_id,
                                automation_cfg,
                                automation_registry,
                            )
                            .await
                            {
                                warn!("Failed to start call automation: {}", e);
                            }
                        }
                        Event::CallRejected(rejected) => {
                            info!("📞 Call {} rejected by remote", rejected.meta.call_id);
                            automation_registry.stop(&rejected.meta.call_id).await;
                        }
                        Event::CallEnded(ended) => {
                            info!("📞 Call {} ended", ended.meta.call_id);
                            automation_registry.stop(&ended.meta.call_id).await;
                        }
                        _ => {}
                    }
                }
            })
            .build()
            .await
            .expect("Failed to build bot");

        let bot_handle = match bot.run().await {
            Ok(handle) => handle,
            Err(e) => {
                error!("Bot failed to start: {}", e);
                return;
            }
        };

        bot_handle
            .await
            .expect("Bot task should complete without panicking");
    });
}

async fn auto_accept_call(
    client: Arc<Client>,
    call_id: &CallId,
    config: &CallAutomationConfig,
) -> Result<(), String> {
    let call_manager = client.get_call_manager().await;

    if let Ok(mute_stanza) = call_manager.send_mute_state(call_id, false).await
        && let Err(e) = client.send_node(mute_stanza).await
    {
        warn!("Failed sending MUTE_V2 for {}: {}", call_id, e);
    }

    let accept_stanza = call_manager
        .accept_call(call_id)
        .await
        .map_err(|e| format!("build ACCEPT failed: {}", e))?;
    client
        .send_node(accept_stanza)
        .await
        .map_err(|e| format!("send ACCEPT failed: {}", e))?;

    info!(
        "Auto-accepted call {} (connect retries: {})",
        call_id, config.connect_retries
    );
    Ok(())
}

async fn start_outgoing_call_with_jid(
    client: Arc<Client>,
    recipient_jid: Jid,
    video: bool,
) -> Result<CallId, String> {
    let call_manager = client.get_call_manager().await;
    let options = if video {
        CallOptions::video()
    } else {
        CallOptions::audio()
    };

    let call_id = call_manager
        .start_call(recipient_jid.clone(), options)
        .await
        .map_err(|e| format!("start_call failed: {}", e))?;

    let creator_mode = std::env::var("WHATSAPP_CALL_CREATOR_MODE")
        .unwrap_or_else(|_| "manager".to_string())
        .trim()
        .to_ascii_lowercase();
    if creator_mode != "manager" {
        let creator_device = client.persistence_manager().get_device_snapshot().await;
        let selected_creator = match creator_mode.as_str() {
            "lid" => creator_device
                .lid
                .clone()
                .or_else(|| creator_device.pn.clone()),
            "pn" => creator_device
                .pn
                .clone()
                .or_else(|| creator_device.lid.clone()),
            "lid_non_ad" => creator_device
                .lid
                .clone()
                .or_else(|| creator_device.pn.clone())
                .map(|j| j.to_non_ad()),
            "pn_non_ad" => creator_device
                .pn
                .clone()
                .or_else(|| creator_device.lid.clone())
                .map(|j| j.to_non_ad()),
            other => {
                warn!(
                    "Unknown WHATSAPP_CALL_CREATOR_MODE='{}' (expected manager|lid|pn|lid_non_ad|pn_non_ad), using manager default",
                    other
                );
                None
            }
        };

        if let Some(call_creator) = selected_creator {
            match call_manager
                .set_call_creator(&call_id, call_creator.clone())
                .await
            {
                Ok(()) => info!(
                    "Using call-creator override mode '{}' -> {} for call {}",
                    creator_mode, call_creator, call_id
                ),
                Err(e) => warn!(
                    "Failed to set call-creator override '{}' for {}: {}",
                    creator_mode, call_id, e
                ),
            }
        } else {
            warn!(
                "WHATSAPP_CALL_CREATOR_MODE='{}' requested but no creator identity available",
                creator_mode
            );
        }
    }

    let session_target = client
        .ensure_call_session(&recipient_jid)
        .await
        .map_err(|e| format!("ensure_call_session failed: {}", e))?;

    let encryption_target = pick_signal_encryption_target(&client, &session_target).await;
    let has_session = client.has_signal_session(&encryption_target).await;
    info!(
        "Call {} session target resolved: session_target={} encryption_target={} has_session={}",
        call_id, session_target, encryption_target, has_session
    );

    let (encrypted_key, device_identity) =
        match client.encrypt_call_key_for(&encryption_target).await {
            Ok((call_key, encrypted)) => {
                if let Err(e) = call_manager.store_encryption_key(&call_id, call_key).await {
                    warn!("Failed storing call key for {}: {}", call_id, e);
                }

                let identity = if encrypted.enc_type == EncType::PkMsg {
                    let device_snapshot = client.persistence_manager().get_device_snapshot().await;
                    device_snapshot.account.as_ref().map(|a| a.encode_to_vec())
                } else {
                    None
                };
                (Some(encrypted), identity)
            }
            Err(e) => {
                warn!(
                    "Call key encryption failed for {} (continuing without encrypted key): {}",
                    encryption_target, e
                );
                (None, None)
            }
        };

    let offer_send_notice = env_bool("WHATSAPP_CALL_OFFER_SEND_NOTICE", false);
    let offer_stanza_id_call_id = env_bool("WHATSAPP_CALL_OFFER_STANZA_ID_CALL_ID", false);
    let offer_dual_audio = env_bool("WHATSAPP_CALL_OFFER_DUAL_AUDIO", true);
    let offer_include_capability = env_bool("WHATSAPP_CALL_OFFER_CAPABILITY", true);
    let offer_include_device_identity = env_bool("WHATSAPP_CALL_OFFER_DEVICE_IDENTITY", true);
    let offer_net_medium = env_u8("WHATSAPP_CALL_OFFER_NET_MEDIUM", 3);
    let offer_participants_wrapper = env_bool("WHATSAPP_CALL_OFFER_PARTICIPANTS", false);
    let call_participants_wrapper = env_bool("WHATSAPP_CALL_CALL_PARTICIPANTS", false);
    let offer_phash = std::env::var("WHATSAPP_CALL_OFFER_PHASH")
        .ok()
        .filter(|v| !v.trim().is_empty());
    let call_phash = std::env::var("WHATSAPP_CALL_CALL_PHASH")
        .ok()
        .filter(|v| !v.trim().is_empty());
    let offer_privacy = std::env::var("WHATSAPP_CALL_OFFER_PRIVACY_HEX")
        .ok()
        .and_then(|hex| {
            if hex.trim().is_empty() {
                None
            } else {
                match parse_hex_bytes(&hex) {
                    Ok(bytes) => Some(bytes),
                    Err(e) => {
                        warn!("Ignoring invalid WHATSAPP_CALL_OFFER_PRIVACY_HEX: {}", e);
                        None
                    }
                }
            }
        });

    let call_info = call_manager
        .get_call(&call_id)
        .await
        .ok_or_else(|| format!("call {} not found after start_call", call_id))?;

    // Fetch fresh device list + hash for the call recipient (same source as WA usync).
    let mut peer_devices: Vec<Jid> = Vec::new();
    let mut usync_phash: Option<String> = None;
    let sid = format!("call-devices-{}", rand::random::<u32>());
    let device_spec = DeviceListSpec::new(vec![call_info.peer_jid.to_non_ad()], sid);
    match client.execute(device_spec).await {
        Ok(resp) => {
            if let Some(list) = resp.device_lists.first() {
                peer_devices = list.devices.clone();
                usync_phash = list.phash.clone();
            }
        }
        Err(e) => warn!(
            "Failed to fetch peer device list/phash for {}: {}",
            call_info.peer_jid, e
        ),
    }

    // Also query device fanout from device registry/session path; this usually contains
    // all companion device JIDs (e.g. :64, :65, :66...) used in normal message fanout.
    match client
        .get_user_devices(std::slice::from_ref(&call_info.peer_jid))
        .await
    {
        Ok(devices) => {
            for device in devices {
                if !peer_devices.iter().any(|d| d.device_eq(&device)) {
                    peer_devices.push(device);
                }
            }
        }
        Err(e) => warn!(
            "Failed to fetch user devices for {}: {}",
            call_info.peer_jid, e
        ),
    }

    if !peer_devices.iter().any(|d| d.device_eq(&session_target)) {
        peer_devices.push(session_target.clone());
    }

    let trusted_contact_token = client
        .ensure_trusted_contact_token(&call_info.peer_jid)
        .await;

    if offer_send_notice {
        if let Ok(offer_notice) = call_manager.send_offer_notice(&call_id).await {
            if let Err(e) = client.send_node(offer_notice).await {
                warn!("Failed sending offer_notice for {}: {}", call_id, e);
            } else {
                debug!("Sent offer_notice for {}", call_id);
            }
        }
    }

    let mut builder = CallStanzaBuilder::new(
        call_id.as_str(),
        call_info.call_creator.clone(),
        call_info.peer_jid.clone(),
        SignalingType::Offer,
    )
    .video(video)
    .net_medium(offer_net_medium)
    .encopt_keygen(2);

    if offer_stanza_id_call_id {
        builder = builder.stanza_id(call_id.as_str());
    }

    if offer_dual_audio {
        builder = builder
            .audio(AcceptAudioParams {
                codec: "opus".to_string(),
                rate: 8000,
            })
            .audio(AcceptAudioParams::default());
    } else {
        builder = builder.audio(AcceptAudioParams::default());
    }

    if offer_include_capability {
        builder = builder.capability(vec![0x01, 0x05, 0xF7, 0x09, 0xE4, 0xBB, 0x07]);
    }

    if let Some(privacy) = offer_privacy.or_else(|| trusted_contact_token.clone()) {
        builder = builder.privacy(privacy);
    }

    let effective_offer_phash = offer_phash.clone().or(usync_phash.clone());
    if let Some(phash) = &effective_offer_phash {
        builder = builder.attr("phash", phash);
    }

    if let Some(phash) = &call_phash {
        builder = builder.call_attr("phash", phash);
    }

    if let Some(encrypted_key) = encrypted_key.clone() {
        builder = builder.encrypted_key(encrypted_key);
    }

    if offer_include_device_identity && let Some(identity) = device_identity {
        builder = builder.device_identity(identity);
    }

    let mut offer_stanza = builder.build();

    if offer_participants_wrapper || call_participants_wrapper {
        let keep_offer_enc = env_bool("WHATSAPP_CALL_OFFER_PARTICIPANTS_KEEP_ENC", true);
        if let Some(enc) = encrypted_key.clone() {
            let mut participant_to_nodes: Vec<Node> = Vec::new();
            for device_jid in peer_devices.clone() {
                let enc_for_device = if device_jid.device_eq(&session_target) {
                    Some(enc.clone())
                } else {
                    match client.encrypt_call_key_for(&device_jid).await {
                        Ok((_extra_key, extra_enc)) => Some(extra_enc),
                        Err(e) => {
                            warn!(
                                "Skipping participant {} due to key encryption error: {}",
                                device_jid, e
                            );
                            None
                        }
                    }
                };

                let Some(enc_for_device) = enc_for_device else {
                    continue;
                };

                let enc_node = NodeBuilder::new("enc")
                    .attr("type", enc_for_device.enc_type.to_string())
                    .attr("v", "2")
                    .bytes(enc_for_device.ciphertext)
                    .build();

                let to_node = NodeBuilder::new("to")
                    .attr("jid", device_jid.to_string())
                    .children(std::iter::once(enc_node))
                    .build();
                participant_to_nodes.push(to_node);
            }

            if participant_to_nodes.is_empty() {
                warn!(
                    "Participants wrapper enabled but no participant recipients built for {}",
                    call_id
                );
            }

            let participants = NodeBuilder::new("participants")
                .children(participant_to_nodes)
                .build();

            if let Some(NodeContent::Nodes(call_children)) = offer_stanza.content.as_mut() {
                if offer_participants_wrapper
                    && let Some(offer_node) = call_children.first_mut()
                    && let Some(NodeContent::Nodes(offer_children)) = offer_node.content.as_mut()
                {
                    if !keep_offer_enc {
                        offer_children.retain(|n| n.tag != "enc");
                    }
                    offer_children.push(participants.clone());
                }

                if call_participants_wrapper {
                    call_children.push(participants);
                }
            }
        } else {
            warn!(
                "Participants wrapper enabled but no encrypted key available for {}",
                call_id
            );
        }
    }

    info!(
        "Offer config for {}: to={} call_creator={} net={} dual_audio={} capability={} privacy={} offer_phash={} call_phash={} stanza_id_call_id={} notice={} device_identity={} offer_participants={} call_participants={}",
        call_id,
        call_info.peer_jid,
        call_info.call_creator,
        offer_net_medium,
        offer_dual_audio,
        offer_include_capability,
        offer_stanza
            .get_optional_child_by_tag(&["offer", "privacy"])
            .is_some(),
        effective_offer_phash.is_some(),
        call_phash.is_some(),
        offer_stanza_id_call_id,
        offer_send_notice,
        offer_include_device_identity,
        offer_participants_wrapper,
        call_participants_wrapper
    );

    if let Some(phash) = effective_offer_phash {
        debug!("Using offer phash {} for call {}", phash, call_id);
    }

    if let Some(token) = trusted_contact_token {
        debug!(
            "Using trusted_contact privacy token ({} bytes) for call {}",
            token.len(),
            call_id
        );
    }

    if !peer_devices.is_empty() {
        match MessageUtils::participant_list_hash(&peer_devices) {
            Ok(local_hash) => debug!(
                "Local computed participant hash for {}: {}",
                call_id, local_hash
            ),
            Err(e) => debug!(
                "Failed to compute local participant hash for {}: {}",
                call_id, e
            ),
        }
    }

    client
        .send_node(offer_stanza)
        .await
        .map_err(|e| format!("send offer stanza failed: {}", e))?;

    if let Err(e) = call_manager.mark_offer_sent(&call_id).await {
        warn!("Failed to mark offer as sent for {}: {}", call_id, e);
    }

    Ok(call_id)
}

async fn resolve_call_target_jid(client: &Client, target: &str) -> Result<Jid, String> {
    let prefer_lid = env_bool("WHATSAPP_CALL_PREFER_LID", false);

    if target.contains('@') {
        let mut jid: Jid = target
            .parse()
            .map_err(|e| format!("invalid target JID '{}': {}", target, e))?;
        // Normalize legacy phone server to current server naming.
        if jid.server == "c.us" {
            jid.server = "s.whatsapp.net".to_string();
        }
        return Ok(jid);
    }

    let Some(digits) = extract_phone_digits(target) else {
        return Err(format!("unable to parse phone digits from '{}'", target));
    };

    let mut probes: Vec<String> = Vec::new();
    probes.push(digits.clone());
    probes.push(format!("+{digits}"));
    if digits.len() > 10 {
        probes.push(digits[digits.len() - 10..].to_string());
    }
    probes.retain(|p| !p.is_empty());
    let mut seen = HashSet::new();
    probes.retain(|p| seen.insert(p.clone()));

    info!("Dial target probes for {}: {:?}", target, probes);

    let probe_refs: Vec<&str> = probes.iter().map(String::as_str).collect();
    match client.contacts().is_on_whatsapp(&probe_refs).await {
        Ok(results) => {
            if results.is_empty() {
                warn!(
                    "is_on_whatsapp returned 0 rows for target {} (probes={:?})",
                    target, probes
                );
            } else {
                for r in &results {
                    info!(
                        "is_on_whatsapp: jid={} registered={}",
                        r.jid, r.is_registered
                    );
                }

                if let Some(registered) = results.iter().find(|r| r.is_registered) {
                    return Ok(registered.jid.clone());
                }
            }
        }
        Err(e) => warn!("is_on_whatsapp failed for {}: {}", target, e),
    }

    match client.contacts().get_info(&probe_refs).await {
        Ok(infos) => {
            if infos.is_empty() {
                warn!(
                    "get_info returned 0 rows for target {} (probes={:?})",
                    target, probes
                );
            } else {
                for info in &infos {
                    info!(
                        "get_info: jid={} lid={:?} registered={} business={}",
                        info.jid, info.lid, info.is_registered, info.is_business
                    );
                }

                if let Some(registered) = infos.iter().find(|i| i.is_registered) {
                    if prefer_lid && let Some(lid) = &registered.lid {
                        return Ok(lid.clone());
                    }
                    return Ok(registered.jid.clone());
                }
            }
        }
        Err(e) => warn!("get_info failed for {}: {}", target, e),
    }

    match query_contact_candidates_raw(client, &probes).await {
        Ok(candidates) => {
            if candidates.is_empty() {
                warn!(
                    "raw usync probe returned 0 rows for target {} (probes={:?})",
                    target, probes
                );
            } else {
                for candidate in &candidates {
                    info!(
                        "raw usync candidate: jid={} lid={:?} registered={}",
                        candidate.jid, candidate.lid, candidate.is_registered
                    );
                }

                if let Some(registered) = candidates.iter().find(|c| c.is_registered) {
                    if prefer_lid && let Some(lid) = &registered.lid {
                        return Ok(lid.clone());
                    }
                    return Ok(registered.jid.clone());
                }
            }
        }
        Err(e) => warn!("raw usync probe failed for {}: {}", target, e),
    }

    let fallback = normalize_call_target_jid(target)?;
    fallback
        .parse()
        .map_err(|e| format!("invalid fallback target JID '{}': {}", fallback, e))
}

fn to_cus_jid(jid: &Jid) -> Option<Jid> {
    if jid.server == "c.us" {
        return Some(jid.clone());
    }

    if jid.server != "s.whatsapp.net" {
        return None;
    }

    let formatted = if jid.device > 0 {
        format!("{}:{}@c.us", jid.user, jid.device)
    } else {
        format!("{}@c.us", jid.user)
    };
    formatted.parse().ok()
}

async fn pick_signal_encryption_target(client: &Client, session_target: &Jid) -> Jid {
    if client.has_signal_session(session_target).await {
        return session_target.clone();
    }

    if let Some(c_us) = to_cus_jid(session_target)
        && client.has_signal_session(&c_us).await
    {
        return c_us;
    }

    session_target.clone()
}

#[derive(Debug)]
struct RawContactCandidate {
    jid: Jid,
    lid: Option<Jid>,
    is_registered: bool,
}

async fn query_contact_candidates_raw(
    client: &Client,
    probes: &[String],
) -> Result<Vec<RawContactCandidate>, String> {
    let sid = format!("probe-{}", rand::random::<u32>());
    let spec = ContactInfoSpec::new(probes.to_vec(), sid);
    let response = client
        .send_iq(spec.build_iq())
        .await
        .map_err(|e| format!("usync iq failed: {}", e))?;

    let Some(list_node) = response.get_optional_child_by_tag(&["usync", "list"]) else {
        return Ok(Vec::new());
    };

    let mut candidates = Vec::new();
    for user_node in list_node.get_children_by_tag("user") {
        let Some(jid) = user_node.attrs().optional_jid("jid") else {
            continue;
        };

        let is_registered = user_node
            .get_children_by_tag("contact")
            .any(|contact| contact.attrs().optional_string("type") == Some("in"));

        let lid = user_node
            .get_optional_child("lid")
            .and_then(|lid_node| lid_node.attrs().optional_jid("val"));

        candidates.push(RawContactCandidate {
            jid,
            lid,
            is_registered,
        });
    }

    Ok(candidates)
}

async fn start_call_automation(
    client: Arc<Client>,
    call_id: CallId,
    config: CallAutomationConfig,
    registry: CallAutomationRegistry,
) -> Result<(), String> {
    let call_id_str = call_id.to_string();
    if !registry.reserve(&call_id_str).await {
        debug!("Automation already active for call {}", call_id_str);
        return Ok(());
    }

    let call_manager = client.get_call_manager().await;
    let setup_result = async {
        let relay_data = wait_for_relay_data(&call_manager, &call_id, &config).await?;

        connect_relay_with_retry(&call_manager, &call_id, &relay_data, &config).await?;

        let hbh_key = relay_data
            .hbh_key
            .clone()
            .ok_or_else(|| format!("No hbh_key available for call {}", call_id))?;

        let (auth_token, relay_key) =
            extract_relay_credentials(&call_manager, &call_id, &relay_data).await?;

        start_media_automation_session(
            client,
            call_manager,
            call_id,
            hbh_key,
            auth_token,
            relay_key,
            config,
        )
        .await
    }
    .await;

    match setup_result {
        Ok(session) => {
            registry.replace(&call_id_str, Arc::new(session)).await;
            Ok(())
        }
        Err(err) => {
            registry.stop(&call_id_str).await;
            Err(err)
        }
    }
}

async fn wait_for_relay_data(
    call_manager: &Arc<CallManager>,
    call_id: &CallId,
    config: &CallAutomationConfig,
) -> Result<whatsapp_rust::calls::RelayData, String> {
    for _ in 0..config.connect_retries {
        if let Some(relay) = call_manager.get_relay_data(call_id).await {
            return Ok(relay);
        }
        tokio::time::sleep(config.connect_retry_delay).await;
    }

    Err(format!(
        "No relay data available after retries for call {}",
        call_id
    ))
}

async fn connect_relay_with_retry(
    call_manager: &Arc<CallManager>,
    call_id: &CallId,
    relay_data: &whatsapp_rust::calls::RelayData,
    config: &CallAutomationConfig,
) -> Result<(), String> {
    for attempt in 1..=config.connect_retries {
        match call_manager.connect_relay(call_id, relay_data).await {
            Ok(relay_name) => {
                info!(
                    "WebRTC relay connected for call {} via {} (attempt {}/{})",
                    call_id, relay_name, attempt, config.connect_retries
                );
                return Ok(());
            }
            Err(e) => {
                warn!(
                    "WebRTC connect attempt {}/{} failed for {}: {}",
                    attempt, config.connect_retries, call_id, e
                );
                tokio::time::sleep(config.connect_retry_delay).await;
            }
        }
    }

    Err(format!(
        "Failed to establish WebRTC relay for {} after {} attempts",
        call_id, config.connect_retries
    ))
}

async fn extract_relay_credentials(
    call_manager: &CallManager,
    call_id: &CallId,
    relay: &whatsapp_rust::calls::RelayData,
) -> Result<(Vec<u8>, Vec<u8>), String> {
    let engine = base64::engine::general_purpose::STANDARD;

    if let Some(transport) = call_manager.get_webrtc_transport(call_id).await
        && let Some(relay_info) = transport.connected_relay().await
    {
        // STUN USERNAME / MESSAGE-INTEGRITY must use the same text credentials
        // present in SDP ice-ufrag / ice-pwd.
        return Ok((
            relay_info.auth_token.as_bytes().to_vec(),
            relay_info.relay_key.as_bytes().to_vec(),
        ));
    }

    let auth = relay
        .auth_tokens
        .first()
        .cloned()
        .ok_or_else(|| "Missing relay auth token".to_string())
        .map(|raw| engine.encode(raw).into_bytes())?;
    let key = relay
        .relay_key
        .clone()
        .ok_or_else(|| "Missing relay key".to_string())
        .map(|raw| engine.encode(raw).into_bytes())?;
    Ok((auth, key))
}

async fn start_media_automation_session(
    client: Arc<Client>,
    call_manager: Arc<CallManager>,
    call_id: CallId,
    hbh_key: Vec<u8>,
    auth_token: Vec<u8>,
    relay_key: Vec<u8>,
    config: CallAutomationConfig,
) -> Result<CallAutomationSession, String> {
    let call_id_string = call_id.to_string();
    let stop = Arc::new(AtomicBool::new(false));

    if hbh_key.len() != 30 {
        return Err(format!(
            "hbh_key must be 30 bytes for {}, got {}",
            call_id_string,
            hbh_key.len()
        ));
    }

    let ssrc = rand::random::<u32>();

    // Post-connect subscription registration strategies:
    // 1. STUN Allocate via DC (legacy, usually disabled)
    // 2. STUN Bind with subs on shared socket (slow, often fails after ICE)
    // 3. Raw protobuf subscription via DataChannel (experimental)
    //
    // Note: The PRIMARY subscription registration now happens in the
    // pre-ICE bind phase (in webrtc.rs, before UDPMux takes over).
    // These post-connect strategies are secondary fallbacks.

    if env_bool("WHATSAPP_CALL_STUN_ALLOCATE", false) {
        perform_stun_allocate(&call_manager, &call_id, &auth_token, &relay_key, ssrc).await?;
    } else {
        debug!(
            "Skipping explicit STUN Allocate for {} (WHATSAPP_CALL_STUN_ALLOCATE=false)",
            call_id_string
        );
    }

    // Post-connect STUN Bind with subs (disabled by default - pre-ICE bind handles this)
    if env_bool("WHATSAPP_CALL_STUN_BIND_SUBS", false) {
        perform_stun_bind_with_subscriptions(
            &call_manager,
            &call_id,
            &auth_token,
            &relay_key,
            ssrc,
        )
        .await?;
    }

    // Experimental: Send raw protobuf subscription via DataChannel
    // This sends the subscription protobuf directly as a DC message
    if env_bool("WHATSAPP_CALL_DC_PROTO_SUBS", true) {
        let relay_options = call_manager.get_relay_data(&call_id).await;
        let call_info = call_manager.get_call(&call_id).await;
        let sender_jid = call_info.as_ref().map(|c| c.call_creator.to_string());
        let self_pid = relay_options.as_ref().and_then(|r| r.self_pid);

        let combined_subs = create_combined_sender_subscriptions(ssrc, self_pid, sender_jid.clone());
        let receiver_subs = create_combined_receiver_subscription();

        info!(
            "Sending protobuf subscriptions via DataChannel for {} (sender={} bytes, receiver={} bytes, ssrc=0x{:08x})",
            call_id_string, combined_subs.len(), receiver_subs.len(), ssrc
        );

        // Send sender subscriptions
        if let Err(e) = call_manager.send_via_webrtc(&call_id, &combined_subs).await {
            warn!("DC sender subscription send failed for {}: {}", call_id_string, e);
        } else {
            info!("Sent sender subscription via DC for {} ({} bytes)", call_id_string, combined_subs.len());
        }

        // Send receiver subscriptions
        if let Err(e) = call_manager.send_via_webrtc(&call_id, &receiver_subs).await {
            warn!("DC receiver subscription send failed for {}: {}", call_id_string, e);
        } else {
            info!("Sent receiver subscription via DC for {} ({} bytes)", call_id_string, receiver_subs.len());
        }

        // Brief wait for relay to process
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let mut master_key = [0u8; 16];
    let mut master_salt = [0u8; 14];
    master_key.copy_from_slice(&hbh_key[..16]);
    master_salt.copy_from_slice(&hbh_key[16..30]);

    let keying = SrtpKeyingMaterial {
        master_key,
        master_salt,
    };

    let srtp_session = Arc::new(tokio::sync::Mutex::new(SrtpSession::new(&keying, &keying)));
    let rtp_payload_type = env_u64("WHATSAPP_CALL_RTP_PAYLOAD_TYPE", 120) as u8;
    let frame_ms = env_u64("WHATSAPP_CALL_FRAME_MS", 60) as u32;
    let samples_per_packet = ((16_000u32 * frame_ms) / 1000).max(160);
    info!(
        "Using RTP payload type {} for call {} (frame_ms={}, samples_per_packet={})",
        rtp_payload_type, call_id_string, frame_ms, samples_per_packet
    );
    let rtp_session = Arc::new(tokio::sync::Mutex::new(RtpSession::new(
        ssrc,
        rtp_payload_type,
        16_000,
        samples_per_packet,
    )));

    let (outgoing_tx, mut outgoing_rx) = mpsc::unbounded_channel::<Vec<u8>>();

    // Try BOTH raw UDP and DataChannel for media delivery
    let use_raw_media = env_bool("WHATSAPP_CALL_RAW_MEDIA", true);
    let send_stop = stop.clone();
    let send_call_id = call_id.clone();
    let send_call_manager = call_manager.clone();
    let send_rtp = rtp_session.clone();
    let send_srtp = srtp_session.clone();
    tokio::spawn(async move {
        let mut sent_packets = 0u64;
        while !send_stop.load(Ordering::Relaxed) {
            if !send_call_manager.has_webrtc_transport(&send_call_id).await {
                info!(
                    "Stopping send loop for {}: WebRTC transport no longer available",
                    send_call_id
                );
                send_stop.store(true, Ordering::Relaxed);
                break;
            }

            let frame =
                match tokio::time::timeout(Duration::from_millis(100), outgoing_rx.recv()).await {
                    Ok(Some(frame)) => frame,
                    Ok(None) => break,
                    Err(_) => continue,
                };

            let rtp_packet = {
                let mut rtp = send_rtp.lock().await;
                rtp.create_packet(frame, sent_packets == 0)
            };

            let encrypted = {
                let mut srtp = send_srtp.lock().await;
                match srtp.protect(&rtp_packet) {
                    Ok(packet) => packet,
                    Err(e) => {
                        warn!("SRTP protect failed for {}: {}", send_call_id, e);
                        continue;
                    }
                }
            };

            let use_dc_media = env_bool("WHATSAPP_CALL_DC_MEDIA", true);

            // Send via raw UDP to relay (bypassing DTLS/SCTP)
            if use_raw_media {
                match send_call_manager
                    .send_raw_via_webrtc(&send_call_id, &encrypted)
                    .await
                {
                    Ok(_) => {
                        if sent_packets < 3 || sent_packets % 100 == 0 {
                            info!(
                                "RAW UDP media #{} for {} ({} bytes SRTP)",
                                sent_packets, send_call_id, encrypted.len()
                            );
                        }
                    }
                    Err(e) => {
                        if sent_packets == 0 {
                            warn!("Raw UDP media send failed for {}: {}", send_call_id, e);
                        }
                    }
                }
            }

            // Send via DataChannel (DTLS/SCTP path)
            if use_dc_media {
                if let Err(e) = send_call_manager
                    .send_via_webrtc(&send_call_id, &encrypted)
                    .await
                {
                    let error_str = e.to_string().to_lowercase();
                    if error_str.contains("no webrtc transport") {
                        info!(
                            "Stopping send loop for {}: transport removed ({})",
                            send_call_id, e
                        );
                        send_stop.store(true, Ordering::Relaxed);
                        break;
                    }
                    if sent_packets == 0 {
                        warn!("DC media send failed for {}: {}", send_call_id, e);
                    }
                    if !use_raw_media {
                        continue;
                    }
                }
            }

            // If neither path is enabled, at least send via DC
            if !use_raw_media && !use_dc_media {
                let _ = send_call_manager.send_via_webrtc(&send_call_id, &encrypted).await;
            }

            sent_packets += 1;
            if sent_packets == 1 {
                info!(
                    "First media packet sent for {} (raw={}, dc={}, {} bytes SRTP, rtp_pt={})",
                    send_call_id, use_raw_media, use_dc_media, encrypted.len(), rtp_payload_type
                );
            }
            if sent_packets % 100 == 0 {
                info!("Sent {} media packets for {} (raw={}, dc={})", sent_packets, send_call_id, use_raw_media, use_dc_media);
            }
        }

        info!("Send loop stopped for call {} ({} packets sent)", send_call_id, sent_packets);
    });

    if config.sample_audio_on_connect {
        let sample_stop = stop.clone();
        let sample_call_id = call_id.clone();
        let sample_tx = outgoing_tx.clone();
        let sample_duration = config.sample_audio_duration_ms;
        let sample_freq = config.sample_audio_frequency_hz;
        let sample_frame_ms = frame_ms;
        tokio::spawn(async move {
            // Start sample audio quickly after media setup.
            tokio::time::sleep(Duration::from_millis(100)).await;
            if sample_stop.load(Ordering::Relaxed) {
                return;
            }

            match generate_sample_opus_frames(sample_duration, sample_freq, sample_frame_ms) {
                Ok(frames) => {
                    info!(
                        "Injecting sample audio into call {} ({} frames, {}ms @ {}Hz, frame={}ms)",
                        sample_call_id,
                        frames.len(),
                        sample_duration,
                        sample_freq,
                        sample_frame_ms
                    );

                    for frame in frames {
                        if sample_stop.load(Ordering::Relaxed) {
                            break;
                        }
                        if sample_tx.send(frame).is_err() {
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(sample_frame_ms as u64)).await;
                    }
                }
                Err(e) => warn!(
                    "Failed generating sample audio for {}: {}",
                    sample_call_id, e
                ),
            }
        });
    }

    let recv_stop = stop.clone();
    let recv_call_id = call_id.clone();
    let recv_call_manager = call_manager.clone();
    let recv_srtp = srtp_session.clone();
    let recv_outgoing_tx = outgoing_tx.clone();
    let recv_config = config.clone();
    let recv_http = UreqHttpClient::new();
    let recv_client = client.clone();
    tokio::spawn(async move {
        let mut batch: Vec<Vec<u8>> = Vec::new();
        let mut batch_seq = 0u64;
        let mut last_flush = Instant::now();
        let mut raw_packets = 0u64;
        let mut stun_packets = 0u64;
        let mut stun_pings = 0u64;
        let mut stun_pongs = 0u64;
        let mut stun_signature_logs = 0usize;
        let mut received_packets = 0u64;
        let mut packet_signature_logs = 0usize;

        while !recv_stop.load(Ordering::Relaxed) {
            if !recv_call_manager.has_webrtc_transport(&recv_call_id).await {
                info!(
                    "Stopping receive loop for {}: WebRTC transport no longer available",
                    recv_call_id
                );
                recv_stop.store(true, Ordering::Relaxed);
                break;
            }

            // Check BOTH DataChannel and interceptor for incoming audio
            let data = {
                // First try interceptor (raw UDP RTP/SRTP from relay)
                let intercepted = recv_call_manager
                    .recv_intercepted_from_webrtc(&recv_call_id, Duration::from_millis(10))
                    .await;
                match intercepted {
                    Ok(idata) => {
                        let first_byte: u8 = idata.first().copied().unwrap_or(0);
                        if first_byte >= 128 {
                            // This is RTP/SRTP from the relay - process it directly
                            if packet_signature_logs < recv_config.packet_signature_debug_count {
                                info!(
                                    "INTERCEPTED RTP #{} for {}: len={}, first8={:02x?}",
                                    packet_signature_logs + 1,
                                    recv_call_id,
                                    idata.len(),
                                    &idata[..idata.len().min(8)]
                                );
                            }
                            idata
                        } else {
                            // STUN or other control - log but don't process as audio
                            if packet_signature_logs < 20 {
                                info!(
                                    "INTERCEPTED non-RTP for {}: len={}, first_byte=0x{:02x}",
                                    recv_call_id, idata.len(), first_byte
                                );
                            }
                            // Fall through to DataChannel check
                            match recv_call_manager
                                .recv_from_webrtc_timeout(&recv_call_id, Duration::from_millis(50))
                                .await
                            {
                                Ok(data) => data,
                                Err(_) => continue,
                            }
                        }
                    }
                    Err(_) => {
                        // No intercepted data, check DataChannel
                        match recv_call_manager
                            .recv_from_webrtc_timeout(&recv_call_id, recv_config.recv_timeout)
                            .await
                        {
                            Ok(data) => data,
                            Err(e) => {
                                let error_str = e.to_string().to_lowercase();
                                if error_str.contains("no webrtc transport") {
                                    info!(
                                        "Stopping receive loop for {}: transport removed ({})",
                                        recv_call_id, e
                                    );
                                    recv_stop.store(true, Ordering::Relaxed);
                                    break;
                                }
                                if !error_str.contains("timeout") {
                                    debug!("Receive error for {}: {}", recv_call_id, e);
                                }

                                if !batch.is_empty() && last_flush.elapsed() >= recv_config.flush_interval {
                                    if let Err(err) = process_audio_batch(
                                        &recv_http,
                                        recv_client.clone(),
                                        &recv_config,
                                        &recv_call_id,
                                        &mut batch_seq,
                                        &mut batch,
                                        &recv_outgoing_tx,
                                    )
                                    .await
                                    {
                                        warn!(
                                            "Audio batch processing failed for {}: {}",
                                            recv_call_id, err
                                        );
                                    }
                                    last_flush = Instant::now();
                                }
                                continue;
                            }
                        }
                    }
                }
            };

            raw_packets += 1;
            if raw_packets.is_multiple_of(200) {
                debug!(
                    "Received {} raw DataChannel packets for {}",
                    raw_packets, recv_call_id
                );
            }

            if looks_like_stun(&data) {
                stun_packets += 1;
                if let Ok(stun) = StunMessage::decode(&data) {
                    if stun_signature_logs < 40 {
                        debug!(
                            "STUN/control packet #{} for {}: type={:?}, len={}, txid={:02x?}",
                            stun_signature_logs + 1,
                            recv_call_id,
                            stun.msg_type,
                            data.len(),
                            stun.transaction_id
                        );
                        stun_signature_logs += 1;
                    }
                    if stun.is_ping() {
                        stun_pings += 1;
                        let pong = StunMessage::whatsapp_pong(stun.transaction_id).encode();
                        if let Err(e) = recv_call_manager
                            .send_via_webrtc(&recv_call_id, &pong)
                            .await
                        {
                            debug!("Failed to send STUN pong for {}: {}", recv_call_id, e);
                        }
                    } else if stun.is_pong() {
                        stun_pongs += 1;
                    }
                }
                if stun_packets.is_multiple_of(100) {
                    debug!(
                        "Received {} STUN/control packets for {} (pings={}, pongs={})",
                        stun_packets, recv_call_id, stun_pings, stun_pongs
                    );
                }
                continue;
            }

            if packet_signature_logs < recv_config.packet_signature_debug_count {
                info!(
                    "Non-STUN DC msg #{} for {}: len={}, first32={:02x?}",
                    packet_signature_logs + 1,
                    recv_call_id,
                    data.len(),
                    &data[..data.len().min(32)]
                );
                packet_signature_logs += 1;
            }

            let packet = {
                let mut srtp = recv_srtp.lock().await;
                let offsets: &[usize] = if recv_config.srtp_offset_scan {
                    &[0, 1, 2, 4, 8]
                } else {
                    &[0]
                };

                let mut decoded = None;
                let mut last_error: Option<(usize, String)> = None;

                for &offset in offsets {
                    if data.len() <= offset + 12 + SRTP_AUTH_TAG_LEN {
                        continue;
                    }

                    match srtp.unprotect(&data[offset..]) {
                        Ok(packet) => {
                            if offset > 0 {
                                debug!(
                                    "SRTP unprotect succeeded for {} with offset {} (len={})",
                                    recv_call_id,
                                    offset,
                                    data.len()
                                );
                            }
                            decoded = Some(packet);
                            break;
                        }
                        Err(e) => {
                            last_error = Some((offset, e.to_string()));
                        }
                    }
                }

                match decoded {
                    Some(packet) => packet,
                    None => {
                        if let Some((offset, err)) = last_error {
                            debug!(
                                "SRTP unprotect failed for {} (last offset {}, len={}): {}",
                                recv_call_id,
                                offset,
                                data.len(),
                                err
                            );
                        }
                        continue;
                    }
                }
            };

            if packet.payload.is_empty() {
                continue;
            }

            received_packets += 1;
            batch.push(packet.payload);

            if batch.len() >= recv_config.batch_frames
                || (!batch.is_empty() && last_flush.elapsed() >= recv_config.flush_interval)
            {
                if let Err(err) = process_audio_batch(
                    &recv_http,
                    recv_client.clone(),
                    &recv_config,
                    &recv_call_id,
                    &mut batch_seq,
                    &mut batch,
                    &recv_outgoing_tx,
                )
                .await
                {
                    warn!(
                        "Audio batch processing failed for {}: {}",
                        recv_call_id, err
                    );
                }
                last_flush = Instant::now();
            }

            if received_packets.is_multiple_of(200) {
                debug!(
                    "Received {} media packets for {}",
                    received_packets, recv_call_id
                );
            }
        }

        if !batch.is_empty()
            && let Err(err) = process_audio_batch(
                &recv_http,
                recv_client,
                &recv_config,
                &recv_call_id,
                &mut batch_seq,
                &mut batch,
                &recv_outgoing_tx,
            )
            .await
        {
            warn!(
                "Final audio batch processing failed for {}: {}",
                recv_call_id, err
            );
        }

        info!("Receive loop stopped for call {}", recv_call_id);
    });

    let ping_stop = stop.clone();
    let ping_call_id = call_id.clone();
    let ping_call_manager = call_manager.clone();
    let ping_interval = config.ping_interval;
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(ping_interval);
        let mut sent = 0u64;

        while !ping_stop.load(Ordering::Relaxed) {
            interval.tick().await;
            if ping_stop.load(Ordering::Relaxed) {
                break;
            }

            if !ping_call_manager.has_webrtc_transport(&ping_call_id).await {
                info!(
                    "Stopping ping loop for {}: WebRTC transport no longer available",
                    ping_call_id
                );
                ping_stop.store(true, Ordering::Relaxed);
                break;
            }

            let ping_msg = StunMessage::whatsapp_ping(generate_transaction_id());
            let ping_data = ping_msg.encode();
            match ping_call_manager
                .send_via_webrtc(&ping_call_id, &ping_data)
                .await
            {
                Ok(()) => {
                    sent += 1;
                    if sent.is_multiple_of(10) {
                        debug!("Sent {} keepalive pings for {}", sent, ping_call_id);
                    }
                }
                Err(e) => {
                    let error_str = e.to_string().to_lowercase();
                    if error_str.contains("no webrtc transport") {
                        info!(
                            "Stopping ping loop for {}: transport removed ({})",
                            ping_call_id, e
                        );
                        ping_stop.store(true, Ordering::Relaxed);
                        break;
                    }
                }
            }
        }

        info!("Ping loop stopped for call {}", ping_call_id);
    });

    info!("Started media automation session for {}", call_id_string);
    Ok(CallAutomationSession { stop })
}

async fn process_audio_batch(
    http_client: &UreqHttpClient,
    client: Arc<Client>,
    config: &CallAutomationConfig,
    call_id: &CallId,
    sequence: &mut u64,
    batch: &mut Vec<Vec<u8>>,
    outgoing_tx: &mpsc::UnboundedSender<Vec<u8>>,
) -> Result<(), String> {
    if batch.is_empty() {
        return Ok(());
    }

    let frames = std::mem::take(batch);

    if config.api_endpoint.is_none() {
        if config.echo_when_no_api {
            for frame in frames {
                let _ = outgoing_tx.send(frame);
            }
        }
        return Ok(());
    }

    let response = call_voice_bot_api(http_client, config, call_id, *sequence, &frames).await?;
    *sequence += 1;

    if let Some(transcript) = response.transcript.as_deref() {
        info!("🗣️  {} transcript: {}", call_id, transcript);
    }

    if let Some(reply_text) = response.reply_text.as_deref() {
        info!("🤖 {} reply: {}", call_id, reply_text);

        if let Some(call_info) = client.get_call_manager().await.get_call_info(call_id).await {
            let msg = wa::Message {
                conversation: Some(reply_text.to_string()),
                ..Default::default()
            };
            if let Err(e) = client.send_message(call_info.peer_jid, msg).await {
                warn!("Failed to send text fallback reply for {}: {}", call_id, e);
            }
        }
    }

    if let Some(reply_frames) = response.reply_opus_frames_b64 {
        for frame_b64 in reply_frames {
            let frame = base64::engine::general_purpose::STANDARD
                .decode(frame_b64)
                .map_err(|e| format!("reply_opus_frames_b64 decode failed: {}", e))?;
            let _ = outgoing_tx.send(frame);
        }
    } else if let Some(single_reply) = response.reply_opus_b64 {
        let frame = base64::engine::general_purpose::STANDARD
            .decode(single_reply)
            .map_err(|e| format!("reply_opus_b64 decode failed: {}", e))?;
        let _ = outgoing_tx.send(frame);
    }

    Ok(())
}

async fn call_voice_bot_api(
    http_client: &UreqHttpClient,
    config: &CallAutomationConfig,
    call_id: &CallId,
    sequence: u64,
    frames: &[Vec<u8>],
) -> Result<VoiceBotApiResponse, String> {
    let endpoint = config
        .api_endpoint
        .as_ref()
        .ok_or_else(|| "WHATSAPP_VOICE_BOT_API not configured".to_string())?;

    let body = VoiceBotApiRequest {
        call_id: call_id.to_string(),
        sequence,
        codec: "opus",
        sample_rate: 16000,
        opus_frames_b64: frames
            .iter()
            .map(|f| base64::engine::general_purpose::STANDARD.encode(f))
            .collect(),
    };

    let payload = serde_json::to_vec(&body)
        .map_err(|e| format!("Failed to serialize voice bot request: {}", e))?;

    let mut req = HttpRequest::post(endpoint.clone())
        .with_header("content-type", "application/json")
        .with_body(payload);

    if let Some(api_key) = &config.api_key {
        req = req.with_header("authorization", format!("Bearer {}", api_key));
    }

    let response = http_client
        .execute(req)
        .await
        .map_err(|e| format!("Voice bot API call failed: {}", e))?;

    if !(200..300).contains(&response.status_code) {
        return Err(format!(
            "Voice bot API returned status {}: {}",
            response.status_code,
            String::from_utf8_lossy(&response.body)
        ));
    }

    serde_json::from_slice::<VoiceBotApiResponse>(&response.body)
        .map_err(|e| format!("Failed to parse voice bot API response: {}", e))
}

async fn perform_stun_allocate(
    call_manager: &Arc<CallManager>,
    call_id: &CallId,
    auth_token: &[u8],
    relay_key: &[u8],
    ssrc: u32,
) -> Result<(), String> {
    let relay_options = call_manager.get_relay_data(call_id).await;
    let call_info = call_manager.get_call(call_id).await;
    let sender_jid = call_info.as_ref().map(|c| c.call_creator.to_string());
    let self_pid = relay_options.as_ref().and_then(|r| r.self_pid);

    // Build combined sender + receiver subscriptions
    let combined_subs = create_combined_sender_subscriptions(ssrc, self_pid, sender_jid.clone());
    let receiver_subs = create_combined_receiver_subscription();

    info!(
        "DC TURN Allocate for {}: ssrc=0x{:08x}, sender_subs={} bytes, receiver_subs={} bytes",
        call_id, ssrc, combined_subs.len(), receiver_subs.len()
    );

    // Helper: send a STUN message via DC and wait for a matching response
    let dc_send_and_recv = |call_mgr: Arc<CallManager>,
                            cid: CallId,
                            msg_data: Vec<u8>,
                            label: String,
                            timeout_ms: u64| {
        async move {
            if let Err(e) = call_mgr.send_via_webrtc(&cid, &msg_data).await {
                warn!("{} send failed: {}", label, e);
                return None;
            }

            let start = Instant::now();
            while start.elapsed() < Duration::from_millis(timeout_ms) {
                match call_mgr
                    .recv_from_webrtc_timeout(&cid, Duration::from_millis(200))
                    .await
                {
                    Ok(data) => {
                        if let Ok(stun) = StunMessage::decode(&data) {
                            if stun.is_ping() {
                                let pong =
                                    StunMessage::whatsapp_pong(stun.transaction_id).encode();
                                let _ = call_mgr.send_via_webrtc(&cid, &pong).await;
                                continue;
                            }
                            if matches!(stun.msg_type, StunMessageType::WhatsAppPong) {
                                continue;
                            }
                            info!(
                                "{} response: type=0x{:04x}, txn={:02x?}, attrs={}",
                                label,
                                stun.msg_type as u16,
                                &stun.transaction_id[..4],
                                stun.attributes.len()
                            );
                            for attr in &stun.attributes {
                                info!("{} attr: {:?}", label, attr);
                            }
                            return Some(stun);
                        } else {
                            info!(
                                "{} non-STUN: {} bytes, first_byte=0x{:02x}",
                                label,
                                data.len(),
                                data.first().copied().unwrap_or(0)
                            );
                        }
                    }
                    Err(_) => {}
                }
            }
            info!("{}: no response after {}ms", label, timeout_ms);
            None
        }
    };

    // Strategy 1: BARE Allocate (no auth, no subs, no fingerprint, no priority)
    // This tests if the relay can parse a minimal TURN Allocate at all.
    {
        let txn = generate_transaction_id();
        let msg = StunMessage::allocate_request(txn)
            .with_fingerprint(false)
            .with_priority(None);
        let msg_data = msg.encode();
        info!(
            "Strategy 1 (bare allocate, no fingerprint/priority): {} bytes, txn={:02x?}",
            msg_data.len(),
            &txn[..4]
        );

        if let Some(stun) = dc_send_and_recv(
            call_manager.clone(),
            call_id.clone(),
            msg_data,
            "S1-bare".to_string(),
            2000,
        )
        .await
        {
            if matches!(stun.msg_type, StunMessageType::AllocateResponse) {
                info!("Strategy 1 SUCCESS: bare Allocate accepted!");
                // Now send subscriptions as Strategy 2
            } else if stun.is_error() {
                let (code, reason) = stun.error_code().unwrap_or((0, "unknown"));
                info!("Strategy 1 error: code={}, reason='{}'", code, reason);

                // If 401, try with auth
                if matches!(code, 401 | 438) {
                    if let (Some(realm), Some(nonce)) = (stun.realm(), stun.nonce()) {
                        info!(
                            "Strategy 1 got 401 challenge! realm='{}', nonce={} bytes - trying with auth",
                            realm,
                            nonce.len()
                        );
                        let txn2 = generate_transaction_id();
                        let retry = StunMessage::allocate_request(txn2)
                            .with_fingerprint(false)
                            .with_priority(None)
                            .with_username(auth_token)
                            .with_integrity_key(relay_key)
                            .with_realm(realm)
                            .with_nonce(nonce.to_vec());
                        let retry_data = retry.encode();
                        info!(
                            "Strategy 1b (auth + realm/nonce, no fingerprint/priority): {} bytes",
                            retry_data.len()
                        );
                        if let Some(stun2) = dc_send_and_recv(
                            call_manager.clone(),
                            call_id.clone(),
                            retry_data,
                            "S1b-auth".to_string(),
                            2000,
                        )
                        .await
                        {
                            if matches!(stun2.msg_type, StunMessageType::AllocateResponse) {
                                info!("Strategy 1b SUCCESS: Allocate with auth accepted!");
                            }
                        }
                    }
                }
            }
        }
    }

    // Strategy 2: Allocate with subscriptions (no fingerprint, no priority, no auth)
    // The previous error 456 was likely caused by FINGERPRINT + ICE PRIORITY confusing
    // the relay's DC-side STUN parser.
    {
        let txn = generate_transaction_id();
        let msg = StunMessage::allocate_request(txn)
            .with_fingerprint(false)
            .with_priority(None)
            .with_sender_subscriptions(combined_subs.clone())
            .with_receiver_subscription(receiver_subs.clone());
        let msg_data = msg.encode();
        info!(
            "Strategy 2 (allocate + subs, no fingerprint/priority): {} bytes, txn={:02x?}",
            msg_data.len(),
            &txn[..4]
        );

        if let Some(stun) = dc_send_and_recv(
            call_manager.clone(),
            call_id.clone(),
            msg_data,
            "S2-subs".to_string(),
            2000,
        )
        .await
        {
            if matches!(stun.msg_type, StunMessageType::AllocateResponse) {
                info!("Strategy 2 SUCCESS: Allocate with subs accepted!");
                return Ok(());
            } else if stun.is_error() {
                let (code, reason) = stun.error_code().unwrap_or((0, "unknown"));
                info!("Strategy 2 error: code={}, reason='{}'", code, reason);
            }
        }
    }

    // Strategy 3: Allocate with auth + subs (no fingerprint, no priority)
    {
        let txn = generate_transaction_id();
        let msg = StunMessage::allocate_request(txn)
            .with_fingerprint(false)
            .with_priority(None)
            .with_username(auth_token)
            .with_integrity_key(relay_key)
            .with_sender_subscriptions(combined_subs.clone())
            .with_receiver_subscription(receiver_subs.clone());
        let msg_data = msg.encode();
        info!(
            "Strategy 3 (allocate + auth + subs, no fingerprint/priority): {} bytes, txn={:02x?}",
            msg_data.len(),
            &txn[..4]
        );

        if let Some(stun) = dc_send_and_recv(
            call_manager.clone(),
            call_id.clone(),
            msg_data,
            "S3-authsubs".to_string(),
            2000,
        )
        .await
        {
            if matches!(stun.msg_type, StunMessageType::AllocateResponse) {
                info!("Strategy 3 SUCCESS: Allocate with auth+subs accepted!");
                return Ok(());
            } else if stun.is_error() {
                let (code, reason) = stun.error_code().unwrap_or((0, "unknown"));
                info!("Strategy 3 error: code={}, reason='{}'", code, reason);

                if matches!(code, 401 | 438) {
                    if let (Some(realm), Some(nonce)) = (stun.realm(), stun.nonce()) {
                        let txn2 = generate_transaction_id();
                        let retry = StunMessage::allocate_request(txn2)
                            .with_fingerprint(false)
                            .with_priority(None)
                            .with_username(auth_token)
                            .with_integrity_key(relay_key)
                            .with_realm(realm)
                            .with_nonce(nonce.to_vec())
                            .with_sender_subscriptions(combined_subs.clone())
                            .with_receiver_subscription(receiver_subs.clone());
                        if let Some(stun2) = dc_send_and_recv(
                            call_manager.clone(),
                            call_id.clone(),
                            retry.encode(),
                            "S3b-authsubs-challenge".to_string(),
                            2000,
                        )
                        .await
                        {
                            if matches!(stun2.msg_type, StunMessageType::AllocateResponse) {
                                info!("Strategy 3b SUCCESS!");
                                return Ok(());
                            }
                        }
                    }
                }
            }
        }
    }

    warn!(
        "DC TURN Allocate: all strategies failed for {}. Continuing anyway.",
        call_id
    );
    Ok(())
}

async fn perform_stun_bind_with_subscriptions(
    call_manager: &Arc<CallManager>,
    call_id: &CallId,
    auth_token: &[u8],
    relay_key: &[u8],
    ssrc: u32,
) -> Result<(), String> {
    let relay_options = call_manager.get_relay_data(call_id).await;
    let disable_ssrc_subscription = relay_options
        .as_ref()
        .and_then(|r| r.disable_ssrc_subscription)
        .unwrap_or(false);
    let app_data_stream_version = relay_options
        .as_ref()
        .and_then(|r| r.app_data_stream_version);

    if let Some(version) = app_data_stream_version {
        info!(
            "Call {} relay voip_settings: app_data_stream_version={}",
            call_id, version
        );
    }

    let call_info = call_manager.get_call(call_id).await;
    let sender_jid = call_info.as_ref().map(|c| c.call_creator.to_string());
    let self_pid = relay_options.as_ref().and_then(|r| r.self_pid);

    // Build audio sender subscription
    let audio_subs = if let Some(ref jid) = sender_jid {
        create_audio_sender_subscriptions_with_jid(ssrc, jid.clone())
    } else {
        create_audio_sender_subscriptions(ssrc)
    };

    // Build app-data sender subscription
    let app_data_subs = create_app_data_sender_subscriptions(self_pid, sender_jid.clone());

    // Build combined sender subscription (audio + app_data in one)
    let combined_subs = create_combined_sender_subscriptions(
        ssrc, self_pid, sender_jid.clone(),
    );

    // Build receiver subscription (tells relay what we want to RECEIVE)
    let receiver_subs = create_combined_receiver_subscription();

    info!(
        "STUN Bind setup for {}: ssrc={}, self_pid={:?}, sender_jid={:?}, combined_subs={} bytes, receiver_subs={} bytes",
        call_id, ssrc, self_pid, sender_jid, combined_subs.len(), receiver_subs.len()
    );

    // Build STUN bind with BOTH sender and receiver subscriptions
    let txn_id = generate_transaction_id();
    let mut bind = StunMessage::binding_request(txn_id)
        .with_username(auth_token)
        .with_integrity_key(relay_key)
        .with_priority(None)
        .with_sender_subscriptions(combined_subs.clone())
        .with_receiver_subscription(receiver_subs.clone());

    let bind_data = bind.encode();
    info!(
        "STUN Bind for {} ({} bytes) txn_id={:02x?} first20={:02x?}",
        call_id,
        bind_data.len(),
        &txn_id[..],
        &bind_data[..bind_data.len().min(20)]
    );

    // Track all transaction IDs we've sent so we can match responses
    let mut sent_txn_ids: Vec<[u8; 12]> = vec![txn_id];

    // STRATEGY: Send STUN bind on the SHARED UDP socket (same as ICE/DTLS)
    let mut shared_socket_sent = false;
    match call_manager.send_raw_via_webrtc(call_id, &bind_data).await {
        Ok(n) => {
            info!("Sent STUN Bind on SHARED socket for {} ({} bytes) - same port as ICE/DTLS", call_id, n);
            shared_socket_sent = true;
        }
        Err(e) => {
            warn!("Shared socket STUN Bind failed for {}: {}", call_id, e);
        }
    }

    // Also send via DataChannel as fallback
    if let Err(e) = call_manager.send_via_webrtc(call_id, &bind_data).await {
        debug!("DataChannel STUN Bind send failed for {}: {}", call_id, e);
    } else {
        info!("Also sent STUN Bind via DataChannel for {} ({} bytes)", call_id, bind_data.len());
    }

    // Wait for response on BOTH interceptor and DataChannel
    let bind_total_ms = env_u64("WHATSAPP_CALL_STUN_BIND_TOTAL_MS", 5000);
    let bind_retry_ms = env_u64("WHATSAPP_CALL_STUN_BIND_RETRY_MS", 800).max(200);
    let mut bind_attempts = 1u32;
    let mut last_bind_send = Instant::now();
    let mut dc_msg_count = 0usize;
    let mut intercepted_count = 0usize;
    let mut matched_bind = false;
    let start = Instant::now();

    while start.elapsed() < Duration::from_millis(bind_total_ms) {
        // Retry periodically
        if last_bind_send.elapsed() >= Duration::from_millis(bind_retry_ms) {
            let retry_txn = generate_transaction_id();
            sent_txn_ids.push(retry_txn);
            let retry_bind = StunMessage::binding_request(retry_txn)
                .with_username(auth_token)
                .with_integrity_key(relay_key)
                .with_priority(None)
                .with_sender_subscriptions(combined_subs.clone())
                .with_receiver_subscription(receiver_subs.clone());
            let retry_data = retry_bind.encode();

            if shared_socket_sent {
                let _ = call_manager.send_raw_via_webrtc(call_id, &retry_data).await;
            }
            let _ = call_manager.send_via_webrtc(call_id, &retry_data).await;
            bind_attempts += 1;
            last_bind_send = Instant::now();
        }

        // Check interceptor (raw UDP responses)
        match call_manager.recv_intercepted_from_webrtc(call_id, Duration::from_millis(50)).await {
            Ok(data) => {
                intercepted_count += 1;
                let first_byte: u8 = data.first().copied().unwrap_or(0);
                info!(
                    "INTERCEPTED UDP #{} for {} bind: len={}, first_byte=0x{:02x}, first20={:02x?}",
                    intercepted_count, call_id, data.len(), first_byte,
                    &data[..data.len().min(20)]
                );

                if first_byte <= 3 {
                    if let Ok(stun) = StunMessage::decode(&data) {
                        let txn_matches = sent_txn_ids.iter().any(|t| *t == stun.transaction_id);
                        if matches!(stun.msg_type, StunMessageType::BindingResponse) {
                            if txn_matches {
                                info!("STUN Bind SUCCESS for {} via SHARED socket (txn matched)!", call_id);
                                matched_bind = true;
                                return Ok(());
                            } else {
                                info!(
                                    "Intercepted BindingResponse for {} but txn_id mismatch (likely ICE consent check), ignoring",
                                    call_id
                                );
                            }
                        }
                        if stun.is_error() {
                            let (code, reason) = stun.error_code().unwrap_or((0, "unknown"));
                            warn!("STUN Bind error for {} (intercepted): code={}, reason={}, txn_match={}", call_id, code, reason, txn_matches);
                        }
                        info!("Intercepted STUN type=0x{:04x} txn_match={} for {}", stun.msg_type as u16, txn_matches, call_id);
                    }
                }
                // Log intercepted RTP/SRTP packets
                if first_byte >= 128 {
                    info!(
                        "INTERCEPTED RTP/SRTP #{} for {}: len={}, first4={:02x?}",
                        intercepted_count, call_id, data.len(),
                        &data[..data.len().min(4)]
                    );
                }
            }
            Err(_) => {}
        }

        // Check DataChannel messages
        match call_manager.recv_from_webrtc_timeout(call_id, Duration::from_millis(50)).await {
            Ok(data) => {
                dc_msg_count += 1;
                if dc_msg_count <= 50 {
                    info!(
                        "DC msg #{} for {} bind: len={}, first20={:02x?}",
                        dc_msg_count, call_id, data.len(),
                        &data[..data.len().min(20)]
                    );
                }

                if let Ok(stun) = StunMessage::decode(&data) {
                    if stun.is_ping() {
                        let pong = StunMessage::whatsapp_pong(stun.transaction_id).encode();
                        let _ = call_manager.send_via_webrtc(call_id, &pong).await;
                        continue;
                    }
                    let txn_matches = sent_txn_ids.iter().any(|t| *t == stun.transaction_id);
                    if matches!(stun.msg_type, StunMessageType::BindingResponse) {
                        if txn_matches {
                            info!("STUN Bind SUCCESS for {} via DataChannel (txn matched)!", call_id);
                            matched_bind = true;
                            return Ok(());
                        } else {
                            info!("DC BindingResponse for {} but txn mismatch, ignoring", call_id);
                        }
                    }
                    if stun.is_error() {
                        let (code, reason) = stun.error_code().unwrap_or((0, "unknown"));
                        warn!("STUN Bind error for {} (DC): code={}, reason={}", call_id, code, reason);
                    }
                }
            }
            Err(_) => {}
        }
    }

    info!(
        "STUN Bind phase completed for {} after {} attempts (shared_socket={}, dc_msgs={}, intercepted={}, matched={}, continuing media startup anyway)",
        call_id, bind_attempts, shared_socket_sent, dc_msg_count, intercepted_count, matched_bind
    );
    Ok(())
}

fn looks_like_stun(data: &[u8]) -> bool {
    if data.len() < 20 {
        return false;
    }

    // STUN header check (RFC5389):
    // - First 2 bits of message type are 0
    // - Magic cookie at bytes [4..8] is 0x2112A442
    if (data[0] & 0xC0) != 0 {
        return false;
    }
    if data[4..8] != [0x21, 0x12, 0xA4, 0x42] {
        return false;
    }

    // Attribute block length must fit in the packet and be 4-byte aligned.
    let msg_len = u16::from_be_bytes([data[2], data[3]]) as usize;
    msg_len % 4 == 0 && data.len() >= 20 + msg_len
}

fn generate_transaction_id() -> [u8; 12] {
    use rand::RngCore;
    let mut id = [0u8; 12];
    rand::rng().fill_bytes(&mut id);
    id
}

fn generate_sample_opus_frames(
    duration_ms: u64,
    frequency_hz: f32,
    frame_ms: u32,
) -> Result<Vec<Vec<u8>>, String> {
    const SAMPLE_RATE: u32 = 16_000;
    const MAX_OPUS_SIZE: usize = 512;
    const AMPLITUDE: f32 = 0.22;

    if duration_ms == 0 {
        return Ok(Vec::new());
    }

    if frame_ms == 0 {
        return Err("frame_ms must be > 0".to_string());
    }
    let frame_samples = ((SAMPLE_RATE as u64 * frame_ms as u64) / 1000) as usize;
    if frame_samples == 0 {
        return Err(format!("invalid frame_ms {}", frame_ms));
    }

    let mut encoder = OpusEncoder::new(SAMPLE_RATE, OpusChannels::Mono, OpusApplication::Voip)
        .map_err(|e| format!("opus encoder init failed: {}", e))?;
    encoder
        .set_bitrate(opus::Bitrate::Bits(24_000))
        .map_err(|e| format!("opus set bitrate failed: {}", e))?;

    let total_samples = ((duration_ms as usize) * (SAMPLE_RATE as usize)) / 1000;
    let frame_count = total_samples.div_ceil(frame_samples);

    let mut frames = Vec::with_capacity(frame_count);
    let mut out = vec![0u8; MAX_OPUS_SIZE];
    let mut phase = 0.0f32;
    let phase_step = (2.0 * std::f32::consts::PI * frequency_hz) / (SAMPLE_RATE as f32);

    for _ in 0..frame_count {
        let mut pcm = vec![0i16; frame_samples];
        for sample in &mut pcm {
            let value = (phase.sin() * AMPLITUDE * (i16::MAX as f32)) as i16;
            *sample = value;
            phase += phase_step;
            if phase > (2.0 * std::f32::consts::PI) {
                phase -= 2.0 * std::f32::consts::PI;
            }
        }

        let size = encoder
            .encode(&pcm, &mut out)
            .map_err(|e| format!("opus encode failed: {}", e))?;
        frames.push(out[..size].to_vec());
    }

    Ok(frames)
}

fn normalize_call_target_jid(target: &str) -> Result<String, String> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return Err("empty call target".to_string());
    }

    if trimmed.contains('@') {
        return Ok(trimmed.to_string());
    }

    let digits: String = trimmed.chars().filter(|c| c.is_ascii_digit()).collect();
    if digits.is_empty() {
        return Err(format!(
            "invalid phone target '{}': must contain at least one digit",
            trimmed
        ));
    }

    Ok(format!("{digits}@s.whatsapp.net"))
}

fn extract_phone_digits(target: &str) -> Option<String> {
    let trimmed = target.trim();
    if trimmed.is_empty() {
        return None;
    }

    if let Some((user, _domain)) = trimmed.split_once('@') {
        let digits: String = user.chars().filter(|c| c.is_ascii_digit()).collect();
        return (!digits.is_empty()).then_some(digits);
    }

    let digits: String = trimmed.chars().filter(|c| c.is_ascii_digit()).collect();
    (!digits.is_empty()).then_some(digits)
}

trait MediaPing: Downloadable {
    fn media_type(&self) -> MediaType;

    fn build_pong_reply(&self, upload: UploadResponse) -> wa::Message;
}

impl MediaPing for wa::message::ImageMessage {
    fn media_type(&self) -> MediaType {
        MediaType::Image
    }

    fn build_pong_reply(&self, upload: UploadResponse) -> wa::Message {
        wa::Message {
            image_message: Some(Box::new(wa::message::ImageMessage {
                mimetype: self.mimetype.clone(),
                caption: Some(MEDIA_PONG_TEXT.to_string()),
                url: Some(upload.url),
                direct_path: Some(upload.direct_path),
                media_key: Some(upload.media_key),
                file_enc_sha256: Some(upload.file_enc_sha256),
                file_sha256: Some(upload.file_sha256),
                file_length: Some(upload.file_length),
                ..Default::default()
            })),
            ..Default::default()
        }
    }
}

impl MediaPing for wa::message::VideoMessage {
    fn media_type(&self) -> MediaType {
        MediaType::Video
    }

    fn build_pong_reply(&self, upload: UploadResponse) -> wa::Message {
        wa::Message {
            video_message: Some(Box::new(wa::message::VideoMessage {
                mimetype: self.mimetype.clone(),
                caption: Some(MEDIA_PONG_TEXT.to_string()),
                url: Some(upload.url),
                direct_path: Some(upload.direct_path),
                media_key: Some(upload.media_key),
                file_enc_sha256: Some(upload.file_enc_sha256),
                file_sha256: Some(upload.file_sha256),
                file_length: Some(upload.file_length),
                gif_playback: self.gif_playback,
                height: self.height,
                width: self.width,
                seconds: self.seconds,
                gif_attribution: self.gif_attribution,
                ..Default::default()
            })),
            ..Default::default()
        }
    }
}

fn get_pingable_media<'a>(message: &'a wa::Message) -> Option<&'a (dyn MediaPing + 'a)> {
    let base_message = message.get_base_message();

    if let Some(msg) = &base_message.image_message
        && msg.caption.as_deref() == Some(MEDIA_PING_TRIGGER)
    {
        return Some(&**msg);
    }
    if let Some(msg) = &base_message.video_message
        && msg.caption.as_deref() == Some(MEDIA_PING_TRIGGER)
    {
        return Some(&**msg);
    }

    None
}

async fn handle_media_ping(ctx: &MessageContext, media: &(dyn MediaPing + '_)) {
    info!(
        "Received {:?} ping from {}",
        media.media_type(),
        ctx.info.source.sender
    );

    let mut data_buffer = Cursor::new(Vec::new());
    if let Err(e) = ctx.client.download_to_file(media, &mut data_buffer).await {
        error!("Failed to download media: {}", e);
        let _ = ctx
            .send_message(wa::Message {
                conversation: Some("Failed to download your media.".to_string()),
                ..Default::default()
            })
            .await;
        return;
    }

    info!(
        "Successfully downloaded media. Size: {} bytes. Now uploading...",
        data_buffer.get_ref().len()
    );
    let plaintext_data = data_buffer.into_inner();
    let upload_response = match ctx.client.upload(plaintext_data, media.media_type()).await {
        Ok(resp) => resp,
        Err(e) => {
            error!("Failed to upload media: {}", e);
            let _ = ctx
                .send_message(wa::Message {
                    conversation: Some("Failed to re-upload the media.".to_string()),
                    ..Default::default()
                })
                .await;
            return;
        }
    };

    info!("Successfully uploaded media. Constructing reply message...");
    let reply_msg = media.build_pong_reply(upload_response);

    if let Err(e) = ctx.send_message(reply_msg).await {
        error!("Failed to send media pong reply: {}", e);
    } else {
        info!("Media pong reply sent successfully.");
    }
}

fn parse_arg(args: &[String], long: &str, short: &str) -> Option<String> {
    let long_prefix = format!("{}=", long);
    let mut iter = args.iter().skip(1);
    while let Some(arg) = iter.next() {
        if arg == long || arg == short {
            return iter.next().cloned();
        }
        if let Some(value) = arg.strip_prefix(&long_prefix) {
            return Some(value.to_string());
        }
    }
    None
}

fn env_bool(key: &str, default: bool) -> bool {
    std::env::var(key)
        .ok()
        .map(|v| {
            let normalized = v.trim().to_lowercase();
            matches!(normalized.as_str(), "1" | "true" | "yes" | "on")
        })
        .unwrap_or(default)
}

fn env_usize(key: &str, default: usize) -> usize {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(default)
}

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

fn env_u8(key: &str, default: u8) -> u8 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<u8>().ok())
        .unwrap_or(default)
}

fn env_f32(key: &str, default: f32) -> f32 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.trim().parse::<f32>().ok())
        .unwrap_or(default)
}

fn parse_hex_bytes(input: &str) -> Result<Vec<u8>, String> {
    let mut s = input.trim().to_string();
    if let Some(rest) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        s = rest.to_string();
    }
    if s.len() % 2 != 0 {
        return Err(format!("hex string must have even length, got {}", s.len()));
    }

    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let hi = bytes[i] as char;
        let lo = bytes[i + 1] as char;
        let pair = [hi, lo];
        let pair_str: String = pair.iter().collect();
        let byte = u8::from_str_radix(&pair_str, 16)
            .map_err(|e| format!("invalid hex at bytes {}-{}: {}", i, i + 1, e))?;
        out.push(byte);
        i += 2;
    }
    Ok(out)
}
