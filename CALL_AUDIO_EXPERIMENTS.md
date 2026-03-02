# WhatsApp Calling + Audio Streaming Experiments

Branch: `pr-218`
Repo: `https://github.com/rsaisankalp/whatsapp-rust`
Server: `root@168.231.120.137` at `/root/experiments/whatsapp/whatsappcall`
Service: `whatsapp-call-bot` (systemd)
Date range: March 2-3, 2026

---

## Goal

Achieve bidirectional audio streaming in WhatsApp VoIP calls from a Rust bot:
1. Bot places outgoing call to a phone number
2. Phone answers
3. Bot sends sample audio (440 Hz tone) that the phone can hear
4. Bot receives and decodes phone's audio
5. Call stays connected (no "Reconnecting" state)

## Baseline Symptom

Calls ring, get answered, but phone shows **"Reconnecting"** with no audio, then disconnects after ~20 seconds.

---

## Architecture Overview

```
Bot (Rust)                    WhatsApp Relay (port 3480)              Phone
    |                                |                                  |
    |--- offer (XMPP stanza) ------>|                                  |
    |<-- offer ACK (relay data) ----|                                  |
    |<-- preaccept -----------------|                                  |
    |                                |                                  |
    |=== WebRTC (ICE/DTLS/SCTP) ===>|<==== WebRTC ===================>|
    |--- DataChannel "wa-web-call" ->|                                  |
    |--- accept (XMPP stanza) ----->|                                  |
    |                                |                                  |
    |--- SRTP audio packets ------->| ----> forward to phone --------->|
    |<-- SRTP audio packets --------|<---- forward from phone ---------|
```

### Key Protocol Details
- **Relay port**: 3480 (not standard STUN 3478)
- **SDP manipulation**: `ice-ufrag` = auth_token, `ice-pwd` = relay_key, hardcoded DTLS fingerprint
- **DataChannel**: "wa-web-call", negotiated, SCTP stream 0
- **SRTP**: SDES keys from signaling (`hbh_key` = 30 bytes: 16 master key + 14 salt)
- **voip_settings from ACK**: `app_data_stream_version=2`, `disable_ssrc_subscription=true`

### Available Keys from Signaling
| Key | Raw Size | Format |
|-----|----------|--------|
| relay_key | 16 bytes | Provided as 24-char base64 string |
| auth_token | 70 bytes | Provided as 96-char base64 string |
| hbh_key | 30 bytes | Raw binary (16B master + 14B salt) |
| relay_token | variable | Per-endpoint token for STUN bind |

---

## Phase 1: Call Setup Stabilization (Mar 2, early)

### Commits
- `d6eac2b` calls: stabilize outgoing ringing and media automation
- `f563fc9` calls: add media diagnostics and voip-settings driven relay behavior

### Changes
1. **DataChannel receive-path robustness** (`webrtc.rs`)
   - Handle remote-created DataChannels via `on_data_channel`
2. **SRTP state safety** (`srtp.rs`)
   - Clone SRTP context before trial decryption to avoid state poisoning
3. **RTP packet diagnostics** (`main.rs`)
   - Added `WHATSAPP_CALL_SRTP_OFFSET_SCAN` and `WHATSAPP_CALL_PACKET_DEBUG_COUNT`
   - Try SRTP unprotect at offsets [0,1,2,4,8] to detect framing bytes
4. **voip_settings parsing** (`stanza.rs`, `main.rs`)
   - Parse `app_data_stream_version` and `disable_ssrc_subscription` from offer ACK
   - Skip sender subscription in STUN bind when `disable_ssrc_subscription=true`

### Result
- Calls can ring and be answered
- Post-answer still shows "Reconnecting" and terminates at ~20s

---

## Phase 2: STUN Ping/Pong + Bind Retries (Mar 2, 12:00-12:30 EST)

### Commits
- `1a02429` calls: document latest test cycle and harden STUN control handling
- `6ce4241` fix: use shared UDP socket for STUN bind + add packet interceptor

### Key Hypothesis
Call drops at ~20s because relay keepalive pings are not answered.

### Changes
1. **STUN ping/pong** (`stun.rs`, `main.rs`)
   - Added `StunMessage::whatsapp_pong(transaction_id)`
   - Receive loop decodes STUN and replies to ping (0x0801) with pong (0x0802)
2. **Bind retry loop** (`main.rs`)
   - Configurable: `WHATSAPP_CALL_STUN_BIND_TOTAL_MS`, `WHATSAPP_CALL_STUN_BIND_RETRY_MS`
   - STUN bind sends repeated attempts
3. **App-data subscription** (`sender_subscriptions.rs`)
   - For `disable_ssrc_subscription=true`: send AppData subscription instead of audio
4. **Shared UDP socket** (`webrtc.rs`)
   - STUN bind uses the same UDP socket as the WebRTC ICE connection
   - Added packet interceptor to capture raw UDP packets

### Test Result (Call ID: `64B5DE395DAC191623B1B82A7FBBCB57`)
- STUN Bind (196 bytes) sent 10 times → **all timed out**
- Only incoming control: `WhatsAppPong` (20 bytes)
- 210+ SRTP packets sent → none received by phone
- Remote terminated at ~20.4s
- SCTP `nDATAs (in): 17` (very low)

### Key Finding
**STUN bind on the shared WebRTC socket gets NO matching response from the relay.** The relay drops STUN messages containing 0x4000/0x4001 comprehension-required subscription attributes.

---

## Phase 3: Receiver Subscriptions + STUN Telemetry (Mar 2, 12:30-13:00 EST)

### Commit
- `1823b9c` fix: add receiver subscriptions, fix STUN bind txn matching, improve media logging

### Changes
1. Added receiver subscription (0x4001) alongside sender subscription
2. Fixed transaction ID matching for STUN responses
3. Enhanced media packet signature logging

### Result
Same outcome - STUN bind still times out. Subscription attributes still rejected.

---

## Phase 4: Pre-ICE Bind Strategies (Mar 2-3, late)

### Commits
- `79b72b6` Add pre-ICE STUN bind with subscription registration
- `95ca550` Try 4 pre-ICE bind strategies for subscription registration

### Hypothesis
Perhaps STUN bind must happen BEFORE ICE negotiation takes over the UDP socket.

### Strategies Tested
1. **Strategy A**: Bind with USERNAME (auth_token) + FINGERPRINT + subscriptions
2. **Strategy B**: Bind with USERNAME (relay_token) + subscriptions
3. **Strategy C**: Bind with USERNAME + FINGERPRINT, no subscriptions
4. **Strategy D**: Minimal bind (no auth, no subs)

### Result
All 4 strategies timed out - no STUN response received. The relay either:
- Ignores pre-ICE packets on our UDP socket
- Requires a different binding approach entirely

---

## Phase 5: DataChannel TURN Allocate (Mar 3, 01:00-02:00 IST)

### Pivot Decision
Since STUN bind on the raw UDP socket fails, try sending TURN Allocate (0x0003) through the DataChannel, which is the only proven bidirectional path to the relay.

### Experiment 5A: Full Allocate with Auth + Subscriptions
**Commit**: `9a5620c`

Sent TURN Allocate via DataChannel with:
- USERNAME (auth_token)
- REQUESTED-TRANSPORT (UDP, 0x0011)
- MESSAGE-INTEGRITY (HMAC-SHA1 with relay_key)
- FINGERPRINT
- ICE PRIORITY
- Sender subscriptions (0x4000)
- Receiver subscriptions (0x4001)

**Result**: Error **456** "Failed to decode allocate request stun message"

**Key Discovery**: The relay CAN receive and process STUN messages on the DataChannel! It identified the message as Allocate (0x0003), returned our transaction ID, but couldn't parse the body.

### Experiment 5B: Remove FINGERPRINT and ICE PRIORITY
**Commit**: `121609b`

Observation: WhatsApp Ping/Pong (which work on DC) have `include_fingerprint: false` and `ice_priority: None`.

Strategies tested:
1. **Bare Allocate** (REQUESTED-TRANSPORT only, 28 bytes)
2. **Allocate + subscriptions** (no fingerprint/priority)
3. **Allocate + auth + subscriptions** (no fingerprint/priority)

**Results**:

| Strategy | Size | Error | Meaning |
|----------|------|-------|---------|
| Bare (REQUESTED-TRANSPORT only) | 28 B | **451** "Hmac missing" | **PARSED CORRECTLY!** |
| + subscriptions | ~120 B | 456 "Failed to decode" | Parser choked on subs |
| + auth + subscriptions | ~220 B | 456 "Failed to decode" | Parser choked on subs |

**Key Finding**: The DC STUN parser CAN parse a bare 28-byte Allocate. Subscription attributes (0x4000/0x4001) cause the parser to fail regardless of other attributes.

### Experiment 5C: Auth Without Subscriptions
**Commit**: `48a5467`

Since `disable_ssrc_subscription=true`, subscriptions may not be needed. Tried Allocate with USERNAME + MESSAGE-INTEGRITY only (no subscriptions).

**Results**:

| Strategy | Size | Error | Meaning |
|----------|------|-------|---------|
| Auth (USERNAME + INTEGRITY, no subs) | 152 B | **456** "Failed to decode" | USERNAME broke parser |
| Bare diagnostic | 28 B | 451 "Hmac missing" | Consistent |

**Key Finding**: Even standard STUN USERNAME attribute (0x0006) causes decode failure. The relay's DC STUN parser ONLY handles minimal messages.

### Experiment 5D: Auth Strategies Without USERNAME
**Commit**: `1c31787`

Since USERNAME causes 456, try MESSAGE-INTEGRITY WITHOUT USERNAME:

| Strategy | Key Used | Size | Error | Meaning |
|----------|----------|------|-------|---------|
| SA: INTEGRITY only | relay_key raw (16B) | 52 B | **450** "Hmac **mismatch**" | **PARSED!** |
| SB: INTEGRITY only | relay_key b64 (24B) | 52 B | **450** "Hmac mismatch" | Parsed |
| SC: INTEGRITY only | hbh_key (30B) | 52 B | **450** "Hmac mismatch" | Parsed |
| SD: FINGERPRINT only | N/A | 36 B | 451 "Hmac missing" | Parsed but needs auth |
| SE: USERNAME + INTEGRITY | relay_key b64 | ~152 B | 456 "Failed to decode" | USERNAME breaks parser |

**BREAKTHROUGH**: The relay CAN parse `REQUESTED-TRANSPORT + MESSAGE-INTEGRITY` (no USERNAME)! Error 450 means the message was fully parsed but the HMAC key is wrong.

### DC STUN Parser Capability Map (Confirmed)

| Attributes | Parseable? | Error |
|-----------|-----------|-------|
| REQUESTED-TRANSPORT only (28B) | Yes | 451 (needs auth) |
| REQUESTED-TRANSPORT + FINGERPRINT (36B) | Yes | 451 (needs auth) |
| REQUESTED-TRANSPORT + MESSAGE-INTEGRITY (52B) | Yes | 450 (wrong key) |
| REQUESTED-TRANSPORT + USERNAME + INTEGRITY | **No** | 456 (decode fail) |
| Any with 0x4000/0x4001 subscription attrs | **No** | 456 (decode fail) |
| Any with ICE PRIORITY | **No** | 456 (decode fail) |

### DC Error Code Reference
| Code | Message | Meaning |
|------|---------|---------|
| 450 | "Integrity failure: Hmac mismatch" | Message fully parsed, wrong HMAC key |
| 451 | "Integrity failure: Hmac missing" | Message parsed, needs MESSAGE-INTEGRITY |
| 456 | "Failed to decode allocate request stun message" | Parser couldn't handle the message |

### Experiment 5E: Try auth_token as HMAC Key
**Commit**: `40b72ee`

Tried additional key candidates:

| Key | Size | Error |
|-----|------|-------|
| auth_token raw (b64 text) | 96 B | 450 mismatch |
| auth_token b64 (double-encoded) | 128 B | 450 mismatch |
| relay_key raw (b64 text) | 24 B | 450 mismatch |
| relay_key b64 (double-encoded) | 32 B | 450 mismatch |
| hbh_key | 30 B | 450 mismatch |
| hbh_master_16 | 16 B | 450 mismatch |

All produce 450 "Hmac mismatch". Realized auth_token/relay_key were already base64-encoded strings.

### Experiment 5F: Base64-Decoded Raw Binary Keys
**Commit**: `3aea6b3`

Properly base64-decoded the signaling keys:

| Key | Size | Error |
|-----|------|-------|
| relay_key decoded | 16 B | 450 mismatch |
| relay_key b64 text | 24 B | 450 mismatch |
| auth_token decoded | 70 B | 450 mismatch |
| auth_token b64 text | 96 B | 450 mismatch |
| hbh_key | 30 B | 450 mismatch |
| hbh_master (first 16B) | 16 B | 450 mismatch |
| hbh_key b64 | 40 B | 450 mismatch |

**ALL 7 keys produce 450 "Hmac mismatch".** The HMAC key for DC STUN is NOT any signaling-provided key.

### Conclusion on HMAC Key
The HMAC key used by the relay for DC STUN Allocate authentication is most likely **derived from the DTLS session** (e.g., DTLS exported keying material, RFC 5705). This key is not available in the signaling data and would require extracting it from the webrtc-rs DTLS context.

---

## Phase 6: Pivot - Media Path Focus (Pending)

### Rationale
The TURN Allocate on DC is a dead end without the correct HMAC key. The 7+ seconds spent trying keys is wasted. The focus should shift to the actual media transport.

### Open Questions
1. **Is TURN Allocate even needed?** The ICE connection is already established (ping/pong work). The WebRTC library may handle relay allocation internally.
2. **Which media path is correct?**
   - Raw UDP (bypasses DTLS): `send_raw_to_relay()` → sends raw SRTP on the ICE socket
   - DataChannel: `send()` → sends through DTLS/SCTP/DataChannel
   - Both? Neither?
3. **Are subscriptions being registered?** We send raw protobuf via DC (`WHATSAPP_CALL_DC_PROTO_SUBS=true`) but the relay may not understand them without a proper envelope/framing.
4. **Is the RTP payload type correct?** Currently using 111, but WhatsApp may expect a different type.

### Planned Experiments
1. Disable STUN Allocate entirely (`WHATSAPP_CALL_STUN_ALLOCATE=false`)
2. Try DC-only media (disable raw UDP): does the relay forward DataChannel binary as RTP?
3. Try raw-UDP-only media (disable DC media): does the relay forward raw SRTP on the ICE socket?
4. Check if the subscription protobuf needs a specific framing/header
5. Try extracting DTLS keying material for proper TURN auth

---

## Server Configuration Reference

### Environment File: `/etc/default/whatsapp-call-bot`

```bash
# Call automation
WHATSAPP_CALL_AUTOMATION_ENABLED=true
WHATSAPP_CALL_AUTO_ACCEPT=true
WHATSAPP_TEST_CALL_TO=+919620515656
WHATSAPP_TEST_CALL_DELAY_SECS=2

# Signaling
WHATSAPP_CALL_DEFER_OUTGOING_SETUP=true
WHATSAPP_CALL_CREATOR_MODE=manager
WHATSAPP_CALL_PREFER_LID=true
WHATSAPP_CALL_OFFER_DEVICE_IDENTITY=true
WHATSAPP_CALL_OFFER_NET_MEDIUM=1

# Media
WHATSAPP_CALL_SAMPLE_AUDIO=true
WHATSAPP_CALL_SAMPLE_AUDIO_DURATION_MS=30000
WHATSAPP_CALL_SAMPLE_AUDIO_FREQ_HZ=440
WHATSAPP_CALL_RTP_PAYLOAD_TYPE=111

# Transport
WHATSAPP_CALL_DC_NEGOTIATED_STREAM0=true
WHATSAPP_CALL_RAW_MEDIA=true
WHATSAPP_CALL_PRE_ICE_BIND=false
WHATSAPP_CALL_STUN_ALLOCATE=true  # Should be false for Phase 6

# STUN/Subscription
WHATSAPP_CALL_STUN_BIND_SUBS=false
WHATSAPP_CALL_BIND_RAW_UDP=true
WHATSAPP_CALL_BIND_BOTH_SUBS=true

# Diagnostics
RUST_LOG=info,webrtc_sctp=warn,webrtc_ice=warn,webrtc_dtls=warn,webrtc=info
WHATSAPP_CALL_SRTP_OFFSET_SCAN=true
WHATSAPP_CALL_PACKET_DEBUG_COUNT=100
```

### Useful Commands
```bash
# Build and deploy
cargo build --release
systemctl restart whatsapp-call-bot

# View logs
journalctl -u whatsapp-call-bot --no-pager -n 500
journalctl -u whatsapp-call-bot --since '2 minutes ago' --no-pager

# Filter for call timeline
journalctl -u whatsapp-call-bot --no-pager | grep -E "offer ACK|preaccept|WebRTC|DataChannel|STUN|SRTP|media|terminate|Reconnect"
```

---

## Key Files Modified

| File | Purpose |
|------|---------|
| `src/main.rs` | Bot entry point, call automation, media send/receive loops, STUN allocate |
| `src/calls/media/webrtc.rs` | WebRTC transport, SDP manipulation, DataChannel, raw UDP socket |
| `src/calls/media/stun.rs` | STUN/TURN message encoding/decoding, ping/pong |
| `src/calls/media/srtp.rs` | SRTP encrypt/decrypt with rollback-safe state |
| `src/calls/media/sender_subscriptions.rs` | Protobuf subscription builders (audio, app-data, receiver) |
| `src/calls/media/ice_interceptor.rs` | Pre-ICE bind, raw UDP packet interception |
| `src/calls/media/relay.rs` | UDP relay connection (standalone, not used with WebRTC path) |
| `src/calls/stanza.rs` | Call signaling stanza parsing (RelayData, voip_settings) |
| `src/calls/manager.rs` | CallManager with WebRTC transport management |

---

## Summary of What Works vs What Doesn't

### Working
- Call signaling: offer → ACK → preaccept → accept
- WebRTC connection: ICE → DTLS → SCTP → DataChannel
- DataChannel ping/pong (keepalive)
- SRTP encryption/packet creation
- Opus sample audio generation
- DC STUN message exchange (can send/receive Allocate with errors)

### Not Working
- **Audio streaming in either direction**
- STUN Bind on shared WebRTC socket (no response)
- STUN Allocate on DataChannel (can't authenticate - wrong HMAC key)
- Subscription registration (relay ignores raw protobuf on DC, rejects 0x4000/0x4001 in STUN)
- Phone stays in "Reconnecting" state
- Remote terminates call after ~20 seconds
