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

## Phase 6: Offer Config Fix + Pre-ICE Bind (Mar 3, ~16:50 IST)

### Problem
Calls suddenly stopped receiving offer ACK with relay data. The session target had changed from LID format (`218304664838270@lid`) to s.whatsapp.net format, with different offer config parameters.

### Root Cause
Missing environment variables for offer config. The defaults were wrong:
- `WHATSAPP_CALL_OFFER_SEND_NOTICE`: default=false (needed true)
- `WHATSAPP_CALL_OFFER_NET_MEDIUM`: default=3/cellular (needed 1/WiFi)
- `WHATSAPP_CALL_OFFER_DUAL_AUDIO`: default=true (needed false)
- `WHATSAPP_CALL_PREFER_LID`: default=false (needed true)

### Fix
Added to `/etc/default/whatsapp-call-bot`:
```
WHATSAPP_CALL_PREFER_LID=true
WHATSAPP_CALL_OFFER_SEND_NOTICE=true
WHATSAPP_CALL_OFFER_NET_MEDIUM=1
WHATSAPP_CALL_OFFER_DUAL_AUDIO=false
WHATSAPP_CALL_OFFER_CAPABILITY=false
```

### Result After Fix
- Session target correctly resolved to LID: `218304664838270@lid`
- Offer ACK with relay data received (3 endpoints)
- Relay probe succeeded (bom2c04 reachable)
- Pre-ICE bind: ALL 4 strategies timed out (no response on raw UDP)
- WebRTC/DTLS/SCTP/DataChannel connected successfully
- Phone answered, shows "Reconnecting", no audio

### Learning
The offer config (LID preference, notice=true, net=1, dual_audio=false) is **critical** for receiving relay data. Without these, the call setup fails silently.

---

## Phase 7: Systematic Attribute Isolation + Derived Keys (Mar 3)

### Purpose
Systematically determine which STUN attributes the DC parser accepts/rejects, and try derived HMAC key candidates.

### IMPORTANT CORRECTION to Phase 5D Capability Map
Previous experiments concluded USERNAME and PRIORITY cause 456 (parse failure). **This was wrong!** Those 456 errors were caused by COMBINING these attributes with 0x4000/0x4001 subscription attributes. When tested INDIVIDUALLY:

### Updated DC STUN Parser Capability Map

| Attributes | Parseable? | Error | Phase Verified |
|-----------|-----------|-------|----------------|
| REQUESTED-TRANSPORT only (28B) | Yes | 451 (needs auth) | 5B |
| REQUESTED-TRANSPORT + FINGERPRINT | Yes | 451 (needs auth) | 5B |
| REQUESTED-TRANSPORT + MESSAGE-INTEGRITY | Yes | 450 (wrong key) | 5D |
| REQUESTED-TRANSPORT + **USERNAME** + INTEGRITY | **Yes** | **450** (wrong key) | **7 (P3a)** |
| REQUESTED-TRANSPORT + **FINGERPRINT** + INTEGRITY | **Yes** | **450** (wrong key) | **7 (P3b)** |
| REQUESTED-TRANSPORT + **PRIORITY** + INTEGRITY | **Yes** | **450** (wrong key) | **7 (P3c)** |
| REQUESTED-TRANSPORT + **SenderSubs (0x4000)** + INTEGRITY | **No** | **456** (decode fail) | **7 (P3d)** |
| USERNAME + SenderSubs + INTEGRITY | No | 456 | 7 (P3e) |
| Any with 0x4000/0x4001 subscription attrs | **No** | 456 (decode fail) | 7 |

**KEY FINDING**: USERNAME, FINGERPRINT, and PRIORITY are ALL individually parseable. The **only** attribute that causes 456 is **SenderSubscriptions (0x4000)**!

### Additional Findings

**auth_token is a protobuf structure**: The decoded auth_token (70 bytes) starts with byte `0x09` which is a protobuf field tag (field 1, wire type 1 = fixed64). The DC STUN parser validates USERNAME content as protobuf.

### SenderSubscriptions Format Mismatch (LIKELY CAUSE OF 456)

**Desktop reference** (`whatsapp-ui/src/audio/call_media_pipeline.rs:116`):
```rust
let sender_subscriptions = create_audio_sender_subscriptions(ssrc);
// → 1 subscription: {ssrc, StreamLayer::Audio, PayloadType::Media}
// → ~12 bytes protobuf
```

**Our code** (`src/main.rs:2281`):
```rust
let combined_subs = create_combined_sender_subscriptions(ssrc, self_pid, sender_jid);
// → 2 subscriptions:
//   {ssrc, StreamLayer::Audio, PayloadType::Media, sender_jid}
//   {pid, StreamLayer::AppDataStream0, PayloadType::AppData, sender_jid}
// → ~67 bytes protobuf
```

**Differences**:
- Desktop: 1 audio-only subscription, ~12 bytes, no sender_jid
- Our code: 2 subscriptions (audio + app-data), ~67 bytes, includes sender_jid and pid
- The extra fields/entries likely cause the 456 parse error

### HMAC Key Candidates Tested (ALL fail with 450)

| # | Key | Size | Source |
|---|-----|------|--------|
| 1 | relay_key_raw | 16B | base64-decoded relay_key |
| 2 | auth_token_raw | 70B | base64-decoded auth_token |
| 3 | relay_key_b64str | 24B | relay_key as string bytes |
| 4 | hbh_key | 30B | hop-by-hop key |
| 5 | warp_auth | 32B | HKDF-derived "warp auth key" |
| 6 | hmac_sha1(relay_key, auth_token) | 20B | HMAC-SHA1 derivation |
| 7 | hmac_sha1(auth_token, relay_key) | 20B | reversed HMAC-SHA1 |
| 8 | sha1(relay_key) | 20B | simple SHA1 hash |
| 9 | md5(auth_token:relay_key) | 16B | TURN long-term style |
| 10 | hkdf(relay_key, "stun") | 20B | HKDF-SHA256 derivation |
| 11-15 | DTLS export labels (Exp 3) | 20-32B | RFC 5705 keying material |

**Total: 15+ key candidates, ALL produce error 450.**

### Pre-ICE Allocate on Raw UDP
- 3 attempts on raw UDP (not DataChannel), all timed out
- The relay does not respond to STUN on raw UDP at all (neither Bind nor Allocate)

---

## Phase 8: Next Steps (PRIORITIZED)

### Step 1: Fix SenderSubscriptions Format (HIGH PRIORITY)
**Hypothesis**: The 0x4000 attribute causes 456 because our protobuf is wrong (67B combined with JID) vs desktop's format (12B audio-only).

**Action**: In `perform_stun_allocate()`, replace:
```rust
let combined_subs = create_combined_sender_subscriptions(ssrc, self_pid, sender_jid.clone());
```
with:
```rust
let audio_subs = create_audio_sender_subscriptions(ssrc);
```
Then test the full desktop-matching STUN Allocate:
```rust
StunMessage::allocate_request(txn)
    .with_username(&auth_token_raw)
    .with_integrity_key(&relay_key_raw)
    .with_sender_subscriptions(audio_subs)
    // default FINGERPRINT=true, PRIORITY=DEFAULT_ICE_PRIORITY
```

**Expected**: 0x4000 should now produce 450 (parseable, wrong key) instead of 456.

### Step 2: Solve the HMAC Key Problem
If Step 1 changes 456→450, the subscription format was the issue but the HMAC key is still wrong.

**Approaches to try**:
1. **DTLS export keying material AFTER DC establishment**: The Experiment 3 DTLS labels were tried but may have been before DTLS was fully established. Retry with labels:
   - `EXTRACTOR-dtls_srtp` (20B)
   - `EXPORTER-Channel-Binding` (32B)
   - `EXPORTER_TURN_CHANNEL_BIND` (20B)
   - `client finished` / `server finished` (20B)
2. **relay_token** (per-endpoint token, different from auth_token): Try `relay_data.relay_tokens[0]` as HMAC key
3. **SaslContinue/challenge-response**: Maybe the relay expects a 401 response with nonce, then re-derive key. Our code has `pre_ice_allocate_with_subscriptions()` in `ice_interceptor.rs` with 401 handling
4. **SCTP association key**: Investigate SCTP-layer keying material
5. **Capture desktop traffic**: Run desktop client with packet capture to see exact bytes

### Step 3: Alternative Subscription Registration (if STUN fails)
1. **No explicit subscription**: Maybe the relay auto-detects streams from RTP packets (since `disable_ssrc_subscription=true`)
2. **Just send audio**: Skip all STUN probing, immediately send SRTP packets via DataChannel. The relay may forward them based on the DataChannel association alone.
3. **Raw protobuf on DC with framing**: The raw protobuf subs sent on DC might need a specific header/framing byte

### Step 4: Connection Timeout Fix
The WebRTC connection drops during STUN probing (~20s). Reduce timeout per probe to 500ms and limit total probing to 5s. Or skip probing entirely and just send audio.

---

## Desktop Reference (WORKING Implementation)

### File: `whatsapp-ui/src/audio/call_media_pipeline.rs`

The desktop client's working audio pipeline does:

1. **STUN Allocate via DataChannel** (lines 100-208):
   ```rust
   StunMessage::allocate_request(transaction_id)
       .with_username(auth_token)           // base64-decoded, ~70B
       .with_integrity_key(relay_key)       // base64-decoded, 16B
       .with_sender_subscriptions(subs)     // audio-only, ~12B
   ```

2. **Credential extraction** (`whatsapp-ui/src/client/whatsapp.rs:58-83`):
   ```rust
   let auth = engine.decode(&relay_info.auth_token).unwrap_or_else(|_| ...);
   let key = engine.decode(&relay_info.relay_key).unwrap_or_else(|_| ...);
   ```

3. **Audio pipeline** (lines 226-400):
   - SSRC generated randomly, used in BOTH SenderSubscriptions and RTP packets
   - Opus codec, payload type 120
   - SRTP with hbh_key (symmetric key for both send/receive)
   - Send: Opus → RTP → SRTP → DataChannel
   - Receive: DataChannel → SRTP → RTP → Opus

### Key Differences from Our Bot Code

| Aspect | Desktop (WORKING) | Bot (NOT WORKING) |
|--------|-------------------|-------------------|
| SenderSubs format | audio-only, ~12B, no JID | combined audio+app-data, ~67B, with JID |
| Credential format | base64-decoded raw bytes | base64 string bytes (decoded in allocate fn) |
| STUN attributes | USERNAME + subs + INTEGRITY + FINGERPRINT + PRIORITY | Varies by experiment |
| RTP payload type | 120 | 111 |
| Subscription count | 1 (audio only) | 2 (audio + app-data) |

---

## Server Configuration Reference

### Environment File: `/etc/default/whatsapp-call-bot` (CURRENT)

```bash
WHATSAPP_CALL_AUDIO_TRANSCEIVER=false
WHATSAPP_CALL_AUDIO_TRACK_SEND=false
WHATSAPP_CALL_DC_MEDIA=true
WHATSAPP_CALL_RAW_MEDIA=false
WHATSAPP_CALL_STUN_ALLOCATE=true
WHATSAPP_CALL_DTLS_ALLOCATE=false
WHATSAPP_CALL_DC_PROTO_SUBS=true
WHATSAPP_CALL_RAW_KEEPALIVE=true
WHATSAPP_CALL_SUB_KEEPALIVE=true
WHATSAPP_CALL_PRE_ICE_BIND=true
WHATSAPP_CALL_PRE_ICE_ALLOCATE=true
WHATSAPP_CALL_STUN_BIND_SUBS=false
WHATSAPP_CALL_KEEPALIVE_MS=2000
WHATSAPP_CALL_STUN_SENDER_SUBS=false
WHATSAPP_CALL_DC_NEGOTIATED_STREAM0=true
WHATSAPP_TEST_CALL_TO=+919620515656
WHATSAPP_TEST_CALL_DELAY_SECS=5
WHATSAPP_CALL_SAMPLE_AUDIO_DURATION_MS=30000
WHATSAPP_VOICE_PING_INTERVAL_SECS=5
WHATSAPP_CALL_PREFER_LID=true
WHATSAPP_CALL_OFFER_SEND_NOTICE=true
WHATSAPP_CALL_OFFER_NET_MEDIUM=1
WHATSAPP_CALL_OFFER_DUAL_AUDIO=false
WHATSAPP_CALL_OFFER_CAPABILITY=false
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
- DC STUN parser accepts: USERNAME, FINGERPRINT, PRIORITY, MESSAGE-INTEGRITY individually
- Offer config with LID target, notice=true, net=1 gets relay data

### Not Working
- **Audio streaming in either direction**
- STUN Bind on raw UDP socket (no response, all strategies timeout)
- STUN Allocate on DataChannel: **two separate problems**:
  1. **SenderSubscriptions (0x4000) format**: Our combined protobuf (67B) causes 456 parse error. Desktop uses audio-only (12B). **FIX KNOWN - not yet applied.**
  2. **HMAC key unknown**: 15+ key candidates (direct + derived + DTLS-exported) all produce 450. **No fix known.**
- Subscription registration not working (relay ignores raw protobuf on DC)
- Phone shows "Reconnecting" state (no audio)
- Call disconnects after ~20s (no keepalive from our side reaches phone)

### Two Remaining Blockers (in order)
1. **Fix SenderSubscriptions format** → change `create_combined_sender_subscriptions()` to `create_audio_sender_subscriptions(ssrc)` (should change 456→450)
2. **Find correct HMAC key** → most likely DTLS-derived or relay_token-based
