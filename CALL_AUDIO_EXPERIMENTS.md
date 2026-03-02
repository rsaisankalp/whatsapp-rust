# WhatsApp Calling + Audio Streaming Experiments (PR-218 branch)

Date range: Mar 2, 2026 (local test loop)

## Goal
- Stable outgoing WhatsApp call from bot account to target number.
- After answer, maintain media session and stream sample audio.
- Receive/decode inbound audio from remote side.

## Baseline
- Branch: `pr-218`
- Runtime: `centos9` service (`whatsapp-call-bot`)
- Symptom before these changes:
  - Outgoing attempts often produced chat "missed voice call" without actual ring.
  - Some calls rang but after answer stayed in "Reconnecting..." and ended.
  - No audible streamed audio.

## Code changes in this cycle

### 1) DataChannel receive-path robustness
File: `src/calls/media/webrtc.rs`
- Added handling for remote-created DataChannels via `on_data_channel`.
- Forwarded remote DataChannel messages into existing receive queue.

Why:
- Some peers create channels from remote side; local-only callback misses these events.

### 2) SRTP state safety under decryption failures
File: `src/calls/media/srtp.rs`
- Changed `unprotect()` to decrypt using trial clone context.
- Commit SRTP rollover/seq state only on successful auth+decrypt.

Why:
- Invalid packets should not poison SRTP state and break later valid packets.

### 3) RTP packet diagnostics + offset scanning
File: `src/main.rs`
- Added env flags:
  - `WHATSAPP_CALL_SRTP_OFFSET_SCAN` (default `true`)
  - `WHATSAPP_CALL_PACKET_DEBUG_COUNT` (default `32`)
- For first N non-STUN packets, log packet signatures.
- Try SRTP unprotect with offsets `[0,1,2,4,8]` when enabled.
- Log non-zero successful offsets and bounded failures.

Why:
- Validate whether relay packets include extra framing bytes before RTP header.

### 4) Parse relay voip settings from ACK and apply on bind
Files:
- `src/calls/stanza.rs`
- `src/main.rs`
- `src/calls/protocol_tests.rs`

Changes:
- Extended `RelayData` with:
  - `app_data_stream_version: Option<u8>`
  - `disable_ssrc_subscription: Option<bool>`
- Parse `voip_settings` JSON from call offer ACK.
- In STUN bind construction, if `disable_ssrc_subscription=true`, skip sender-subscription attribute.

Why:
- ACK explicitly communicated relay behavior flags; bind request should follow those options.

## Runtime configuration used
File: `/etc/default/whatsapp-call-bot`
- `WHATSAPP_CALL_DC_NEGOTIATED_STREAM0=true`
- `WHATSAPP_CALL_STUN_BIND_SUBS=true`
- `WHATSAPP_CALL_SRTP_OFFSET_SCAN=true`
- `WHATSAPP_CALL_PACKET_DEBUG_COUNT=80`
- `WHATSAPP_CALL_RTP_PAYLOAD_TYPE=120`
- `WHATSAPP_CALL_OFFER_NET_MEDIUM=1`
- `WHATSAPP_CALL_SAMPLE_AUDIO_DURATION_MS=15000`

Service cycled repeatedly with fresh logs per experiment iteration.

## Observations from logs
- Parsed ACK relay options seen in live logs:
  - `app_data_stream_version=Some(2)`
  - `disable_ssrc_subscription=Some(true)`
- Call setup improved intermittently:
  - Some attempts rang and could be answered.
- Post-answer failure remains:
  - State enters reconnecting and eventually terminates.
  - STUN bind frequently times out.
  - SCTP stats show low inbound app-data (`nDATAs (in)` very small), suggesting app data/control path still incomplete or incompatible.

## Current status
- Outgoing call ring: **intermittently working**.
- Stable post-answer media session: **not achieved yet**.
- Outbound sample audio playback to remote: **not reliably audible yet**.
- Inbound voice decode/listen path: **not functional yet**.

## Last relevant commits
- `f563fc9` calls: add media diagnostics and voip-settings driven relay behavior
- `d6eac2b` calls: stabilize outgoing ringing and media automation
- `aafb1c1` feat: update data channel creation to use negotiated mode for SCTP stream 0
- `1439f74` feat: enhance call handling with reject and terminate cleanup logic
- `4991570` feat: enhance call stanza handling and privacy token notifications

## Next technical focus
1. Align STUN/TURN bind payload exactly with WhatsApp Web wire behavior for app-data-stream v2.
2. Verify DTLS/SRTP keying and timing against real successful session traces.
3. Compare SCTP/DataChannel label/id/open sequence with known working Web client capture.
4. Add targeted logs around remote relay responses to confirm whether bind is accepted or ignored.
