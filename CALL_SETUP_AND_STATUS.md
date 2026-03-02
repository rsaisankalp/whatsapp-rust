# WhatsApp Call Setup + Current Status

Updated: March 2, 2026

## Current standing
- Outbound call trigger is working from service startup (auto-dial).
- Recent verified call id: `64B5DE395DAC191623B1B82A7FBBCB57` (Mar 2, 2026 12:16 server time).
- In logs for this call we see:
  - offer sent + offer ACK received
  - preaccept received
  - relay connected
  - ICE connected
  - DTLS/SCTP connected
  - DataChannel `wa-web-call` opened
- Remaining blocker: accepted calls still end in reconnecting/no stable bidirectional audio stream.
- Current failure pattern after accept:
  - `STUN Bind timed out ... after 10 attempts`
  - repeated incoming control frames are only `WhatsAppPong` (20-byte)
  - remote terminates at ~20s
  - `nDATAs (in)` stays low (~17)

## Environment used
File: `/etc/default/whatsapp-call-bot`

Key flags:
- `WHATSAPP_CALL_AUTOMATION_ENABLED=true`
- `WHATSAPP_TEST_CALL_TO=+919620515656`
- `WHATSAPP_CALL_DEFER_OUTGOING_SETUP=true`
- `WHATSAPP_CALL_SAMPLE_AUDIO=true`
- `WHATSAPP_CALL_SAMPLE_AUDIO_DURATION_MS=15000`
- `WHATSAPP_CALL_OFFER_NET_MEDIUM=1`
- `WHATSAPP_CALL_STUN_BIND_SUBS=true`
- `WHATSAPP_CALL_DC_NEGOTIATED_STREAM0=true`
- `WHATSAPP_CALL_SRTP_OFFSET_SCAN=true`
- `WHATSAPP_CALL_PACKET_DEBUG_COUNT=80`

## Build and run
From repo root:

```bash
cargo build --release
systemctl restart whatsapp-call-bot
systemctl status whatsapp-call-bot --no-pager -l
```

## QR linking (when session is not linked)
1. Start service and watch logs:

```bash
journalctl -u whatsapp-call-bot -f
```

2. If QR is printed in logs/terminal, scan it from WhatsApp mobile:
- WhatsApp -> Linked Devices -> Link a device -> scan QR shown by bot.

3. Confirm link success in logs (client connected, initial sync complete).

## Trigger and verify one test call
Auto-dial runs after connect when `WHATSAPP_TEST_CALL_TO` is set.

Use logs:

```bash
journalctl -u whatsapp-call-bot -S "now-5min" --no-pager | rg "Started audio test call|offer ACK|preaccept|WebRTC connection established|DataChannel"
```

Expected indicators:
- `Started audio test call ...`
- `Received offer ACK with relay data ...`
- `Received preaccept ...`
- `WebRTC connection established ...`
- `DataChannel ... opened ...`

Failure indicators currently seen:
- `Using app-data sender subscription in STUN bind ...`
- `STUN Bind timed out ...`
- many `STUN/control packet #... type=WhatsAppPong`
- terminate around 20s: `<terminate ... audio_duration="20xxx" .../>`

## What still needs work
- Stabilize post-answer media path so call does not go to reconnecting.
- Make RTP/SRTP audio consistently audible both directions.
- Complete app-data-stream-v2/STUN bind behavior parity with WhatsApp Web.
