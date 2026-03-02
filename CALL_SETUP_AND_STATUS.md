# WhatsApp Call Setup + Current Status

Updated: March 2, 2026

## Current standing
- Outbound call trigger is working from service startup (auto-dial).
- Recent verified call id: `A1EC67CC7BBEF83D5AE9AB80AB58CC0F`.
- In logs for that call we see:
  - offer sent + offer ACK received
  - preaccept received
  - relay connected
  - ICE connected
  - DTLS/SCTP connected
  - DataChannel `wa-web-call` opened
- Remaining blocker: call media still intermittently ends in reconnecting/no stable bidirectional audio stream.

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

## What still needs work
- Stabilize post-answer media path so call does not go to reconnecting.
- Make RTP/SRTP audio consistently audible both directions.
- Complete app-data-stream-v2/STUN bind behavior parity with WhatsApp Web.
