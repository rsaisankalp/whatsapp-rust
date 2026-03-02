# Call Audio Handoff (Mar 2, 2026)

## Branch + Repo
- Branch: `pr-218`
- Repo: `https://github.com/rsaisankalp/whatsapp-rust`

## What Works
- QR linking/session persistence works.
- Outgoing call setup can ring and can be accepted.
- Signaling path is stable enough through:
  - offer -> offer ACK -> preaccept -> accept
  - deferred WebRTC setup
  - ICE + DTLS + SCTP + DataChannel open

## Current Blocking Behavior
- Accepted call shows reconnecting and ends around ~20s.
- STUN bind in automation path times out even with retries.
- Runtime shows only incoming `WhatsAppPong` control packets (20 bytes).
- Sample audio injection runs but remote still reports no audible stream.

## Latest Repro (fresh test)
- Call id: `64B5DE395DAC191623B1B82A7FBBCB57`
- Key lines:
  - `Using app-data sender subscription in STUN bind ...`
  - `Sending STUN Bind ... (196 bytes)`
  - `STUN Bind timed out ... after 10 attempts`
  - `Injecting sample audio ...`
  - repeated `STUN/control packet #... type=WhatsAppPong`
  - remote terminate at ~20.4s (`audio_duration=20448`)
  - SCTP stat: `nDATAs (in) : 17`

## Code Changes In This Iteration
- `src/calls/media/stun.rs`
  - added `StunMessage::whatsapp_pong(transaction_id)`
- `src/calls/media/sender_subscriptions.rs`
  - added app-data sender subscription builder
- `src/calls/media/mod.rs`
  - re-exported app-data subscription helper
- `src/main.rs`
  - bind/allocate loops now respond to incoming STUN ping with pong
  - stricter bind/allocate success type checks
  - bind retry loop with env-configured retry/timeout
  - STUN packet telemetry during bind + receive loop
  - app-data sender subscription path when `disable_ssrc_subscription=true`

## Runtime Config Used
- `/etc/default/whatsapp-call-bot` (current notable values):
  - `WHATSAPP_VOICE_PING_INTERVAL_SECS=1`
  - `WHATSAPP_CALL_STUN_BIND_TOTAL_MS=5000`
  - `WHATSAPP_CALL_STUN_BIND_RETRY_MS=400`
  - `WHATSAPP_CALL_STUN_BIND_SUBS=true`
  - `WHATSAPP_CALL_SAMPLE_AUDIO=true`

## Useful Commands
- Rebuild/restart:
```bash
cargo build --release
systemctl restart whatsapp-call-bot
```
- Capture latest 2-minute run:
```bash
journalctl -u whatsapp-call-bot --since '2 minutes ago' --no-pager > /tmp/wa_call_test_latest.log
```
- Pull one call timeline:
```bash
CALL_ID=<ID>
rg -n "$CALL_ID|STUN Bind|Using app-data sender subscription|Injecting sample audio|terminate|nDATAs \\(in\\)" /tmp/wa_call_test_latest.log
```

## Next Experiments (ordered)
1. Credential format toggle for bind/allocate:
   - try raw relay bytes vs base64 SDP text for USERNAME + MESSAGE-INTEGRITY key.
2. Subscription mode variants:
   - send audio + app-data sender subscriptions together;
   - test adding receiver subscription (`0x4001`) payload variants.
3. Bind strategy variants:
   - force allocate+bind path;
   - test bind without integrity/fingerprint/priority to match observed relay behavior.
4. Improve bind diagnostics:
   - log undecodable bind responses (first bytes + msg_type heuristic) to catch malformed/unknown reply formats.
