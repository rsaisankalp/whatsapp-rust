//! SenderSubscriptions builder for STUN 0x4000 attribute and
//! ReceiverSubscription for STUN 0x4001 attribute.
//!
//! WhatsApp uses protobuf-encoded subscription messages in the
//! STUN bind/allocate request to tell the relay what streams we send and receive.

use prost::Message;
use waproto::voip::{PayloadType, SenderSubscription, SenderSubscriptions, StreamLayer};

fn encode_subscriptions(senders: Vec<SenderSubscription>) -> Vec<u8> {
    SenderSubscriptions { senders }.encode_to_vec()
}

fn build_audio_subscription(ssrc: u32, sender_jid: Option<String>) -> Vec<u8> {
    let subscription = SenderSubscription {
        sender_jid,
        ssrc: Some(ssrc),
        stream_layer: Some(StreamLayer::Audio.into()),
        payload_type: Some(PayloadType::Media.into()),
        ..Default::default()
    };

    encode_subscriptions(vec![subscription])
}

/// Create an app-data stream sender subscription for STUN bind/app-data v2.
pub fn create_app_data_sender_subscriptions(
    pid: Option<u32>,
    sender_jid: Option<String>,
) -> Vec<u8> {
    let subscription = SenderSubscription {
        sender_jid,
        pid,
        stream_layer: Some(StreamLayer::AppDataStream0.into()),
        payload_type: Some(PayloadType::AppData.into()),
        ..Default::default()
    };

    encode_subscriptions(vec![subscription])
}

/// Create a combined sender subscription with BOTH audio + app-data in one message.
/// This is the preferred format for a single STUN bind carrying all subscriptions.
pub fn create_combined_sender_subscriptions(
    ssrc: u32,
    pid: Option<u32>,
    sender_jid: Option<String>,
) -> Vec<u8> {
    let audio = SenderSubscription {
        sender_jid: sender_jid.clone(),
        ssrc: Some(ssrc),
        stream_layer: Some(StreamLayer::Audio.into()),
        payload_type: Some(PayloadType::Media.into()),
        ..Default::default()
    };
    let app_data = SenderSubscription {
        sender_jid,
        pid,
        stream_layer: Some(StreamLayer::AppDataStream0.into()),
        payload_type: Some(PayloadType::AppData.into()),
        ..Default::default()
    };
    encode_subscriptions(vec![audio, app_data])
}

/// Create a receiver subscription (0x4001) for audio.
/// Tells the relay we want to RECEIVE audio from the remote side.
pub fn create_audio_receiver_subscription() -> Vec<u8> {
    let subscription = SenderSubscription {
        stream_layer: Some(StreamLayer::Audio.into()),
        payload_type: Some(PayloadType::Media.into()),
        ..Default::default()
    };
    encode_subscriptions(vec![subscription])
}

/// Create a combined receiver subscription for audio + app-data.
pub fn create_combined_receiver_subscription() -> Vec<u8> {
    let audio = SenderSubscription {
        stream_layer: Some(StreamLayer::Audio.into()),
        payload_type: Some(PayloadType::Media.into()),
        ..Default::default()
    };
    let app_data = SenderSubscription {
        stream_layer: Some(StreamLayer::AppDataStream0.into()),
        payload_type: Some(PayloadType::AppData.into()),
        ..Default::default()
    };
    encode_subscriptions(vec![audio, app_data])
}

/// Create a minimal SenderSubscriptions for a 1:1 audio call.
pub fn create_audio_sender_subscriptions(ssrc: u32) -> Vec<u8> {
    build_audio_subscription(ssrc, None)
}

/// Create SenderSubscriptions with a device JID for multi-party calls.
pub fn create_audio_sender_subscriptions_with_jid(ssrc: u32, sender_jid: String) -> Vec<u8> {
    build_audio_subscription(ssrc, Some(sender_jid))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audio_subscription_encoding() {
        let data = create_audio_sender_subscriptions(0x12345678);

        // Should produce valid protobuf that can be decoded
        let decoded = SenderSubscriptions::decode(data.as_slice()).unwrap();
        assert_eq!(decoded.senders.len(), 1);
        assert_eq!(decoded.senders[0].ssrc, Some(0x12345678));
        assert_eq!(
            decoded.senders[0].stream_layer,
            Some(StreamLayer::Audio.into())
        );
        assert_eq!(
            decoded.senders[0].payload_type,
            Some(PayloadType::Media.into())
        );
    }

    #[test]
    fn test_audio_subscription_with_jid() {
        let jid = "user@s.whatsapp.net:0".to_string();
        let data = create_audio_sender_subscriptions_with_jid(0xABCDEF00, jid.clone());

        let decoded = SenderSubscriptions::decode(data.as_slice()).unwrap();
        assert_eq!(decoded.senders.len(), 1);
        assert_eq!(decoded.senders[0].ssrc, Some(0xABCDEF00));
        assert_eq!(decoded.senders[0].sender_jid, Some(jid));
    }

    #[test]
    fn test_encoding_size() {
        let data = create_audio_sender_subscriptions(0x12345678);

        // Should be relatively small (< 20 bytes for minimal subscription)
        assert!(data.len() < 20);
        println!("Minimal audio subscription size: {} bytes", data.len());
        println!("Encoded bytes: {:?}", data);
    }

    #[test]
    fn test_app_data_subscription_encoding() {
        let data = create_app_data_sender_subscriptions(Some(1), Some("12345:1@lid".to_string()));
        let decoded = SenderSubscriptions::decode(data.as_slice()).unwrap();

        assert_eq!(decoded.senders.len(), 1);
        assert_eq!(decoded.senders[0].pid, Some(1));
        assert_eq!(
            decoded.senders[0].stream_layer,
            Some(StreamLayer::AppDataStream0.into())
        );
        assert_eq!(
            decoded.senders[0].payload_type,
            Some(PayloadType::AppData.into())
        );
    }
}
