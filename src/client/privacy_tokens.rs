//! Trusted contact privacy token helpers.

use crate::client::Client;
use crate::jid_utils::server_jid;
use crate::request::{InfoQuery, InfoQueryType, IqError};
use base64::Engine;
use log::{debug, warn};
use std::collections::HashSet;
use std::time::Duration;
use wacore_binary::builder::NodeBuilder;
use wacore_binary::jid::Jid;
use wacore_binary::node::{Node, NodeContent};

impl Client {
    async fn trusted_contact_token_keys_for_jid(&self, jid: &Jid) -> Vec<String> {
        let mut keys = Vec::new();
        let mut seen = HashSet::new();
        let base = jid.to_non_ad();

        let mut push_key = |k: String| {
            if seen.insert(k.clone()) {
                keys.push(k);
            }
        };

        push_key(base.to_string());

        if let Some(lid) = self.lid_pn_cache.get_current_lid(&base.user).await {
            push_key(Jid::lid(&lid).to_string());
        }

        if let Some(pn) = self.lid_pn_cache.get_phone_number(&base.user).await {
            push_key(Jid::pn(&pn).to_string());
        }

        keys
    }

    pub(crate) async fn store_trusted_contact_token(&self, jid: &Jid, token: Vec<u8>) {
        for key in self.trusted_contact_token_keys_for_jid(jid).await {
            self.trusted_contact_tokens.insert(key, token.clone()).await;
        }
    }

    pub(crate) async fn get_trusted_contact_token(&self, jid: &Jid) -> Option<Vec<u8>> {
        for key in self.trusted_contact_token_keys_for_jid(jid).await {
            if let Some(token) = self.trusted_contact_tokens.get(&key).await {
                return Some(token);
            }
        }
        None
    }

    pub async fn ensure_trusted_contact_token(&self, jid: &Jid) -> Option<Vec<u8>> {
        if let Some(token) = self.get_trusted_contact_token(jid).await {
            return Some(token);
        }

        if let Ok(token) = self.fetch_trusted_contact_token(jid).await
            && token.is_some()
        {
            return token;
        }

        // Try alternate address family if mapping exists.
        let base = jid.to_non_ad();
        if base.is_lid() {
            if let Some(pn) = self.lid_pn_cache.get_phone_number(&base.user).await {
                let alt = Jid::pn(&pn);
                if let Ok(token) = self.fetch_trusted_contact_token(&alt).await
                    && token.is_some()
                {
                    return token;
                }
            }
        } else if let Some(lid) = self.lid_pn_cache.get_current_lid(&base.user).await {
            let alt = Jid::lid(&lid);
            if let Ok(token) = self.fetch_trusted_contact_token(&alt).await
                && token.is_some()
            {
                return token;
            }
        }

        None
    }

    pub(crate) async fn fetch_trusted_contact_token(
        &self,
        jid: &Jid,
    ) -> Result<Option<Vec<u8>>, IqError> {
        let target = jid.to_non_ad();
        let timestamp = chrono::Utc::now().timestamp().to_string();
        let token_request = NodeBuilder::new("token")
            .attr("jid", target.to_string())
            .attr("t", timestamp)
            .attr("type", "trusted_contact")
            .build();
        let tokens = NodeBuilder::new("tokens")
            .children(std::iter::once(token_request))
            .build();

        let query = InfoQuery {
            namespace: "privacy",
            query_type: InfoQueryType::Set,
            to: server_jid(),
            target: None,
            content: Some(NodeContent::Nodes(vec![tokens])),
            id: None,
            timeout: Some(Duration::from_secs(15)),
        };

        let response = self.send_iq(query).await?;
        let parsed = extract_trusted_contact_tokens(&response);
        if parsed.is_empty() {
            debug!("No trusted_contact token returned for {}", target);
            return Ok(None);
        }

        for (token_jid, token, _timestamp) in &parsed {
            if let Some(token_jid) = token_jid {
                self.store_trusted_contact_token(token_jid, token.clone()).await;
            } else {
                self.store_trusted_contact_token(&target, token.clone()).await;
            }
        }

        Ok(self.get_trusted_contact_token(&target).await)
    }
}

fn extract_trusted_contact_tokens(node: &Node) -> Vec<(Option<Jid>, Vec<u8>, Option<String>)> {
    let mut out = Vec::new();
    extract_trusted_contact_tokens_recursive(node, &mut out);
    out
}

fn extract_trusted_contact_tokens_recursive(
    node: &Node,
    out: &mut Vec<(Option<Jid>, Vec<u8>, Option<String>)>,
) {
    if node.tag == "token" {
        let mut attrs = node.attrs();
        let token_type = attrs.optional_string("type").unwrap_or_default();
        if token_type == "trusted_contact" {
            let token_jid = attrs.optional_jid("jid");
            let timestamp = attrs.optional_string("t").map(|s| s.to_string());
            let token_bytes = match &node.content {
                Some(NodeContent::Bytes(b)) => Some(b.clone()),
                Some(NodeContent::String(s)) => {
                    // Fallback for servers/clients that serialize token content as base64 string.
                    base64::engine::general_purpose::STANDARD
                        .decode(s)
                        .ok()
                        .or_else(|| Some(s.as_bytes().to_vec()))
                }
                _ => None,
            };

            if let Some(token_bytes) = token_bytes {
                out.push((token_jid, token_bytes, timestamp));
            } else {
                warn!("trusted_contact token without bytes payload");
            }
        }
    }

    if let Some(children) = node.children() {
        for child in children {
            extract_trusted_contact_tokens_recursive(child, out);
        }
    }
}
