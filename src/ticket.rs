use data_encoding::BASE32_NOPAD;
use iroh::{EndpointAddr, RelayUrl};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::endpoint_id::EndpointId;
use crate::error::{P2pError, Result};
use crate::identity::{Identity, verify};
use crate::signature::WireSignature;

pub const TICKET_SIGN_DOMAIN: &[u8] = b"iroh-p2p-ticket-v1";
pub const DEFAULT_MAX_TICKET_STRING_LEN: usize = 64 * 1024; // 64 KB limit

/// A self-contained, cryptographically signed ticket enabling nodes to discover and join P2P swarms.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SignedTicket<T> {
    pub endpoint_id: EndpointId,
    pub relay_url: Option<String>,
    pub direct_addrs: Vec<SocketAddr>,
    pub created_at_ms: u64,
    #[serde(default)]
    pub app_scope: Option<String>,
    pub payload: T,
    pub signature: WireSignature,
}

impl<T: Serialize + for<'de> Deserialize<'de> + Clone> SignedTicket<T> {
    pub fn new_unsigned(
        endpoint_id: EndpointId,
        relay_url: Option<String>,
        direct_addrs: Vec<SocketAddr>,
        created_at_ms: u64,
        payload: T,
    ) -> Self {
        Self {
            endpoint_id,
            relay_url,
            direct_addrs,
            created_at_ms,
            app_scope: None,
            payload,
            signature: WireSignature::default(),
        }
    }

    /// Construct an unsigned ticket with cryptographic application/protocol domain separation.
    pub fn new_unsigned_scoped(
        endpoint_id: EndpointId,
        relay_url: Option<String>,
        direct_addrs: Vec<SocketAddr>,
        created_at_ms: u64,
        app_scope: impl Into<String>,
        payload: T,
    ) -> Self {
        Self {
            endpoint_id,
            relay_url,
            direct_addrs,
            created_at_ms,
            app_scope: Some(app_scope.into()),
            payload,
            signature: WireSignature::default(),
        }
    }

    /// Attach an application / protocol scope for domain separation.
    pub fn with_app_scope(mut self, scope: impl Into<String>) -> Self {
        self.app_scope = Some(scope.into());
        self
    }

    /// Construct and sign a ticket directly from an active `iroh::EndpointAddr`.
    pub fn from_endpoint_addr(
        identity: &Identity,
        addr: &EndpointAddr,
        payload: T,
        created_at_ms: u64,
    ) -> Result<Self> {
        let relay_url = addr.relay_urls().next().map(|u| u.to_string());
        let direct_addrs: Vec<SocketAddr> = addr.ip_addrs().copied().collect();
        let mut ticket = Self::new_unsigned(
            identity.endpoint_id(),
            relay_url,
            direct_addrs,
            created_at_ms,
            payload,
        );
        ticket.sign(identity)?;
        Ok(ticket)
    }

    /// Canonical sign bytes including domain separator and optional application scope.
    pub fn sign_bytes(&self) -> Result<Vec<u8>> {
        #[derive(Serialize)]
        struct Payload<'a, P> {
            domain: &'static [u8],
            app_scope: &'a Option<String>,
            endpoint_id: &'a EndpointId,
            relay_url: &'a Option<String>,
            direct_addrs: &'a [SocketAddr],
            created_at_ms: u64,
            payload: &'a P,
        }

        let wrapper = Payload {
            domain: TICKET_SIGN_DOMAIN,
            app_scope: &self.app_scope,
            endpoint_id: &self.endpoint_id,
            relay_url: &self.relay_url,
            direct_addrs: &self.direct_addrs,
            created_at_ms: self.created_at_ms,
            payload: &self.payload,
        };

        Ok(bincode::serialize(&wrapper)?)
    }

    /// Sign the ticket using the creator's Identity.
    pub fn sign(&mut self, identity: &Identity) -> Result<()> {
        let bytes = self.sign_bytes()?;
        self.signature = WireSignature(identity.sign(&bytes));
        Ok(())
    }

    /// Cryptographically verify ticket signature against the embedded endpoint_id.
    pub fn verify(&self) -> Result<()> {
        let bytes = self.sign_bytes()?;
        verify(&self.endpoint_id, &bytes, self.signature.as_bytes())
    }

    /// Encode ticket into a compact Base32 string with the specified prefix.
    ///
    /// If the ticket has an `app_scope`, verifies that the prefix matches `app_scope`.
    pub fn encode_base32(&self, prefix: &str) -> Result<String> {
        if let Some(scope) = &self.app_scope
            && scope != prefix
        {
            return Err(P2pError::TicketFormat(format!(
                "ticket app_scope '{scope}' does not match prefix '{prefix}'"
            )));
        }
        let binary = bincode::serialize(self)?;
        let mut encoded = BASE32_NOPAD.encode(&binary);
        encoded.make_ascii_lowercase();
        Ok(format!("{prefix}{encoded}"))
    }

    /// Decode and verify ticket from a Base32 string.
    ///
    /// Validates maximum string length, enforces required prefix match (no silent fallback),
    /// verifies `app_scope` if present, and cryptographically checks the Ed25519 signature.
    pub fn decode_base32(s: &str, prefix: &str) -> Result<Self> {
        Self::decode_base32_bounded(s, prefix, DEFAULT_MAX_TICKET_STRING_LEN)
    }

    /// Decode and verify ticket with a custom maximum length limit.
    pub fn decode_base32_bounded(s: &str, prefix: &str, max_len: usize) -> Result<Self> {
        let s = s.trim();
        if s.len() > max_len {
            return Err(P2pError::TicketFormat(format!(
                "ticket string length {} exceeds maximum allowed {}",
                s.len(),
                max_len
            )));
        }

        let rest = s.strip_prefix(prefix).ok_or_else(|| {
            P2pError::TicketFormat(format!(
                "ticket does not start with expected prefix '{prefix}'"
            ))
        })?;

        let binary = BASE32_NOPAD
            .decode(rest.to_ascii_uppercase().as_bytes())
            .map_err(|e| P2pError::TicketFormat(e.to_string()))?;

        let ticket: Self = bincode::deserialize(&binary)?;

        if let Some(scope) = &ticket.app_scope
            && scope != prefix
        {
            return Err(P2pError::TicketFormat(format!(
                "ticket app_scope '{scope}' does not match expected prefix '{prefix}'"
            )));
        }

        ticket.verify()?;
        Ok(ticket)
    }

    /// Convert ticket into an iroh `EndpointAddr`.
    pub fn to_endpoint_addr(&self) -> Result<EndpointAddr> {
        let pubkey = self.endpoint_id.to_iroh_pubkey()?;
        let mut addr = EndpointAddr::new(pubkey);

        if let Some(url_str) = &self.relay_url {
            let trimmed = url_str.trim();
            if !trimmed.is_empty()
                && let Ok(relay) = trimmed.parse::<RelayUrl>()
            {
                addr = addr.with_relay_url(relay);
            }
        }

        for &sock in &self.direct_addrs {
            addr = addr.with_ip_addr(sock);
        }

        Ok(addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
    struct DemoPayload {
        name: String,
        room: u32,
    }

    #[test]
    fn test_ticket_encode_decode_roundtrip() {
        let id = Identity::generate();
        let payload = DemoPayload {
            name: "AlphaRoom".into(),
            room: 101,
        };

        let mut ticket = SignedTicket::new_unsigned(
            id.endpoint_id(),
            Some("https://relay.example.com".into()),
            vec!["127.0.0.1:4000".parse().unwrap()],
            1700000000000,
            payload.clone(),
        );
        ticket.sign(&id).unwrap();
        assert!(ticket.verify().is_ok());

        let prefix = "demo:v1:";
        let encoded = ticket.encode_base32(prefix).unwrap();
        assert!(encoded.starts_with(prefix));

        let decoded = SignedTicket::<DemoPayload>::decode_base32(&encoded, prefix).unwrap();
        assert_eq!(ticket, decoded);
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn test_ticket_tampering_fails() {
        let id = Identity::generate();
        let mut ticket = SignedTicket::new_unsigned(
            id.endpoint_id(),
            None,
            vec![],
            1700000000000,
            "secret-room".to_string(),
        );
        ticket.sign(&id).unwrap();

        let mut tampered = ticket.clone();
        tampered.payload = "evil-room".to_string();
        assert!(tampered.verify().is_err());
    }

    #[test]
    fn test_ticket_cross_application_tampering_fails() {
        let id = Identity::generate();
        let prefix_a = "glyph:v1:";
        let prefix_b = "rune-net:v1:";

        // Generate a ticket cryptographically scoped to "glyph:v1:"
        let mut ticket_a = SignedTicket::new_unsigned_scoped(
            id.endpoint_id(),
            None,
            vec![],
            1700000000000,
            prefix_a,
            "payload-data".to_string(),
        );
        ticket_a.sign(&id).unwrap();

        let encoded_a = ticket_a.encode_base32(prefix_a).unwrap();

        // 1. Trying to decode encoded_a with prefix_b fails immediately due to prefix check
        let res1 = SignedTicket::<String>::decode_base32(&encoded_a, prefix_b);
        assert!(matches!(res1, Err(P2pError::TicketFormat(_))));

        // 2. An attacker strips "glyph:v1:" and prepends "rune-net:v1:"
        let raw_base32 = encoded_a.strip_prefix(prefix_a).unwrap();
        let forged_for_b = format!("{prefix_b}{raw_base32}");

        // Attempting to decode forged ticket under prefix_b fails because app_scope is cryptographically bound!
        let res2 = SignedTicket::<String>::decode_base32(&forged_for_b, prefix_b);
        assert!(matches!(res2, Err(P2pError::TicketFormat(_))));
    }

    #[test]
    fn test_ticket_missing_prefix_rejected() {
        let id = Identity::generate();
        let mut ticket = SignedTicket::new_unsigned(
            id.endpoint_id(),
            None,
            vec![],
            1700000000000,
            "data".to_string(),
        );
        ticket.sign(&id).unwrap();

        let encoded = ticket.encode_base32("app:v1:").unwrap();
        // Decode expecting "other:v1:" fails immediately
        let res = SignedTicket::<String>::decode_base32(&encoded, "other:v1:");
        assert!(matches!(res, Err(P2pError::TicketFormat(_))));
    }

    #[test]
    fn test_ticket_oversized_string_rejected() {
        let hostile = "a".repeat(DEFAULT_MAX_TICKET_STRING_LEN + 1);
        let res = SignedTicket::<String>::decode_base32(&hostile, "app:");
        assert!(matches!(res, Err(P2pError::TicketFormat(_))));
    }
}
