use data_encoding::BASE32_NOPAD;
use iroh::{EndpointAddr, RelayUrl};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use crate::endpoint_id::EndpointId;
use crate::error::{P2pError, Result};
use crate::identity::{Identity, verify};
use crate::signature::WireSignature;

pub const TICKET_SIGN_DOMAIN: &[u8] = b"iroh-p2p-ticket-v1";

/// A self-contained, cryptographically signed ticket enabling nodes to discover and join P2P swarms.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct SignedTicket<T> {
    pub endpoint_id: EndpointId,
    pub relay_url: Option<String>,
    pub direct_addrs: Vec<SocketAddr>,
    pub created_at_ms: u64,
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
            payload,
            signature: WireSignature::default(),
        }
    }

    /// Construct and sign a ticket directly from an active `iroh::EndpointAddr`.
    pub fn from_endpoint_addr(
        identity: &Identity,
        addr: &EndpointAddr,
        payload: T,
        created_at_ms: u64,
    ) -> Self {
        let relay_url = addr.relay_urls().next().map(|u| u.to_string());
        let direct_addrs: Vec<SocketAddr> = addr.ip_addrs().copied().collect();
        let mut ticket = Self::new_unsigned(
            identity.endpoint_id(),
            relay_url,
            direct_addrs,
            created_at_ms,
            payload,
        );
        ticket.sign(identity);
        ticket
    }

    /// Canonical sign bytes including domain separator.
    pub fn sign_bytes(&self) -> Vec<u8> {
        #[derive(Serialize)]
        struct Payload<'a, P> {
            domain: &'static [u8],
            endpoint_id: &'a EndpointId,
            relay_url: &'a Option<String>,
            direct_addrs: &'a [SocketAddr],
            created_at_ms: u64,
            payload: &'a P,
        }

        let wrapper = Payload {
            domain: TICKET_SIGN_DOMAIN,
            endpoint_id: &self.endpoint_id,
            relay_url: &self.relay_url,
            direct_addrs: &self.direct_addrs,
            created_at_ms: self.created_at_ms,
            payload: &self.payload,
        };

        bincode::serialize(&wrapper).unwrap_or_default()
    }

    /// Sign the ticket using the creator's Identity.
    pub fn sign(&mut self, identity: &Identity) {
        let bytes = self.sign_bytes();
        self.signature = WireSignature(identity.sign(&bytes));
    }

    /// Cryptographically verify ticket signature against the embedded endpoint_id.
    pub fn verify(&self) -> Result<()> {
        let bytes = self.sign_bytes();
        verify(&self.endpoint_id, &bytes, self.signature.as_bytes())
    }

    /// Encode ticket into a compact Base32 string with the specified prefix.
    pub fn encode_base32(&self, prefix: &str) -> Result<String> {
        let binary = bincode::serialize(self)?;
        let mut encoded = BASE32_NOPAD.encode(&binary);
        encoded.make_ascii_lowercase();
        Ok(format!("{prefix}{encoded}"))
    }

    /// Decode and verify ticket from a Base32 string.
    pub fn decode_base32(s: &str, prefix: &str) -> Result<Self> {
        let s = s.trim();
        let rest = s.strip_prefix(prefix).unwrap_or(s);
        let binary = BASE32_NOPAD
            .decode(rest.to_ascii_uppercase().as_bytes())
            .map_err(|e| P2pError::TicketFormat(e.to_string()))?;
        let ticket: Self = bincode::deserialize(&binary)?;
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
        ticket.sign(&id);
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
        ticket.sign(&id);

        let mut tampered = ticket.clone();
        tampered.payload = "evil-room".to_string();
        assert!(tampered.verify().is_err());
    }
}
