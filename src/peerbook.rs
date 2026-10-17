use iroh::{EndpointAddr, RelayUrl};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::endpoint_id::EndpointId;
use crate::error::Result;

/// A thread-safe dynamic catalog of remote peer addresses (direct IP endpoints and Relay URLs).
#[derive(Clone, Default, Debug)]
pub struct PeerBook {
    peers: Arc<RwLock<HashMap<EndpointId, EndpointAddr>>>,
}

impl PeerBook {
    pub fn new() -> Self {
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Insert or update a peer's `EndpointAddr`.
    pub fn update(&self, addr: EndpointAddr) {
        let id = EndpointId::from(addr.id);
        let mut map = self.peers.write();
        if let Some(existing) = map.get_mut(&id) {
            for r in addr.relay_urls() {
                *existing = existing.clone().with_relay_url(r.clone());
            }
            for ip in addr.ip_addrs() {
                *existing = existing.clone().with_ip_addr(*ip);
            }
        } else {
            map.insert(id, addr);
        }
    }

    /// Update peer addresses from raw relay URL string and slice of socket addresses.
    pub fn update_raw(
        &self,
        peer: EndpointId,
        relay_url: Option<&str>,
        direct_addrs: &[SocketAddr],
    ) -> Result<()> {
        let pubkey = peer.to_iroh_pubkey()?;
        let mut addr = self
            .peers
            .read()
            .get(&peer)
            .cloned()
            .unwrap_or_else(|| EndpointAddr::new(pubkey));

        if let Some(r_str) = relay_url {
            let trimmed = r_str.trim();
            if !trimmed.is_empty()
                && let Ok(relay) = trimmed.parse::<RelayUrl>()
            {
                addr = addr.with_relay_url(relay);
            }
        }

        for &ip in direct_addrs {
            addr = addr.with_ip_addr(ip);
        }

        self.peers.write().insert(peer, addr);
        Ok(())
    }

    /// Add a direct IP socket address to the peer's record.
    pub fn add_ip(&self, peer: EndpointId, ip: SocketAddr) {
        if let Ok(pubkey) = peer.to_iroh_pubkey() {
            let mut map = self.peers.write();
            let addr = map.entry(peer).or_insert_with(|| EndpointAddr::new(pubkey));
            *addr = addr.clone().with_ip_addr(ip);
        }
    }

    /// Add a Relay URL to the peer's record.
    pub fn add_relay(&self, peer: EndpointId, relay: RelayUrl) {
        if let Ok(pubkey) = peer.to_iroh_pubkey() {
            let mut map = self.peers.write();
            let addr = map.entry(peer).or_insert_with(|| EndpointAddr::new(pubkey));
            *addr = addr.clone().with_relay_url(relay);
        }
    }

    /// Retrieve the known `EndpointAddr` for a peer.
    pub fn get(&self, peer: EndpointId) -> Option<EndpointAddr> {
        self.peers.read().get(&peer).cloned()
    }

    /// Get existing `EndpointAddr` or construct a bare-bones one from EndpointId.
    pub fn get_or_create(&self, peer: EndpointId) -> Result<EndpointAddr> {
        if let Some(addr) = self.get(peer) {
            return Ok(addr);
        }
        let pubkey = peer.to_iroh_pubkey()?;
        let addr = EndpointAddr::new(pubkey);
        self.peers.write().insert(peer, addr.clone());
        Ok(addr)
    }

    /// Remove peer from registry.
    pub fn remove(&self, peer: &EndpointId) -> Option<EndpointAddr> {
        self.peers.write().remove(peer)
    }

    /// Return all registered peer IDs.
    pub fn all_peers(&self) -> Vec<EndpointId> {
        self.peers.read().keys().copied().collect()
    }

    pub fn len(&self) -> usize {
        self.peers.read().len()
    }

    pub fn is_empty(&self) -> bool {
        self.peers.read().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_peerbook_update_and_lookup() {
        let book = PeerBook::new();
        let id = crate::Identity::generate();
        let peer = id.endpoint_id();
        let socket: SocketAddr = "192.168.1.50:9000".parse().unwrap();

        book.add_ip(peer, socket);
        assert_eq!(book.len(), 1);

        let addr = book.get(peer).unwrap();
        assert_eq!(addr.ip_addrs().next(), Some(&socket));
    }
}
