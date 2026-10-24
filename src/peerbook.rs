use iroh::{EndpointAddr, RelayUrl};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use crate::endpoint_id::EndpointId;
use crate::error::{P2pError, Result};

pub const DEFAULT_MAX_PEERS: usize = 10_000;

/// A thread-safe dynamic catalog of remote peer addresses (direct IP endpoints and Relay URLs).
#[derive(Clone, Debug)]
pub struct PeerBook {
    peers: Arc<RwLock<HashMap<EndpointId, EndpointAddr>>>,
    max_peers: usize,
}

impl Default for PeerBook {
    fn default() -> Self {
        Self::new()
    }
}

impl PeerBook {
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_MAX_PEERS)
    }

    pub fn with_capacity(max_peers: usize) -> Self {
        Self {
            peers: Arc::new(RwLock::new(HashMap::new())),
            max_peers,
        }
    }

    /// Insert or update a peer's `EndpointAddr` atomically.
    pub fn update(&self, addr: EndpointAddr) {
        let _ = self.try_update(addr);
    }

    /// Fallible version of `update` that returns an error if `max_peers` is exceeded.
    pub fn try_update(&self, addr: EndpointAddr) -> Result<()> {
        let id = EndpointId::from(addr.id);
        let mut map = self.peers.write();
        if map.len() >= self.max_peers && !map.contains_key(&id) {
            return Err(P2pError::PeerBookFull(self.max_peers));
        }

        let existing = map.entry(id).or_insert_with(|| addr.clone());
        if existing != &addr {
            for r in addr.relay_urls() {
                let mut has_r = false;
                for er in existing.relay_urls() {
                    if er == r {
                        has_r = true;
                        break;
                    }
                }
                if !has_r {
                    *existing = existing.clone().with_relay_url(r.clone());
                }
            }
            for ip in addr.ip_addrs() {
                let mut has_ip = false;
                for eip in existing.ip_addrs() {
                    if eip == ip {
                        has_ip = true;
                        break;
                    }
                }
                if !has_ip {
                    *existing = existing.clone().with_ip_addr(*ip);
                }
            }
        }
        Ok(())
    }

    /// Atomically update peer addresses from raw relay URL string and slice of socket addresses.
    /// Addresses are validated upfront and mutations are performed under a single write lock.
    pub fn update_raw(
        &self,
        peer: EndpointId,
        relay_url: Option<&str>,
        direct_addrs: &[SocketAddr],
    ) -> Result<()> {
        let pubkey = peer.to_iroh_pubkey()?;
        let relay = if let Some(r_str) = relay_url {
            let trimmed = r_str.trim();
            if trimmed.is_empty() {
                None
            } else {
                Some(trimmed.parse::<RelayUrl>().map_err(|e| {
                    P2pError::InvalidAddress(format!("invalid relay URL '{trimmed}': {e}"))
                })?)
            }
        } else {
            None
        };

        let mut map = self.peers.write();
        if map.len() >= self.max_peers && !map.contains_key(&peer) {
            return Err(P2pError::PeerBookFull(self.max_peers));
        }

        let entry = map.entry(peer).or_insert_with(|| EndpointAddr::new(pubkey));
        if let Some(r) = relay {
            let mut has_r = false;
            for er in entry.relay_urls() {
                if er == &r {
                    has_r = true;
                    break;
                }
            }
            if !has_r {
                *entry = entry.clone().with_relay_url(r);
            }
        }

        for &ip in direct_addrs {
            let mut has_ip = false;
            for eip in entry.ip_addrs() {
                if eip == &ip {
                    has_ip = true;
                    break;
                }
            }
            if !has_ip {
                *entry = entry.clone().with_ip_addr(ip);
            }
        }

        Ok(())
    }

    /// Update peer addresses from raw relay URL string and slice of string addresses with strict parsing.
    pub fn update_raw_strings(
        &self,
        peer: EndpointId,
        relay_url: Option<&str>,
        addrs: &[impl AsRef<str>],
    ) -> Result<()> {
        let mut direct = Vec::with_capacity(addrs.len());
        for s in addrs {
            let s_ref = s.as_ref().trim();
            if !s_ref.is_empty() {
                let sock = s_ref.parse::<SocketAddr>().map_err(|e| {
                    P2pError::InvalidAddress(format!("invalid socket address '{s_ref}': {e}"))
                })?;
                direct.push(sock);
            }
        }
        self.update_raw(peer, relay_url, &direct)
    }

    /// Add a direct IP socket address to the peer's record atomically.
    pub fn add_ip(&self, peer: EndpointId, ip: SocketAddr) {
        if let Ok(pubkey) = peer.to_iroh_pubkey() {
            let mut map = self.peers.write();
            if map.len() < self.max_peers || map.contains_key(&peer) {
                let addr = map.entry(peer).or_insert_with(|| EndpointAddr::new(pubkey));
                let mut has_ip = false;
                for existing_ip in addr.ip_addrs() {
                    if existing_ip == &ip {
                        has_ip = true;
                        break;
                    }
                }
                if !has_ip {
                    *addr = addr.clone().with_ip_addr(ip);
                }
            }
        }
    }

    /// Add a Relay URL to the peer's record atomically.
    pub fn add_relay(&self, peer: EndpointId, relay: RelayUrl) {
        if let Ok(pubkey) = peer.to_iroh_pubkey() {
            let mut map = self.peers.write();
            if map.len() < self.max_peers || map.contains_key(&peer) {
                let addr = map.entry(peer).or_insert_with(|| EndpointAddr::new(pubkey));
                let mut has_r = false;
                for er in addr.relay_urls() {
                    if er == &relay {
                        has_r = true;
                        break;
                    }
                }
                if !has_r {
                    *addr = addr.clone().with_relay_url(relay);
                }
            }
        }
    }

    /// Retrieve the known `EndpointAddr` for a peer.
    pub fn get(&self, peer: EndpointId) -> Option<EndpointAddr> {
        self.peers.read().get(&peer).cloned()
    }

    /// Atomically get existing `EndpointAddr` or initialize a bare-bones one from EndpointId under a single lock.
    pub fn get_or_create(&self, peer: EndpointId) -> Result<EndpointAddr> {
        let pubkey = peer.to_iroh_pubkey()?;
        let mut map = self.peers.write();
        if map.len() >= self.max_peers && !map.contains_key(&peer) {
            return Err(P2pError::PeerBookFull(self.max_peers));
        }
        let addr = map.entry(peer).or_insert_with(|| EndpointAddr::new(pubkey));
        Ok(addr.clone())
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

    pub fn max_peers(&self) -> usize {
        self.max_peers
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

    #[test]
    fn test_peerbook_atomic_concurrent_updates() {
        let book = Arc::new(PeerBook::new());
        let id = crate::Identity::generate();
        let peer = id.endpoint_id();

        let s1: SocketAddr = "10.0.0.1:8001".parse().unwrap();
        let s2: SocketAddr = "10.0.0.2:8002".parse().unwrap();

        let b1 = book.clone();
        let b2 = book.clone();

        let t1 = std::thread::spawn(move || {
            b1.update_raw(peer, None, &[s1]).unwrap();
        });

        let t2 = std::thread::spawn(move || {
            b2.update_raw(peer, None, &[s2]).unwrap();
        });

        t1.join().unwrap();
        t2.join().unwrap();

        let addr = book.get(peer).unwrap();
        let addrs: Vec<SocketAddr> = addr.ip_addrs().copied().collect();
        // Both addresses MUST be present, neither clobbered by the other!
        assert_eq!(addrs.len(), 2);
        assert!(addrs.contains(&s1));
        assert!(addrs.contains(&s2));
    }

    #[test]
    fn test_peerbook_invalid_address_returns_error() {
        let book = PeerBook::new();
        let id = crate::Identity::generate();
        let peer = id.endpoint_id();

        let res = book.update_raw_strings(peer, None, &["not-an-ip-address"]);
        assert!(matches!(res, Err(P2pError::InvalidAddress(_))));
    }

    #[test]
    fn test_peerbook_capacity_enforced() {
        let book = PeerBook::with_capacity(1);
        let id1 = crate::Identity::generate().endpoint_id();
        let id2 = crate::Identity::generate().endpoint_id();

        assert!(book.get_or_create(id1).is_ok());
        let res = book.get_or_create(id2);
        assert!(matches!(res, Err(P2pError::PeerBookFull(1))));
    }
}
