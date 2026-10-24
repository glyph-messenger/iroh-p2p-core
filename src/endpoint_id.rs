use iroh_base::PublicKey;
use serde::{Deserialize, Serialize};
use std::fmt;
use std::str::FromStr;

use crate::error::{P2pError, Result};

pub const ENDPOINT_ID_LEN: usize = 32;

/// Unique 32-byte Ed25519 public key identifier for an iroh network node.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default, Serialize, Deserialize)]
pub struct EndpointId(pub [u8; ENDPOINT_ID_LEN]);

impl EndpointId {
    pub const fn from_bytes(bytes: [u8; ENDPOINT_ID_LEN]) -> Self {
        Self(bytes)
    }

    pub fn from_slice(slice: &[u8]) -> Result<Self> {
        if slice.len() != ENDPOINT_ID_LEN {
            return Err(P2pError::PublicKey(format!(
                "expected {} bytes, got {}",
                ENDPOINT_ID_LEN,
                slice.len()
            )));
        }
        let mut arr = [0u8; ENDPOINT_ID_LEN];
        arr.copy_from_slice(slice);
        Ok(Self(arr))
    }

    pub fn as_bytes(&self) -> &[u8; ENDPOINT_ID_LEN] {
        &self.0
    }

    pub fn to_hex(&self) -> String {
        let mut s = String::with_capacity(ENDPOINT_ID_LEN * 2);
        for b in &self.0 {
            use std::fmt::Write;
            let _ = write!(s, "{:02x}", b);
        }
        s
    }

    pub fn short_hex(&self) -> String {
        self.fmt_short_len(4)
    }

    pub fn fmt_short(&self) -> String {
        self.short_hex()
    }

    pub fn fmt_short_len(&self, chars_per_side: usize) -> String {
        let full = self.to_hex();
        let n = chars_per_side.clamp(2, 16);
        format!("{}...{}", &full[0..n], &full[full.len() - n..])
    }

    pub fn hex_prefix(&self, bytes_count: usize) -> String {
        let full = self.to_hex();
        let n = (bytes_count * 2).min(full.len());
        full[..n].to_string()
    }

    pub fn to_iroh_pubkey(&self) -> Result<PublicKey> {
        PublicKey::from_bytes(&self.0).map_err(|e| P2pError::PublicKey(e.to_string()))
    }
}

impl fmt::Display for EndpointId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if f.alternate() {
            write!(f, "{}", self.short_hex())
        } else {
            write!(f, "{}", self.to_hex())
        }
    }
}

impl fmt::Debug for EndpointId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EndpointId({})", self.short_hex())
    }
}

impl FromStr for EndpointId {
    type Err = P2pError;

    fn from_str(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.len() != ENDPOINT_ID_LEN * 2 || !s.is_ascii() {
            return Err(P2pError::PublicKey(format!(
                "expected {} ASCII hex characters, got byte length {}",
                ENDPOINT_ID_LEN * 2,
                s.len()
            )));
        }
        let mut bytes = [0u8; ENDPOINT_ID_LEN];
        for i in 0..ENDPOINT_ID_LEN {
            bytes[i] = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16)
                .map_err(|e| P2pError::PublicKey(e.to_string()))?;
        }
        Ok(Self(bytes))
    }
}

impl From<[u8; ENDPOINT_ID_LEN]> for EndpointId {
    fn from(bytes: [u8; ENDPOINT_ID_LEN]) -> Self {
        Self(bytes)
    }
}

impl From<EndpointId> for [u8; ENDPOINT_ID_LEN] {
    fn from(id: EndpointId) -> Self {
        id.0
    }
}

impl From<PublicKey> for EndpointId {
    fn from(pk: PublicKey) -> Self {
        Self(*pk.as_bytes())
    }
}

impl TryFrom<&[u8]> for EndpointId {
    type Error = P2pError;

    fn try_from(slice: &[u8]) -> Result<Self> {
        Self::from_slice(slice)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_endpoint_id_hex_roundtrip() {
        let id = EndpointId([42u8; 32]);
        let hex = id.to_hex();
        assert_eq!(hex.len(), 64);
        let parsed: EndpointId = hex.parse().unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn test_endpoint_id_short_hex() {
        let id = EndpointId([0xab; 32]);
        assert_eq!(id.short_hex(), "abab...abab");
    }

    #[test]
    fn test_endpoint_id_non_ascii_multibyte_no_panic() {
        // "€" is 3 bytes (0xE2, 0x82, 0xAC). Total byte length is 3 + 61 = 64 bytes.
        let hostile = format!("€{}", "a".repeat(61));
        assert_eq!(hostile.len(), 64);
        let res: Result<EndpointId> = hostile.parse();
        assert!(matches!(res, Err(P2pError::PublicKey(_))));
    }
}
