use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::ops::Deref;

pub const SIGNATURE_LEN: usize = 64;

/// A 64-byte Ed25519 signature with full Serde and binary serialization support.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct WireSignature(pub [u8; SIGNATURE_LEN]);

impl Default for WireSignature {
    fn default() -> Self {
        Self([0u8; SIGNATURE_LEN])
    }
}

impl WireSignature {
    pub const fn new(bytes: [u8; SIGNATURE_LEN]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; SIGNATURE_LEN] {
        &self.0
    }
}

impl Deref for WireSignature {
    type Target = [u8; SIGNATURE_LEN];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<[u8; SIGNATURE_LEN]> for WireSignature {
    fn from(bytes: [u8; SIGNATURE_LEN]) -> Self {
        Self(bytes)
    }
}

impl From<WireSignature> for [u8; SIGNATURE_LEN] {
    fn from(sig: WireSignature) -> Self {
        sig.0
    }
}

impl fmt::Debug for WireSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = String::with_capacity(16);
        for b in &self.0[0..4] {
            use std::fmt::Write;
            let _ = write!(s, "{:02x}", b);
        }
        write!(f, "WireSignature({}...)", s)
    }
}

impl fmt::Display for WireSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut s = String::with_capacity(128);
        for b in &self.0 {
            use std::fmt::Write;
            let _ = write!(s, "{:02x}", b);
        }
        write!(f, "{}", s)
    }
}

impl Serialize for WireSignature {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for WireSignature {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = WireSignature;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("a 64-byte Ed25519 signature")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.len() == SIGNATURE_LEN {
                    let mut arr = [0u8; SIGNATURE_LEN];
                    arr.copy_from_slice(v);
                    Ok(WireSignature(arr))
                } else {
                    Err(E::invalid_length(v.len(), &self))
                }
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut arr = [0u8; SIGNATURE_LEN];
                let mut idx = 0;
                while let Some(b) = seq.next_element()? {
                    if idx >= SIGNATURE_LEN {
                        return Err(serde::de::Error::invalid_length(idx + 1, &self));
                    }
                    arr[idx] = b;
                    idx += 1;
                }
                if idx != SIGNATURE_LEN {
                    return Err(serde::de::Error::invalid_length(idx, &self));
                }
                Ok(WireSignature(arr))
            }
        }

        deserializer.deserialize_bytes(Visitor)
    }
}
