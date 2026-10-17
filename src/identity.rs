use iroh_base::{PublicKey, SecretKey, Signature};
use std::path::Path;

use crate::endpoint_id::EndpointId;
use crate::error::{P2pError, Result};
use crate::signature::{SIGNATURE_LEN, WireSignature};

/// Persistent node identity wrapping an Ed25519 secret key.
#[derive(Clone)]
pub struct Identity {
    secret: SecretKey,
}

impl Identity {
    pub fn generate() -> Self {
        Self {
            secret: SecretKey::generate(),
        }
    }

    pub fn from_secret(secret: SecretKey) -> Self {
        Self { secret }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            secret: SecretKey::from_bytes(bytes),
        }
    }

    /// Load identity from file or create a newly generated one and save it.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
            Self::load(path)
        } else {
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let id = Self::generate();
            id.save(path)?;
            Ok(id)
        }
    }

    /// Load 32-byte private key from disk.
    pub fn load(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path)?;
        if bytes.len() != 32 {
            return Err(P2pError::PublicKey(format!(
                "invalid private key file length: {}",
                bytes.len()
            )));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Ok(Self::from_bytes(&key))
    }

    /// Save identity key to disk, setting 0600 file permissions on Unix.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(path, self.secret.to_bytes())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(path)?.permissions();
            perms.set_mode(0o600);
            std::fs::set_permissions(path, perms)?;
        }
        Ok(())
    }

    pub fn secret(&self) -> &SecretKey {
        &self.secret
    }

    pub fn public(&self) -> PublicKey {
        self.secret.public()
    }

    pub fn endpoint_id(&self) -> EndpointId {
        EndpointId(*self.public().as_bytes())
    }

    pub fn sign(&self, msg: &[u8]) -> [u8; SIGNATURE_LEN] {
        let sig = self.secret.sign(msg);
        sig.to_bytes()
    }

    pub fn sign_wire(&self, msg: &[u8]) -> WireSignature {
        WireSignature(self.sign(msg))
    }
}

/// Verify an Ed25519 signature against an EndpointId.
pub fn verify(sender: &EndpointId, msg: &[u8], signature: &[u8; SIGNATURE_LEN]) -> Result<()> {
    let pk =
        PublicKey::from_bytes(sender.as_bytes()).map_err(|e| P2pError::PublicKey(e.to_string()))?;
    let sig = Signature::from_bytes(signature);
    pk.verify(msg, &sig)
        .map_err(|e| P2pError::Signature(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_identity_sign_and_verify() {
        let id = Identity::generate();
        let msg = b"P2P Core Authentication Message";
        let sig = id.sign(msg);
        assert!(verify(&id.endpoint_id(), msg, &sig).is_ok());

        let corrupted = b"Corrupted Message Content";
        assert!(verify(&id.endpoint_id(), corrupted, &sig).is_err());
    }

    #[test]
    fn test_identity_persistence() {
        let tmp = std::env::temp_dir().join(format!("p2p-test-id-{}", rand::random::<u64>()));
        let id1 = Identity::generate();
        id1.save(&tmp).unwrap();

        let id2 = Identity::load(&tmp).unwrap();
        assert_eq!(id1.endpoint_id(), id2.endpoint_id());
        let _ = std::fs::remove_file(tmp);
    }
}
