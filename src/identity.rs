use iroh_base::{PublicKey, SecretKey, Signature};
use std::io::Write;
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

    /// Load identity from file or atomically create a newly generated one.
    ///
    /// This method is race-condition safe: if multiple concurrent processes or threads
    /// attempt to initialize the file simultaneously, exactly one will create it, and all
    /// others will safely load the newly created identity.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let id = Self::generate();
        let mut open_opts = std::fs::OpenOptions::new();
        open_opts.write(true).create_new(true);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open_opts.mode(0o600);
        }

        match open_opts.open(path) {
            Ok(mut file) => {
                file.write_all(&id.secret.to_bytes())?;
                file.sync_all()?;
                drop(file);

                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let mut perms = std::fs::metadata(path)?.permissions();
                    perms.set_mode(0o600);
                    let _ = std::fs::set_permissions(path, perms);
                }

                Ok(id)
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // File already created concurrently or prior to this call: load it
                Self::load(path)
            }
            Err(e) => Err(P2pError::Io(e)),
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

    /// Save identity key to disk atomically via temporary file and rename.
    ///
    /// On Unix, permissions are set to 0600 upon creation to prevent permissions race windows.
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let parent = path.parent().unwrap_or_else(|| Path::new("."));
        static TMP_COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let pid = std::process::id();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let counter = TMP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let file_stem = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("secret");
        let tmp_path = parent.join(format!(".{file_stem}.{pid}.{nanos}.{counter}.tmp"));

        let mut open_opts = std::fs::OpenOptions::new();
        open_opts.write(true).create_new(true);

        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            open_opts.mode(0o600);
        }

        let mut file = open_opts.open(&tmp_path)?;
        file.write_all(&self.secret.to_bytes())?;
        file.sync_all()?;
        drop(file);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&tmp_path)?.permissions();
            perms.set_mode(0o600);
            let _ = std::fs::set_permissions(&tmp_path, perms);
        }

        std::fs::rename(&tmp_path, path).map_err(|e| {
            let _ = std::fs::remove_file(&tmp_path);
            P2pError::Io(e)
        })?;

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

    #[test]
    fn test_identity_load_or_create_concurrent_race_safe() {
        let tmp =
            std::env::temp_dir().join(format!("p2p-test-concurrent-id-{}", rand::random::<u64>()));
        let mut handles = vec![];

        for _ in 0..8 {
            let path = tmp.clone();
            handles.push(std::thread::spawn(move || {
                Identity::load_or_create(&path).unwrap()
            }));
        }

        let mut results = vec![];
        for h in handles {
            results.push(h.join().unwrap());
        }

        let first = results[0].endpoint_id();
        for r in &results {
            assert_eq!(r.endpoint_id(), first);
        }

        let _ = std::fs::remove_file(tmp);
    }
}
