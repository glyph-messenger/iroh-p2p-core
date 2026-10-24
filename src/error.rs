use thiserror::Error;

pub type Result<T, E = P2pError> = std::result::Result<T, E>;

#[derive(Error, Debug)]
pub enum P2pError {
    #[error("invalid Ed25519 public key / endpoint id: {0}")]
    PublicKey(String),

    #[error("cryptographic signature verification failed: {0}")]
    Signature(String),

    #[error("replay detected for nonce {0:?}")]
    ReplayDetected([u8; 16]),

    #[error("replay filter capacity exceeded ({capacity}); active nonces cannot be pruned")]
    ReplayFilterFull { capacity: usize },

    #[error("peerbook capacity exceeded (max {0} peers)")]
    PeerBookFull(usize),

    #[error("timestamp skew exceeded: timestamp={timestamp_ms}ms, local_now={now_ms}ms")]
    TimestampSkew { timestamp_ms: u64, now_ms: u64 },

    #[error("invalid ticket format: {0}")]
    TicketFormat(String),

    #[error("invalid network address: {0}")]
    InvalidAddress(String),

    #[error("incoming frame size {size} exceeds maximum {max}")]
    FrameTooLarge { size: usize, max: usize },

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] bincode::Error),

    #[error("{0}")]
    Other(String),
}
