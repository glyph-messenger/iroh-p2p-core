//! # iroh-p2p-core
//!
//! Shared core primitives for decentralized P2P applications built on `iroh` and QUIC.
//! Provides unified identity, cryptographic tickets, peer address catalog (PeerBook),
//! anti-replay filtering, and length-prefixed stream framing.

pub mod endpoint_id;
pub mod error;
pub mod framing;
pub mod identity;
pub mod peerbook;
pub mod replay;
pub mod signature;
pub mod ticket;

pub use endpoint_id::{ENDPOINT_ID_LEN, EndpointId};
pub use error::{P2pError, Result};
pub use framing::{
    DEFAULT_MAX_FRAME_SIZE, read_bincode_msg, read_frame, write_bincode_msg, write_frame,
    write_frame_bounded,
};
pub use identity::{Identity, verify};
pub use peerbook::{DEFAULT_MAX_PEERS, PeerBook};
pub use replay::{
    DEFAULT_CAPACITY, DEFAULT_MAX_CLOCK_SKEW_MS, DEFAULT_MAX_FUTURE_SKEW_MS,
    DEFAULT_MAX_PAST_AGE_MS, OverflowPolicy, PeerReplayFilter, ReplayFilter,
};
pub use signature::{SIGNATURE_LEN, WireSignature};
pub use ticket::{DEFAULT_MAX_TICKET_STRING_LEN, SignedTicket, TICKET_SIGN_DOMAIN};
