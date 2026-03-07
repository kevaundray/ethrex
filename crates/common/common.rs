#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub use ethereum_types::*;
pub mod constants;
#[cfg(feature = "std")]
pub mod serde_utils;
pub mod types;
pub mod validation;
pub use bytes::Bytes;
#[cfg(feature = "std")]
pub mod base64;
#[cfg(feature = "std")]
pub use ethrex_trie::{TrieLogger, TrieWitness};
pub mod errors;
pub mod evm;
#[cfg(feature = "std")]
pub mod fd_limit;
#[cfg(feature = "std")]
pub mod genesis_utils;
#[cfg(feature = "std")]
pub mod rkyv_utils;
#[cfg(feature = "std")]
pub mod tracing;
pub mod utils;

pub use errors::{EcdsaError, InvalidBlockError};
pub use validation::{
    get_total_blob_gas, validate_block_access_list_hash, validate_block_pre_execution,
    validate_gas_used, validate_receipts_root, validate_requests_hash,
};
