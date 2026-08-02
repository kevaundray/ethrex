//! Raw EIP-8297 binary tree: a compressed binary radix trie mapping
//! prefix-free variable-length bit keys to 32-byte values, committing
//! to its contents with BLAKE3 hashes up to a single root.

mod binary_trie;
pub mod bits;
pub mod node;
pub mod proof;
pub mod rebuild;

pub use binary_trie::BinaryTrie;
pub use node::EMPTY_TRIE_ROOT;
pub use proof::{ProofError, verify_proof};

/// Longest accepted key, in bytes. Bounds branch-prefix bit counts
/// below the two-byte limit of `encode_bit_prefix`.
pub const MAX_KEY_LENGTH: usize = 8192;
