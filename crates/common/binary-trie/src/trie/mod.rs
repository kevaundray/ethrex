//! Raw EIP-8297 binary tree: a compressed binary radix trie mapping
//! prefix-free variable-length bit keys to 32-byte values, committing
//! to its contents with BLAKE3 hashes up to a single root.

pub mod bits;
