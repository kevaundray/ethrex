use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum BinaryTrieError {
    /// The empty key is a prefix of every other key.
    #[error("empty key")]
    EmptyKey,
    /// Key exceeds MAX_KEY_LENGTH (8192 bytes), past which a branch
    /// prefix bit count could overflow its two-byte encoding.
    #[error("key longer than 8192 bytes")]
    KeyTooLong,
    /// Inserting this key would make some key a prefix of another,
    /// which the tree cannot represent (a leaf terminates its path).
    #[error("key is a prefix of another key in the trie")]
    PrefixViolation,
}
