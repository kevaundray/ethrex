//! Incremental insertion-based binary radix trie.
//!
//! The trie retains its node structure across insertions, splitting
//! nodes on descent, and hashes that structure on [`BinaryTrie::root`].
//! Canonical-form invariant: a branch's prefix is exactly the bits its
//! two subtrees share beyond the parent split, so the structure — and
//! therefore the root — depends only on the key/value set, never on
//! insertion order. This matches the rebuild-from-scratch oracle in
//! [`super::rebuild`] for any prefix-free key set.
//!
//! Deliberate simplifications, deferred to the storage-integration
//! plan: no hash caching (every `root()` call rehashes the whole
//! tree), no deletion, and no `TrieDB` backing (all nodes live in
//! memory). Recursion depth is bounded by the key length in bits, so
//! max-length keys could theoretically overflow the stack; embedding
//! keys are at most 66 bytes, and the storage-integration rework is
//! the place to go iterative if ever needed.

use ethereum_types::H256;

use crate::error::BinaryTrieError;

use super::MAX_KEY_LENGTH;
use super::bits::bytes_to_bits;
use super::node::{EMPTY_TRIE_ROOT, branch_hash, branch_preimage, leaf_hash, leaf_preimage};

enum Node {
    Leaf {
        key: Vec<u8>,
        value: [u8; 32],
    },
    Branch {
        /// Bits (0/1 per element) shared by every key below, relative
        /// to the parent's split point.
        prefix: Vec<u8>,
        left: Box<Node>,
        right: Box<Node>,
    },
}

/// Compressed binary radix trie over prefix-free byte keys and
/// 32-byte values, committing to its contents with a BLAKE3 root.
#[derive(Default)]
pub struct BinaryTrie {
    root: Option<Node>,
}

impl BinaryTrie {
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert `key` with `value`, overwriting any existing value for
    /// the same key.
    ///
    /// # Errors
    ///
    /// The trie is left unchanged on every error:
    /// - [`BinaryTrieError::EmptyKey`] if `key` is empty.
    /// - [`BinaryTrieError::KeyTooLong`] if `key` exceeds
    ///   [`MAX_KEY_LENGTH`] bytes.
    /// - [`BinaryTrieError::PrefixViolation`] if inserting `key` would
    ///   make some key a bit-prefix of another.
    pub fn insert(&mut self, key: Vec<u8>, value: [u8; 32]) -> Result<(), BinaryTrieError> {
        if key.is_empty() {
            return Err(BinaryTrieError::EmptyKey);
        }
        if key.len() > MAX_KEY_LENGTH {
            return Err(BinaryTrieError::KeyTooLong);
        }
        let bits = bytes_to_bits(&key);
        match self.root.take() {
            None => {
                self.root = Some(Node::Leaf { key, value });
                Ok(())
            }
            Some(node) => match Self::insert_at(node, &bits, 0, key, value) {
                Ok(node) => {
                    self.root = Some(node);
                    Ok(())
                }
                Err((node, e)) => {
                    self.root = Some(node);
                    Err(e)
                }
            },
        }
    }

    /// Insert into the subtree rooted at `node`, whose path from the
    /// trie root has consumed the first `depth` bits of every key
    /// below it. On error the original node is handed back unchanged.
    fn insert_at(
        node: Node,
        bits: &[u8],
        depth: usize,
        key: Vec<u8>,
        value: [u8; 32],
    ) -> Result<Node, (Node, BinaryTrieError)> {
        match node {
            Node::Leaf {
                key: leaf_key,
                value: leaf_value,
            } => {
                if leaf_key == key {
                    return Ok(Node::Leaf { key, value });
                }
                // Scan from `depth` for the first divergent bit; a key
                // running out of bits first would be a prefix of the
                // other.
                let other_bits = bytes_to_bits(&leaf_key);
                let mut split = depth;
                loop {
                    if split >= bits.len() || split >= other_bits.len() {
                        return Err((
                            Node::Leaf {
                                key: leaf_key,
                                value: leaf_value,
                            },
                            BinaryTrieError::PrefixViolation,
                        ));
                    }
                    if bits[split] != other_bits[split] {
                        break;
                    }
                    split += 1;
                }
                let prefix = bits[depth..split].to_vec();
                let old = Box::new(Node::Leaf {
                    key: leaf_key,
                    value: leaf_value,
                });
                let new = Box::new(Node::Leaf { key, value });
                let (left, right) = if bits[split] == 0 {
                    (new, old)
                } else {
                    (old, new)
                };
                Ok(Node::Branch {
                    prefix,
                    left,
                    right,
                })
            }
            Node::Branch {
                prefix,
                left,
                right,
            } => {
                // Count how many prefix bits the key matches from `depth`.
                let mut shared = 0;
                while shared < prefix.len() {
                    let position = depth + shared;
                    if position >= bits.len() {
                        return Err((
                            Node::Branch {
                                prefix,
                                left,
                                right,
                            },
                            BinaryTrieError::PrefixViolation,
                        ));
                    }
                    if bits[position] != prefix[shared] {
                        break;
                    }
                    shared += 1;
                }
                if shared == prefix.len() {
                    // Full prefix match: descend on the bit at the split.
                    let split = depth + prefix.len();
                    if split >= bits.len() {
                        return Err((
                            Node::Branch {
                                prefix,
                                left,
                                right,
                            },
                            BinaryTrieError::PrefixViolation,
                        ));
                    }
                    return if bits[split] == 0 {
                        let (child, outcome) =
                            match Self::insert_at(*left, bits, split + 1, key, value) {
                                Ok(c) => (c, Ok(())),
                                Err((c, e)) => (c, Err(e)),
                            };
                        let node = Node::Branch {
                            prefix,
                            left: Box::new(child),
                            right,
                        };
                        match outcome {
                            Ok(()) => Ok(node),
                            Err(e) => Err((node, e)),
                        }
                    } else {
                        let (child, outcome) =
                            match Self::insert_at(*right, bits, split + 1, key, value) {
                                Ok(c) => (c, Ok(())),
                                Err((c, e)) => (c, Err(e)),
                            };
                        let node = Node::Branch {
                            prefix,
                            left,
                            right: Box::new(child),
                        };
                        match outcome {
                            Ok(()) => Ok(node),
                            Err(e) => Err((node, e)),
                        }
                    };
                }
                // The key diverges inside the prefix: the surviving
                // branch keeps the bits after the divergence, and a
                // new branch takes the bits before it.
                let new_prefix = prefix[..shared].to_vec();
                let survivor = Box::new(Node::Branch {
                    prefix: prefix[shared + 1..].to_vec(),
                    left,
                    right,
                });
                let leaf = Box::new(Node::Leaf { key, value });
                let (left, right) = if bits[depth + shared] == 0 {
                    (leaf, survivor)
                } else {
                    (survivor, leaf)
                };
                Ok(Node::Branch {
                    prefix: new_prefix,
                    left,
                    right,
                })
            }
        }
    }

    /// Value stored under `key`, or `None` if absent.
    pub fn get(&self, key: &[u8]) -> Option<[u8; 32]> {
        let bits = bytes_to_bits(key);
        let mut node = self.root.as_ref()?;
        let mut depth = 0;
        loop {
            match node {
                Node::Leaf {
                    key: leaf_key,
                    value,
                } => return (leaf_key.as_slice() == key).then_some(*value),
                Node::Branch {
                    prefix,
                    left,
                    right,
                } => {
                    let split = depth + prefix.len();
                    if split >= bits.len() || bits[depth..split] != prefix[..] {
                        return None;
                    }
                    node = if bits[split] == 0 { left } else { right };
                    depth = split + 1;
                }
            }
        }
    }

    /// Per-key proof: the ordered node preimages along `key`'s walk
    /// from the root, for [`super::proof::verify_proof`] to check by
    /// pure recomputation (format: `docs/eip-draft-pbt-eth-getproof.md`).
    ///
    /// The same walk serves both claims — the terminal node decides:
    /// a leaf carrying `key` yields an inclusion proof; a leaf with a
    /// different key, or a branch whose prefix `key`'s bits diverge
    /// from (or exhaust inside), yields an exclusion proof, and the
    /// walk stops there (a diverging branch's committed prefix
    /// already excludes `key` from its whole subtree). The empty trie
    /// returns the empty proof, which proves exclusion against
    /// [`EMPTY_TRIE_ROOT`].
    ///
    /// Cost: with no hash caching, sibling subtrees along the path
    /// are hashed from scratch — O(trie size) per call, same order as
    /// [`Self::root`]. Fine at the experimental scale this crate
    /// targets; hash caching is a documented Phase 2 upgrade.
    pub fn prove(&self, key: &[u8]) -> Vec<Vec<u8>> {
        let mut proof = Vec::new();
        let Some(mut node) = self.root.as_ref() else {
            return proof;
        };
        let bits = bytes_to_bits(key);
        let mut depth = 0;
        loop {
            match node {
                Node::Leaf {
                    key: leaf_key,
                    value,
                } => {
                    proof.push(leaf_preimage(leaf_key, value));
                    return proof;
                }
                Node::Branch {
                    prefix,
                    left,
                    right,
                } => {
                    proof.push(branch_preimage(
                        prefix,
                        Self::merkleize(left),
                        Self::merkleize(right),
                    ));
                    let split = depth + prefix.len();
                    if split >= bits.len() || bits[depth..split] != prefix[..] {
                        // The key diverges from (or exhausts inside)
                        // this branch's prefix: terminal exclusion
                        // witness, mirroring the verifier's walk.
                        return proof;
                    }
                    node = if bits[split] == 0 { left } else { right };
                    depth = split + 1;
                }
            }
        }
    }

    /// Root hash: [`EMPTY_TRIE_ROOT`] for the empty trie, otherwise
    /// the recursive tagged BLAKE3 commitment of the retained node
    /// structure.
    pub fn root(&self) -> H256 {
        match &self.root {
            None => EMPTY_TRIE_ROOT,
            Some(node) => Self::merkleize(node),
        }
    }

    fn merkleize(node: &Node) -> H256 {
        match node {
            Node::Leaf { key, value } => leaf_hash(key, value),
            Node::Branch {
                prefix,
                left,
                right,
            } => branch_hash(prefix, Self::merkleize(left), Self::merkleize(right)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::BinaryTrieError;
    use crate::trie::node::EMPTY_TRIE_ROOT;
    use hex_literal::hex;

    #[test]
    fn empty_trie_root_is_sentinel() {
        assert_eq!(BinaryTrie::new().root(), EMPTY_TRIE_ROOT);
    }

    #[test]
    fn single_leaf_matches_spec_vector() {
        let mut trie = BinaryTrie::new();
        trie.insert(vec![0u8; 34], [0x01; 32]).unwrap();
        assert_eq!(
            trie.root().0,
            hex!("4b60a28dce9f3529d103a26e00fadb98514cbd16ce03b7df752426addef9bbc7")
        );
    }

    #[test]
    fn get_returns_inserted_value_and_none_for_absent() {
        let mut trie = BinaryTrie::new();
        trie.insert(vec![0xab; 34], [7; 32]).unwrap();
        assert_eq!(trie.get(&[0xab; 34]), Some([7; 32]));
        assert_eq!(trie.get(&[0xac; 34]), None);
    }

    #[test]
    fn overwrite_replaces_value() {
        let mut trie = BinaryTrie::new();
        trie.insert(vec![0x42; 34], [1; 32]).unwrap();
        trie.insert(vec![0x42; 34], [2; 32]).unwrap();
        assert_eq!(trie.get(&[0x42; 34]), Some([2; 32]));
    }

    #[test]
    fn rejects_empty_key_and_oversized_key() {
        let mut trie = BinaryTrie::new();
        assert_eq!(trie.insert(vec![], [0; 32]), Err(BinaryTrieError::EmptyKey));
        assert_eq!(
            trie.insert(vec![0; 8193], [0; 32]),
            Err(BinaryTrieError::KeyTooLong)
        );
    }

    #[test]
    fn rejects_prefix_violations_both_directions() {
        let mut trie = BinaryTrie::new();
        trie.insert(vec![0xaa, 0xbb], [1; 32]).unwrap();
        assert_eq!(
            trie.insert(vec![0xaa], [2; 32]),
            Err(BinaryTrieError::PrefixViolation)
        );
        assert_eq!(
            trie.insert(vec![0xaa, 0xbb, 0xcc], [2; 32]),
            Err(BinaryTrieError::PrefixViolation)
        );
    }

    #[test]
    fn failed_insert_leaves_trie_unchanged() {
        let mut trie = BinaryTrie::new();
        trie.insert(vec![0xaa, 0xbb], [1; 32]).unwrap();
        let root_before = trie.root();
        let _ = trie.insert(vec![0xaa], [2; 32]);
        let _ = trie.insert(vec![0xaa, 0xbb, 0xcc], [2; 32]);
        assert_eq!(trie.root(), root_before);
        assert_eq!(trie.get(&[0xaa, 0xbb]), Some([1; 32]));
    }

    #[test]
    fn failed_insert_below_branch_leaves_trie_unchanged() {
        // Two keys sharing their first 9 bits force a root branch with
        // a long prefix, so both Branch-arm error sites are reachable.
        let mut trie = BinaryTrie::new();
        trie.insert(vec![0xaa, 0xbb], [1; 32]).unwrap();
        trie.insert(vec![0xaa, 0xcc], [2; 32]).unwrap();
        let root_before = trie.root();
        // Runs out of bits inside the branch's prefix walk.
        assert_eq!(
            trie.insert(vec![0xaa], [3; 32]),
            Err(BinaryTrieError::PrefixViolation)
        );
        // Fails at the leaf below the branch, exercising error
        // propagation and branch reconstruction on the way back up.
        assert_eq!(
            trie.insert(vec![0xaa, 0xbb, 0xcc], [3; 32]),
            Err(BinaryTrieError::PrefixViolation)
        );
        assert_eq!(trie.root(), root_before);
        assert_eq!(trie.get(&[0xaa, 0xbb]), Some([1; 32]));
        assert_eq!(trie.get(&[0xaa, 0xcc]), Some([2; 32]));
    }

    #[test]
    fn insertion_order_does_not_change_root() {
        let keys: [&[u8]; 3] = [&[0xf0, 0x00], &[0xf1, 0x00], &[0x0f, 0x00]];
        let mut forward = BinaryTrie::new();
        let mut reverse = BinaryTrie::new();
        for k in keys {
            forward.insert(k.to_vec(), [9; 32]).unwrap();
        }
        for k in keys.iter().rev() {
            reverse.insert(k.to_vec(), [9; 32]).unwrap();
        }
        assert_eq!(forward.root(), reverse.root());
    }
}
