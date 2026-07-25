//! Standalone verification of per-key binary-trie proofs.
//!
//! A proof is the ordered list of node preimages along the target
//! key's walk from the root — branch preimages
//! `0x01 ‖ encode_bit_prefix(prefix) ‖ left ‖ right` and, when the
//! walk ends at one, a leaf preimage `0x00 ‖ key ‖ value` (see
//! [`super::node`]). [`BinaryTrie::prove`] produces them; this module
//! verifies them by pure recomputation, needing no trie: hash the
//! first preimage against the root, hash each next preimage against
//! the parent's chosen-child commitment, and enforce the target key's
//! bit path at every branch so the prover cannot steer the walk.
//!
//! Inclusion and exclusion use the same walk. The terminal node
//! decides which claim the proof supports: a leaf carrying the target
//! key proves inclusion; a leaf carrying a different key, or a branch
//! the target's bits diverge from (or exhaust inside), proves
//! exclusion — the branch's committed prefix already excludes the
//! target from the whole subtree, so no children are opened.
//!
//! Format reference: `docs/eip-draft-pbt-eth-getproof.md`
//! (`pbt-getproof-v1`).
//!
//! [`BinaryTrie::prove`]: super::BinaryTrie::prove

use ethereum_types::H256;
use thiserror::Error;

use super::EMPTY_TRIE_ROOT;
use super::bits::bytes_to_bits;
use super::node::{BRANCH_NODE_TAG, LEAF_NODE_TAG, blake3_hash};

/// Why a proof failed verification.
///
/// Structural errors (malformed nodes, broken hash chain) and claim
/// errors (the proof is sound but supports the opposite claim, or a
/// different value) are deliberately distinct: the latter are
/// meaningful answers about state, the former mean the proof bytes
/// are garbage or tampered.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProofError {
    /// The empty root commits to no nodes, so its (empty) proof can
    /// only support exclusion.
    #[error("the empty trie root admits only an empty exclusion proof")]
    EmptyRootConflict,
    /// A non-empty root requires at least the root node's preimage.
    #[error("proof is empty but the root is non-empty")]
    MissingNodes,
    /// The first preimage does not hash to the expected root.
    #[error("first node does not hash to the expected root")]
    RootHashMismatch,
    /// Preimage at this index does not hash to the parent branch's
    /// committed child.
    #[error("node {0} does not hash to its parent's child commitment")]
    ChildHashMismatch(usize),
    /// Preimage at this index has an unknown tag, a wrong length, or
    /// non-zero prefix padding bits.
    #[error("node {0} is not a well-formed node preimage")]
    MalformedNode(usize),
    /// Elements follow a terminal (leaf or diverging branch) node.
    #[error("proof continues past its terminal node")]
    TrailingNodes,
    /// The last element is a branch the key descends through: the
    /// child on the key's path is missing.
    #[error("proof stops at a branch the key descends through")]
    Truncated,
    /// Inclusion was claimed and the key is present, but with a
    /// different value.
    #[error("key is present with a different value")]
    ValueMismatch,
    /// Exclusion was claimed but the proof shows the key present.
    #[error("proof shows the key present but absence was claimed")]
    UnexpectedInclusion,
    /// Inclusion was claimed but the proof shows the key absent.
    #[error("proof shows the key absent but inclusion was claimed")]
    UnexpectedExclusion,
}

/// A node preimage parsed for verification.
enum ParsedNode<'a> {
    Leaf {
        key: &'a [u8],
        value: &'a [u8; 32],
    },
    Branch {
        /// Prefix as one bit per byte, in consumption order.
        prefix_bits: Vec<u8>,
        left: H256,
        right: H256,
    },
}

/// Parse one node preimage, strictly: exact lengths, known tags, and
/// zero padding bits only — so a given `(root, key, claim)` admits
/// essentially one accepted proof (no malleability through padding
/// or trailing bytes; anything non-canonical is rejected rather than
/// silently normalized).
fn parse_node(encoded: &[u8]) -> Option<ParsedNode<'_>> {
    let (&tag, body) = encoded.split_first()?;
    match tag {
        LEAF_NODE_TAG => {
            // Key (>= 1 byte, per the tree's empty-key ban) + 32-byte value.
            if body.len() < 1 + 32 {
                return None;
            }
            let (key, value) = body.split_at(body.len() - 32);
            Some(ParsedNode::Leaf {
                key,
                value: value.try_into().ok()?,
            })
        }
        BRANCH_NODE_TAG => {
            // encode_bit_prefix output (2-byte bit count + packed bits)
            // followed by two 32-byte child hashes, nothing else.
            let (count, rest) = body.split_first_chunk::<2>()?;
            let bit_count = u16::from_be_bytes(*count) as usize;
            let packed_len = bit_count.div_ceil(8);
            if rest.len() != packed_len + 64 {
                return None;
            }
            let (packed, children) = rest.split_at(packed_len);
            let prefix_bits: Vec<u8> = (0..bit_count)
                .map(|i| (packed[i / 8] >> (7 - i % 8)) & 1)
                .collect();
            if !bit_count.is_multiple_of(8) {
                let padding_mask = 0xffu8 >> (bit_count % 8);
                if packed[packed_len - 1] & padding_mask != 0 {
                    return None;
                }
            }
            Some(ParsedNode::Branch {
                prefix_bits,
                left: H256::from_slice(&children[..32]),
                right: H256::from_slice(&children[32..]),
            })
        }
        _ => None,
    }
}

/// Verify a per-key proof against `root`.
///
/// `expected` is the claim: `Some(value)` demands an inclusion proof
/// of exactly that 32-byte value, `None` demands an exclusion proof.
/// Pure recomputation — no trie access, no state.
///
/// Depth needs no explicit cap: every accepted branch consumes at
/// least one key bit (its split bit), so a proof longer than
/// `8 * key.len() + 1` nodes cannot keep satisfying the path checks.
///
/// # Errors
///
/// See [`ProofError`]; verification succeeds only for a structurally
/// sound proof supporting exactly the given claim.
pub fn verify_proof(
    root: H256,
    key: &[u8],
    expected: Option<[u8; 32]>,
    proof: &[Vec<u8>],
) -> Result<(), ProofError> {
    if root == EMPTY_TRIE_ROOT {
        if !proof.is_empty() {
            return Err(ProofError::EmptyRootConflict);
        }
        return match expected {
            None => Ok(()),
            Some(_) => Err(ProofError::UnexpectedExclusion),
        };
    }
    let first = proof.first().ok_or(ProofError::MissingNodes)?;
    if blake3_hash(first) != root {
        return Err(ProofError::RootHashMismatch);
    }

    let bits = bytes_to_bits(key);
    let mut depth = 0usize;
    let mut index = 0usize;
    loop {
        let terminal = |i: usize| {
            if i + 1 == proof.len() {
                Ok(())
            } else {
                Err(ProofError::TrailingNodes)
            }
        };
        match parse_node(&proof[index]).ok_or(ProofError::MalformedNode(index))? {
            ParsedNode::Leaf {
                key: leaf_key,
                value,
            } => {
                terminal(index)?;
                return match (leaf_key == key, expected) {
                    (true, Some(claimed)) if *value == claimed => Ok(()),
                    (true, Some(_)) => Err(ProofError::ValueMismatch),
                    (true, None) => Err(ProofError::UnexpectedInclusion),
                    (false, None) => Ok(()),
                    (false, Some(_)) => Err(ProofError::UnexpectedExclusion),
                };
            }
            ParsedNode::Branch {
                prefix_bits,
                left,
                right,
            } => {
                let split = depth + prefix_bits.len();
                // Divergence inside the prefix, or the key's bits
                // exhausted at/before the split: nothing below this
                // branch can be the key, so it is a terminal
                // exclusion witness.
                if split >= bits.len() || bits[depth..split] != prefix_bits[..] {
                    terminal(index)?;
                    return match expected {
                        None => Ok(()),
                        Some(_) => Err(ProofError::UnexpectedExclusion),
                    };
                }
                let child = if bits[split] == 0 { left } else { right };
                let next = proof.get(index + 1).ok_or(ProofError::Truncated)?;
                if blake3_hash(next) != child {
                    return Err(ProofError::ChildHashMismatch(index + 1));
                }
                depth = split + 1;
                index += 1;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::BinaryTrie;
    use super::*;

    fn two_leaf_trie() -> BinaryTrie {
        let mut trie = BinaryTrie::new();
        trie.insert(vec![0xaa, 0xbb], [1; 32]).unwrap();
        trie.insert(vec![0xaa, 0xcc], [2; 32]).unwrap();
        trie
    }

    #[test]
    fn empty_root_proves_exclusion_only_with_empty_proof() {
        assert_eq!(verify_proof(EMPTY_TRIE_ROOT, &[0x01], None, &[]), Ok(()));
        assert_eq!(
            verify_proof(EMPTY_TRIE_ROOT, &[0x01], Some([0; 32]), &[]),
            Err(ProofError::UnexpectedExclusion)
        );
        assert_eq!(
            verify_proof(EMPTY_TRIE_ROOT, &[0x01], None, &[vec![0x00]]),
            Err(ProofError::EmptyRootConflict)
        );
    }

    #[test]
    fn empty_proof_against_nonempty_root_is_missing_nodes() {
        assert_eq!(
            verify_proof(H256::repeat_byte(1), &[0x01], None, &[]),
            Err(ProofError::MissingNodes)
        );
    }

    #[test]
    fn inclusion_and_exclusion_round_trip() {
        let trie = two_leaf_trie();
        let root = trie.root();

        let proof = trie.prove(&[0xaa, 0xbb]);
        assert_eq!(
            verify_proof(root, &[0xaa, 0xbb], Some([1; 32]), &proof),
            Ok(())
        );

        // Absent key diverging at the root branch's split.
        let proof = trie.prove(&[0x11, 0x22]);
        assert_eq!(verify_proof(root, &[0x11, 0x22], None, &proof), Ok(()));

        // Absent key reaching a leaf with a different key.
        let proof = trie.prove(&[0xaa, 0xbf]);
        assert_eq!(verify_proof(root, &[0xaa, 0xbf], None, &proof), Ok(()));
    }

    #[test]
    fn claim_mismatches_are_rejected() {
        let trie = two_leaf_trie();
        let root = trie.root();

        let inclusion = trie.prove(&[0xaa, 0xbb]);
        assert_eq!(
            verify_proof(root, &[0xaa, 0xbb], Some([9; 32]), &inclusion),
            Err(ProofError::ValueMismatch)
        );
        assert_eq!(
            verify_proof(root, &[0xaa, 0xbb], None, &inclusion),
            Err(ProofError::UnexpectedInclusion)
        );

        let exclusion = trie.prove(&[0xaa, 0xbf]);
        assert_eq!(
            verify_proof(root, &[0xaa, 0xbf], Some([1; 32]), &exclusion),
            Err(ProofError::UnexpectedExclusion)
        );
    }

    #[test]
    fn wrong_root_is_rejected() {
        let trie = two_leaf_trie();
        let proof = trie.prove(&[0xaa, 0xbb]);
        assert_eq!(
            verify_proof(
                H256::repeat_byte(0x7f),
                &[0xaa, 0xbb],
                Some([1; 32]),
                &proof
            ),
            Err(ProofError::RootHashMismatch)
        );
    }

    #[test]
    fn any_single_byte_tamper_is_rejected() {
        let trie = two_leaf_trie();
        let root = trie.root();
        let proof = trie.prove(&[0xaa, 0xbb]);
        assert!(proof.len() >= 2, "want a branch and a leaf to tamper with");
        for node_index in 0..proof.len() {
            for byte_index in 0..proof[node_index].len() {
                let mut tampered = proof.clone();
                tampered[node_index][byte_index] ^= 0x01;
                assert!(
                    verify_proof(root, &[0xaa, 0xbb], Some([1; 32]), &tampered).is_err(),
                    "tampering node {node_index} byte {byte_index} must fail"
                );
            }
        }
    }

    #[test]
    fn truncated_and_padded_proofs_are_rejected() {
        let trie = two_leaf_trie();
        let root = trie.root();
        let proof = trie.prove(&[0xaa, 0xbb]);

        let truncated = &proof[..proof.len() - 1];
        assert_eq!(
            verify_proof(root, &[0xaa, 0xbb], Some([1; 32]), truncated),
            Err(ProofError::Truncated)
        );

        let mut padded = proof.clone();
        padded.push(vec![0x00; 40]);
        assert_eq!(
            verify_proof(root, &[0xaa, 0xbb], Some([1; 32]), &padded),
            Err(ProofError::TrailingNodes)
        );
    }

    #[test]
    fn malformed_nodes_are_rejected() {
        let leaf = |key: &[u8], value: [u8; 32]| {
            let mut trie = BinaryTrie::new();
            trie.insert(key.to_vec(), value).unwrap();
            (trie.root(), trie.prove(key))
        };
        // Unknown tag.
        let (_, mut proof) = leaf(&[0xab], [3; 32]);
        proof[0][0] = 0x02;
        assert_eq!(
            verify_proof(blake3_hash(&proof[0]), &[0xab], Some([3; 32]), &proof),
            Err(ProofError::MalformedNode(0))
        );
        // Leaf too short to carry a key and a value.
        let stub = vec![vec![LEAF_NODE_TAG; 33]];
        assert_eq!(
            verify_proof(blake3_hash(&stub[0]), &[0xab], None, &stub),
            Err(ProofError::MalformedNode(0))
        );
        // Branch with non-zero padding bits: 1-bit prefix, low bits set.
        let mut branch = vec![BRANCH_NODE_TAG, 0x00, 0x01, 0b1100_0000];
        branch.extend_from_slice(&[0u8; 64]);
        let stub = vec![branch];
        assert_eq!(
            verify_proof(blake3_hash(&stub[0]), &[0xab], None, &stub),
            Err(ProofError::MalformedNode(0))
        );
        // Branch with a wrong total length (one child byte missing).
        let mut branch = vec![BRANCH_NODE_TAG, 0x00, 0x00];
        branch.extend_from_slice(&[0u8; 63]);
        let stub = vec![branch];
        assert_eq!(
            verify_proof(blake3_hash(&stub[0]), &[0xab], None, &stub),
            Err(ProofError::MalformedNode(0))
        );
    }

    #[test]
    fn key_exhaustion_inside_a_branch_is_a_valid_exclusion() {
        // Keys sharing their first byte force a root branch whose
        // split sits past bit 8, so the 1-byte query exhausts inside it.
        let trie = two_leaf_trie();
        let root = trie.root();
        let proof = trie.prove(&[0xaa]);
        assert_eq!(proof.len(), 1, "the root branch alone is the witness");
        assert_eq!(verify_proof(root, &[0xaa], None, &proof), Ok(()));
    }
}
