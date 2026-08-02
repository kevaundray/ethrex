//! Rebuild-from-scratch reference implementation: a direct port of
//! the spec's `binarize`, which recomputes the canonical node
//! structure from a flat map on every call. Used as the differential
//! oracle for the incremental trie and kept public as executable
//! documentation of canonical form.

use std::collections::BTreeMap;

use ethereum_types::H256;

use super::bits::bytes_to_bits;
use super::node::{EMPTY_TRIE_ROOT, branch_hash, leaf_hash};

pub type Entries = BTreeMap<Vec<u8>, [u8; 32]>;

pub fn rebuild_root(entries: &Entries) -> H256 {
    if entries.is_empty() {
        return EMPTY_TRIE_ROOT;
    }
    let refs: Vec<(&[u8], &[u8; 32])> = entries.iter().map(|(k, v)| (k.as_slice(), v)).collect();
    binarize(&refs, 0)
}

/// Hash the canonical node structure for `entries`, whose keys all
/// share their first `depth` bits. Panics on prefix-violating or
/// empty input: this is a test oracle whose callers only feed
/// prefix-free non-empty key sets.
fn binarize(entries: &[(&[u8], &[u8; 32])], depth: usize) -> H256 {
    assert!(!entries.is_empty());
    if let [(key, value)] = entries {
        return leaf_hash(key, value);
    }

    let bit_lists: Vec<Vec<u8>> = entries.iter().map(|(k, _)| bytes_to_bits(k)).collect();

    // Advance past the run of bits all keys share; the first
    // disagreement is the split. A key running out of bits while
    // still grouped with others would be a prefix of theirs.
    let mut split = depth;
    loop {
        for bits in &bit_lists {
            assert!(split < bits.len(), "prefix violation");
        }
        let first = bit_lists[0][split];
        if bit_lists.iter().any(|bits| bits[split] != first) {
            break;
        }
        split += 1;
    }

    let mut left = Vec::new();
    let mut right = Vec::new();
    for (entry, bits) in entries.iter().zip(&bit_lists) {
        if bits[split] == 0 {
            left.push(*entry);
        } else {
            right.push(*entry);
        }
    }

    branch_hash(
        &bit_lists[0][depth..split],
        binarize(&left, split + 1),
        binarize(&right, split + 1),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex_literal::hex;

    #[test]
    fn empty_root_is_zero() {
        assert_eq!(rebuild_root(&Default::default()), EMPTY_TRIE_ROOT);
    }

    #[test]
    fn single_leaf_vector() {
        // fixture: trie_roots["single_leaf"]
        let mut entries = std::collections::BTreeMap::new();
        entries.insert(vec![0u8; 34], [0x01u8; 32]);
        assert_eq!(
            rebuild_root(&entries).0,
            hex!("4b60a28dce9f3529d103a26e00fadb98514cbd16ce03b7df752426addef9bbc7")
        );
    }

    #[test]
    fn leaf_commits_full_key_not_suffix() {
        // Two single-entry trees whose keys agree on every bit below
        // the root must still differ: the leaf preimage holds the
        // complete key.
        let mut a = std::collections::BTreeMap::new();
        a.insert(vec![0x00, 0xaa], [1u8; 32]);
        let mut b = std::collections::BTreeMap::new();
        b.insert(vec![0xaa], [1u8; 32]);
        assert_ne!(rebuild_root(&a), rebuild_root(&b));
    }
}
