//! Differential test: the incremental BinaryTrie and the
//! rebuild-from-scratch reference must agree on every root. Because
//! the two implementations were written independently (insertion vs
//! canonical rebuild), agreement also checks that insertion order
//! never changes the structure.

use std::collections::BTreeMap;

use ethrex_binary_trie::trie::BinaryTrie;
use ethrex_binary_trie::trie::rebuild::rebuild_root;
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

#[test]
fn incremental_agrees_with_rebuild_on_random_workloads() {
    let mut rng = StdRng::seed_from_u64(8297);
    for round in 0..20 {
        let mut trie = BinaryTrie::new();
        let mut entries: BTreeMap<Vec<u8>, [u8; 32]> = BTreeMap::new();
        for step in 0..200 {
            // Embedding-realistic key lengths; equal length per zone
            // byte keeps keys prefix-free.
            let (zone, len) = if rng.gen_bool(0.5) {
                (0x00u8, 34)
            } else {
                (0xffu8, 66)
            };
            let mut key = vec![zone];
            // Small alphabet forces deep shared prefixes and branch
            // splits, the interesting structural cases.
            key.extend((1..len).map(|_| [0u8, 1, 0xfe, 0xff][rng.gen_range(0..4)]));
            let value: [u8; 32] = rng.r#gen();

            trie.insert(key.clone(), value).unwrap();
            entries.insert(key, value);

            if step % 50 == 49 {
                assert_eq!(
                    trie.root(),
                    rebuild_root(&entries),
                    "divergence at round {round} step {step}"
                );
            }
        }
        assert_eq!(
            trie.root(),
            rebuild_root(&entries),
            "final root, round {round}"
        );
    }
}
