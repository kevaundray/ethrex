//! Conformance tests against vectors generated from the EELS
//! reference implementation (see tests/vectors/dump_vectors.py).

use ethrex_binary_trie::trie::rebuild::{Entries, rebuild_root};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    trie_roots: Vec<TrieCase>,
}

#[derive(Deserialize)]
struct TrieCase {
    name: String,
    entries: Vec<Entry>,
    root: String,
}

#[derive(Deserialize)]
struct Entry {
    key: String,
    value: String,
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s.strip_prefix("0x").unwrap_or(s)).expect("fixture hex string")
}

fn load() -> Fixture {
    serde_json::from_str(include_str!("vectors/binary_trie_vectors.json")).unwrap()
}

#[test]
fn rebuild_matches_spec_roots() {
    for case in load().trie_roots {
        let mut entries = Entries::new();
        for e in &case.entries {
            entries.insert(unhex(&e.key), unhex(&e.value).try_into().unwrap());
        }
        assert_eq!(
            rebuild_root(&entries).as_bytes(),
            unhex(&case.root).as_slice(),
            "trie case {}",
            case.name
        );
    }
}
