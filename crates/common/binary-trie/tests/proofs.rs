//! Proof round-trips against the spec-generated fixture tries: the
//! roots are pinned to the EELS reference implementation (see
//! tests/vectors/dump_vectors.py), so every proof verified here is
//! checked against ground-truth commitments, not just our own trie.

use ethrex_binary_trie::trie::{BinaryTrie, ProofError, verify_proof};
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

fn load() -> Vec<TrieCase> {
    let fixture: Fixture =
        serde_json::from_str(include_str!("vectors/binary_trie_vectors.json")).unwrap();
    assert_eq!(fixture.trie_roots.len(), 9, "fixture case count");
    fixture.trie_roots
}

fn build(case: &TrieCase) -> (BinaryTrie, ethereum_types::H256) {
    let mut trie = BinaryTrie::new();
    for e in &case.entries {
        trie.insert(unhex(&e.key), unhex(&e.value).try_into().unwrap())
            .unwrap();
    }
    let root = ethereum_types::H256::from_slice(&unhex(&case.root));
    assert_eq!(trie.root(), root, "trie case {}", case.name);
    (trie, root)
}

/// A key absent from `case` but bit-compatible with its walk: the
/// last byte of an existing key flipped keeps the key length (and
/// zone/stem shape) while guaranteeing absence.
fn absent_key_from(case: &TrieCase) -> Option<Vec<u8>> {
    let present: Vec<Vec<u8>> = case.entries.iter().map(|e| unhex(&e.key)).collect();
    for key in &present {
        let mut candidate = key.clone();
        *candidate.last_mut().unwrap() ^= 0xff;
        if !present.contains(&candidate) {
            return Some(candidate);
        }
    }
    None
}

#[test]
fn every_fixture_entry_proves_inclusion_against_the_pinned_root() {
    for case in load() {
        let (trie, root) = build(&case);
        // Entries apply in order with last-write-wins (the
        // overwrite_takes_last_value case repeats a key), so prove
        // the final mapping, not each raw fixture line.
        let final_entries: std::collections::BTreeMap<Vec<u8>, [u8; 32]> = case
            .entries
            .iter()
            .map(|e| (unhex(&e.key), unhex(&e.value).try_into().unwrap()))
            .collect();
        for (key, value) in final_entries {
            let proof = trie.prove(&key);
            assert_eq!(
                verify_proof(root, &key, Some(value), &proof),
                Ok(()),
                "inclusion failed for case {} key 0x{}",
                case.name,
                hex::encode(&key)
            );
        }
    }
}

#[test]
fn absent_keys_prove_exclusion_against_the_pinned_root() {
    for case in load() {
        let (trie, root) = build(&case);
        let Some(absent) = absent_key_from(&case) else {
            continue; // empty-trie case: covered below
        };
        let proof = trie.prove(&absent);
        assert_eq!(
            verify_proof(root, &absent, None, &proof),
            Ok(()),
            "exclusion failed for case {}",
            case.name
        );
        // And the exclusion proof cannot be repurposed as inclusion.
        assert_eq!(
            verify_proof(root, &absent, Some([0u8; 32]), &proof),
            Err(ProofError::UnexpectedExclusion),
            "case {}",
            case.name
        );
    }
}

#[test]
fn empty_fixture_trie_proves_exclusion_with_the_empty_proof() {
    let empty = load()
        .into_iter()
        .find(|case| case.entries.is_empty())
        .expect("fixture has an empty-trie case");
    let (trie, root) = build(&empty);
    let proof = trie.prove(&[0u8; 34]);
    assert!(proof.is_empty());
    assert_eq!(verify_proof(root, &[0u8; 34], None, &proof), Ok(()));
}

#[test]
fn fixture_proofs_reject_single_byte_tampering() {
    // The deepest fixture trie gives the longest paths; tampering any
    // byte of any node in any entry's proof must fail verification.
    let case = load()
        .into_iter()
        .max_by_key(|case| case.entries.len())
        .unwrap();
    let (trie, root) = build(&case);
    let e = &case.entries[0];
    let key = unhex(&e.key);
    let value: [u8; 32] = unhex(&e.value).try_into().unwrap();
    let proof = trie.prove(&key);
    assert!(proof.len() > 1, "want a multi-node proof");
    for node_index in 0..proof.len() {
        for byte_index in 0..proof[node_index].len() {
            let mut tampered = proof.clone();
            tampered[node_index][byte_index] ^= 0x01;
            assert!(
                verify_proof(root, &key, Some(value), &tampered).is_err(),
                "case {} node {node_index} byte {byte_index}",
                case.name
            );
        }
    }
}

#[test]
fn fixture_proofs_fail_against_other_fixture_roots() {
    let cases = load();
    let (trie, root) = build(&cases[1]);
    let other_root = ethereum_types::H256::from_slice(&unhex(&cases[2].root));
    assert_ne!(root, other_root, "fixture roots must differ");
    let key = unhex(&cases[1].entries[0].key);
    let value: [u8; 32] = unhex(&cases[1].entries[0].value).try_into().unwrap();
    let proof = trie.prove(&key);
    assert!(verify_proof(other_root, &key, Some(value), &proof).is_err());
}
