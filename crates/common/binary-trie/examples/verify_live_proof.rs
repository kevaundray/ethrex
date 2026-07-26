//! Verify a live devnet `eth_getProof` (pbt-getproof-v1) response
//! OFFLINE against a block header's PBT state root, using only the
//! stateless verifier and embedding key derivation — no node access.
//!
//! Input: a JSON file `{"proof": <eth_getProof result>, "stateRoot": "0x.."}`.
//! Assumes the address is an EOA (code size 0, keccak("") code hash) and
//! that storageProof[0] queries an absent slot; adapt for contracts.
//!
//! Usage: cargo run -p ethrex-binary-trie --example verify_live_proof -- proof.json

use ethereum_types::{H160, H256, U256};
use ethrex_binary_trie::embedding::{
    address20_to_address32, encode_basic_data, get_tree_key_for_basic_data,
    get_tree_key_for_code_hash, get_tree_key_for_storage_slot,
};
use ethrex_binary_trie::trie::proof::verify_proof;

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s.trim_start_matches("0x")).unwrap()
}

fn main() {
    let raw = std::fs::read_to_string(std::env::args().nth(1).expect("json path")).unwrap();
    let v: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let root = H256::from_slice(&unhex(v["stateRoot"].as_str().unwrap()));
    let p = &v["proof"];
    let addr = H160::from_slice(&unhex(p["address"].as_str().unwrap()));
    let a32 = address20_to_address32(addr);

    let nodes = |val: &serde_json::Value| -> Vec<Vec<u8>> {
        val.as_array()
            .unwrap()
            .iter()
            .map(|n| unhex(n.as_str().unwrap()))
            .collect()
    };

    // 1) basicData inclusion: reconstruct the expected leaf from the
    //    response's convenience fields (EOA: code size 0).
    let balance =
        U256::from_str_radix(p["balance"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    let nonce =
        u64::from_str_radix(p["nonce"].as_str().unwrap().trim_start_matches("0x"), 16).unwrap();
    let expected_basic = encode_basic_data(0, nonce, balance).unwrap();
    let ok1 = verify_proof(
        root,
        &get_tree_key_for_basic_data(&a32),
        Some(expected_basic),
        &nodes(&p["binaryAccountProof"]["basicData"]["proof"]),
    );
    println!("basicData inclusion (recomputed leaf): {ok1:?}");

    // 2) codeHash inclusion: EOA => keccak("")
    let empty_code_keccak: [u8; 32] =
        unhex("0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
            .try_into()
            .unwrap();
    let ok2 = verify_proof(
        root,
        &get_tree_key_for_code_hash(&a32),
        Some(empty_code_keccak),
        &nodes(&p["binaryAccountProof"]["codeHash"]["proof"]),
    );
    println!("codeHash inclusion (keccak of empty): {ok2:?}");

    // 3) storage slot 0 of an EOA: exclusion
    let ok3 = verify_proof(
        root,
        &get_tree_key_for_storage_slot(&a32, U256::zero()),
        None,
        &nodes(&p["storageProof"][0]["proof"]),
    );
    println!("storage slot 0 exclusion: {ok3:?}");

    assert!(
        ok1.is_ok() && ok2.is_ok() && ok3.is_ok(),
        "verification failed"
    );
    println!("ALL LIVE PROOFS VERIFIED OFFLINE against header root {root:#x}");
}
