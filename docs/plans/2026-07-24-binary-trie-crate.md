# Binary Trie Crate (`ethrex-binary-trie`) Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** A new `crates/common/binary-trie` crate implementing the EIP-8297 Partitioned Binary Tree — the raw compressed binary radix trie plus the state embedding (key derivation, code chunking, basic-data packing) — validated against test vectors generated from the `ethereum/execution-specs` reference implementation.

**Architecture:** Two layers, mirroring the spec's `src/ethereum/binary_trie/{trie,embedding}.py`. The `trie` module has two implementations: an **incremental** insertion-based tree (the production shape: descend/split insertion, `root()` hashes the retained node structure) and a **rebuild-from-scratch** module (`rebuild.rs`, a direct port of the spec's `binarize`, kept as a public spec-faithful reference and used as a differential-test oracle). The `embedding` module is pure key/value derivation with no trie dependency. No storage, blockchain, or fork integration in this plan — that is a follow-up (see "Out of scope").

**Tech Stack:** Rust (edition 2024, ethrex workspace), `blake3` crate for hashing, `ethereum-types` (`H256`, `U256`, `H160`), `thiserror`. Dev-deps: `serde_json` (fixture loading), `rand` (differential test), `hex-literal`.

**Reference implementation:** `/Users/kev/work/ethereum/execution-specs` (branch `projects/binary-trie` or `kw/sketch-embedding-changes`), files `src/ethereum/binary_trie/trie.py` and `src/ethereum/binary_trie/embedding.py`. When in doubt about semantics, that Python code is the source of truth.

**Domain background (read this before Task 1):**

- The tree maps variable-length byte keys to 32-byte values. Keys are consumed **bit by bit, MSB first**. Keys must be **prefix-free** (no key is a prefix of another) — a leaf ends a path, so a longer key could never pass through where a shorter key terminates. Callers guarantee this; the embedding guarantees it structurally (all keys within a zone have equal length, and zones differ in their first byte).
- Nodes hash with **BLAKE3**, with domain-separation tags: leaf preimage = `0x00 ‖ full_key ‖ value` (the *complete* key, not the remaining suffix); branch preimage = `0x01 ‖ encode_bit_prefix(prefix) ‖ left_hash ‖ right_hash`.
- A branch stores a **prefix**: the run of bits shared by every key below it, *relative* to the parent's split point (like an MPT extension node, inlined). `encode_bit_prefix` = 2-byte big-endian bit count, then the bits packed MSB-first, zero-padded to a byte boundary. The explicit count keeps the encoding injective.
- The empty tree root is **32 zero bytes** (a sentinel, not a hash output).
- Max key length: **8192 bytes** (so a branch prefix's bit count always fits in 2 bytes).
- Embedding: one unified tree holds accounts, storage, and code. First key byte is a **zone** (`0x00` account headers, `0x01` content-addressed overflow code, `0xff` overflow storage). A key's **stem** = all bytes but the last; the final byte is a **sub-index** (0–255). The account header stem packs: basic data (sub-index 0), code hash (1), storage slots 0–63 (sub-indices 64–127), code chunks 0–127 (sub-indices 128–255). Overflow storage/code live in their zones, grouped 256 per stem. Key hashing uses BLAKE3 (`key_hash`); the account `code_hash` *value* stays keccak (EVM-observable).

---

## Task 1: Crate scaffold

**Files:**
- Create: `crates/common/binary-trie/Cargo.toml`
- Create: `crates/common/binary-trie/src/lib.rs`
- Modify: `Cargo.toml` (workspace root — `members` list, `[workspace.dependencies]`)

**Step 1: Write the manifest**

`crates/common/binary-trie/Cargo.toml`:

```toml
[package]
name = "ethrex-binary-trie"
version.workspace = true
edition.workspace = true
authors.workspace = true
documentation.workspace = true
license.workspace = true
description = "EIP-8297 Partitioned Binary Tree for the ethrex Ethereum execution client"
repository.workspace = true

[dependencies]
ethereum-types.workspace = true
blake3.workspace = true
thiserror.workspace = true

[dev-dependencies]
serde = { workspace = true, features = ["derive"] }
serde_json.workspace = true
rand.workspace = true
hex-literal.workspace = true

[lints]
workspace = true
```

**Step 2: Register in the workspace**

In the root `Cargo.toml`:
- Add `"crates/common/binary-trie"` to `members` (after `"crates/common/trie"`).
- In `[workspace.dependencies]`, add (alphabetically near the other entries):
  ```toml
  blake3 = "1"
  ethrex-binary-trie = { path = "./crates/common/binary-trie" }
  ```
  Note: `blake3` already appears in `Cargo.lock` as a transitive dep of the proving stack; check the locked version with `grep -A1 'name = "blake3"' Cargo.lock | head -4` and pin the same major version.

**Step 3: Write the empty lib**

`crates/common/binary-trie/src/lib.rs`:

```rust
//! EIP-8297 Partitioned Binary Tree.
//!
//! [`trie`] is the raw prefix-free key/value tree committing to its
//! contents with a single BLAKE3 root. [`embedding`] maps Ethereum
//! state (accounts, storage, code) onto tree keys and values.
//!
//! Reference: `ethereum/execution-specs`, `src/ethereum/binary_trie/`.

pub mod embedding;
pub mod trie;
```

Create empty `src/trie.rs` and `src/embedding.rs` (module docs only, ported from the corresponding Python module docstrings, condensed).

**Step 4: Verify it builds**

Run: `cargo check -p ethrex-binary-trie`
Expected: clean check. Also run `cargo check --workspace` to confirm the member addition didn't break lockfile resolution.

**Step 5: Commit**

```bash
git add Cargo.toml Cargo.lock crates/common/binary-trie
git commit -m "feat(binary-trie): scaffold ethrex-binary-trie crate"
```

---

## Task 2: Spec test-vector fixture

The fixture is generated from the EELS reference implementation so our expected hashes are ground truth, never hand-computed. The generator is deterministic (seeded RNG), so regeneration always produces byte-identical output.

**Files:**
- Create: `crates/common/binary-trie/tests/vectors/dump_vectors.py`
- Create: `crates/common/binary-trie/tests/vectors/binary_trie_vectors.json` (generated)

**Step 1: Add the generator script**

Copy the script below verbatim to `crates/common/binary-trie/tests/vectors/dump_vectors.py`. It was already run successfully against the spec checkout on 2026-07-24; expected sample outputs are in Step 3.

```python
"""
Dump EIP-8297 binary trie + embedding test vectors from the EELS
reference implementation (execution-specs, projects/binary-trie) as
JSON, for use as fixtures in ethrex's Rust implementation.

Run from the root of the execution-specs checkout:
    uv run python dump_vectors.py > binary_trie_vectors.json

The script records the checkout's HEAD commit in the fixture's
`source_commit` field (via `git rev-parse HEAD` in the CWD), pinning
the exact spec revision the vectors were generated from.
"""

import json
import random
import subprocess
import sys

from ethereum_types.bytes import Bytes, Bytes20, Bytes32
from ethereum_types.numeric import U32, U64, U256, Uint

from ethereum.binary_trie.trie import BinaryTrie, root, trie_set
from ethereum.binary_trie.embedding import (
    address20_to_address32,
    chunkify_code,
    encode_basic_data,
    get_tree_key_for_basic_data,
    get_tree_key_for_code_chunk,
    get_tree_key_for_code_hash,
    get_tree_key_for_header,
    get_tree_key_for_storage_slot,
)
from ethereum.crypto.hash import keccak256


def hx(b: bytes) -> str:
    return "0x" + bytes(b).hex()


def trie_root_case(name: str, entries: list) -> dict:
    """`entries` is an ordered list of (key, value) pairs, applied in
    order with trie_set; duplicates are preserved in the serialized
    output so consumers can replay overwrites."""
    t = BinaryTrie()
    for k, v in entries:
        trie_set(t, Bytes(k), Bytes32(v))
    return {
        "name": name,
        "entries": [{"key": hx(k), "value": hx(v)} for k, v in entries],
        "root": hx(root(t)),
    }


V1 = bytes.fromhex("01" * 32)
V2 = bytes.fromhex("02" * 32)
V3 = bytes.fromhex("03" * 32)

trie_cases = [
    trie_root_case("empty", []),
    trie_root_case("single_leaf", [(b"\x00" * 34, V1)]),
    trie_root_case("single_leaf_one_byte_key", [(b"\xab", V1)]),
    trie_root_case(
        "two_leaves_diverge_first_bit",
        [(b"\x00" + b"\x11" * 33, V1), (b"\x80" + b"\x11" * 33, V2)],
    ),
    trie_root_case(
        "two_leaves_diverge_last_bit",
        [(b"\x22" * 33 + b"\x00", V1), (b"\x22" * 33 + b"\x01", V2)],
    ),
    trie_root_case(
        "three_leaves_shared_prefix",
        [
            (b"\xf0" + b"\x00" * 33, V1),
            (b"\xf1" + b"\x00" * 33, V2),
            (b"\x0f" + b"\x00" * 33, V3),
        ],
    ),
    trie_root_case(
        "mixed_key_lengths_34_and_66",
        [
            (b"\x00" + b"\xaa" * 32 + b"\x05", V1),
            (b"\xff" + b"\xbb" * 64 + b"\x07", V2),
        ],
    ),
    trie_root_case(
        "overwrite_takes_last_value",
        # same key written twice: the second trie_set overwrites
        [(b"\x42" * 34, V1), (b"\x42" * 34, V2)],
    ),
]

# Deterministic pseudo-random case: 50 distinct 34-byte keys, listed in
# generation (insertion) order.
rng = random.Random(8297)
rand_entries = {}
while len(rand_entries) < 50:
    k = bytes(rng.randrange(256) for _ in range(34))
    v = bytes(rng.randrange(256) for _ in range(32))
    rand_entries[k] = v
trie_cases.append(
    trie_root_case("random_50_keys_seed_8297", list(rand_entries.items()))
)

ADDRESS20 = bytes.fromhex("00112233445566778899aabbccddeeff00112233")
ADDR32 = address20_to_address32(Bytes20(ADDRESS20))
CODE_HASH = keccak256(b"\xfe")  # hash of some 1-byte code

embedding_cases = {
    "address20": hx(ADDRESS20),
    "address32": hx(ADDR32),
    "basic_data_key": hx(get_tree_key_for_basic_data(ADDR32)),
    "code_hash_key": hx(get_tree_key_for_code_hash(ADDR32)),
    "header_sub_index_255_key": hx(get_tree_key_for_header(ADDR32, Uint(255))),
    "storage_slot_keys": {
        str(slot): hx(get_tree_key_for_storage_slot(ADDR32, U256(slot)))
        for slot in [0, 1, 63, 64, 255, 256, 511, 512, 2**200]
    },
    "code_chunk_keys": {
        str(cid): hx(
            get_tree_key_for_code_chunk(ADDR32, Bytes32(CODE_HASH), Uint(cid))
        )
        for cid in [0, 1, 127, 128, 129, 383, 384]
    },
    "code_chunk_content_hash": hx(CODE_HASH),
}

# chunkify vectors
PUSH4 = bytes([0x63])
PUSH32 = bytes([0x7F])
chunkify_cases = [
    {"name": "empty", "code": hx(b""), "chunks": []},
    {
        "name": "stop_padded",
        "code": hx(b"\x00"),
        "chunks": [hx(c) for c in chunkify_code(Bytes(b"\x00"))],
    },
    {
        "name": "eip_example_push4_boundary",
        # PUSH4 at position 29: its 4 data bytes spill 2 into chunk 1
        "code": hx(b"\x01" * 29 + PUSH4 + b"\xaa\xbb\xcc\xdd" + b"\x01" * 10),
        "chunks": [
            hx(c)
            for c in chunkify_code(
                Bytes(b"\x01" * 29 + PUSH4 + b"\xaa\xbb\xcc\xdd" + b"\x01" * 10)
            )
        ],
    },
    {
        "name": "push32_at_chunk_end_spills_31",
        "code": hx(b"\x01" * 30 + PUSH32 + bytes(range(32)) + b"\x01" * 5),
        "chunks": [
            hx(c)
            for c in chunkify_code(
                Bytes(b"\x01" * 30 + PUSH32 + bytes(range(32)) + b"\x01" * 5)
            )
        ],
    },
]

basic_data_cases = [
    {
        "code_size": 0,
        "nonce": 0,
        "balance": "0x0",
        "encoded": hx(encode_basic_data(U32(0), U64(0), U256(0))),
    },
    {
        "code_size": 1234,
        "nonce": 42,
        "balance": hex(10**18),
        "encoded": hx(encode_basic_data(U32(1234), U64(42), U256(10**18))),
    },
    {
        "code_size": 2**32 - 1,
        "nonce": 2**64 - 1,
        "balance": hex(2**128 - 1),
        "encoded": hx(
            encode_basic_data(U32(2**32 - 1), U64(2**64 - 1), U256(2**128 - 1))
        ),
    },
]

json.dump(
    {
        "source": "ethereum/execution-specs projects/binary-trie",
        "source_commit": subprocess.check_output(
            ["git", "rev-parse", "HEAD"], text=True
        ).strip(),
        "trie_roots": trie_cases,
        "embedding": embedding_cases,
        "chunkify_code": chunkify_cases,
        "encode_basic_data": basic_data_cases,
    },
    sys.stdout,
    indent=2,
)
print()
```

**Step 2: Generate the fixture**

```bash
cd /Users/kev/work/ethereum/execution-specs
uv run python /Users/kev/work/ethereum/ethrex/crates/common/binary-trie/tests/vectors/dump_vectors.py \
  > /Users/kev/work/ethereum/ethrex/crates/common/binary-trie/tests/vectors/binary_trie_vectors.json
```

(The execution-specs checkout must be on `projects/binary-trie` or any branch containing `src/ethereum/binary_trie/`.)

**Step 3: Sanity-check the output**

`python3 -c "import json; d=json.load(open('crates/common/binary-trie/tests/vectors/binary_trie_vectors.json')); print(len(d['trie_roots']), d['trie_roots'][1]['root'], d['trie_roots'][-1]['root'])"`

Expected output (must match exactly — deterministic generator):

```
9 0x4b60a28dce9f3529d103a26e00fadb98514cbd16ce03b7df752426addef9bbc7 0xd966e4d5b3676b62c732a8c267753f375226322ec44b1c1d4f8f8c40de77e9be
```

The fixture's top-level `source_commit` field records the execution-specs
commit the vectors were generated from (`git rev-parse HEAD` of the spec
checkout at generation time); it changes when regenerating from a different
spec revision, but all vector values must stay identical unless the spec
itself changed.

Other spot values for reference:
- `embedding.basic_data_key` = `0x00f4e42504054ae2ba2c9aab59b7cafad1e3df583c385d10fcb8ab0a0ab82e7a0800`
- `embedding.storage_slot_keys["64"]` = `0xfff4e42504054ae2ba2c9aab59b7cafad1e3df583c385d10fcb8ab0a0ab82e7a08b7b7ba8d57e997347b504830cfb1837de0bb46da8c5c53654442588e0ca0bdbf40`
- `encode_basic_data[1].encoded` = `0x00000000000004d2000000000000002a00000000000000000de0b6b3a7640000`

**Step 4: Commit**

```bash
git add crates/common/binary-trie/tests/vectors
git commit -m "test(binary-trie): add spec-generated test vector fixture"
```

---

## Task 3: Bit utilities and prefix encoding

**Files:**
- Create: `crates/common/binary-trie/src/trie/bits.rs`
- Modify: `crates/common/binary-trie/src/trie.rs` (becomes `mod bits;` re-export point — or convert to `src/trie/mod.rs`; use `src/trie/mod.rs` layout from here on)

Bits are represented as `Vec<u8>` with one bit per byte (values 0/1), matching the spec's readability-first layout. Do not micro-optimize with a bitvec type in this plan.

**Step 1: Write the failing tests**

In `src/trie/bits.rs`:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_to_bits_msb_first() {
        assert_eq!(bytes_to_bits(&[0b1010_0001]), vec![1, 0, 1, 0, 0, 0, 0, 1]);
        assert_eq!(bytes_to_bits(&[]), Vec::<u8>::new());
        assert_eq!(bytes_to_bits(&[0x80, 0x01])[0], 1);
        assert_eq!(bytes_to_bits(&[0x80, 0x01])[15], 1);
    }

    #[test]
    fn encode_bit_prefix_empty() {
        // 0 bits: count 0x0000, no payload
        assert_eq!(encode_bit_prefix(&[]), vec![0x00, 0x00]);
    }

    #[test]
    fn encode_bit_prefix_packs_msb_first_and_pads() {
        // 3 bits [1,0,1] -> count 0x0003, packed 0b1010_0000
        assert_eq!(encode_bit_prefix(&[1, 0, 1]), vec![0x00, 0x03, 0b1010_0000]);
        // 9 bits -> count 0x0009, two payload bytes
        let nine = vec![1, 1, 1, 1, 1, 1, 1, 1, 1];
        assert_eq!(encode_bit_prefix(&nine), vec![0x00, 0x09, 0xff, 0x80]);
    }

    #[test]
    fn encode_bit_prefix_is_injective_on_trailing_zeros() {
        // [1] and [1,0] pack to the same payload byte; the count must differ
        assert_ne!(encode_bit_prefix(&[1]), encode_bit_prefix(&[1, 0]));
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p ethrex-binary-trie bits`
Expected: compile error, `bytes_to_bits` not found.

**Step 3: Implement**

```rust
//! Bit-level helpers. Bits are `Vec<u8>` of 0/1 values, MSB-first,
//! matching the spec's readability-first representation.

/// Expand each byte into eight bits, most significant bit first.
pub fn bytes_to_bits(data: &[u8]) -> Vec<u8> {
    data.iter()
        .flat_map(|byte| (0..8).map(move |offset| (byte >> (7 - offset)) & 1))
        .collect()
}

/// Encode a branch prefix: a two-byte big-endian bit count followed by
/// the bits packed MSB-first, zero-padded to a byte boundary.
///
/// The explicit count keeps the encoding injective: without it, two
/// prefixes differing only in trailing zero bits would pack to the
/// same bytes and two different trees could share a root.
pub fn encode_bit_prefix(prefix: &[u8]) -> Vec<u8> {
    debug_assert!(prefix.len() < 1 << 16);
    let mut out = vec![0u8; 2 + prefix.len().div_ceil(8)];
    out[..2].copy_from_slice(&(prefix.len() as u16).to_be_bytes());
    for (i, bit) in prefix.iter().enumerate() {
        out[2 + i / 8] |= bit << (7 - i % 8);
    }
    out
}
```

**Step 4: Run tests to verify they pass**

Run: `cargo test -p ethrex-binary-trie bits`
Expected: 4 passed.

**Step 5: Commit**

```bash
git add crates/common/binary-trie
git commit -m "feat(binary-trie): bit expansion and injective prefix encoding"
```

---

## Task 4: Node types, hashing, and the rebuild-from-scratch reference

This is the direct port of the spec's `merkleize` + `binarize`. It becomes the differential-test oracle for the incremental implementation in Task 6, and doubles as executable documentation, so it is a public module.

**Files:**
- Create: `crates/common/binary-trie/src/trie/node.rs`
- Create: `crates/common/binary-trie/src/trie/rebuild.rs`
- Create: `crates/common/binary-trie/src/error.rs`
- Modify: `crates/common/binary-trie/src/trie/mod.rs`, `src/lib.rs`

**Step 1: Write the failing tests**

In `src/trie/rebuild.rs` tests: hard-code two vectors from the fixture (full fixture-driven testing comes in Task 5; hard-coding two here keeps this task self-contained):

```rust
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
        // the root must still have different roots, because the leaf
        // preimage contains the complete key.
        let mut a = std::collections::BTreeMap::new();
        a.insert(vec![0x00, 0xaa], [1u8; 32]);
        let mut b = std::collections::BTreeMap::new();
        b.insert(vec![0xaa], [1u8; 32]);
        assert_ne!(rebuild_root(&a), rebuild_root(&b));
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p ethrex-binary-trie rebuild`
Expected: compile error.

**Step 3: Implement**

`src/error.rs`:

```rust
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
```

`src/trie/node.rs` — shared node shape and hashing (used by both implementations):

```rust
use ethereum_types::H256;

use super::bits::encode_bit_prefix;

/// Root hash of an empty tree: a 32-zero-byte sentinel, not a hash output.
pub const EMPTY_TRIE_ROOT: H256 = H256::zero();

pub const LEAF_NODE_TAG: u8 = 0x00;
pub const BRANCH_NODE_TAG: u8 = 0x01;

pub(crate) fn blake3_hash(data: &[u8]) -> H256 {
    H256(*blake3::hash(data).as_bytes())
}

/// Hash committing to a leaf: `blake3(0x00 ‖ full_key ‖ value)`.
/// The complete key is committed so a leaf's meaning never depends
/// on the path taken to reach it.
pub fn leaf_hash(key: &[u8], value: &[u8; 32]) -> H256 {
    let mut preimage = Vec::with_capacity(1 + key.len() + 32);
    preimage.push(LEAF_NODE_TAG);
    preimage.extend_from_slice(key);
    preimage.extend_from_slice(value);
    blake3_hash(&preimage)
}

/// Hash committing to a branch:
/// `blake3(0x01 ‖ encode_bit_prefix(prefix) ‖ left ‖ right)`.
pub fn branch_hash(prefix: &[u8], left: H256, right: H256) -> H256 {
    let encoded_prefix = encode_bit_prefix(prefix);
    let mut preimage = Vec::with_capacity(1 + encoded_prefix.len() + 64);
    preimage.push(BRANCH_NODE_TAG);
    preimage.extend_from_slice(&encoded_prefix);
    preimage.extend_from_slice(left.as_bytes());
    preimage.extend_from_slice(right.as_bytes());
    blake3_hash(&preimage)
}
```

`src/trie/rebuild.rs` — port of the spec's `binarize`/`root`. Signature works over `BTreeMap<Vec<u8>, [u8; 32]>` (deterministic iteration; the map itself is the "trie"):

```rust
//! Rebuild-from-scratch reference implementation: a direct port of
//! the spec's `binarize`, which recomputes the canonical node
//! structure from a flat map on every call. Used as the differential
//! oracle for the incremental [`BinaryTrie`](super::BinaryTrie) and
//! kept public as executable documentation of canonical form.

use std::collections::BTreeMap;

use ethereum_types::H256;

use super::bits::bytes_to_bits;
use super::node::{branch_hash, leaf_hash, EMPTY_TRIE_ROOT};

pub type Entries = BTreeMap<Vec<u8>, [u8; 32]>;

pub fn rebuild_root(entries: &Entries) -> H256 {
    if entries.is_empty() {
        return EMPTY_TRIE_ROOT;
    }
    let refs: Vec<(&[u8], &[u8; 32])> =
        entries.iter().map(|(k, v)| (k.as_slice(), v)).collect();
    binarize(&refs, 0)
}

/// Hash the canonical node structure for `entries`, whose keys all
/// share their first `depth` bits. Panics on prefix-violating or
/// empty input: `rebuild_root` is a test oracle, and its callers
/// (the fixture and the differential test) only feed prefix-free
/// non-empty key sets.
fn binarize(entries: &[(&[u8], &[u8; 32])], depth: usize) -> H256 {
    assert!(!entries.is_empty());
    if let [(key, value)] = entries {
        return leaf_hash(key, value);
    }

    let bit_lists: Vec<Vec<u8>> =
        entries.iter().map(|(k, _)| bytes_to_bits(k)).collect();

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

    let (left, right): (Vec<_>, Vec<_>) = entries
        .iter()
        .zip(&bit_lists)
        .partition(|(_, bits)| bits[split] == 0);
    let unzip = |side: Vec<(&(&[u8], &[u8; 32]), &Vec<u8>)>| {
        side.into_iter().map(|(e, _)| *e).collect::<Vec<_>>()
    };

    branch_hash(
        &bit_lists[0][depth..split],
        binarize(&unzip(left), split + 1),
        binarize(&unzip(right), split + 1),
    )
}
```

Wire up `src/trie/mod.rs`:

```rust
pub mod bits;
pub mod node;
pub mod rebuild;

pub use node::EMPTY_TRIE_ROOT;

/// Longest accepted key, in bytes. Bounds branch-prefix bit counts
/// below the two-byte limit of `encode_bit_prefix`.
pub const MAX_KEY_LENGTH: usize = 8192;
```

and `src/lib.rs`: add `pub mod error;` and re-export `pub use error::BinaryTrieError;`.

**Step 4: Run tests to verify they pass**

Run: `cargo test -p ethrex-binary-trie`
Expected: all tests pass (bits + rebuild).

**Step 5: Commit**

```bash
git add crates/common/binary-trie
git commit -m "feat(binary-trie): node hashing and rebuild-from-scratch reference"
```

---

## Task 5: Fixture-driven trie root tests

**Files:**
- Create: `crates/common/binary-trie/tests/spec_vectors.rs`

**Step 1: Write the test harness (it should pass immediately for the rebuild oracle — that's the point: the oracle is now pinned to the spec)**

```rust
//! Conformance tests against vectors generated from the EELS
//! reference implementation (see tests/vectors/dump_vectors.py).

use std::collections::BTreeMap;

use ethrex_binary_trie::trie::rebuild::rebuild_root;
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    trie_roots: Vec<TrieCase>,
    embedding: serde_json::Value,
    chunkify_code: Vec<ChunkCase>,
    encode_basic_data: Vec<BasicDataCase>,
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

#[derive(Deserialize)]
struct ChunkCase {
    name: String,
    code: String,
    chunks: Vec<String>,
}

#[derive(Deserialize)]
struct BasicDataCase {
    code_size: u32,
    nonce: u64,
    balance: String,
    encoded: String,
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s.trim_start_matches("0x")).unwrap()
}

fn load() -> Fixture {
    serde_json::from_str(include_str!("vectors/binary_trie_vectors.json")).unwrap()
}

#[test]
fn rebuild_matches_spec_roots() {
    for case in load().trie_roots {
        let entries: BTreeMap<Vec<u8>, [u8; 32]> = case
            .entries
            .iter()
            .map(|e| (unhex(&e.key), unhex(&e.value).try_into().unwrap()))
            .collect();
        assert_eq!(
            rebuild_root(&entries).as_bytes(),
            unhex(&case.root).as_slice(),
            "trie case {}",
            case.name
        );
    }
}
```

Note: this needs the tiny `hex` crate or hand-rolled decoding. `hex` is already a workspace dependency in ethrex (`grep '^hex' Cargo.toml` to confirm the exact key); add `hex.workspace = true` to `[dev-dependencies]`. If it is not a workspace dep, write a 6-line `unhex` by hand instead of adding a dependency.

**Step 2: Run**

Run: `cargo test -p ethrex-binary-trie --test spec_vectors`
Expected: `rebuild_matches_spec_roots` passes across all 9 cases. If any case fails, the Rust port has a bug — diff against `trie.py` line by line; do not touch the fixture.

**Step 3: Commit**

```bash
git add crates/common/binary-trie
git commit -m "test(binary-trie): pin rebuild reference to spec-generated root vectors"
```

---

## Task 6: Incremental `BinaryTrie`

The production-shaped implementation: retained node structure, descend/split insertion, `root()` hashes what's already built (no per-call rebuild). Mirrors the spec repo's `tests/binary_trie/incremental_trie.py` (`IncrementalRadixTree`) — consult it if the algorithm below is unclear.

**Files:**
- Create: `crates/common/binary-trie/src/trie/binary_trie.rs`
- Modify: `crates/common/binary-trie/src/trie/mod.rs`

**Step 1: Write the failing tests**

```rust
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
        // new key is a prefix of an existing key
        assert_eq!(
            trie.insert(vec![0xaa], [2; 32]),
            Err(BinaryTrieError::PrefixViolation)
        );
        // an existing key is a prefix of the new key
        assert_eq!(
            trie.insert(vec![0xaa, 0xbb, 0xcc], [2; 32]),
            Err(BinaryTrieError::PrefixViolation)
        );
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
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p ethrex-binary-trie binary_trie`
Expected: compile error, `BinaryTrie` not found.

**Step 3: Implement**

```rust
//! Insertion-based (incremental) binary radix trie: the
//! production-shaped implementation. Nodes are retained between
//! operations; `root()` hashes the existing structure.
//!
//! Canonical-form invariant: a branch's `prefix` holds exactly the
//! bits its two subtrees share beyond the parent's split point, so
//! any insertion order yields the same structure — cross-checked
//! against the rebuild-from-scratch reference in tests.

use ethereum_types::H256;

use crate::error::BinaryTrieError;

use super::bits::bytes_to_bits;
use super::node::{branch_hash, leaf_hash, EMPTY_TRIE_ROOT};
use super::MAX_KEY_LENGTH;

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

#[derive(Default)]
pub struct BinaryTrie {
    root: Option<Node>,
}

impl BinaryTrie {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(
        &mut self,
        key: Vec<u8>,
        value: [u8; 32],
    ) -> Result<(), BinaryTrieError> {
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

    /// Insert below `node`, whose position consumed `depth` bits of
    /// the path. On error the original node is handed back so the
    /// trie is left untouched.
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
                let leaf_bits = bytes_to_bits(&leaf_key);
                // First bit index at or after `depth` where the two
                // keys disagree. Running out of either key first
                // means one is a prefix of the other.
                let mut split = depth;
                loop {
                    match (bits.get(split), leaf_bits.get(split)) {
                        (Some(a), Some(b)) if a == b => split += 1,
                        (Some(_), Some(_)) => break,
                        _ => {
                            return Err((
                                Node::Leaf {
                                    key: leaf_key,
                                    value: leaf_value,
                                },
                                BinaryTrieError::PrefixViolation,
                            ));
                        }
                    }
                }
                let prefix = bits[depth..split].to_vec();
                let new_leaf = Node::Leaf { key, value };
                let old_leaf = Node::Leaf {
                    key: leaf_key,
                    value: leaf_value,
                };
                let (left, right) = if bits[split] == 0 {
                    (new_leaf, old_leaf)
                } else {
                    (old_leaf, new_leaf)
                };
                Ok(Node::Branch {
                    prefix,
                    left: Box::new(left),
                    right: Box::new(right),
                })
            }
            Node::Branch {
                prefix,
                left,
                right,
            } => {
                // How many of the branch's prefix bits the new key
                // shares, starting at `depth`.
                let mut shared = 0;
                while shared < prefix.len() {
                    match bits.get(depth + shared) {
                        Some(&bit) if bit == prefix[shared] => shared += 1,
                        Some(_) => break,
                        None => {
                            return Err((
                                Node::Branch {
                                    prefix,
                                    left,
                                    right,
                                },
                                BinaryTrieError::PrefixViolation,
                            ));
                        }
                    }
                }

                if shared == prefix.len() {
                    // Full prefix match: descend on the split bit.
                    let split = depth + prefix.len();
                    let Some(&bit) = bits.get(split) else {
                        return Err((
                            Node::Branch {
                                prefix,
                                left,
                                right,
                            },
                            BinaryTrieError::PrefixViolation,
                        ));
                    };
                    let child_depth = split + 1;
                    if bit == 0 {
                        match Self::insert_at(*left, bits, child_depth, key, value) {
                            Ok(new_left) => Ok(Node::Branch {
                                prefix,
                                left: Box::new(new_left),
                                right,
                            }),
                            Err((old_left, e)) => Err((
                                Node::Branch {
                                    prefix,
                                    left: Box::new(old_left),
                                    right,
                                },
                                e,
                            )),
                        }
                    } else {
                        match Self::insert_at(*right, bits, child_depth, key, value) {
                            Ok(new_right) => Ok(Node::Branch {
                                prefix,
                                left,
                                right: Box::new(new_right),
                            }),
                            Err((old_right, e)) => Err((
                                Node::Branch {
                                    prefix,
                                    left,
                                    right: Box::new(old_right),
                                },
                                e,
                            )),
                        }
                    }
                } else {
                    // Diverges inside the prefix: split the branch.
                    // Old branch keeps the tail past the split bit.
                    let new_leaf = Node::Leaf { key, value };
                    let old_branch = Node::Branch {
                        prefix: prefix[shared + 1..].to_vec(),
                        left,
                        right,
                    };
                    let (new_left, new_right) = if bits[depth + shared] == 0 {
                        (new_leaf, old_branch)
                    } else {
                        (old_branch, new_leaf)
                    };
                    Ok(Node::Branch {
                        prefix: prefix[..shared].to_vec(),
                        left: Box::new(new_left),
                        right: Box::new(new_right),
                    })
                }
            }
        }
    }

    pub fn get(&self, key: &[u8]) -> Option<[u8; 32]> {
        let bits = bytes_to_bits(key);
        let mut depth = 0;
        let mut node = self.root.as_ref()?;
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
                    if bits.len() <= split
                        || bits[depth..split] != prefix[..]
                    {
                        return None;
                    }
                    node = if bits[split] == 0 { left } else { right };
                    depth = split + 1;
                }
            }
        }
    }

    /// Root hash: [`EMPTY_TRIE_ROOT`] for an empty trie, otherwise
    /// the recursive tagged BLAKE3 commitment of the node structure.
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
```

Add to `src/trie/mod.rs`: `mod binary_trie;` and `pub use binary_trie::BinaryTrie;`.

Note the deliberate simplifications, to be revisited only when the storage-integration plan needs them (YAGNI now): no hash caching/memoization, no deletion (the spec's trie has no delete either; the commitment layer expresses deletion by re-embedding), no `TrieDB` backing.

**Step 4: Run tests to verify they pass**

Run: `cargo test -p ethrex-binary-trie`
Expected: all pass, including the new 7.

**Step 5: Add the fixture cross-check for the incremental implementation**

In `tests/spec_vectors.rs` add:

```rust
#[test]
fn incremental_matches_spec_roots() {
    for case in load().trie_roots {
        let mut trie = ethrex_binary_trie::trie::BinaryTrie::new();
        for e in &case.entries {
            trie.insert(unhex(&e.key), unhex(&e.value).try_into().unwrap())
                .unwrap();
        }
        assert_eq!(
            trie.root().as_bytes(),
            unhex(&case.root).as_slice(),
            "trie case {}",
            case.name
        );
    }
}
```

Run: `cargo test -p ethrex-binary-trie --test spec_vectors`
Expected: both vector tests pass.

**Step 6: Commit**

```bash
git add crates/common/binary-trie
git commit -m "feat(binary-trie): incremental insertion-based BinaryTrie"
```

---

## Task 7: Randomized differential test (incremental vs rebuild)

**Files:**
- Create: `crates/common/binary-trie/tests/differential.rs`

**Step 1: Write the test**

```rust
//! Differential test: the incremental BinaryTrie and the
//! rebuild-from-scratch reference must agree on every root. Because
//! the two implementations were written independently (insertion vs
//! canonical rebuild), agreement also checks that insertion order
//! never changes the structure.

use std::collections::BTreeMap;

use ethrex_binary_trie::trie::rebuild::rebuild_root;
use ethrex_binary_trie::trie::BinaryTrie;
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
            key.extend((1..len).map(|_| *[0u8, 1, 0xfe, 0xff]
                .get(rng.gen_range(0..4))
                .unwrap()));
            let value: [u8; 32] = rng.gen();

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
        assert_eq!(trie.root(), rebuild_root(&entries), "final root, round {round}");
    }
}
```

**Step 2: Run it**

Run: `cargo test -p ethrex-binary-trie --test differential`
Expected: passes in a few seconds. If it fails, minimize: print the entry set at the first divergent checkpoint, reduce to the smallest reproducing subset, then compare node structures by hand against `incremental_trie.py`'s algorithm.

**Step 3: Commit**

```bash
git add crates/common/binary-trie
git commit -m "test(binary-trie): differential test incremental vs rebuild reference"
```

---

## Task 8: Embedding — constants, key derivation

**Files:**
- Modify: `crates/common/binary-trie/src/embedding.rs`

**Step 1: Write the failing tests**

Tests hard-code the fixture's embedding vectors (they are small); full fixture-driven assertions come in Step 5.

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use ethereum_types::{H160, U256};
    use hex_literal::hex;

    const ADDR20: H160 = H160(hex!("00112233445566778899aabbccddeeff00112233"));

    #[test]
    fn address32_prepends_twelve_zero_bytes() {
        let a32 = address20_to_address32(ADDR20);
        assert_eq!(&a32[..12], &[0u8; 12]);
        assert_eq!(&a32[12..], ADDR20.as_bytes());
    }

    #[test]
    fn basic_data_key_vector() {
        // fixture: embedding.basic_data_key
        assert_eq!(
            get_tree_key_for_basic_data(&address20_to_address32(ADDR20)),
            hex!("00f4e42504054ae2ba2c9aab59b7cafad1e3df583c385d10fcb8ab0a0ab82e7a0800").to_vec()
        );
    }

    #[test]
    fn header_key_layout() {
        let a32 = address20_to_address32(ADDR20);
        let key = get_tree_key_for_header(&a32, 255);
        assert_eq!(key.len(), 34);
        assert_eq!(key[0], ACCOUNT_ZONE);
        assert_eq!(key[33], 255);
        // code-hash key differs from basic-data key only in sub-index
        assert_eq!(get_tree_key_for_code_hash(&a32)[..33], key[..33]);
        assert_eq!(get_tree_key_for_code_hash(&a32)[33], 1);
    }

    #[test]
    fn storage_slot_63_in_header_64_in_storage_zone() {
        let a32 = address20_to_address32(ADDR20);
        let slot63 = get_tree_key_for_storage_slot(&a32, U256::from(63));
        let slot64 = get_tree_key_for_storage_slot(&a32, U256::from(64));
        assert_eq!(slot63.len(), 34);
        assert_eq!(slot63[0], ACCOUNT_ZONE);
        assert_eq!(slot63[33], 64 + 63); // HEADER_STORAGE_OFFSET + slot
        assert_eq!(slot64.len(), 66);
        assert_eq!(slot64[0], STORAGE_ZONE);
        assert_eq!(slot64[65], 64); // 64 % 256
    }

    #[test]
    fn storage_slot_group_zero_is_short() {
        // Slots 64..=255 share tree_index 0; slot 256 starts group 1
        // with a different stem.
        let a32 = address20_to_address32(ADDR20);
        let k255 = get_tree_key_for_storage_slot(&a32, U256::from(255));
        let k256 = get_tree_key_for_storage_slot(&a32, U256::from(256));
        assert_eq!(k255[..65], get_tree_key_for_storage_slot(&a32, U256::from(64))[..65]);
        assert_ne!(k255[..65], k256[..65]);
    }

    #[test]
    fn huge_storage_key_does_not_overflow() {
        let a32 = address20_to_address32(ADDR20);
        // 2^200: tree_index arithmetic must be U256, not u64
        let key = get_tree_key_for_storage_slot(&a32, U256::from(2).pow(U256::from(200)));
        assert_eq!(key.len(), 66);
        assert_eq!(key[0], STORAGE_ZONE);
    }

    #[test]
    fn code_chunk_127_in_header_128_in_code_zone() {
        let a32 = address20_to_address32(ADDR20);
        let code_hash = [0x11u8; 32];
        let c127 = get_tree_key_for_code_chunk(&a32, &code_hash, 127);
        let c128 = get_tree_key_for_code_chunk(&a32, &code_hash, 128);
        assert_eq!(c127[0], ACCOUNT_ZONE);
        assert_eq!(c127[33], 128 + 127); // CODE_OFFSET + chunk
        assert_eq!(c128[0], CODE_ZONE);
        assert_eq!(c128.len(), 34);
        assert_eq!(c128[33], 0); // first overflow chunk, sub-index 0
    }

    #[test]
    fn overflow_code_is_content_addressed_not_per_account() {
        let a = address20_to_address32(ADDR20);
        let b = address20_to_address32(H160([0x99; 20]));
        let code_hash = [0x11u8; 32];
        // overflow chunks: same for any account with the same code
        assert_eq!(
            get_tree_key_for_code_chunk(&a, &code_hash, 128),
            get_tree_key_for_code_chunk(&b, &code_hash, 128)
        );
        // header chunks: per-account
        assert_ne!(
            get_tree_key_for_code_chunk(&a, &code_hash, 0),
            get_tree_key_for_code_chunk(&b, &code_hash, 0)
        );
    }
}
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p ethrex-binary-trie embedding`
Expected: compile error.

**Step 3: Implement**

Port `embedding.py` faithfully. Skeleton (fill in doc comments from the Python docstrings, condensed):

```rust
use ethereum_types::{H160, H256, U256};

use crate::trie::node::blake3_hash; // make blake3_hash pub(crate) in node.rs

pub type Address32 = [u8; 32];
pub type Key = Vec<u8>;

pub const BASIC_DATA_LEAF_KEY: u8 = 0;
pub const BASIC_DATA_VERSION: u8 = 0;
pub const CODE_HASH_LEAF_KEY: u8 = 1;
pub const HEADER_STORAGE_OFFSET: u64 = 64;
pub const CODE_OFFSET: u64 = 128;
pub const STEM_SUBTREE_WIDTH: u64 = 256;
pub const ACCOUNT_ZONE: u8 = 0;
pub const CODE_ZONE: u8 = 1;
pub const STORAGE_ZONE: u8 = 255;
pub const ACCOUNT_KEY_LENGTH: usize = 34;
pub const CODE_KEY_LENGTH: usize = 34;
pub const STORAGE_KEY_LENGTH: usize = 66;

pub fn address20_to_address32(address: H160) -> Address32 {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(address.as_bytes());
    out
}

/// Hash for tree key derivation: the tree's own BLAKE3.
fn key_hash(data: &[u8]) -> H256 {
    blake3_hash(data)
}

fn get_tree_key(zone: u8, tree_position: &[u8], sub_index: u8) -> Key {
    let mut key = Vec::with_capacity(2 + tree_position.len());
    key.push(zone);
    key.extend_from_slice(tree_position);
    key.push(sub_index);
    key
}

pub fn get_tree_key_for_header(address: &Address32, sub_index: u64) -> Key {
    debug_assert!(sub_index < STEM_SUBTREE_WIDTH);
    let key = get_tree_key(
        ACCOUNT_ZONE,
        key_hash(address).as_bytes(),
        sub_index as u8,
    );
    debug_assert_eq!(key.len(), ACCOUNT_KEY_LENGTH);
    key
}

pub fn get_tree_key_for_basic_data(address: &Address32) -> Key {
    get_tree_key_for_header(address, BASIC_DATA_LEAF_KEY as u64)
}

pub fn get_tree_key_for_code_hash(address: &Address32) -> Key {
    get_tree_key_for_header(address, CODE_HASH_LEAF_KEY as u64)
}

/// Two digests: `hash(address)` groups all of an account's overflow
/// storage under one subtree; `hash(address ‖ tree_index)` spreads
/// its groups within it. Both depend on the address, so ground-out
/// storage keys cannot be reused against another contract.
fn storage_tree_position(address: &Address32, tree_index: U256) -> Vec<u8> {
    let mut index_bytes = [0u8; 32];
    tree_index.to_big_endian(&mut index_bytes);
    let mut addr_and_index = Vec::with_capacity(64);
    addr_and_index.extend_from_slice(address);
    addr_and_index.extend_from_slice(&index_bytes);

    let mut position = Vec::with_capacity(64);
    position.extend_from_slice(key_hash(address).as_bytes());
    position.extend_from_slice(key_hash(&addr_and_index).as_bytes());
    position
}

pub fn get_tree_key_for_storage_slot(address: &Address32, storage_key: U256) -> Key {
    if storage_key < U256::from(CODE_OFFSET - HEADER_STORAGE_OFFSET) {
        return get_tree_key_for_header(
            address,
            HEADER_STORAGE_OFFSET + storage_key.as_u64(),
        );
    }
    let tree_index = storage_key / U256::from(STEM_SUBTREE_WIDTH);
    let sub_index = (storage_key % U256::from(STEM_SUBTREE_WIDTH)).as_u64() as u8;
    let key = get_tree_key(
        STORAGE_ZONE,
        &storage_tree_position(address, tree_index),
        sub_index,
    );
    debug_assert_eq!(key.len(), STORAGE_KEY_LENGTH);
    key
}

pub fn get_tree_key_for_code_chunk(
    address: &Address32,
    code_hash: &[u8; 32],
    chunk_id: u64,
) -> Key {
    let header_chunk_count = STEM_SUBTREE_WIDTH - CODE_OFFSET;
    if chunk_id < header_chunk_count {
        return get_tree_key_for_header(address, CODE_OFFSET + chunk_id);
    }
    let overflow = chunk_id - header_chunk_count;
    let tree_index = overflow / STEM_SUBTREE_WIDTH;
    let sub_index = (overflow % STEM_SUBTREE_WIDTH) as u8;
    let mut hash_and_index = Vec::with_capacity(64);
    hash_and_index.extend_from_slice(code_hash);
    hash_and_index.extend_from_slice(&U256::from(tree_index).to_big_endian_vec());
    let key = get_tree_key(
        CODE_ZONE,
        key_hash(&hash_and_index).as_bytes(),
        sub_index,
    );
    debug_assert_eq!(key.len(), CODE_KEY_LENGTH);
    key
}
```

Adjust `to_big_endian` calls to the `ethereum-types` version actually in the workspace (older versions use `to_big_endian(&mut buf)`, newer have `to_big_endian()` returning an array — check `crates/common` usage for the idiom, e.g. `grep -rn "to_big_endian" crates/common --include="*.rs" | head -3`).

**Step 4: Run tests to verify they pass**

Run: `cargo test -p ethrex-binary-trie embedding`
Expected: 8 passed.

**Step 5: Fixture-driven embedding assertions**

Add to `tests/spec_vectors.rs` a `embedding_keys_match_spec` test asserting `basic_data_key`, `code_hash_key`, `header_sub_index_255_key`, every entry in `storage_slot_keys` (parse the decimal string keys with `U256::from_dec_str`), and every entry in `code_chunk_keys` against the fixture values, using the fixture's `address20` and `code_chunk_content_hash`.

Run: `cargo test -p ethrex-binary-trie --test spec_vectors`
Expected: passes.

**Step 6: Commit**

```bash
git add crates/common/binary-trie
git commit -m "feat(binary-trie): EIP-8297 state embedding key derivation"
```

---

## Task 9: Embedding — code chunking and basic data

**Files:**
- Modify: `crates/common/binary-trie/src/embedding.rs`
- Modify: `crates/common/binary-trie/src/error.rs`
- Modify: `crates/common/binary-trie/tests/spec_vectors.rs`

**Step 1: Write the failing tests**

```rust
    // in embedding tests module

    #[test]
    fn chunkify_empty_code_is_empty() {
        assert!(chunkify_code(&[]).is_empty());
    }

    #[test]
    fn chunkify_pads_to_31_and_prepends_offset_byte() {
        let chunks = chunkify_code(&[0x00]); // STOP
        assert_eq!(chunks.len(), 1);
        assert_eq!(chunks[0][0], 0); // no leading push data
        assert_eq!(chunks[0][1], 0x00);
        assert_eq!(&chunks[0][2..], &[0u8; 30]);
    }

    #[test]
    fn chunkify_push4_spilling_into_next_chunk() {
        // fixture: chunkify_code["eip_example_push4_boundary"]
        // PUSH4 at position 29; data bytes at 30..34; chunk 1 starts
        // at 31 with 3 leading push-data bytes.
        let mut code = vec![0x01; 29];
        code.push(0x63); // PUSH4
        code.extend([0xaa, 0xbb, 0xcc, 0xdd]);
        code.extend([0x01; 10]);
        let chunks = chunkify_code(&code);
        assert_eq!(chunks.len(), 2);
        assert_eq!(chunks[0][0], 0);
        assert_eq!(chunks[1][0], 3);
    }

    #[test]
    fn chunkify_caps_offset_byte_at_31() {
        // PUSH32 as the last byte of a chunk: all 32 data bytes are
        // in later chunks, but the count byte saturates at 31.
        let mut code = vec![0x01; 30];
        code.push(0x7f); // PUSH32 at position 30, last byte of chunk 0
        code.extend(0..32u8);
        code.extend([0x01; 5]);
        let chunks = chunkify_code(&code);
        assert_eq!(chunks[1][0], 31); // capped, real count is 32
    }

    #[test]
    fn encode_basic_data_layout_vector() {
        // fixture: encode_basic_data[1]
        assert_eq!(
            encode_basic_data(1234, 42, U256::from(10).pow(U256::from(18))).unwrap(),
            hex!("00000000000004d2000000000000002a00000000000000000de0b6b3a7640000")
        );
    }

    #[test]
    fn encode_basic_data_rejects_balance_at_2_pow_128() {
        assert_eq!(
            encode_basic_data(0, 0, U256::from(1) << 128),
            Err(BinaryTrieError::BalanceTooLarge)
        );
        assert!(encode_basic_data(0, 0, (U256::from(1) << 128) - 1).is_ok());
    }
```

**Step 2: Run tests to verify they fail**

Run: `cargo test -p ethrex-binary-trie embedding`
Expected: compile error.

**Step 3: Implement**

Add `BalanceTooLarge` to `BinaryTrieError` (`#[error("balance does not fit the 16-byte basic-data field")]`).

```rust
pub const PUSH_OFFSET: u8 = 95;
pub const PUSH1: u8 = PUSH_OFFSET + 1;
pub const PUSH32: u8 = PUSH_OFFSET + 32;

/// Split `code` into 32-byte chunks: byte 0 counts how many of the
/// chunk's leading payload bytes are push data continuing from an
/// earlier chunk (capped at 31), bytes 1..32 are the next 31 code
/// bytes (zero-padded).
pub fn chunkify_code(code: &[u8]) -> Vec<[u8; 32]> {
    if code.is_empty() {
        return Vec::new();
    }
    let padded_len = code.len().div_ceil(31) * 31;

    // remaining_push_data[i]: push-data bytes remaining at position i,
    // counting position i itself; 0 marks executable bytes. Extra 32
    // entries let the largest push record data past the end of code.
    let mut remaining_push_data = vec![0usize; padded_len + 32];
    let mut position = 0;
    while position < code.len() {
        let opcode = code[position];
        let push_data_bytes = if (PUSH1..=PUSH32).contains(&opcode) {
            (opcode - PUSH_OFFSET) as usize
        } else {
            0
        };
        position += 1;
        for offset in 0..push_data_bytes {
            remaining_push_data[position + offset] = push_data_bytes - offset;
        }
        position += push_data_bytes;
    }

    (0..padded_len)
        .step_by(31)
        .map(|start| {
            let mut chunk = [0u8; 32];
            chunk[0] = remaining_push_data[start].min(31) as u8;
            let end = (start + 31).min(code.len());
            if start < code.len() {
                chunk[1..1 + end - start].copy_from_slice(&code[start..end]);
            }
            chunk
        })
        .collect()
}

/// Pack version ‖ 3 reserved zero bytes ‖ code_size:4 ‖ nonce:8 ‖
/// balance:16, all big-endian.
pub fn encode_basic_data(
    code_size: u32,
    nonce: u64,
    balance: U256,
) -> Result<[u8; 32], BinaryTrieError> {
    if balance >= U256::from(1) << 128 {
        return Err(BinaryTrieError::BalanceTooLarge);
    }
    let mut out = [0u8; 32];
    out[0] = BASIC_DATA_VERSION;
    // out[1..4] reserved zero bytes
    out[4..8].copy_from_slice(&code_size.to_be_bytes());
    out[8..16].copy_from_slice(&nonce.to_be_bytes());
    out[16..32].copy_from_slice(&balance.low_u128().to_be_bytes());
    Ok(out)
}
```

(Check `low_u128` exists on the workspace `ethereum-types`; otherwise take the low 16 bytes of `to_big_endian` output.)

**Step 4: Run tests to verify they pass**

Run: `cargo test -p ethrex-binary-trie embedding`
Expected: all pass.

**Step 5: Fixture-driven assertions**

Extend `tests/spec_vectors.rs` with `chunkify_matches_spec` (all 4 chunk cases: decode `code`, compare chunk-by-chunk) and `basic_data_matches_spec` (all 3 cases; parse `balance` hex strings with `U256::from_str_radix(s.trim_start_matches("0x"), 16)`).

Run: `cargo test -p ethrex-binary-trie --test spec_vectors`
Expected: all vector tests pass.

**Step 6: Commit**

```bash
git add crates/common/binary-trie
git commit -m "feat(binary-trie): code chunking and basic-data encoding"
```

---

## Task 10: Lint, docs, and final verification

**Files:**
- Modify: `crates/common/binary-trie/src/*` (doc polish only)
- Create: `crates/common/binary-trie/README.md`

**Step 1: README**

Short README (model on `crates/common/trie/README.md`): what the crate is, the two trie implementations and why both exist, the vector fixture provenance (`tests/vectors/dump_vectors.py` + which execution-specs branch), and the explicit non-goals (no persistence, no deletion, no proofs, no fork wiring — deferred to the state-commitment integration plan). Note the spec discrepancy the EELS code itself flags: its basic-data `code_size` is 4 bytes at offset 4 vs EIP-7864's 3 bytes at offset 5 — we follow the EELS branch, and the fixture pins that choice; revisit when EIP-8297's final layout lands.

**Step 2: Workspace-level checks**

Run, in order, and fix anything that surfaces:

```bash
cargo fmt -- --check   # or the repo's `make lint` equivalent
cargo clippy -p ethrex-binary-trie --all-targets -- -D warnings
cargo test -p ethrex-binary-trie
cargo check --workspace
```

Expected: all clean. (Check `CLAUDE.md` / `Makefile` in the repo root for the canonical lint invocation and use that if it differs.)

**Step 3: Commit**

```bash
git add crates/common/binary-trie README.md
git commit -m "docs(binary-trie): crate README and doc polish"
```

---

## Out of scope (deliberately)

Deferred to a follow-up "state commitment integration" plan, per the mapping analysis:

1. **Commitment seam** — trait or enum switch in `Store::apply_account_updates_from_trie_batch` (`crates/storage/store.rs:2180`), `setup_genesis_state_trie` (`store.rs:2343`), and `GuestProgramState::apply_account_updates` (`crates/common/types/block_execution_witness.rs:504`), gated on `Fork::Hegota`.
2. **`Crypto` trait integration** — moving `blake3` behind `crates/common/crypto/provider.rs` for zkVM guest substitution.
3. **Persistence** — `TrieDB`-backed node storage, hash caching, deletion support.
4. **EF test conformance** — running fixtures filled from the spec's `BinaryTree` fork (execution-specs PR #3216) once available.
5. **Sync, proofs, witness format** — all MPT-shaped today; blocked on the EIP's transition design.
