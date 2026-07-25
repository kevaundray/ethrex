# `eth_getProof` over the EIP-8297 Partitioned Binary Tree — investigation

Status: investigation record for the implementation on this branch.
Companion: `docs/eip-draft-pbt-eth-getproof.md` (the format specification),
`docs/plans/2026-07-25-binary-trie-state-commitment.md` (the state-commitment
integration this closes a documented gap of).

## 1. What exists upstream

**No proof or witness format exists anywhere upstream.** Checked:

- `ethereum/execution-specs`, branch `kw/sketch-embedding-changes`:
  `src/ethereum/binary_trie/{trie,embedding}.py` and `state_pbt.py` define the
  tree, the hashing, and the state embedding — nothing proof-shaped. The only
  mention is prose in `embedding.py` ("one proof path covers them all",
  about stem co-location). No `tests/binary_trie/` proof vectors.
- `EIPS/eip-8297.md` and `EIPS/eip-7864.md` (local checkout): both discuss
  Merkle proof *size* in Motivation/Rationale (binary arity shrinks branches
  to `32 * log2(N)`-ish) and witness friendliness, but neither specifies a
  proof encoding, a multiproof, nor an `eth_getProof` response shape.
- `execution-apis` has no PBT-aware `eth_getProof` schema (the current schema
  hard-codes `storageHash` and MPT node lists).

Consequence: any format we ship is **interim and experimental**, versioned so
EIP-8297's eventual canonical witness format can supersede it. That framing
is baked into the EIP draft.

## 2. Proof building blocks the tree gives us

From `trie.py` / `ethrex-binary-trie`:

- Node commitments are BLAKE3 over **tagged preimages**:
  - leaf: `0x00 ‖ key ‖ value` — the *complete* key is committed, so a leaf's
    meaning never depends on the path taken to reach it;
  - branch: `0x01 ‖ encode_bit_prefix(prefix) ‖ left_hash ‖ right_hash` —
    the child hashes are embedded at fixed offsets from the end.
- `encode_bit_prefix` = 2-byte big-endian bit count + MSB-first packed bits,
  zero-padded. Injective (the count disambiguates trailing zeros), and
  self-delimiting inside a preimage, so a branch preimage parses
  unambiguously.
- Keys are consumed bit by bit, MSB first; the walk down a key is
  deterministic. Empty tree root is the 32-zero-byte sentinel.

These properties make "ordered list of node preimages root→terminal" a
complete proof: the verifier re-hashes each preimage, checks the first
against the root, checks each branch's chosen-child hash against the next
preimage's hash, and checks the target key's bits against every branch
prefix and split bit. No out-of-band structure information is needed — the
tags distinguish node types and the preimages parse unambiguously given
their length.

## 3. Format options considered

1. **Per-key node-path proofs** (chosen for v1). One proof per tree key:
   the ordered preimages from root to the terminal node of that key's walk.
   Simple to generate (one walk), simple to verify (pure recompute, no trie
   needed), simple to test against the spec-pinned fixture roots. Redundant
   when several keys share a stem — the shared path is repeated per key.
2. **Stem-level multiproofs.** The embedding co-locates an account's hot
   data (basic data, code hash, first 64 slots, first 128 code chunks) under
   one 33-byte stem, so the natural proof unit is "one shared path to the
   stem's subtree + the subtree's relevant nodes". Smaller for multi-slot
   queries, but requires a deduplicated node-set encoding plus reassembly
   rules on the verifier side. Deferred: it is a *compatible extension* — a
   multiproof verifier can be layered over the same preimage encoding, and
   the response format carries a version tag precisely so this can land
   later without breaking v1 consumers.
3. **Full block witness.** Out of scope; that is EIP-8297's eventual
   canonical format to define.

## 4. Inclusion and exclusion semantics

Checked against `trie.py`'s structure: the walk down a target key's bits is
deterministic, so the terminal node of that walk is the complete witness in
both directions.

- **Inclusion**: the walk ends at a leaf whose committed key equals the
  target and whose value is the claimed value.
- **Exclusion** — the walk *diverges*, in one of exactly three ways:
  1. terminal **leaf with a different key**: the position the target's bits
     lead to is occupied by another key (the leaf commits its full key, so
     this is directly checkable);
  2. terminal **branch whose prefix the target's bits diverge from**: every
     key below that branch shares the prefix, so no key below can be the
     target — neither child needs to be opened;
  3. the target's bits **run out** inside a branch's prefix or at its split
     bit: every key below extends past the target, so the target (which
     would be a bit-prefix of them) cannot be present. Cannot happen for
     well-formed embedding queries (all keys in a zone have equal length)
     but the verifier handles it for completeness.
- **Empty trie** (root = 32 zero bytes): the empty proof proves every key
  absent.

Soundness note: the verifier enforces the target's bit path at every branch,
so the prover cannot steer the walk; under BLAKE3 collision resistance the
hash chain pins each shown node to the committed tree, so a divergent
terminal genuinely proves absence.

## 5. How the `eth_getProof` response must change

The standard response cannot be kept:

- **No `storageHash`**: the unified tree has no per-account storage root.
  The field is serialized as `null` (kept, explicitly null, rather than
  dropped — so consumers fail loudly instead of misreading a stale field).
- **No single `accountProof`**: an account is not one RLP record but
  separate 32-byte leaves — basic data (version/code size/nonce/balance
  packed) and code hash — each with its own tree key and proof.
- **Storage slots** are tree-key proofs (34-byte header-stem keys for slots
  0–63, 66-byte storage-zone keys above), not storage-trie-of-the-account
  proofs.
- `balance`/`nonce`/`codeHash` remain as decoded convenience fields; the
  leaf values inside the proofs are authoritative. Absent leaves (`value:
  null`) are the account-nonexistence signal.

Shape (full spec in the EIP draft): top-level `format` version string,
`binaryAccountProof.{basicData,codeHash}` and `storageProof[]` entries each
carrying `treeKey`, `value` (leaf value or null / quantity for storage), and
`proof` — the hex-encoded preimage list.

## 6. What the verifier needs

- BLAKE3 (only hash involved; note `codeHash` *values* are keccak, but they
  are opaque leaf bytes to the verifier).
- The two tagged preimage layouts and `encode_bit_prefix` decoding
  (including rejecting non-zero padding bits and length mismatches).
- MSB-first bit expansion of keys.
- Tree-key derivation (embedding) to check that a proof is for the claimed
  address/slot: `blake3` again, plus the zone/sub-index layout.
- Nothing stateful: verification is pure recomputation from
  `(root, key, expected_value, preimages)`.

## 7. Ethrex: exists vs built here

| Piece | Status before this branch |
| --- | --- |
| `BinaryTrie` incremental trie, retained nodes, spec-conformant root | exists (`crates/common/binary-trie/src/trie/binary_trie.rs`) |
| Tagged preimage hashing (`leaf_hash`/`branch_hash`) | exists; preimage construction extracted for reuse by proofs |
| `encode_bit_prefix` / bit helpers | exists (`trie/bits.rs`) |
| Rebuild oracle + spec fixture vectors (pinned roots) | exists (`trie/rebuild.rs`, `tests/vectors/`) |
| Embedding key derivation | exists (`embedding.rs`); `decode_basic_data` added for response building |
| **`BinaryTrie::prove`** (walk → preimage list, sibling hashing) | **built here** |
| **`verify_proof`** (standalone, trie-free) | **built here** (`trie/proof.rs`) |
| `PbtState` per-block snapshots (`Store::{get,put}_pbt_state`) | exists, in-memory only — proofs for old/pruned blocks error clearly |
| **`PbtState::build_trie`** (deliberate Seam-B API; `Entries` stays private) | **built here** |
| **RPC wiring** (flag-gated `eth_getProof` branch + serde types) | **built here** (`rpc/eth/account.rs`, `rpc/types/account_proof.rs`) |

Cost note: with no hash caching in the trie, `prove` hashes sibling subtrees
along the path — O(state) per proof, the same order as the per-block
`compute_root` re-embed the integration already pays. Acceptable at the
experimental/devnet scale the flag is scoped to; incremental maintenance
(plan doc, Phase 2 Upgrade 3) is where this gets cheap.

## 8. Decisions

1. **Per-key preimage-list proofs, v1** — simplest sound thing; stem
   multiproof documented as a compatible, versioned extension.
2. **One shared walk for inclusion and exclusion** — `prove` returns the
   terminal-inclusive preimage list either way; the verifier decides which
   claim the proof supports.
3. **`verify_proof` takes `Option<[u8;32]>`** — `Some(v)` demands inclusion
   with value `v`, `None` demands exclusion; mismatches are distinct errors.
4. **Flag-gated response shape swap** — under `enableBinaryTreeAtGenesis`
   the same `eth_getProof` method returns the new shape (tagged with
   `format`); flag-off behavior is byte-identical to before.
5. **Zero storage values verify as exclusions** — the state invariant stores
   no zero-valued slots, so `value == 0` in a storage proof entry means
   "prove absent", mirroring how the MPT path treats missing slots.
