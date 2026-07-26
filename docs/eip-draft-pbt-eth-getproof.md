---
eip: draft
title: eth_getProof for Partitioned Binary Tree state
description: Interim experimental eth_getProof response format for chains committing state via the EIP-8297 Partitioned Binary Tree
author: (draft, unassigned)
discussions-to: (none — implementation-track draft, see Abstract)
# TODO: author and discussions-to must be filled with real values before any submission toward the EIPs repo.
status: Draft
type: Standards Track
category: Interface
created: 2026-07-25
requires: 8297
---

## Abstract

This document specifies an alternative response format for the
`eth_getProof` JSON-RPC method on chains whose `state_root` commits to the
[EIP-8297](https://eips.ethereum.org/EIPS/eip-8297) Partitioned Binary Tree
(PBT) rather than the Merkle Patricia Trie (MPT). Proofs are per-tree-key:
each proof is the ordered list of node preimages from the root to the
terminal node of the key's walk, hex-encoded. A verifier recomputes BLAKE3
hashes upward and checks the key's bit path against every branch, requiring
no access to the tree itself. The format covers inclusion and exclusion, and
replaces the MPT-specific `accountProof`/`storageHash` fields, which have no
meaning in a unified single-tree commitment.

**This is an interim, experimental format**, scoped to chains activating
the tree at genesis (ethrex: `binaryTreeTime` at or before the genesis
timestamp, canonically `binaryTreeTime: 0`). It is
version-tagged (`format` field) so that the canonical witness/proof format
EIP-8297 eventually standardizes can supersede it without ambiguity.

## Motivation

EIP-8297 replaces the account-trie/storage-trie hierarchy with a single
binary radix tree holding account fields, storage slots, and code chunks as
separate 32-byte leaves. On such a chain, the standard `eth_getProof`
response is unconstructible:

- `accountProof` proves an RLP account record; PBT accounts are multiple
  independent leaves (basic data, code hash) with no combined record.
- `storageHash` names a per-account storage root; the PBT has none — storage
  slots are leaves of the same tree the accounts live in.
- Proof nodes are MPT RLP nodes hashed with keccak; PBT nodes are tagged
  BLAKE3 preimages.

Wallets, bridges, and light clients still need state proofs on experimental
PBT chains, and implementers need a common shape to test against before the
canonical EIP-8297 witness format lands. This document specifies the minimal
sound format.

## Specification

The key words "MUST", "MUST NOT", "SHOULD", and "MAY" in this document are
to be interpreted as described in RFC 2119.

### Applicability

A node MUST serve this response format from `eth_getProof` if and only if
the chain commits `header.state_root` to the PBT (for ethrex: the
`binaryTreeTime` chain-config field, active at the block's timestamp).
Request parameters are
unchanged: `(address, storageKeys, block)`.

### Node preimages

A proof is an ordered list of **node preimages**, each hex-encoded with a
`0x` prefix. Exactly two layouts exist, distinguished by the first byte:

- **Leaf**: `0x00 ‖ key ‖ value` where `key` is the complete tree key
  (variable length, ≥ 1 byte) and `value` is 32 bytes. Total length
  `1 + len(key) + 32`.
- **Branch**: `0x01 ‖ encode_bit_prefix(prefix) ‖ left_hash ‖ right_hash`
  where `encode_bit_prefix` is EIP-8297's encoding — a 2-byte big-endian bit
  count `n` followed by `ceil(n/8)` bytes of MSB-first packed prefix bits,
  zero-padded — and each child hash is 32 bytes. Total length
  `1 + 2 + ceil(n/8) + 64`.

The BLAKE3 hash of a node's preimage is that node's commitment. The empty
tree's root is the sentinel `0x0000…0000` (32 zero bytes) and has no
preimage.

### Proof construction (prover)

For a target key, walk the tree from the root consuming the key's bits MSB
first, appending each visited node's preimage:

1. At a branch whose prefix matches the key's next bits and whose split bit
   is within the key: append the branch preimage and descend into the child
   selected by the key's bit at the split position.
2. At a branch whose prefix the key's bits diverge from — or where the key's
   bits are exhausted at or before the split: append the branch preimage and
   **stop** (exclusion terminal; children are not opened).
3. At a leaf: append the leaf preimage and stop (inclusion terminal if the
   leaf key equals the target, exclusion terminal otherwise).

For the empty tree the proof is the empty list.

### Verification (verifier)

Given `root` (the block header's `state_root`), the target `key`, an
expected value (`present(value32)` or `absent`), and the preimage list:

1. If `root` is the 32-zero-byte sentinel: the proof MUST be empty and the
   claim MUST be `absent`. Done.
2. Otherwise the proof MUST be non-empty and `blake3(proof[0])` MUST equal
   `root`.
3. Walk with `depth = 0` over the list. For each element, parse it by tag;
   parsing MUST reject unknown tags, length mismatches, and branch preimages
   whose zero-padding bits are non-zero.
   - **Branch** with prefix bits `p` (length `n`): let `split = depth + n`.
     - If `split ≥ len(key_bits)` or `key_bits[depth..split] ≠ p`: this MUST
       be the last element, and the claim MUST be `absent`. Done.
     - Otherwise select `left_hash` if `key_bits[split] = 0`, else
       `right_hash`. A next element MUST exist and its BLAKE3 hash MUST
       equal the selected hash. Set `depth = split + 1` and continue.
   - **Leaf** with committed key `k` and value `v`: this MUST be the last
     element.
     - `k = key`: the claim MUST be `present(v)`. A `present` claim with a
       different value, or an `absent` claim, MUST fail.
     - `k ≠ key`: the claim MUST be `absent`. A `present` claim MUST fail.
4. Any structural violation (trailing elements after a terminal, a
   non-terminal final element, hash mismatch, malformed preimage) MUST fail
   verification.

Note the walk consumes at least one key bit per branch, so proof length is
intrinsically bounded by `8 * len(key) + 1` elements; verifiers need no
separate depth limit.

### Tree keys

Tree keys are derived per EIP-8297's embedding (all hashes BLAKE3):

- account basic data: `0x00 ‖ blake3(address32) ‖ 0x00` (34 bytes)
- account code hash: `0x00 ‖ blake3(address32) ‖ 0x01` (34 bytes)
- storage slot `s < 64`: `0x00 ‖ blake3(address32) ‖ (64 + s)` (34 bytes)
- storage slot `s ≥ 64`: `0xff ‖ blake3(address32) ‖
  blake3(address32 ‖ tree_index) ‖ sub_index` (66 bytes), with
  `tree_index = s // 256`, `sub_index = s % 256`

where `address32` is the 20-byte address left-padded with 12 zero bytes.
Responses echo each derived key (`treeKey`) so consumers can cross-check the
derivation.

### Response format

```
{
  "format": "pbt-getproof-v1",
  "address": DATA20,
  "balance": QUANTITY,        // decoded from the basic-data leaf; 0x0 if absent
  "nonce": QUANTITY,          // decoded from the basic-data leaf; 0x0 if absent
  "codeHash": DATA32,         // the code-hash leaf value; 0x00…00 if absent
  "storageHash": null,        // ALWAYS null: no per-account storage root exists
  "binaryAccountProof": {
    "basicData": {
      "treeKey": DATA34,
      "value": DATA32 | null, // leaf value; null = leaf absent (exclusion proof)
      "proof": [DATA, ...]    // node preimages, root → terminal
    },
    "codeHash": {
      "treeKey": DATA34,
      "value": DATA32 | null,
      "proof": [DATA, ...]
    }
  },
  "storageProof": [
    {
      "key": QUANTITY,        // the requested storage slot, as given
      "treeKey": DATA,        // 34 bytes (header slots 0–63) or 66 bytes
      "value": QUANTITY,      // slot value; 0x0 when the leaf is absent
      "proof": [DATA, ...]
    },
    ...
  ]
}
```

Field semantics:

- `format` MUST be the exact string `pbt-getproof-v1`. Consumers MUST reject
  unknown format strings.
- `binaryAccountProof.basicData.value`, when present, is the packed
  basic-data leaf: `version(1) ‖ reserved(3) ‖ code_size(4) ‖ nonce(8) ‖
  balance(16)`, all big-endian. The top-level `balance`/`nonce` MUST equal
  the decoded fields; the leaf value is authoritative.
- Account nonexistence is signaled by `value: null` on both account leaves
  (whose proofs are then exclusion proofs). The top-level convenience fields
  then default to zero — including `codeHash`, which is `0x00…00` rather
  than the empty-code keccak, because no leaf attests to any code hash.
- A storage entry with `value ≠ 0` carries an inclusion proof of the
  32-byte big-endian encoding of `value`. A storage entry with `value = 0`
  carries an exclusion proof: PBT state stores no zero-valued slots, so
  "zero" and "absent" coincide. Verifiers MUST check the corresponding
  claim (`present(be32(value))` when non-zero, `absent` when zero).
- There is no `accountProof` field. Producers MUST NOT emit one; its absence
  plus the `format` tag is how generic clients detect the new shape.

### Errors

If the node cannot materialize the tree for the requested block (e.g. its
per-block PBT snapshot is unavailable — ethrex keeps snapshots in memory
only), it MUST return a JSON-RPC error rather than an empty or partial
proof.

## Rationale

**Per-key proofs rather than stem multiproofs (v1).** The embedding
co-locates an account's hot data under one stem, so several requested keys
often share most of their path; a stem-level multiproof (deduplicated node
set + reassembly rules) would be smaller. v1 chooses per-key proofs because
they are the simplest sound unit: one deterministic walk per key, a
stateless verifier, and direct testability against spec-pinned fixture
roots. A multiproof is a strictly additive extension — same preimage
encoding, new `format` string — and is explicitly anticipated.

**Preimages rather than structured JSON nodes.** Sending raw preimages makes
the verifier's job exactly "hash and compare" and leaves zero room for
re-serialization mismatches. It mirrors what `eth_getProof` does today (RLP
node bytes) with the PBT's native encoding.

**The exclusion terminal is the natural witness.** In a binary radix trie
the walk down a key either reaches the key's leaf or provably diverges
(different-keyed leaf, prefix divergence, or bit exhaustion). Divergence at
a branch needs no child openings: the committed prefix already excludes the
target from the whole subtree. This is smaller and simpler than
sibling-path exclusion schemes.

**`storageHash: null` rather than omitted or zero.** Explicit null makes
the field's meaninglessness visible to consumers that would otherwise read
a zero hash as "empty storage trie" (which has a defined, different, MPT
meaning).

**Zero storage = exclusion.** Follows the state invariant (zero slots are
deleted, never stored) and matches user expectations from the MPT method,
where querying an unset slot returns value `0x0`.

## Backwards Compatibility

Flag-off chains are unaffected: the standard MPT response is byte-identical
to before. Flag-on chains never had a working `eth_getProof`, so no working
consumer breaks. Generic `eth_getProof` clients pointed at a PBT chain will
fail to find `accountProof` and SHOULD treat the `format` field as the
discriminator. When EIP-8297 standardizes a canonical witness format, a new
`format` string supersedes `pbt-getproof-v1`; producers MAY serve both
during a transition.

## Test Cases

Implemented in `ethrex` (`crates/common/binary-trie`, fixture
`tests/vectors/binary_trie_vectors.json` generated from the EELS reference
implementation):

1. **Inclusion round-trip**: for every entry of every fixture trie, `prove`
   then `verify_proof(root, key, present(value))` succeeds, with `root` the
   spec-pinned fixture root.
2. **Exclusion round-trip**: absent keys (perturbed fixture keys, empty-trie
   queries) verify as `absent` against the same pinned roots.
3. **Tamper rejection**: flipping any single byte of any proof node makes
   verification fail.
4. **Wrong root rejection**: a valid proof fails against any other root.
5. **Claim mismatches**: inclusion proofs fail `absent` claims and
   wrong-value claims; exclusion proofs fail `present` claims.
6. **End-to-end**: on a genesis-activated (`binaryTreeTime: 0`) chain, `eth_getProof`
   for a live account, a set storage slot, and an unset slot returns proofs
   that verify against the block header's `state_root`.

## Security Considerations

- **Soundness** reduces to BLAKE3 collision resistance: the verifier-side
  bit-path enforcement means a prover cannot steer the walk, and every shown
  node is pinned to the root by the hash chain. Tagged preimages prevent
  leaf/branch confusion; the explicit bit count in `encode_bit_prefix`
  keeps branch preimages injective.
- **Malleability**: verifiers MUST apply the strict parsing rules (exact
  lengths, zero padding bits, tag whitelist) so that a given (root, key,
  claim) admits essentially one accepted proof.
- **Resource bounds**: proof length is bounded by the key's bit length
  (≤ 529 nodes for 66-byte storage keys), and verification is linear in
  proof size. Provers on the reference implementation pay O(state) per
  proof (no hash caching); nodes SHOULD rate-limit accordingly.
- **The convenience fields are unauthenticated**: `balance`, `nonce`,
  `codeHash` at the top level are decoded hints. Consumers MUST derive
  authoritative values from the verified leaf values.

## Copyright

Copyright and related rights waived via [CC0](https://creativecommons.org/publicdomain/zero/1.0/).
