# PBT Snap Sync (`pbtsnap/1`) Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** An experimental, ethrex-only snap-sync capability (`pbtsnap/1`) that lets a node join a `binaryTreeTime`-scheduled chain after the flip without replaying from genesis: it range-downloads the pivot block's flat state with binary-trie range proofs, rebuilds a `PbtState` (plus the MPT lookup structure) locally, seeds the Seam-A registries through the existing `put_pbt_state`/`put_mpt_lookup_root` contract, and continues with full sync — ending indistinguishable from a node that replayed the chain.

**Architecture:** The unified tree collapses snap sync's three-trie decomposition into one flat, lexicographically ordered keyspace: the client range-syncs the account-header zone (`0x00`) and the overflow-storage zone (`0xff`) with a single message pair, skips the content-addressed code zone (`0x01`) entirely (derived locally from bytecode fetched over the existing `snap/1` `GetByteCodes`), and verifies each range with a new binary-trie `verify_range` built from two per-key boundary-proof walks (the `pbt-getproof-v1` preimage format) merged into a root recomputation. Because tree keys are blake3 digests, every response also carries per-stem **preimages** (address, or address‖tree_index) — each hash-verifiable against the stem digest, which is what makes the downloaded data land as an address-keyed `PbtState` and lets the client materialize the companion MPT that execution reads from. The server serves ranges from its in-memory `PbtState` snapshots (Seam A/B); there is no healing in v1 — a stale pivot restarts the (small, devnet-scale) state download against a fresh pivot.

**Tech Stack:** Rust (ethrex workspace); `ethrex-binary-trie` (proof walk + new range module); ethrex's RLPx stack (manual `RLPxMessage` codecs, capability offset ladder); the Seam A/B APIs from `docs/plans/2026-07-25-binary-trie-state-commitment.md` (as-built sections); kurtosis `binary-tree-devnet-fast` for live verification.

**Status framing:** There is NO upstream wire spec for PBT state sync — nothing in EELS, devp2p, or EIP-8297. Everything here is a de-facto draft in the exact mold of `pbt-getproof-v1`: an ethrex-namespaced experimental shape, version-tagged, recorded in a draft doc under `docs/` (Task 4) so it can be superseded or upstreamed cleanly.

**Protocol decisions settled up front** (each states the alternative and why it lost — no forks left for the implementer):

1. **New capability `pbtsnap/1`**, 2 implemented messages + 2 reserved codes, offsets stacked ABOVE `based` in the hard-coded ladder so existing `eth`/`snap`/`based` offsets are untouched (foreign-peer interop unaffected; peers that don't advertise the capability never see the IDs). Alternative — overloading `snap/1` semantics on PBT chains — rejected: it would collide with upstream snap evolution and break the "root_hash names an MPT" invariant every existing snap client assumes.
2. **The wire carries raw embedded leaves `(tree_key, value32)` plus per-stem preimages**, not flat address-keyed records. Rationale: the range proof is then over exactly the transferred bytes (a pure trie check, verifiable immediately, independent of code availability — flat records would make account-stem verification wait on bytecode for `code_size`/chunk leaves); the preimages are individually hash-verifiable against the stem digests, so nothing is taken on trust.
3. **One range message for the whole keyspace; the client only requests zones `0x00` and `0xff`.** Zone `0x01` (overflow code) is content-addressed and a deterministic function of bytecode — downloading it would be pure redundancy; the final `PbtState::compute_root() == pivot.state_root` check catches any divergence (a mis-derived chunk changes the root).
4. **Bytecode rides the existing `snap/1` `GetByteCodes`/`ByteCodes`** (`ACCOUNT_CODES` is keyed by keccak code-hash, root-independent, and responses are keccak-self-verifying). Alternative — duplicate messages inside `pbtsnap` — rejected as dead weight; ethrex peers on these devnets all speak `snap/1`.
5. **Range proofs = two boundary walks in the `pbt-getproof-v1` node-preimage format** (left: walk of the request origin; right: walk of the last returned leaf), verified by a frontier-merge root recomputation (algorithm in Task 2). Alternative — shipping the full boundary subtree node sets — rejected: larger, and the per-key walk machinery (`prove`/`verify_proof`) already exists and is fixture-pinned.
6. **Progress rule: the server MUST include the first leaf ≥ origin if one exists anywhere in the tree, even past `limit` or the byte budget.** This makes "empty response" provable (it is legal only when nothing ≥ origin exists, which the left walk shows as "no right-side siblings") and kills the range-emptiness edge case that MPT snap handles with special absence proofs.
7. **No healing in v1 — pivot-restart only.** Devnet state is tiny relative to the staleness window, and ethrex PBT servers retain every snapshot since boot (registries are never evicted), so "stale pivot" is rare and cheap to recover from by re-downloading. Message codes `0x02`/`0x03` are reserved for a future `GetPbtNodes`/`PbtNodes` (fetch node preimages by bit-path) if real networks ever need incremental healing.
8. **Client landing = the seeded-snapshot contract.** Downloaded state lands via a new `install_pbt_snapshot` seam that verifies the root against the stored header, materializes the MPT (state trie + storage tries + codes) from the flat data, and calls `put_pbt_state` + `put_mpt_lookup_root` — exactly the "snapshot indistinguishable from replay" invariant the restart-recovery tests already pin. Post-flip there is no MPT *on the wire*, but because preimages travel, the MPT is derivable locally — this is what keeps execution (which reads state through the MPT), full sync's `is_resume_point`, tracing, and the engine-API probes working on a snap-synced node. Pre-pivot state/history remains unavailable (same as MPT snap sync).
9. **v0 stepping stone: YES — trusted snapshot export/import ships first** (Task 6): an RPC that serializes a block's `PbtState` to a canonical RLP blob, and a startup flag that imports it through `install_pbt_snapshot`. It exercises the entire landing path with zero networking AND doubles as the offline-seeding artifact the in-memory-registry restart contract has been missing.
10. **Serving depth:** the server can only serve roots whose snapshots it holds in memory (everything since its own boot — never evicted). Persisted flat tables (Phase-2 Upgrade 2 in the state-commitment plan) are the prerequisite for serving deep history; v1 sidesteps it by always picking a fresh pivot.
11. **Sync-mode wiring:** on a `binary_tree_scheduled()` chain, `--syncmode snap` routes to the PBT path and NEVER to legacy MPT snap (which today would heal an MPT against a PBT root — it reads `pivot_header.state_root` raw at `snap_sync.rs:335,422,529,…`). The `MIN_FULL_BLOCKS` (10 000) downgrade-to-full gate is skipped for the PBT path — devnet chains are short and the whole point is exercising the protocol; operators who want full sync say so.
12. **Pivot must be post-flip.** If the sync head is pre-flip on a scheduled chain, PBT snap logs a warning and falls back to full sync (which shadow-tracks correctly from genesis). MPT-snap-then-flip is unsound by construction — the MPT has no preimages, so a pre-flip snap node could never build the `PbtState` the flip block requires.

**Domain background (read before Task 1):**

- **Leaf order = byte order.** `rebuild::Entries` is `BTreeMap<Vec<u8>, [u8; 32]>`; because embedding keys are prefix-free (fixed length per zone, zone byte first), lexicographic byte order over keys equals MSB-first bit-path order, i.e. the tree's left-to-right leaf order. Range = consecutive run in that order.
- **Zones and stems.** Account-header stems: `0x00 ‖ blake3(addr32)` — 34-byte keys, sub-index 0 basic data, 1 code hash, 64–127 storage slots 0–63, 128–255 code chunks 0–127. Overflow storage: `0xff ‖ blake3(addr32) ‖ blake3(addr32 ‖ tree_index)` — 66-byte keys, `tree_index = slot/256`, `sub_index = slot%256`; the FIRST digest means every contract's overflow storage is one contiguous key range (the embedding doc calls this out as the designed sync/expiry unit — this plan is that design cashing out). Overflow code: `0x01 ‖ blake3(code_hash ‖ tree_index)` — 34-byte keys, content-addressed, shared across accounts.
- **Why preimages must travel:** digests are one-way; a raw leaf stream reconstructs the tree but not the address-keyed flat state that `apply_account_updates`/re-embedding need. Every preimage is checkable: `blake3(addr32) == stem digest`, `blake3(addr32 ‖ tree_index) == second digest`. Header-slot numbers need no preimage at all (`slot = sub_index − 64`), and overflow slots need only the per-stem `tree_index` (`slot = tree_index·256 + sub_index`).
- **What the final root check buys:** after assembly, `PbtState::compute_root()` re-embeds everything — basic data (with `code_size` from fetched code), code-hash leaves, all code chunks (header + zone `0x01`), all storage. Equality with the pivot header root is therefore a whole-state differential check; any inconsistency between served leaves, served preimages, and fetched bytecode surfaces there at the latest.

**Reference files** (line refs from branch `kw/bin-trie-integration` @ `88a82c14`):

- Crate: `crates/common/binary-trie/src/trie/{proof.rs,binary_trie.rs:288 (prove),rebuild.rs:14 (Entries)}`, `src/embedding.rs`, `tests/proofs.rs`, fixture `tests/vectors/binary_trie_vectors.json`.
- Seams: `crates/common/types/pbt_state.rs` (`PbtState` :62, `compute_root` :155, `build_trie` :173, private `embed_entries` :184); `crates/storage/store.rs` (`pbt_states` :224, `mpt_lookup_roots` :235, `get_pbt_state` :2581, `put_pbt_state` :2601, `put_mpt_lookup_root` :2648, `mpt_state_root_for_header_opt` :2703, `has_reconstructible_state` :2729, `get_account_code` :885, `write_account_code_batch` :1486); `crates/blockchain/blockchain.rs` (`store_block` PBT branch :2184-2245, `require_pbt_state` :2251).
- Snap machinery to mirror: `crates/networking/p2p/rlpx/snap/{messages.rs,codec.rs}`, `rlpx/message.rs` (offset ladder :28-39, decode ladder :197-292, `request_id` :363), `rlpx/p2p.rs:23,48-68` (Capability), `rlpx/connection/server.rs` (negotiation :1096-1166, dispatch :1293-1327, `outgoing_request` :206), `snap/server.rs` (handlers + `MAX_RESPONSE_BYTES`), `snap/client.rs` (`request_bytecodes` :373, worker verify loops :1260,:1398), `sync.rs` (`SyncMode` :54, `sync_cycle` :215-278), `sync/snap_sync.rs` (header phase :116-286, pivot/staleness :690-886, switch-over :632-657), `crates/common/trie/verify_range.rs` (the four-case contract to mirror).
- Prior art for the experimental-spec framing: `docs/eip-draft-pbt-eth-getproof.md`, `docs/binary-trie-getproof-investigation.md`.

---

## Task 1: Extract the shared proof walk (`verify_walk`)

`verify_range` needs the same strict preimage walk `verify_proof` does, plus the per-step data (`split`, taken bit, sibling hash) that `verify_proof` throws away. Extract it without changing `verify_proof`'s observable behavior — the existing proof tests (unit + `tests/proofs.rs`, all error variants pinned) are the regression net.

**Files:**
- Modify: `crates/common/binary-trie/src/trie/proof.rs`

**Step 1: Write the failing tests** (in `proof.rs` tests):

```rust
#[test]
fn walk_exposes_steps_and_terminal() {
    let trie = two_leaf_trie(); // keys [0xaa,0xbb], [0xaa,0xcc]
    let root = trie.root();

    // Inclusion walk: one branch step + leaf terminal.
    let proof = trie.prove(&[0xaa, 0xbb]);
    let (steps, end) = verify_walk(root, &[0xaa, 0xbb], &proof).unwrap();
    assert_eq!(steps.len(), 1);
    // The two keys first disagree at bit 9 (0xbb=1011_1011 vs 0xcc=1100_1100
    // diverge at their second bit), so the root branch splits there.
    assert_eq!(steps[0].split, 9);
    assert_eq!(steps[0].taken, 0); // 0xbb's bit 9 is 0
    match end {
        Some(WalkEnd::AtLeaf { key, value }) => {
            assert_eq!(key, &[0xaa, 0xbb]);
            assert_eq!(value, &[1u8; 32]);
        }
        other => panic!("expected leaf terminal, got {other:?}"),
    }

    // Divergent walk: terminal branch, no steps consumed.
    let proof = trie.prove(&[0x11, 0x22]);
    let (steps, end) = verify_walk(root, &[0x11, 0x22], &proof).unwrap();
    assert!(steps.is_empty());
    match end {
        Some(WalkEnd::Diverged { subtree_bits, hash }) => {
            assert!(!subtree_bits.is_empty());
            assert_eq!(hash, root); // terminal IS the root branch here
        }
        other => panic!("expected divergence, got {other:?}"),
    }

    // Empty root: no steps, no terminal, empty proof only.
    assert_eq!(verify_walk(EMPTY_TRIE_ROOT, &[0x01], &[]).unwrap().0.len(), 0);
    assert!(verify_walk(EMPTY_TRIE_ROOT, &[0x01], &[vec![0]]).is_err());
}
```

(Adjust the hard-coded `split`/`taken` expectations to reality if the bit arithmetic above is off — derive them once from a debug print, then pin. Do NOT weaken the assertions to `> 0`.)

**Step 2: Run** `cargo test -p ethrex-binary-trie walk_exposes` — expect compile failure (`verify_walk` not found).

**Step 3: Implement.** In `proof.rs`, add (all `pub(crate)` — Task 2's `range.rs` is the only consumer; promote to `pub` only if the draft doc later wants external verifiers to reuse it):

```rust
/// One descended branch of a verified walk.
pub(crate) struct WalkStep {
    /// Absolute bit index of the branch's split (depth + prefix len).
    pub split: usize,
    /// The key's bit at `split` (the child descended into).
    pub taken: u8,
    /// Commitment of the child NOT descended into.
    pub sibling: H256,
}

/// Where a verified walk ended. `None` only for the empty root.
pub(crate) enum WalkEnd<'a> {
    /// The walk reached a leaf (key may or may not equal the target).
    AtLeaf { key: &'a [u8], value: &'a [u8; 32] },
    /// The walk ended at a branch the target's bits diverge from or
    /// exhaust inside. `subtree_bits` is the branch's full covered
    /// bit-prefix (path bits up to its start ++ its own prefix bits);
    /// `hash` is blake3 of its preimage.
    Diverged { subtree_bits: Vec<u8>, hash: H256 },
}

pub(crate) fn verify_walk<'a>(
    root: H256,
    key: &[u8],
    proof: &'a [Vec<u8>],
) -> Result<(Vec<WalkStep>, Option<WalkEnd<'a>>), ProofError>
```

Body: lift the loop out of `verify_proof` verbatim — same parse, same hash-chain checks, same `terminal`/`Truncated`/`TrailingNodes`/`MalformedNode` errors — but record a `WalkStep` per descended branch (sibling = the unchosen child) and return the terminal instead of judging a claim. `verify_proof` becomes a thin wrapper: run `verify_walk`, then map `(WalkEnd, expected)` to the existing `Ok`/`ValueMismatch`/`UnexpectedInclusion`/`UnexpectedExclusion` outcomes (the empty-root special case moves into the wrapper unchanged: `EmptyRootConflict` on non-empty proof, walk returns `(vec![], None)`).

**Step 4: Verify:** `cargo test -p ethrex-binary-trie` — ALL existing proof tests green (this is the point: behavior-preserving refactor), plus the new walk test.

**Step 5: Commit:** `refactor(binary-trie): extract verify_walk from verify_proof`

---

## Task 2: `verify_range` + `prove_range` — binary-trie range proofs

The heart of the plan: the `verify_range` analog for the binary trie, mirroring the MPT contract (`crates/common/trie/verify_range.rs`: preconditions → special cases → recompute-and-compare, returning "more to the right") so the download loops can be structured the same way.

**Files:**
- Create: `crates/common/binary-trie/src/trie/range.rs`
- Modify: `crates/common/binary-trie/src/trie/mod.rs` (`pub mod range;` + re-exports)

**The algorithm (specified; the implementation follows this exactly):**

*Server (`prove_range`):* given the entry map, its trie, `origin`, `limit`, and a leaf budget: take the consecutive run of leaves starting at the first key ≥ `origin` (BTreeMap `range(origin..)`), stopping when the budget is reached or right after including the first leaf whose key > `limit` (the terminator; the progress rule means the run is never empty unless nothing ≥ `origin` exists). `left_proof = trie.prove(origin)`; `right_proof = trie.prove(last_key)` if leaves are non-empty, else empty.

*Verifier (`verify_range`):*
1. **Preconditions:** leaf keys strictly increasing; `leaves[0].key ≥ origin`. If `root == EMPTY_TRIE_ROOT`: leaves and both proofs MUST be empty → `Ok(has_more: false)`.
2. **Left walk:** `verify_walk(root, origin, left_proof)` (structural errors propagate).
3. **Empty-leaves case:** `right_proof` MUST be empty. The claim is "nothing ≥ origin exists": every `WalkStep` must have `taken == 1` (a step with `taken == 0` has a right-side sibling, i.e. keys > origin the server withheld → `MissingLeaves`), and the terminal must lie left of origin (leaf with key < origin, or `Diverged` subtree whose position is < origin — see the comparison rule below; a terminal ≥ origin is withheld content → `MissingLeaves`). Then recompute the root from the left-side items alone (step 5) and compare. `has_more: false`.
4. **Right walk:** `verify_walk(root, last_key, right_proof)`; its terminal MUST be `AtLeaf` with key == last leaf key and value == last leaf value (`RightProofMismatch` otherwise). If the left walk's terminal is `AtLeaf` with key ≥ origin, that leaf MUST equal `leaves[0]` (`OriginMismatch` otherwise) — the walk-terminal-is-successor property guarantees this for honest servers (proof: any key strictly between origin and the terminal leaf would have branched off the walk with a bit ordering that contradicts it lying between them).
5. **Item extraction + root recomputation** (the frontier merge — this is where gaps and injections die):
   - From the **left** walk: for each step with `taken == 1`, emit `Subtree { bits: key_bits(origin)[..split] ++ [0], hash: sibling }` (a completed subtree wholly < origin). Terminal: `AtLeaf` with key < origin → emit as a `Leaf` item; `Diverged` with subtree position < origin → emit `Subtree { bits: subtree_bits, hash }`; terminal ≥ origin → emit nothing (its content is the returned leaves — enforced by the recomputation).
   - From the **right** walk: for each step with `taken == 0`, emit `Subtree { bits: key_bits(last_key)[..split] ++ [1], hash: sibling }` (wholly > last_key — the legitimately-not-yet-synced remainder). The terminal leaf is `leaves.last()`, already in the item list as a leaf. Steps on the walks' shared prefix dedupe naturally: the left walk only ever emits left-side siblings, the right walk only right-side ones.
   - **Position comparison rule** (subtree vs a key's bits): compare bit-by-bit to the shorter length; the first differing bit decides (`subtree_bit < key_bit` ⇒ subtree < key). If the subtree's bits are a prefix of the key's bits, every key beneath it extends the target's prefix ⇒ subtree > key (relevant only for `Diverged`-by-exhaustion terminals).
   - **Recompute:** items = left items ++ leaves (as `Leaf` items, full key bytes retained for `leaf_hash`) ++ right items, which MUST already be in ascending bit-string order (`Malformed` if not — cheap sanity check, honest inputs always are). Run a `binarize`-style recursion over bit-strings (port of `rebuild.rs`, generalized): a group of one `Leaf` → `leaf_hash(key, value)`; a group of one `Subtree` → its hash (its remaining bits are committed inside the hash); a group whose shared-bit scan would run past a `Subtree`'s bit length while the group still has > 1 member → `Malformed` (cannot happen for honest inputs — every emitted sibling becomes alone in its group exactly at its own depth, because its walk-side content sits across the split); otherwise split at the first disagreement and recurse, hashing with `branch_hash(shared_bits, left, right)`. The result MUST equal `root` (`RootMismatch` otherwise). Any dropped, injected, or altered leaf in `[leaves[0], last_key]` changes a recomputed branch hash and fails here — that is the gap-smuggling defense, same trust story as MPT `verify_range`.
6. **Return** `has_more:` true iff the right walk emitted ≥ 1 right-side subtree.

**Step 1: Write the failing tests** (in `range.rs`):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::trie::rebuild::{rebuild_root, Entries};
    use crate::trie::{BinaryTrie, EMPTY_TRIE_ROOT};

    /// Build trie + entries from (key, value) pairs.
    fn build(pairs: &[(&[u8], u8)]) -> (BinaryTrie, Entries) {
        let mut trie = BinaryTrie::new();
        let mut entries = Entries::new();
        for (k, v) in pairs {
            trie.insert(k.to_vec(), [*v; 32]).unwrap();
            entries.insert(k.to_vec(), [*v; 32]);
        }
        (trie, entries)
    }

    const KEYS: [&[u8]; 4] = [&[0x00, 0x10], &[0x00, 0x20], &[0x80, 0x01], &[0xf0, 0x0f]];

    fn four_leaf() -> (BinaryTrie, Entries) {
        (build(&[(KEYS[0], 1), (KEYS[1], 2), (KEYS[2], 3), (KEYS[3], 4)]))
    }

    #[test]
    fn empty_tree_verifies_empty_range() {
        let out = verify_range(EMPTY_TRIE_ROOT, &[0x00, 0x00], &[], &[], &[]).unwrap();
        assert!(!out.has_more);
    }

    #[test]
    fn full_range_round_trips() {
        let (trie, entries) = four_leaf();
        let slice = prove_range(&entries, &trie, &[0x00, 0x00], &[0xff, 0xff], 100);
        assert_eq!(slice.leaves.len(), 4);
        let out = verify_range(trie.root(), &[0x00, 0x00], &slice.leaves,
                               &slice.left_proof, &slice.right_proof).unwrap();
        assert!(!out.has_more);
    }

    #[test]
    fn partial_range_reports_more_and_resumes() {
        let (trie, entries) = four_leaf();
        // Budget of 2 leaves: expect KEYS[0..2], has_more = true.
        let slice = prove_range(&entries, &trie, &[0x00, 0x00], &[0xff, 0xff], 2);
        assert_eq!(slice.leaves.len(), 2);
        let out = verify_range(trie.root(), &[0x00, 0x00], &slice.leaves,
                               &slice.left_proof, &slice.right_proof).unwrap();
        assert!(out.has_more);
        // Resume from successor of last key: remaining two leaves, no more.
        let next = increment_key(slice.leaves.last().unwrap().0.clone()).unwrap();
        let slice2 = prove_range(&entries, &trie, &next, &[0xff, 0xff], 100);
        assert_eq!(slice2.leaves.len(), 2);
        let out2 = verify_range(trie.root(), &next, &slice2.leaves,
                                &slice2.left_proof, &slice2.right_proof).unwrap();
        assert!(!out2.has_more);
    }

    #[test]
    fn terminator_leaf_past_limit_is_included() {
        let (trie, entries) = four_leaf();
        // limit between KEYS[1] and KEYS[2]: run is KEYS[0], KEYS[1],
        // then KEYS[2] as terminator.
        let slice = prove_range(&entries, &trie, &[0x00, 0x00], &[0x40, 0x00], 100);
        assert_eq!(slice.leaves.len(), 3);
        assert!(verify_range(trie.root(), &[0x00, 0x00], &slice.leaves,
                             &slice.left_proof, &slice.right_proof).is_ok());
    }

    #[test]
    fn provable_emptiness_past_all_keys() {
        let (trie, entries) = four_leaf();
        let origin = [0xf1u8, 0x00]; // > every key
        let slice = prove_range(&entries, &trie, &origin, &[0xff, 0xff], 100);
        assert!(slice.leaves.is_empty());
        assert!(slice.right_proof.is_empty());
        let out = verify_range(trie.root(), &origin, &[], &slice.left_proof, &[]).unwrap();
        assert!(!out.has_more);
    }

    #[test]
    fn withheld_leaves_on_empty_response_rejected() {
        let (trie, _) = four_leaf();
        // origin below all keys, but server claims emptiness: the left
        // walk exposes right-side siblings -> MissingLeaves.
        let left = trie.prove(&[0x00, 0x00]);
        assert_eq!(
            verify_range(trie.root(), &[0x00, 0x00], &[], &left, &[]),
            Err(RangeProofError::MissingLeaves)
        );
    }

    #[test]
    fn gap_smuggling_rejected() {
        let (trie, entries) = four_leaf();
        let slice = prove_range(&entries, &trie, &[0x00, 0x00], &[0xff, 0xff], 100);
        // Drop a MIDDLE leaf (boundary proofs untouched, still valid walks).
        let mut leaves = slice.leaves.clone();
        leaves.remove(1);
        assert_eq!(
            verify_range(trie.root(), &[0x00, 0x00], &leaves,
                         &slice.left_proof, &slice.right_proof),
            Err(RangeProofError::RootMismatch)
        );
    }

    #[test]
    fn injected_and_tampered_leaves_rejected() {
        let (trie, entries) = four_leaf();
        let slice = prove_range(&entries, &trie, &[0x00, 0x00], &[0xff, 0xff], 100);
        // Injected leaf inside the range.
        let mut leaves = slice.leaves.clone();
        leaves.insert(1, (vec![0x00, 0x18], [9; 32]));
        assert!(verify_range(trie.root(), &[0x00, 0x00], &leaves,
                             &slice.left_proof, &slice.right_proof).is_err());
        // Tampered value.
        let mut leaves = slice.leaves.clone();
        leaves[2].1[0] ^= 1;
        assert_eq!(
            verify_range(trie.root(), &[0x00, 0x00], &leaves,
                         &slice.left_proof, &slice.right_proof),
            Err(RangeProofError::RootMismatch)
        );
    }

    #[test]
    fn single_leaf_tree_and_origin_hit() {
        let (trie, entries) = build(&[(KEYS[0], 7)]);
        // origin == the key itself (inclusion boundary).
        let slice = prove_range(&entries, &trie, KEYS[0], &[0xff, 0xff], 100);
        let out = verify_range(trie.root(), KEYS[0], &slice.leaves,
                               &slice.left_proof, &slice.right_proof).unwrap();
        assert!(!out.has_more);
    }
}
```

**Step 2: Run** `cargo test -p ethrex-binary-trie range` — expect compile failure.

**Step 3: Implement** in `range.rs`:

```rust
//! Range proofs: prove and verify that a consecutive run of leaves is
//! EXACTLY the tree's content over a key interval, using two boundary
//! walks in the pbt-getproof-v1 preimage format merged into a root
//! recomputation. The binary-trie analog of the MPT's verify_range.
//! Wire spec: docs/eip-draft-pbtsnap.md (once Task 4 lands).

pub struct RangeSlice {
    /// Consecutive leaves, ascending, starting at the successor of the
    /// requested origin.
    pub leaves: Vec<(Vec<u8>, [u8; 32])>,
    pub left_proof: Vec<Vec<u8>>,
    pub right_proof: Vec<Vec<u8>>,
}

pub struct VerifiedRange {
    /// Leaves exist beyond the last returned key.
    pub has_more: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum RangeProofError {
    #[error(transparent)]
    Proof(#[from] ProofError),          // structural walk failures
    #[error("leaf keys not strictly ascending")]
    UnsortedLeaves,
    #[error("first leaf precedes the requested origin")]
    LeafBeforeOrigin,
    #[error("left walk terminal >= origin does not match the first leaf")]
    OriginMismatch,
    #[error("right walk terminal does not match the last leaf")]
    RightProofMismatch,
    #[error("proof shows in-range leaves the response omitted")]
    MissingLeaves,
    #[error("unexpected right proof on an empty range")]
    UnexpectedRightProof,
    #[error("recomputed root does not match")]
    RootMismatch,
    #[error("range item structure is inconsistent")]
    Malformed,
    #[error("empty root admits only an empty range with empty proofs")]
    EmptyRootConflict,
}

pub fn prove_range(
    entries: &Entries,
    trie: &BinaryTrie,
    origin: &[u8],
    limit: &[u8],
    max_leaves: usize,
) -> RangeSlice { ... }

pub fn verify_range(
    root: H256,
    origin: &[u8],
    leaves: &[(Vec<u8>, [u8; 32])],
    left_proof: &[Vec<u8>],
    right_proof: &[Vec<u8>],
) -> Result<VerifiedRange, RangeProofError> { ... }

/// Successor of a fixed-length key in leaf order (byte-wise +1 with
/// carry). None when the key is all 0xff (keyspace exhausted).
pub fn increment_key(mut key: Vec<u8>) -> Option<Vec<u8>> { ... }
```

Internals per the algorithm block above: `enum RangeItem { Leaf { bits, key, value }, Subtree { bits, hash } }`, extraction from the two walks, and `fn recompute_root(items: &[RangeItem]) -> Result<H256, RangeProofError>` as the generalized `binarize` (model it on `rebuild.rs::binarize`, replacing panics with `Malformed`). Byte-budget mapping lives at the p2p layer (Task 8); `prove_range` deliberately takes `max_leaves` to stay transport-agnostic.

**Step 4: Run** `cargo test -p ethrex-binary-trie` — all green, including all pre-existing suites.

**Step 5: Commit:** `feat(binary-trie): range proofs — prove_range and verify_range over boundary walks`

---

## Task 3: Range-proof differential + fixture conformance tests

Pin `verify_range` to the spec-pinned fixture roots and to the rebuild oracle under random workloads, and grind the adversarial surface. No new spec vectors are generated: range proofs are OUR construction (no EELS reference exists) — ground truth is (a) fixture tries whose roots are already EELS-pinned and (b) `rebuild_root` as the oracle, the same trust chain the proof tests use.

**Files:**
- Create: `crates/common/binary-trie/tests/range_proofs.rs`

**Step 1: Write the tests** (they should pass immediately if Task 2 is correct — failures here are Task 2 bugs):

1. `fixture_tries_verify_all_sub_ranges`: for every fixture trie (load pattern verbatim from `tests/proofs.rs`), for every leaf index pair `(i, j)` with `i <= j`: serve `[key_i, key_j]` via `prove_range` (origin = `key_i`, budget = `j - i + 1`) and verify against the PINNED fixture root; assert `has_more == (j < n-1)`. Also one perturbed-origin variant per trie (origin = predecessor byte-string of `key_i`, exclusion left boundary).
2. `random_workload_against_rebuild_oracle`: seeded `StdRng` (seed 8297, matching `differential.rs` conventions), 20 rounds: random embedding-shaped key sets (34/66-byte keys, small alphabet — reuse the generation scheme from `tests/differential.rs`), random origins/budgets covering: origin below all keys, between keys, equal to a key, above all keys; verify every slice against `rebuild_root(&entries)`; chain slices via `increment_key` until `has_more == false` and assert the union of downloaded leaves equals the full entry map (the client-loop invariant in miniature).
3. `adversarial_mutations_rejected`: for a mid-size fixture trie and a mid-tree range: every single-byte flip in each boundary proof node → `Err(..)` (any variant); leaf reordering → `UnsortedLeaves`; first leaf < origin → `LeafBeforeOrigin`; boundary proofs swapped → error; right proof replaced with a proof of a DIFFERENT present key → `RightProofMismatch`; valid slice against a different fixture root → error.
4. `empty_and_boundary_cases`: empty trie; origin = all-zeros; origin = all-0xff (`increment_key` → `None`); tree where the entire left walk terminal is the root branch (single-branch divergence, exercised by a 2-leaf trie and an origin diverging at bit 0).

**Step 2: Run** `cargo test -p ethrex-binary-trie --test range_proofs` — expect pass; on failure, minimize with the oracle (dump the item list at the first divergence; an item-count mismatch localizes to extraction, a hash mismatch to recomputation) and fix Task 2. NEVER touch fixture values.

**Step 3: Commit:** `test(binary-trie): range-proof differential and adversarial coverage`

---

## Task 4: Draft wire spec — `docs/eip-draft-pbtsnap.md`

The protocol's normative record, in the exact register of `docs/eip-draft-pbt-eth-getproof.md` (interim experimental format, version-tagged, explicit TODO header for authorship before any upstream submission). Written BEFORE the p2p code so Tasks 5–10 implement a written spec rather than the other way around.

**Files:**
- Create: `docs/eip-draft-pbtsnap.md`

**Step 1: Write the document** with these sections (content = the decisions in this plan's header, made normative):

- **Abstract/Motivation:** why MPT snap cannot sync a PBT chain (no per-account tries, keccak vs blake3, digest keys without preimages) and why leaves+preimages is the minimal sound transfer.
- **Capability:** `pbtsnap/1`, RLPx, 4 message codes (2 reserved). Explicit note that offsets in ethrex are ladder-assigned above `based` and that the capability is ethrex-experimental pending EIP-8297 sync standardization.
- **Messages** (RLP schemas, request-id convention as in snap):
  - `GetPbtLeafRange (0x00)`: `[id: u64, root_hash: B32, origin: B, limit: B, response_bytes: u64]`. `origin`/`limit` are full-length tree keys (34 or 66 bytes); servers MUST treat them as opaque byte strings ordered lexicographically.
  - `PbtLeafRange (0x01)`: `[id, leaves: [[key: B, value: B32], ...], stem_preimages: [B, ...], left_proof: [B, ...], right_proof: [B, ...]]`.
  - `Reserved (0x02, 0x03)`: earmarked `GetPbtNodes`/`PbtNodes` (healing by bit-path); receivers MUST disconnect-or-ignore per their unknown-message policy.
  - Bytecode retrieval: normatively delegated to `snap/1 GetByteCodes` (code storage is content-addressed by keccak; responses self-verify).
- **Serving semantics:** the progress rule (first leaf ≥ origin MUST be included if one exists anywhere), the terminator rule (SHOULD stop after the first leaf > limit), byte budget as a soft cap that never suppresses the first leaf, boundary proofs = `pbt-getproof-v1` preimage walks of origin and last key, empty response ⇔ nothing ≥ origin exists.
- **Stem preimages:** one entry per distinct stem among `leaves`, ascending stem order; shapes per zone — `0x00`: 20-byte address, check `blake3(addr32) == stem[1..33]`; `0x01`: 64-byte `code_hash ‖ tree_index_be32`, check `blake3(preimage) == stem[1..33]`; `0xff`: 52-byte `address ‖ tree_index_be32`, check `blake3(addr32) == stem[1..33]` AND `blake3(addr32 ‖ tree_index) == stem[33..65]`. Verifiers MUST reject responses whose preimages don't cover exactly the distinct stems, in order, or fail any digest check.
- **Range verification:** the Task-2 algorithm, spelled normatively (walk rules by reference to the getproof draft, item extraction, recomputation, has_more).
- **Client reconstruction:** sub-index decode table (0 basic data via `decode_basic_data`, 1 code hash, 64–127 header slots `sub−64`, 128–255 header code chunks — content ignored for state building; zone `0xff` slots `tree_index·256 + sub`), zone `0x01` derived from bytecode, final whole-state check `compute_root == pivot state_root`, unknown sub-indices (2–63) MUST be rejected.
- **Security considerations:** soundness reduces to blake3 (walks + recomputation pin every byte to the root); preimage checks make identity unforgeable; convenience data is nonexistent by design (everything on the wire is either proof-bound or hash-bound); DoS bounds (proof length ≤ 529 nodes, response byte cap, request rate limiting); the trust-minimized element is the pivot header, exactly as in snap.

**Step 2: Verify** internal consistency against `crates/common/binary-trie/src/embedding.rs` constants (zone bytes, key lengths, sub-index layout) — every number in the doc must be traceable to a constant or a fixture value.

**Step 3: Commit:** `docs(pbtsnap): draft wire spec for experimental PBT snap sync`

---

## Task 5: Landing seam — `Store::install_pbt_snapshot`

One store-level entry point through which BOTH v0 import and the real sync land state: verify against the header, materialize the MPT lookup structure, seed both registries. After it runs, the node satisfies the "indistinguishable from replay" invariant the restart-recovery tests pin.

**Files:**
- Modify: `crates/storage/store.rs`, `crates/storage/error.rs` (if a new variant reads better than `StoreError::Custom`)
- Test: `test/tests/blockchain/binary_tree_tests.rs` (extend; harness exists)

**Step 1: Write the failing test** (model on the existing `binary_tree_restart_loses_registries_and_replay_recovers` test — same two-store shape):

```rust
#[tokio::test]
async fn install_pbt_snapshot_makes_snap_seeded_node_equal_to_replayed() {
    // Source: replay 3 blocks on the binary-tree genesis (existing helpers),
    // capture block-2's snapshot + the source's registered MPT lookup root.
    // Target: fresh store from the same genesis, import ONLY headers of
    // blocks 1-3 and the block bodies (no execution), then:
    let snapshot = (*source.get_pbt_state(b2_hash).unwrap().unwrap()).clone();
    target.install_pbt_snapshot(b2_hash, snapshot).await.unwrap();

    // 1. Registries seeded.
    assert!(target.get_pbt_state(b2_hash).unwrap().is_some());
    let mpt_root = target.get_mpt_lookup_root(b2_hash).unwrap().unwrap();
    // 2. Materialized MPT root equals what replay produced on the source.
    assert_eq!(mpt_root, source.get_mpt_lookup_root(b2_hash).unwrap().unwrap());
    // 3. The MPT actually exists (execution's read path).
    assert!(target.has_reconstructible_state(&b2_header).unwrap());
    // 4. Block 3 now imports through the normal path.
    target_blockchain.add_block(block3).await.unwrap();

    // 5. Tampered snapshot is rejected before any write.
    let mut bad = (*source.get_pbt_state(b2_hash).unwrap().unwrap()).clone();
    bad.accounts.iter_mut().next().map(|(_, a)| a.balance += 1.into());
    assert!(fresh_target.install_pbt_snapshot(b2_hash, bad).await.is_err());
}
```

(Adapt to the harness's actual helper names — read `binary_tree_tests.rs` first; the restart test already builds exactly this two-store choreography.)

**Step 2: Run** the test file's invocation (check how `test/` runs, e.g. `cd test && cargo test binary_tree`) — red (method missing).

**Step 3: Implement** `pub async fn install_pbt_snapshot(&self, block_hash: BlockHash, state: PbtState) -> Result<(), StoreError>`:

1. **Verify:** header for `block_hash` must exist, `is_binary_tree_active(header.timestamp)` must hold, and `state.compute_root()? == header.state_root` — hard error BEFORE any write (self-verifying seed, same contract as the state-commitment plan's `put_pbt_state` docs, now enforced).
2. **Materialize the MPT:** from the flat state build the exact tries replay would have produced — per account: storage trie from `keccak(slot) → RLP(value)` (skip empties), state trie `keccak(address) → AccountState { nonce, balance, storage_root, code_hash }`. Model the write path on the genesis materialization (`setup_genesis_state_trie`, `store.rs:2867` call site) rather than the snap SST machinery — devnet-scale states don't need bulk ingestion. Write code via `write_account_code_batch` (`store.rs:1486`).
3. **Seed:** `put_pbt_state(block_hash, state)`; `put_mpt_lookup_root(block_hash, computed_mpt_root)`.

Document on the method: this is the landing seam for snap sync and offline seeding; it is the third writer of the registries (after genesis and `store_block`).

**Step 4: Run** — green; also `cargo test -p ethrex-storage` and the full binary-tree suite (no regression in the replay/restart tests).

**Step 5: Commit:** `feat(storage): install_pbt_snapshot landing seam — verify, materialize MPT, seed registries`

---

## Task 6: v0 — snapshot export/import (the stepping stone)

Trusted snapshot transfer without a protocol: an RPC that serializes a block's `PbtState` to a canonical RLP blob, and a startup flag that imports it through Task 5's seam. Verdict on "is v0 worth a task": **yes** — it exercises the entire client landing path with zero networking, AND it is the offline-seeding artifact the in-memory-registry restart contract has needed since the state-commitment plan (a long-lived scheduled devnet currently has NO recovery path once replay is off the table). The import MUST run inside the node process (the registries are in-memory — an out-of-process seeder would seed nothing), hence a startup flag rather than a subcommand; the export MUST read a live process's memory, hence an RPC rather than a subcommand.

**Files:**
- Modify: `crates/common/types/pbt_state.rs` (canonical encoding)
- Modify: `crates/networking/rpc/` (new experimental method — register alongside the existing ethrex-namespaced/admin methods; find the namespace registry first)
- Modify: `cmd/ethrex/cli.rs` + `cmd/ethrex/initializers.rs` (import flag, applied after store init, before networking)

**Step 1: Failing tests.**

(a) Encoding round-trip, in `pbt_state.rs` tests:

```rust
#[test]
fn snapshot_encoding_round_trips_and_is_canonical() {
    let state = /* 2 accounts, storage incl. slot >= 64, one contract w/ code */;
    let bytes = state.encode_snapshot();
    let decoded = PbtState::decode_snapshot(&bytes).unwrap();
    assert_eq!(decoded.compute_root().unwrap(), state.compute_root().unwrap());
    // Canonical: re-encoding the decoded state is byte-identical.
    assert_eq!(decoded.encode_snapshot(), bytes);
    // Tamper detection is the caller's job (root check) — but garbage
    // must fail decode, not panic.
    assert!(PbtState::decode_snapshot(&bytes[..bytes.len() - 3]).is_err());
}
```

(b) End-to-end, extend the Task 5 test file: export from source via the encoding (unit-level; the RPC method is a thin wrapper returning the hex blob), write to a temp file, boot-import into a fresh store via the initializer function (call it directly), assert same postconditions as Task 5's test.

**Step 2:** red. **Step 3: Implement.**

- **Encoding** (`encode_snapshot`/`decode_snapshot` on `PbtState`, using `ethrex-rlp` like the rest of the codebase): RLP list `[version: u8 = 1, accounts: [[address, nonce, balance, code_hash], ...], storage: [[address, [[slot, value], ...]], ...], codes: [bytes, ...]]` — BTreeMap iteration makes it canonical for free. `decode_snapshot` rejects unknown versions, rebuilds `Code` via `Code::from_bytecode` (recomputing keccak — imported code is self-verifying), and rejects zero-valued storage entries (invariant).
- **RPC** `ethrex_exportPbtSnapshot(block: BlockIdentifier) -> hex string`: resolve block → `get_pbt_state(hash)` (missing snapshot → clear error, mirroring the getProof handler's message at `rpc/eth/account.rs:293`) → `encode_snapshot` → `0x…`. Returning the blob (not writing server-side files) keeps the RPC side-effect-free; devnet states are small.
- **CLI** `--experimental.import-pbt-snapshot <path> --experimental.import-pbt-snapshot-block <block_hash>`: in `initializers.rs` after store init: read file, `decode_snapshot`, `install_pbt_snapshot(block_hash, state)` — the seam does all verification. Refuse to start on failure (a half-seeded node is worse than a dead one). Note in the flag's help text: like `--experimental.binary-tree-delay`, this is per-boot (registries are in-memory; re-supply on every restart until Phase-2 persistence lands).

**Step 4:** green: unit + e2e + `cargo check --workspace`. **Step 5: Commit:** `feat(binary-tree): v0 snapshot export RPC and boot-time import via install_pbt_snapshot`

---

## Task 7: `pbtsnap/1` capability and wire messages

**Files:**
- Create: `crates/networking/p2p/rlpx/pbtsnap/mod.rs`, `messages.rs`, `codec.rs`
- Modify: `crates/networking/p2p/rlpx/message.rs` (offsets + decode ladder + `request_id`), `crates/networking/p2p/rlpx/p2p.rs` (Capability constructor + supported list), `crates/networking/p2p/rlpx/connection/server.rs` (hello advertisement + negotiation arm)

**Step 1: Write the failing tests** (codec round-trips, in `codec.rs` tests — mirror however the snap codec is tested; if it isn't, these are the first, which is fine):

```rust
#[test]
fn pbtsnap_messages_round_trip_through_rlp() {
    let req = GetPbtLeafRange {
        id: 7,
        root_hash: H256::repeat_byte(0xab),
        origin: Bytes::from(vec![0u8; 34]),
        limit: Bytes::from(vec![0xff; 34]),
        response_bytes: 512 * 1024,
    };
    let mut buf = vec![];
    req.encode(&mut buf).unwrap();
    assert_eq!(GetPbtLeafRange::decode(&buf).unwrap(), req); // needs PartialEq derive

    let resp = PbtLeafRange {
        id: 7,
        leaves: vec![PbtLeaf { key: Bytes::from(vec![0u8; 34]), value: H256::repeat_byte(1) }],
        stem_preimages: vec![Bytes::from(vec![0x11; 20])],
        left_proof: vec![Bytes::from(vec![0x00, 0x01])],
        right_proof: vec![],
    };
    // ... same round-trip
}

#[test]
fn pbtsnap_offsets_sit_above_based_for_every_eth_version() {
    // For each EthCapVersion: pbtsnap_capability_offset() ==
    // based_capability_offset() + BASED_CAPABILITY_SLOT_COUNT, and the
    // decode ladder routes (offset + 0x00 / 0x01) to the new variants.
}
```

**Step 2: Run** `cargo test -p ethrex-p2p pbtsnap` (confirm the crate's test invocation name first) — compile failure.

**Step 3: Implement**, mirroring the snap module file-for-file:

- `messages.rs` (derive `Debug, Clone, PartialEq`):

```rust
pub struct GetPbtLeafRange {
    pub id: u64,
    pub root_hash: H256,       // pivot header state_root (a PBT root)
    pub origin: Bytes,         // full-length tree key, lexicographic
    pub limit: Bytes,          // inclusive; terminator may exceed it
    pub response_bytes: u64,   // soft cap, never suppresses the first leaf
}

pub struct PbtLeaf {
    pub key: Bytes,            // 34 or 66 bytes
    pub value: H256,           // the 32-byte leaf value
}

pub struct PbtLeafRange {
    pub id: u64,
    pub leaves: Vec<PbtLeaf>,
    /// One per distinct stem among `leaves`, ascending stem order.
    /// Zone 0x00: 20B address; 0x01: 64B code_hash‖tree_index;
    /// 0xff: 52B address‖tree_index. See docs/eip-draft-pbtsnap.md.
    pub stem_preimages: Vec<Bytes>,
    pub left_proof: Vec<Bytes>,   // pbt-getproof-v1 preimages, walk of origin
    pub right_proof: Vec<Bytes>,  // walk of the last leaf; empty iff leaves empty
}
```

- `codec.rs`: `RLPxMessage` impls in the exact snap pattern (`Encoder::encode_field` chain → `snappy_compress`; decode via `snappy_decompress` → `Decoder::decode_field`). Codes: `GetPbtLeafRange::CODE = 0x00`, `PbtLeafRange::CODE = 0x01`. `PbtLeaf` gets a small manual RLP encode/decode pair like `StorageSlot`'s (`snap/codec.rs:332-349`).
- `message.rs`: `PBTSNAP_CAPABILITY_SLOT_COUNT = 4` (two implemented + two reserved); `pbtsnap_capability_offset(self) = based_capability_offset() + BASED_SLOT_COUNT` (read the ladder's final arm to extract based's slot count into a named const first — it is currently implicit); new `Message::GetPbtLeafRange/PbtLeafRange` variants; decode ladder gains a final arm (`match msg_id - pbtsnap_offset { 0x00 => .., 0x01 => .., 0x02 | 0x03 => Err(reserved) , .. }`); `request_id()` returns `Some(id)` for both.
- `p2p.rs`: `Capability::pbtsnap(1)` (pad `b"pbtsnap"` to 8), `pub const SUPPORTED_PBTSNAP_CAPABILITIES: [Capability; 1]`.
- `connection/server.rs`: advertise in hello and negotiate ONLY when `chain_config.binary_tree_scheduled()` (an unscheduled node must be byte-identical on the wire to today's — the existing devnets assert zero behavioral drift); store `negotiated_pbtsnap_capability` next to the snap one.

**Step 4: Run** `cargo test -p ethrex-p2p` + `cargo check --workspace` — green. **Step 5: Commit:** `feat(p2p): pbtsnap/1 capability and leaf-range wire messages`

---

## Task 8: Server side — serving leaf ranges from PbtState snapshots

**Files:**
- Create: `crates/networking/p2p/pbtsnap/mod.rs`, `server.rs`
- Modify: `crates/networking/p2p/rlpx/connection/server.rs` (dispatch + rate-limit list), `crates/storage/store.rs` (root→snapshot resolution helper)

**Step 1: Write the failing test** (in `pbtsnap/server.rs` tests; build an in-memory `Store`, add a canonical header whose `state_root` is the snapshot's root — model store setup on the existing store unit tests):

```rust
#[tokio::test]
async fn served_range_verifies_and_reassembles() {
    let (store, pivot_header, pbt_state) = store_with_snapshot().await; // helper:
    //   PbtState with ~5 accounts (one with slots 0,63,64,300; one with code),
    //   put_pbt_state under a canonical header whose state_root == compute_root.
    let root = pivot_header.state_root;

    // Zone 0x00 from the very start.
    let req = GetPbtLeafRange { id: 1, root_hash: root,
        origin: Bytes::from(vec![0u8; 34]),
        limit: Bytes::copy_from_slice(&account_zone_limit()), // 0x00 ‖ ff*33
        response_bytes: 512 * 1024 };
    let resp = process_pbt_leaf_range_request(&store, &req).unwrap();
    assert!(!resp.leaves.is_empty());
    let leaves: Vec<_> = resp.leaves.iter()
        .map(|l| (l.key.to_vec(), l.value.0)).collect();
    verify_range(root, &req.origin, &leaves, &to_vecs(&resp.left_proof),
                 &to_vecs(&resp.right_proof)).unwrap();
    // Preimages: one per distinct stem, digests check out.
    assert_stem_preimages_cover(&leaves, &resp.stem_preimages);

    // Unknown root -> error (client will re-pivot).
    assert!(process_pbt_leaf_range_request(&store, &GetPbtLeafRange {
        root_hash: H256::repeat_byte(9), ..req.clone() }).is_err());

    // Byte budget of ~2 leaves still returns the first leaf and verifies.
    let small = process_pbt_leaf_range_request(&store, &GetPbtLeafRange {
        response_bytes: 150, ..req.clone() }).unwrap();
    assert!(!small.leaves.is_empty() && small.leaves.len() < resp.leaves.len());
}
```

**Step 2:** red. **Step 3: Implement:**

- **Root resolution** — `Store::get_pbt_state_by_root(&self, root: H256) -> Result<Option<(BlockHash, Arc<PbtState>)>, StoreError>`: walk canonical headers from `get_latest_block_number()` down at most 128 (snap's `SNAP_LIMIT` precedent), returning the first with `header.state_root == root && is_binary_tree_active(header.timestamp)` and a registered snapshot. Alternative — an eager root→hash index maintained at every `put_pbt_state` — rejected: it burdens the seeding API and duplicates reorg handling the canonical walk gets for free; the walk cost is amortized by the serving cache.
- **Serving cache** — in `pbtsnap/server.rs`, a `static` `Mutex<LruCache<H256, Arc<PbtServingIndex>>>` (capacity 2 — current pivot + one straggler):

```rust
struct PbtServingIndex {
    entries: Entries,                       // full embedded leaf set
    trie: BinaryTrie,                       // for boundary proofs
    stem_preimages: BTreeMap<Vec<u8>, Bytes>, // stem -> wire preimage
}
```

  Built once per root from the snapshot: embedding needs a way to get the entries — `PbtState::embed_entries` is private; **promote it to `pub` (doc: Seam-B read surface for servers; the entry map is the spec's canonical flat form, safe to expose)** rather than re-deriving the embedding in p2p. Stem preimages come straight from the flat state (addresses and tree_indices are in hand; recompute each stem digest with the `embedding` functions). O(state) once per root, then every request is a BTreeMap range scan + two `prove` calls.
- **Handler** — `process_pbt_leaf_range_request(store, req) -> Result<PbtLeafRange, PbtSnapError>` inside `spawn_blocking` like the snap handlers: clamp `response_bytes` to snap's `MAX_RESPONSE_BYTES`; map budget → leaf count (charge `key.len() + 32` per leaf, proofs and preimages uncharged, matching snap's accounting spirit); `prove_range(...)`; collect preimages for the distinct stems of the returned run; unknown root → error (the connection layer answers errors with an empty `PbtLeafRange { id, .. }`, mirroring the `TrieNodes` precedent at `server.rs:1711-1717` — an empty response fails client verification and triggers retry/re-pivot, never a silent gap).
- **Dispatch** — `Message::GetPbtLeafRange` arm in `handle_incoming_message` + add it to the `is_data_request` rate-limit list.

**Step 4:** green (`cargo test -p ethrex-p2p`). **Step 5: Commit:** `feat(p2p): serve pbtsnap leaf ranges from PbtState snapshots`

---

## Task 9: Client assembler — reverse embedding into `PbtState`

Pure, transport-free state reconstruction: verified leaves + preimages in, `PbtState` out. All trust decisions happen here or in `verify_range`; the network loop (Task 10) stays dumb.

**Files:**
- Create: `crates/networking/p2p/pbtsnap/assembler.rs`

**Step 1: Write the failing tests:**

```rust
#[test]
fn assembler_round_trips_a_pbt_state() {
    let original: PbtState = fixture_state(); // accounts incl.: EOA; contract
        // with slots {0, 63, 64, 300} and >127-chunk code; empty-code account
    let index = serving_index(&original);     // Task 8's builder, reused

    let mut asm = PbtSyncAssembler::new();
    // Feed zone 0x00 then 0xff in several chunks, INCLUDING a chunk split
    // mid-stem (budget 3) — stems must reassemble across responses.
    for slice in serve_zone_in_chunks(&index, ACCOUNT_ZONE, 3) {
        asm.ingest(&slice.leaves, &slice.stem_preimages).unwrap();
    }
    for slice in serve_zone_in_chunks(&index, STORAGE_ZONE, 3) {
        asm.ingest(&slice.leaves, &slice.stem_preimages).unwrap();
    }
    let wanted = asm.wanted_code_hashes();
    assert_eq!(wanted, original.code.keys().copied().collect::<BTreeSet<_>>());
    let rebuilt = asm.finish(codes_for(&original, &wanted)).unwrap();
    assert_eq!(rebuilt.compute_root().unwrap(), original.compute_root().unwrap());
    assert_eq!(rebuilt.accounts, original.accounts);
    assert_eq!(rebuilt.storage, original.storage);
}

#[test]
fn assembler_rejects_bad_preimages_and_leaves() {
    // (a) wrong address for a stem digest -> StemDigestMismatch
    // (b) missing preimage for a served stem -> MissingStemPreimage
    // (c) account-zone sub-index 2 (reserved) -> UnknownSubIndex
    // (d) finish() with a stem lacking its basic-data leaf -> IncompleteAccountStem
    // (e) finish() with code whose keccak != code-hash leaf -> CodeHashMismatch
    // (f) finish() with code whose length != decoded code_size -> CodeSizeMismatch
    // (g) zero-valued storage leaf -> ZeroStorageValue (state never stores zeros)
}
```

**Step 2:** red. **Step 3: Implement:**

```rust
pub struct PbtSyncAssembler {
    accounts: BTreeMap<Address, PbtAccount>,
    code_sizes: BTreeMap<Address, u32>,     // from decoded basic data
    storage: BTreeMap<Address, BTreeMap<H256, U256>>,
    seen_header_leaves: BTreeMap<Address, (bool, bool)>, // (basic_data, code_hash)
}

impl PbtSyncAssembler {
    /// Ingest one VERIFIED range (caller has already run verify_range).
    /// Checks preimage digests, decodes leaves per sub-index, skips
    /// zone 0x01 (derived from bytecode later). Idempotent per leaf.
    pub fn ingest(&mut self, leaves: &[(Vec<u8>, [u8; 32])],
                  stem_preimages: &[Bytes]) -> Result<(), AssembleError>;

    /// Distinct non-empty code hashes referenced by code-hash leaves.
    pub fn wanted_code_hashes(&self) -> BTreeSet<H256>;

    /// Cross-check codes (keccak vs code-hash leaves, length vs decoded
    /// code_size), require every account stem complete (sub 0 AND 1
    /// seen), and produce the PbtState. The caller then does the final
    /// compute_root() == pivot check — that, not this, is the
    /// whole-state seal.
    pub fn finish(self, codes: Vec<(H256, Code)>) -> Result<PbtState, AssembleError>;
}
```

Decode table (per the draft doc): stem → preimage lookup (build a map stem→preimage per ingest call; a stem appearing in `leaves` without a preimage entry is an error); zone `0x00` sub 0 → `decode_basic_data` (reject `version != BASIC_DATA_VERSION`), sub 1 → code-hash leaf, sub 64–127 → slot `sub − 64` (reject zero values), sub 128–255 → header code chunk (content dropped — revalidated by the final root check), sub 2–63 → `UnknownSubIndex`; zone `0xff` → slot `tree_index·256 + sub` (reject `slot < 64`, which can never legitimately live in the storage zone); zone `0x01` → skip. A terminator leaf past the requested limit is ingested like any other (it is proven state; idempotence makes the overlap with the next zone request harmless).

**Step 4:** green. **Step 5: Commit:** `feat(p2p): pbtsnap client assembler — verified leaves to PbtState`

---

## Task 10: Sync driver — the `pbt_snap` cycle and the legacy-snap guard

**Files:**
- Create: `crates/networking/p2p/sync/pbt_snap.rs`
- Create: `crates/networking/p2p/pbtsnap/client.rs` (request helpers)
- Modify: `crates/networking/p2p/sync.rs` (routing in `sync_cycle`), `crates/networking/p2p/sync/snap_sync.rs` (guard)

**Step 1: Write the failing tests.** Network-free, via a provider trait (the mock-peer seam Task 11 exploits adversarially):

```rust
/// Transport abstraction: the real impl sends pbtsnap/snap requests via
/// PeerHandler; tests implement it over a PbtServingIndex + code map.
#[async_trait] // match the codebase's async-trait convention — check first
pub trait PbtSnapProvider {
    async fn get_leaf_range(&self, req: GetPbtLeafRange) -> Result<PbtLeafRange, PbtSnapError>;
    async fn get_bytecodes(&self, hashes: &[H256]) -> Result<Vec<Bytes>, PbtSnapError>;
}

#[tokio::test]
async fn download_state_reconstructs_pivot_state() {
    let (provider, pivot_header, source_state) = fake_provider(); // serves Task 8's index
    let state = download_pbt_state(&provider, &pivot_header).await.unwrap();
    assert_eq!(state.compute_root().unwrap(), pivot_header.state_root);
    assert_eq!(state.accounts, source_state.accounts);
}

#[tokio::test]
async fn download_fails_cleanly_on_root_mismatch() {
    // Provider whose snapshot differs from the pivot header root:
    // ranges verify against the WRONG root -> every request errors ->
    // download returns Err, no partial state escapes.
}
```

**Step 2:** red. **Step 3: Implement:**

- **`download_pbt_state(provider, pivot_header) -> Result<PbtState, SyncError>`** (in `pbt_snap.rs`, transport-generic): for zone `0x00` then `0xff`: `origin = zone_min_key()`, loop — `get_leaf_range(root, origin, zone_limit, MAX_RESPONSE_BYTES)` → `verify_range` → `assembler.ingest` → if `!has_more` or last key > zone limit: zone done; else `origin = increment_key(last_key)`. Then `wanted_code_hashes()` → `get_bytecodes` in snap's `BYTECODE_CHUNK_SIZE` batches → `assembler.finish(codes)` → final `compute_root() == pivot.state_root` check (belt over the seam's braces — fail HERE with a clear "peer served consistent-but-wrong state" error rather than inside `install_pbt_snapshot`). v1 is deliberately sequential (one in-flight request); parallel chunking à la snap's 800-way split is a recorded non-goal until a devnet is slow enough to care.
- **Real provider** (`pbtsnap/client.rs`): `get_best_peer(SUPPORTED_PBTSNAP_CAPABILITIES)` + `outgoing_request(Message::GetPbtLeafRange(..), PEER_REPLY_TIMEOUT)` with the snap client's permit/score bookkeeping (`record_success`/`record_failure`); 3 attempts across peers per request, then error upward. Bytecodes delegate to the existing `request_bytecodes` (snap client re-export).
- **Cycle** (`sync_cycle_pbt` in `pbt_snap.rs`): reuse the snap header phase machinery verbatim (`SnapBlockSyncState`, `process_incoming_headers` — refactor to `pub(crate)` if needed); pivot = last downloaded header. Gates: `is_binary_tree_active(pivot.timestamp)` else warn + fall back to `full::sync_cycle_full` (Decision 12). Then `download_pbt_state` → `store.install_pbt_snapshot(pivot.hash(), state)` → store the pivot block body + `forkchoice_update` (mirror snap's switch-over, `snap_sync.rs:632-657`) → `clear_snap_state()` + `snap_enabled = false`. **Stale/failed pivot:** any unrecoverable download error (root unknown to peers, repeated verification failures) drops the assembler and restarts the cycle with a fresh pivot — pivot-restart IS the v1 healing story; bound it (3 pivots per cycle) before surfacing `SyncError`.
- **Routing + guard:** in `sync_cycle` (`sync.rs:215-278`): if `snap_enabled && chain_config.binary_tree_scheduled()` → `sync_cycle_pbt` unconditionally (skipping the `MIN_FULL_BLOCKS` probe — Decision 11, comment why). In `sync_cycle_snap`, add a defensive `binary_tree_scheduled()` bail-out (legacy snap would heal an MPT against a PBT root; make the failure mode a one-line error, not a mystery).

**Step 4:** green: new tests + `cargo test -p ethrex-p2p` + existing sync tests untouched (`cargo check --workspace`). **Step 5: Commit:** `feat(sync): pbtsnap download cycle, pivot-restart recovery, legacy-snap guard`

---

## Task 11: Adversarial end-to-end tests (malicious provider)

The `PbtSnapProvider` seam makes byzantine-peer testing cheap: wrap the honest fake provider and corrupt one thing at a time; the driver must reject every corruption with no partial state landing.

**Files:**
- Modify: `crates/networking/p2p/pbtsnap/` tests (or a `tests/` integration file in the p2p crate — match where Task 10's tests landed)

**Step 1: Write the tests** — each a small wrapper provider + one assertion that `download_pbt_state` errors (and, where retries apply, that an honest retry succeeds after a byzantine first answer):

1. **Tampered leaf value** mid-range → `RootMismatch` at verify, request retried, honest second answer completes the sync.
2. **Gap smuggling**: provider drops one mid-range leaf (boundary proofs untouched) → `RootMismatch`.
3. **Truncated proofs**: left or right proof missing its last node → `Proof(Truncated)`.
4. **Forged emptiness**: empty response while leaves ≥ origin exist → `MissingLeaves`.
5. **Preimage lies**: valid leaves, wrong address in a stem preimage → assembler `StemDigestMismatch`; missing preimage → `MissingStemPreimage`.
6. **Wrong-but-consistent state**: provider serves a fully self-consistent snapshot for a DIFFERENT root → every range fails `RootMismatch` immediately (the pivot root anchors everything).
7. **Bytecode substitution**: correct leaves, wrong bytecode for a hash → `CodeHashMismatch` at `finish` (never reaches `install_pbt_snapshot`).
8. **Stall/short responses**: provider that always returns exactly one leaf → sync still completes (progress rule), bounded only by round-trips.

**Step 2: Run** — these should pass against Tasks 2/9/10 as built; any failure is a real hole (fix the component, never soften the test).

**Step 3: Commit:** `test(pbtsnap): byzantine-provider coverage for the download path`

---

## Task 12: Kurtosis late-join scenario, docs, wrap-up

**Files:**
- Modify: `fixtures/networks/binary-tree-devnet-fast.yaml` (or a sibling `binary-tree-devnet-snap.yaml` if the fast config's participant set is load-bearing elsewhere — check who consumes it first)
- Modify: `crates/common/binary-trie/README.md`, `docs/eip-draft-pbtsnap.md` (status notes), the state-commitment plan's as-built section pointer style is the model
- Verify: full lint/test sweep

1. **Devnet scenario:** document (in the yaml's comments + the README) the late-join flow: bring up the fast devnet (flip at ~30 s), wait past the flip plus a few blocks, then `kurtosis service add` (or a second run with an extra participant using `el_extra_params: [--syncmode, snap]`) a snap-mode ethrex node. Success criteria to record after a live run, mirroring the transition plan's "Fast devnet" as-built register: joiner reaches the head without genesis replay (grep its logs for the pbtsnap phases), state roots match across all nodes at several heights, `eth_getProof` on the joiner serves `pbt-getproof-v1` for the pivot and later blocks, a post-join transfer mines with identical reads everywhere, and `eth_getProof`/tracing for PRE-pivot blocks fail with the documented "no snapshot" error (expected, recorded, not a bug).
2. **README/docs:** binary-trie README non-goals updated (sync now EXISTS, experimental, pointer to the draft doc and this plan); draft doc gets an "implemented in ethrex" test-cases section like the getproof draft's; note in both places the serving-depth limitation (in-memory snapshots, Phase-2 Upgrade 2 for deep history) and the per-boot import flag contract.
3. **Sweep:** `cargo fmt --check`; `cargo clippy -p ethrex-binary-trie -p ethrex-common -p ethrex-storage -p ethrex-p2p -p ethrex-blockchain --all-targets -- -D warnings` (plus `make lint` if practical); `cargo test -p ethrex-binary-trie -p ethrex-common -p ethrex-storage -p ethrex-p2p`; `cd test && cargo test binary_tree`; `cargo check --workspace`.
4. **Commit:** `docs(pbtsnap): kurtosis late-join scenario and wrap-up`

---

## Testing strategy (summary of what the tasks build, by layer)

- **Unit / conformance:** range prove+verify against the EELS-pinned fixture roots (every sub-range of every fixture trie, Task 3) and against `rebuild_root` as the oracle on random embedding-shaped workloads — the same two-source trust chain the per-key proof suite uses. Assembler decode-table round-trips including mid-stem chunk splits (Task 9).
- **Differential:** the load-bearing invariant at every level is `synced_state.compute_root() == source_root` — per-slice (verify_range), post-assembly (Task 10's final check), at landing (`install_pbt_snapshot` re-verifies), and across nodes on the devnet (Task 12). Plus `materialized MPT root == replayed node's registered lookup root` (Task 5), which pins the MPT side.
- **Adversarial:** proof tampering, gap smuggling, truncated ranges, forged emptiness, preimage lies, consistent-but-wrong state, bytecode substitution — all through the byzantine provider seam (Task 11), plus the crate-level mutation grinding (Task 3).
- **Live:** kurtosis late-join on `binary-tree-devnet-fast` (Task 12) — the only place real RLPx framing, negotiation, rate limiting, and peer scoring get exercised end-to-end.

## Out of scope (deliberately)

- **Upstream spec work.** The draft doc is a de-facto record for future upstreaming, like `pbt-getproof-v1`; no EIP/devp2p submission, no cross-client coordination.
- **Healing protocol.** Codes `0x02`/`0x03` are reserved; v1 recovers from staleness by pivot restart. Justified by devnet state sizes and never-evicted server snapshots; revisit when a devnet's sync time approaches the pivot window.
- **Deep-history serving / persistence.** Servers serve since-boot snapshots only; Phase-2 Upgrade 2 (persisted flat tables) is the prerequisite for more and is unchanged by this plan. Likewise the synced client's registries remain in-memory — a restarted snap node re-syncs or re-imports (the v0 artifact mitigates).
- **MPT→PBT conversion.** Unchanged from the transition plan's scope note: in-protocol gradual conversion is an upstream gap; this plan syncs chains that are ALREADY PBT-committed at the pivot.
- **Parallel range download, peer striping, disk spill.** v1 is sequential and in-memory end-to-end; snap's 800-chunk machinery is the template when scale demands it.
- **Pre-pivot state availability** (tracing, getProof, `debug_*` for blocks before the pivot) — same contract as MPT snap sync; errors are explicit.
- **Mainnet-grade scheduling, request pricing, and DoS economics** beyond the byte cap + existing rate limiter.

## Open questions (recorded, not blocking)

1. **Multiproof compression.** Boundary walks per response are O(key-bits); a stem-level multiproof (shared-prefix dedup) would shrink responses meaningfully once ranges span many stems. Strictly additive (new message version), anticipated in the draft doc — worth it only when response sizes show up in devnet measurements.
2. **Serving cache sizing.** Capacity-2 LRU assumes one active pivot; several simultaneously syncing peers with staggered pivots could thrash the O(state) index build. Fine at devnet scale; a per-root build mutex (or building from persisted flat tables post-Upgrade-2) is the fix if it bites.
3. **`based` offset coupling.** The pbtsnap offsets sit above `based` in ethrex's hard-coded ladder; if `based` ever grows message slots, the pbtsnap offsets shift — an ethrex↔ethrex version-skew hazard between releases. Acceptable for an experimental capability (both ends ship in lockstep on devnets); a negotiated-offset scheme is the durable answer if the capability outlives experiments.
4. **Should `pbtsnap` also carry bytecodes eventually?** Reusing `snap/1 GetByteCodes` couples PBT sync to the peer also advertising snap. True for all ethrex nodes today; if a future PBT-only node profile drops snap, mirror the two messages into the reserved code space (or a `pbtsnap/2`).
5. **Storage-expiry alignment.** The per-contract contiguity of zone `0xff` (first digest = blake3(address)) was designed as a sync AND expiry unit; when expiry lands upstream, per-contract sub-range requests (origin/limit within one contract's digest prefix) fall out of this protocol for free — worth stating in the upstream pitch.
6. **Snap-then-flip for scheduled-pre-flip chains.** A node joining before the flip must full-sync (Decision 12). A hybrid (MPT snap + preimage-carrying side channel to seed the shadow state) would close the gap but is a research question about preimage transfer at MPT scale — exactly what this protocol avoids by syncing post-flip flat state.
