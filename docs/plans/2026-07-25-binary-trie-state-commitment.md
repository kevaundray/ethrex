# Binary Trie State Commitment Integration Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** An experimental genesis flag (`enableBinaryTreeAtGenesis`) under which ethrex commits block and genesis state roots through the EIP-8297 binary trie (via the existing `ethrex-binary-trie` crate) instead of the MPT — the ethrex analog of execution-specs PR #3216. No new `Fork` variant: with genesis-only activation the commitment scheme is orthogonal to the fork schedule, so it's a config bit (mirroring the existing `enable_verkle_at_genesis` precedent, `genesis.rs:297-298`); the `Fork::BinaryTree` variant is deferred to the transition phase, where timestamp activation genuinely requires it (see the appendix for the fully mapped enum plumbing).

**Architecture:** A new flat state model `PbtState` (accounts/storage/code keyed by **real 20-byte addresses and unhashed slot keys** — the MPT is keccak-keyed with no preimage table, so the binary state must be tracked separately). **PBT-from-birth**: this phase supports exactly one configuration — `enableBinaryTreeAtGenesis: true` in the chain config. The chain is born committed to the binary tree: `PbtState` is seeded from the genesis alloc, the genesis header's `state_root` is a PBT root, and every block clones the parent snapshot, applies the block's `AccountUpdate` stream (which carries real addresses and unhashed slot keys — the reason no preimage table is needed), re-embeds through `ethrex_binary_trie::embedding`, and hashes with `rebuild_root` — spec-faithful (`state_pbt.py` does exactly this), correct under deletion, full-state commitment on every block. The MPT remains ethrex's storage/lookup structure and is still maintained; only the **header commitment** differs from a normal chain. Snapshots are in-memory keyed by block hash (reorgs fall out for free); a missing parent snapshot (process restart) is a hard error — re-import from genesis, or seed via `put_pbt_state`. **Mid-chain activation/transition is deliberately deferred**: the shadow-tracking design for it is worked out and recorded in the Phase 2 roadmap below, and genesis activation is its degenerate case, so nothing built here is throwaway. Mid-chain activation is unrepresentable by construction: the flag has no timestamp (the `Fork::BinaryTree` variant and `binaryTreeTime` arrive with the transition phase).

**Tech Stack:** Rust (ethrex workspace), `ethrex-binary-trie` (from the previous plan, `docs/plans/2026-07-24-binary-trie-crate.md`), spec vectors regenerated from the execution-specs checkout (`kw/sketch-embedding-changes` branch, which has `state_pbt.py`).

**Constraints settled up front:**
- Activation is a boolean `ChainConfig` field: `#[serde(default)] pub enable_binary_tree_at_genesis: bool` (serialized `enableBinaryTreeAtGenesis`), exactly mirroring `enable_verkle_at_genesis` (`genesis.rs:297-298`). No `Fork` enum variant, no fork-time field, no ForkId interaction — the invalid configuration (mid-chain activation) is unrepresentable rather than rejected. EVM semantics come from whatever forks the genesis schedules; the flag changes only the state commitment.
- EEST fixture consumption later: the spec test framework's fork is named `BinaryTree`, and the blockchain-test tooling has its own fork-name enum (`tooling/ef_tests/blockchain/fork.rs`) — `"BinaryTree"` maps to "latest fork schedule + this flag" in tooling when that wiring lands. Nothing needed now.
- Scope: L1 store + genesis + block import + payload building. NOT in scope: witness/guest path, snap sync, proofs, `Crypto`-trait blake3, persistence of the binary state.
- **Genesis-activation only (this phase).** All nodes on a flagged network are PBT from birth — no transition, no boundary, no carry-over question. Mid-chain activation via shadow tracking is fully designed (see Phase 2 roadmap, "Transition machinery") and lands as its own phase, together with the real `Fork::BinaryTree` variant.
- A missing parent snapshot at import time is a hard error (process restart, or a node that didn't replay from genesis). The escape hatch is offline seeding: `put_pbt_state(parent_hash, state)` installs a snapshot equal to what replay would have computed (self-verifying: its root must match the fork-active header it corresponds to).
- Spec conformance: PBT-from-genesis with full-state commitment is exactly `state_pbt.py`'s model, so the Task 2/4 conformance vectors apply directly — and this is the mode EEST `BinaryTree`-fork fixtures will exercise.
- Balances under the fork must be `< 2^128` (`encode_basic_data` bound). No general validation is added; the error surfaces from root computation. Genesis fixtures for this fork must use compliant balances.

**Reference files:**
- Spec: `/Users/kev/work/ethereum/execution-specs/src/ethereum/state_pbt.py` (on `kw/sketch-embedding-changes`), `src/ethereum/binary_trie/embedding.py`.
- Exploration findings this plan is grounded in (file:line refs are from commit `bad1f85c`): fork mechanics `crates/common/types/genesis.rs:313-712,1275-1348`; commitment path `crates/storage/store.rs:2163-2244`, `crates/blockchain/blockchain.rs:2163-2221,2272-2390,2789-2801,4280-4292`, `crates/blockchain/payload.rs:979-992`; `AccountUpdate` `crates/common/types/account_update.rs:9-19`; genesis `crates/common/types/genesis.rs:777-821`, `crates/storage/store.rs:2342-2400,2571-2639`.

---

## Task 1: `enable_binary_tree_at_genesis` config flag

**Files:**
- Modify: `crates/common/types/genesis.rs` (ChainConfig)
- Modify: `crates/networking/rpc/rpc.rs` (~:1813, exact-JSON config test — only if the new field appears in that serialization; run it and see)

**Step 1: Write the failing test** (next to the existing ChainConfig tests in `genesis.rs`):

```rust
#[test]
fn test_enable_binary_tree_at_genesis_flag() {
    // Default off, and absent from JSON deserializes to off.
    let config = ChainConfig::default();
    assert!(!config.enable_binary_tree_at_genesis);
    let parsed: ChainConfig = serde_json::from_str("{}").unwrap_or_default();
    assert!(!parsed.enable_binary_tree_at_genesis);

    // Round-trips through camelCase.
    let parsed: ChainConfig = serde_json::from_value(serde_json::json!({
        "chainId": 1, "enableBinaryTreeAtGenesis": true
    })).unwrap();
    assert!(parsed.enable_binary_tree_at_genesis);
}
```

(Adapt to how the existing ChainConfig serde tests construct minimal configs — `from_str("{}")` may fail if fields lack defaults; model on the nearest existing deserialize test rather than fighting it.)

**Step 2: Run** `cargo test -p ethrex-common enable_binary_tree` — expect compile failure (no field).

**Step 3: Implement.** In `ChainConfig`, directly below `enable_verkle_at_genesis` (`genesis.rs:297-298`) and mirroring it exactly:

```rust
#[serde(default)]
pub enable_binary_tree_at_genesis: bool,
```

with a doc comment: experimental EIP-8297 commitment — when set, genesis and block state roots are Partitioned-Binary-Tree roots instead of MPT roots; activation is genesis-only (transition machinery is a later phase). No `Fork` variant, no fork-time field, no `gather_forks`/ForkId involvement — the flag does not participate in fork identity (nodes disagreeing on it already diverge at the genesis hash, since the genesis state root differs).

**Step 4: Verify:** `cargo test -p ethrex-common` green; `cargo check --workspace` (rkyv derive on ChainConfig means the archived layout changes — the workspace check catches any fallout); run the RPC config test (`grep -rn "hegotaTime" crates/networking/rpc/rpc.rs` to find it, then run that test) and update its expected JSON only if it fails.

**Step 5: Commit:** `feat(config): enableBinaryTreeAtGenesis flag for EIP-8297 commitment`

---

## Task 2: Spec vectors for flat-state embedding

Pin our `PbtState` root computation to the spec's `state_pbt.py` before writing it. Extend the existing generator.

**Files:**
- Modify: `crates/common/binary-trie/tests/vectors/dump_vectors.py`
- Regenerate: `crates/common/binary-trie/tests/vectors/binary_trie_vectors.json`

**Step 1:** The execution-specs checkout must be on `kw/sketch-embedding-changes` (it currently is — verify with `git -C /Users/kev/work/ethereum/execution-specs branch --show-current`; that branch has `src/ethereum/state_pbt.py`). Append a `pbt_state` section to the generator. Add after the `basic_data_cases` block (adapt imports at top of file):

```python
# --- Flat-state embedding vectors (state_pbt.py) ---
from ethereum_types.bytes import Bytes20 as _B20
from ethereum.state import Account, BlockDiff
from ethereum.state_pbt import State as PbtState, apply_changes_to_state, state_root, store_code

ADDR_EOA = _B20(bytes.fromhex("1000000000000000000000000000000000000001"))
ADDR_CONTRACT = _B20(bytes.fromhex("2000000000000000000000000000000000000002"))
# > 127 chunks of code so content-addressed overflow chunks are exercised:
# 130 chunks * 31 bytes = 4030 bytes. Deterministic pattern, has PUSH data
# crossing chunk boundaries.
CONTRACT_CODE = Bytes(bytes([0x60, 0xAA, 0x01] * 1343 + [0x00]))  # 4030 bytes

state = PbtState()
code_hash = store_code(state, CONTRACT_CODE)
from ethereum.state_pbt import set_account, set_storage
set_account(state, ADDR_EOA, Account(nonce=U64(7), balance=U256(10**18), code_hash=keccak256(b"")))
set_account(state, ADDR_CONTRACT, Account(nonce=U64(1), balance=U256(2**127 - 1), code_hash=code_hash))
set_storage(state, ADDR_CONTRACT, Bytes32((0).to_bytes(32, "big")), U256(0xDEAD))      # header slot
set_storage(state, ADDR_CONTRACT, Bytes32((63).to_bytes(32, "big")), U256(1))          # last header slot
set_storage(state, ADDR_CONTRACT, Bytes32((64).to_bytes(32, "big")), U256(2))          # first overflow slot
set_storage(state, ADDR_CONTRACT, Bytes32((300).to_bytes(32, "big")), U256(3))         # second overflow group

pre_root = state_root(state)

# Diff: EOA balance bump, contract slot 0 zeroed (delete), slot 64 changed,
# then a second diff deleting the contract entirely (orphans its code chunks).
diff1 = BlockDiff(
    account_changes={ADDR_EOA: Account(nonce=U64(8), balance=U256(2 * 10**18), code_hash=keccak256(b""))},
    storage_changes={ADDR_CONTRACT: {Bytes32((0).to_bytes(32, "big")): U256(0),
                                     Bytes32((64).to_bytes(32, "big")): U256(9)}},
    code_changes={},
)
apply_changes_to_state(state, diff1)
post_diff1_root = state_root(state)

diff2 = BlockDiff(account_changes={ADDR_CONTRACT: None}, storage_changes={}, code_changes={})
apply_changes_to_state(state, diff2)
post_delete_root = state_root(state)

pbt_state_cases = {
    "eoa_address": hx(ADDR_EOA),
    "contract_address": hx(ADDR_CONTRACT),
    "contract_code": hx(CONTRACT_CODE),
    "pre": {
        "eoa": {"nonce": 7, "balance": hex(10**18)},
        "contract": {"nonce": 1, "balance": hex(2**127 - 1),
                      "storage": {"0": hex(0xDEAD), "63": "0x1", "64": "0x2", "300": "0x3"}},
        "root": hx(pre_root),
    },
    "post_diff1_root": hx(post_diff1_root),
    "post_delete_contract_root": hx(post_delete_root),
}
```

and add `"pbt_state": pbt_state_cases` to the final `json.dump` dict. IMPORTANT: the exact `Account` constructor signature and `set_storage` key type must match the spec code — read `state_pbt.py` and `state.py` first and adapt (e.g. `Account` may take positional args or have a different field set; `set_storage` takes `Bytes32` keys). If `state_root(state)` isn't exported use `state.compute_state_root(BlockDiff())` per the module's API. Do not guess; the script must run.

**Step 2:** Regenerate (from the spec checkout root, as the script requires for `source_commit`):
```bash
cd /Users/kev/work/ethereum/execution-specs
uv run python /Users/kev/work/ethereum/ethrex/crates/common/binary-trie/tests/vectors/dump_vectors.py > /Users/kev/work/ethereum/ethrex/crates/common/binary-trie/tests/vectors/binary_trie_vectors.json
```

**Step 3: Verify invariants:** all previously pinned values UNCHANGED (`trie_roots[1].root` = `0x4b60a28d...bbc7`, `trie_roots[-1].root` = `0xd966...e9be`, 9 trie cases, `embedding.basic_data_key` unchanged); new `pbt_state` section present with three distinct non-zero roots; `source_commit` updated to the current spec HEAD (`git -C /Users/kev/work/ethereum/execution-specs rev-parse HEAD`). Confirm `cargo test -p ethrex-binary-trie` still passes (37 tests — existing sections untouched).

**Step 4: Commit:** `test(binary-trie): flat-state embedding vectors from spec state_pbt`

---

## Task 3: `PbtState` — flat state model and update application

**Files:**
- Create: `crates/common/types/pbt_state.rs`
- Modify: `crates/common/types/mod.rs` (or wherever sibling type modules are declared — check how `account_update` is registered), `crates/common/Cargo.toml` (add `ethrex-binary-trie.workspace = true`)

Dependency direction is safe: `ethrex-binary-trie` depends only on `ethereum-types`/`blake3`/`thiserror` — no cycle. Watch item: `ethrex-common` is built by the guest-program host path; `blake3` already builds in this workspace (it's in the proving stack), but `cargo check --workspace` at the end of the task is the verification.

**Step 1: Write the failing tests** (in `pbt_state.rs`):

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use ethereum_types::{H160, H256, U256};

    fn addr(n: u8) -> H160 { H160([n; 20]) }

    fn update_with_balance(a: H160, balance: u64) -> AccountUpdate {
        let mut u = AccountUpdate::new(a);
        u.info = Some(AccountInfo { balance: U256::from(balance), nonce: 1, code_hash: *EMPTY_KECCAK_HASH });
        u
    }

    #[test]
    fn apply_creates_and_updates_accounts() {
        let mut state = PbtState::default();
        state.apply_account_updates(&[update_with_balance(addr(1), 100)]);
        assert_eq!(state.accounts.len(), 1);
        state.apply_account_updates(&[update_with_balance(addr(1), 200)]);
        assert_eq!(state.accounts[&addr(1)].balance, U256::from(200));
    }

    #[test]
    fn zero_storage_write_removes_slot_and_empty_map_is_dropped() {
        let mut state = PbtState::default();
        let mut u = update_with_balance(addr(1), 1);
        u.added_storage.insert(H256::from_low_u64_be(5), U256::from(9));
        state.apply_account_updates(std::slice::from_ref(&u));
        assert_eq!(state.storage[&addr(1)].len(), 1);

        let mut z = AccountUpdate::new(addr(1));
        z.added_storage.insert(H256::from_low_u64_be(5), U256::zero());
        state.apply_account_updates(std::slice::from_ref(&z));
        assert!(!state.storage.contains_key(&addr(1)));
    }

    #[test]
    fn removed_account_drops_account_and_storage() {
        let mut state = PbtState::default();
        let mut u = update_with_balance(addr(1), 1);
        u.added_storage.insert(H256::from_low_u64_be(5), U256::from(9));
        state.apply_account_updates(std::slice::from_ref(&u));

        let mut removal = AccountUpdate::new(addr(1));
        removal.removed = true;
        state.apply_account_updates(std::slice::from_ref(&removal));
        assert!(state.accounts.is_empty());
        assert!(state.storage.is_empty());
    }

    #[test]
    fn removed_storage_clears_storage_but_keeps_account() {
        let mut state = PbtState::default();
        let mut u = update_with_balance(addr(1), 1);
        u.added_storage.insert(H256::from_low_u64_be(5), U256::from(9));
        state.apply_account_updates(std::slice::from_ref(&u));

        let mut wipe = AccountUpdate::new(addr(1));
        wipe.removed_storage = true;
        state.apply_account_updates(std::slice::from_ref(&wipe));
        assert!(state.accounts.contains_key(&addr(1)));
        assert!(!state.storage.contains_key(&addr(1)));
    }

    #[test]
    fn new_code_lands_in_code_store() {
        let mut state = PbtState::default();
        let mut u = AccountUpdate::new(addr(2));
        // Build a Code from bytecode — check Code's constructor
        // (`Code::from_bytecode(bytes, &NativeCrypto)` per store.rs:2354).
        let code = test_code(&[0x60, 0x01, 0x00]);
        u.info = Some(AccountInfo { balance: U256::zero(), nonce: 1, code_hash: code.hash() });
        u.code = Some(code);
        state.apply_account_updates(std::slice::from_ref(&u));
        assert!(state.code.contains_key(&state.accounts[&addr(2)].code_hash));
    }

    #[test]
    fn storage_update_without_info_keeps_existing_account() {
        let mut state = PbtState::default();
        state.apply_account_updates(&[update_with_balance(addr(1), 77)]);
        let mut s = AccountUpdate::new(addr(1));
        s.added_storage.insert(H256::from_low_u64_be(1), U256::from(1));
        state.apply_account_updates(std::slice::from_ref(&s));
        assert_eq!(state.accounts[&addr(1)].balance, U256::from(77));
    }
}
```

Adjust to real type APIs before running: `AccountUpdate::new` exists (`account_update.rs:21`); check `AccountInfo` field names and `EMPTY_KECCAK_HASH` location (`crates/common/types/account.rs:249-258`); check `Code`'s constructor and hash accessor (`Code::from_bytecode(..., &NativeCrypto)` used at `store.rs:2354`, `.hash` used in blockchain.rs) — write a small `fn test_code(bytes: &[u8]) -> Code` helper accordingly. Read the types; don't guess.

**Step 2:** `cargo test -p ethrex-common pbt_state` — red (module missing).

**Step 3: Implement:**

```rust
//! Flat state model for the experimental EIP-8297 BinaryTree fork.
//!
//! The MPT is keyed by keccak(address) with no preimage table, so the
//! binary-tree commitment cannot be derived from the trie. This model
//! tracks state by real address instead: seeded from the genesis
//! alloc, advanced per block from the [`AccountUpdate`] stream, and
//! re-embedded + re-hashed from scratch for each root — mirroring the
//! spec's `state_pbt.py` reference. Correct under deletion (orphaned
//! content-addressed code chunks vanish on re-embed), O(state) per
//! block; experimental/test scale only.

use std::collections::BTreeMap;

use ethereum_types::{H160, H256, U256};

use crate::types::{AccountUpdate, /* Code, GenesisAccount — adapt paths */};

/// Account fields the binary tree commits (no storage_root — the tree
/// is unified).
#[derive(Debug, Clone, PartialEq)]
pub struct PbtAccount {
    pub nonce: u64,
    pub balance: U256,
    pub code_hash: H256,
}

#[derive(Debug, Clone, Default)]
pub struct PbtState {
    pub accounts: BTreeMap<H160, PbtAccount>,
    /// Unhashed slot key -> value. Zero-valued slots are absent.
    pub storage: BTreeMap<H160, BTreeMap<H256, U256>>,
    /// code_hash -> bytecode, self-contained so root computation
    /// needs no store access.
    pub code: BTreeMap<H256, Code>,
}

impl PbtState {
    pub fn from_genesis_alloc(alloc: &BTreeMap<H160, GenesisAccount>) -> Self { /* per-account:
        code -> Code::from_bytecode + insert into self.code;
        PbtAccount { nonce, balance, code_hash };
        storage: skip zero values, key = H256(slot.to_big_endian()) */ }

    /// Mirrors store.rs apply_account_updates_from_trie_batch semantics
    /// (removed -> drop account+storage; removed_storage -> clear
    /// storage first; info -> overwrite fields; code -> code store;
    /// zero storage value -> remove slot, drop empty maps).
    pub fn apply_account_updates(&mut self, updates: &[AccountUpdate]) { ... }
}
```

Semantics must match `store.rs:2180-2244` order: handle `removed` first (drop + continue), then `removed_storage` (clear), then `info`, then `code`, then `added_storage` (zero removes; drop the per-account map if it ends empty). An update with storage but no `info` for an unknown account: create nothing implicitly — but note the MPT path load-or-defaults (`:2197-2200`); mirror it by inserting a default `PbtAccount` (nonce 0, balance 0, `EMPTY_KECCAK_HASH`) so the two models never diverge on which accounts exist. Add a test for that choice.

Register the module + re-exports the way `account_update.rs` is registered (find it: `grep -rn "account_update" crates/common/types/mod.rs crates/common/lib.rs 2>/dev/null`).

**Step 4:** green. **Step 5: Commit:** `feat(common): PbtState flat state model for BinaryTree fork`

---

## Task 4: `PbtState::compute_root` — embedding + spec conformance

**Files:**
- Modify: `crates/common/types/pbt_state.rs`
- Test: extend `crates/common/binary-trie/tests/spec_vectors.rs`? No — the vectors test for PbtState lives with PbtState: create `test/tests/common/pbt_state_vectors.rs` OR a unit test in `pbt_state.rs` reading the fixture via a relative `include_str!`. Decision: unit test in `pbt_state.rs` with `include_str!("../../binary-trie/tests/vectors/binary_trie_vectors.json")` — verify the relative path from `crates/common/types/` to `crates/common/binary-trie/` by checking the crate layout, and add a comment noting the cross-crate fixture reference.

**Step 1: Failing test** — deserialize the fixture's `pbt_state` section (serde already available in ethrex-common; check), build the pre-state (two accounts, contract code from hex, four storage slots), assert:

```rust
#[test]
fn root_matches_spec_state_pbt_vectors() {
    let v = load_pbt_vectors();
    let mut state = build_pre_state(&v);
    assert_eq!(state.compute_root().unwrap(), v.pre_root);

    // diff1: EOA nonce 8 / balance 2e18; contract slot 0 -> 0, slot 64 -> 9
    apply_diff1(&mut state, &v);
    assert_eq!(state.compute_root().unwrap(), v.post_diff1_root);

    // delete the contract entirely: its storage AND its orphaned
    // content-addressed overflow code chunks must vanish on re-embed
    let mut removal = AccountUpdate::new(v.contract_address);
    removal.removed = true;
    state.apply_account_updates(std::slice::from_ref(&removal));
    assert_eq!(state.compute_root().unwrap(), v.post_delete_contract_root);
}
```

(diff1 must be expressed as `AccountUpdate`s — EOA update with info{nonce 8, balance 2e18, EMPTY_KECCAK_HASH}; contract update with added_storage {slot0: 0, slot64: 9}. The spec BlockDiff and our AccountUpdate express the same mutation.)

Also a small property test: `compute_root` of empty state == `H256::zero()` (EMPTY_TRIE_ROOT), and an EOA-only state root is non-zero and changes when balance changes.

**Step 2:** red. **Step 3: Implement** `compute_root`:

```rust
/// Re-embed the whole state into a fresh set of binary-trie entries
/// and hash. Spec-faithful (state_pbt.py embed_flat_state):
/// per account -> basic-data leaf + code-hash leaf + one leaf per
/// code chunk + one leaf per storage slot. Storage for addresses
/// with no account entry is skipped.
pub fn compute_root(&self) -> Result<H256, BinaryTrieError> {
    use ethrex_binary_trie::embedding::*;
    use ethrex_binary_trie::trie::rebuild::{rebuild_root, Entries};

    let mut entries = Entries::new();
    for (address, account) in &self.accounts {
        let a32 = address20_to_address32(*address);
        let code_bytes: &[u8] = if account.code_hash == *EMPTY_KECCAK_HASH {
            &[]
        } else {
            self.code.get(&account.code_hash)
                .ok_or(/* missing-code error, see below */)?
                .code() // check accessor name
        };
        entries.insert(
            get_tree_key_for_basic_data(&a32),
            encode_basic_data(code_bytes.len() as u32, account.nonce, account.balance)?,
        );
        entries.insert(get_tree_key_for_code_hash(&a32), account.code_hash.0);
        for (i, chunk) in chunkify_code(code_bytes).into_iter().enumerate() {
            entries.insert(get_tree_key_for_code_chunk(&a32, &account.code_hash.0, i as u64), chunk);
        }
        if let Some(slots) = self.storage.get(address) {
            for (slot, value) in slots {
                entries.insert(
                    get_tree_key_for_storage_slot(&a32, U256::from_big_endian(slot.as_bytes())),
                    value.to_big_endian(), // check to_big_endian returns [u8;32] on this version
                );
            }
        }
    }
    Ok(rebuild_root(&entries))
}
```

Error type: `compute_root` needs to express both `BinaryTrieError` (balance cap) and "code missing from store" — add a `CodeMissing(H256)`-style variant. Decide: add `#[error("code for hash {0:#x} missing from PbtState code store")] CodeMissing(H256)` to `BinaryTrieError`? NO — that error belongs to the state model, not the trie crate. Define in `pbt_state.rs`:

```rust
#[derive(Debug, thiserror::Error)]
pub enum PbtStateError {
    #[error(transparent)]
    Trie(#[from] ethrex_binary_trie::BinaryTrieError),
    #[error("bytecode for code hash {0:#x} not in the PbtState code store")]
    CodeMissing(H256),
}
```

(check ethrex-common already depends on thiserror; it almost certainly does).

`code_size` check: `code_bytes.len() as u32` — code is bounded far below u32::MAX by protocol; add a `debug_assert!(code_bytes.len() <= u32::MAX as usize)`.

Seam note (see "Phase 2 roadmap"): `compute_root` is Seam B — Phase 2 swaps its internals for incremental maintenance. Keep its signature diff-free (`&self -> Result<H256, _>`) and don't let callers reach past it into `Entries`; the doc comment should state that the re-embed strategy is an implementation detail validated against the rebuild oracle.

**Step 4:** green — if the pre/post roots mismatch the fixture, debug against `state_pbt.py`'s `embed_flat_state` (leaf-by-leaf: dump our entries sorted and compare counts first — an entry-count mismatch localizes the bug to a key family). NEVER adjust fixture values.

**Step 5: Commit:** `feat(common): PbtState binary-trie root computation, spec-conformant`

---

## Task 5: Genesis integration

**Files:**
- Modify: `crates/common/types/genesis.rs` (`compute_state_root` `:813-821`)
- Modify: `crates/storage/error.rs` (`StoreError`), `crates/storage/store.rs` (`add_initial_state_inner` `:2571-2639`, new PbtState registry + accessors)
- Create: `fixtures/genesis/l1-binarytree.json`

**Step 1: Failing test** (in `genesis.rs` tests): construct a small `Genesis` whose config sets `enable_binary_tree_at_genesis: true` and 1-2 alloc accounts with balances `< 2^128`; assert `genesis.compute_state_root()` equals `PbtState::from_genesis_alloc(&alloc).compute_root().unwrap()` and differs from the MPT root of the same alloc. Model Genesis construction on the existing deserialize tests (`genesis.rs:909-1054`) or build the struct directly.

**Step 2:** red (compute_state_root has no branch). **Step 3: Implement:**

- `Genesis::compute_state_root` (`:813-821`): branch first —
  ```rust
  if self.config.enable_binary_tree_at_genesis {
      return PbtState::from_genesis_alloc(&self.alloc)
          .compute_root()
          .expect("genesis alloc must satisfy BinaryTree fork constraints (balances < 2^128)");
  }
  ```
  `compute_state_root` is infallible today (check the signature) — an `expect` with a constraint-stating message is acceptable for the experimental fork at genesis-construction time; a malformed test genesis should fail loudly.
- `StoreError`: add `#[error(transparent)] PbtState(#[from] PbtStateError)` (or equivalent — `crates/storage/error.rs:7-55`).
- Store registry: add to `Store`'s in-memory state (next to `chain_config`, `store.rs:188` area):
  ```rust
  pbt_states: Arc<Mutex<FxHashMap<BlockHash, Arc<PbtState>>>>,
  ```
  with `get_pbt_state(&self, block_hash) -> Option<Arc<PbtState>>` and `put_pbt_state(&self, block_hash, PbtState)`. Check how `Store` is constructed/cloned (it must be `Clone` — confirm) and initialize the map in every constructor path.
- `add_initial_state_inner` (`:2571-2639`): when `chain_config.enable_binary_tree_at_genesis`, build `PbtState::from_genesis_alloc(&genesis.alloc)` BEFORE `genesis.alloc` is moved into `setup_genesis_state_trie` (`:2627`), verify its root equals `genesis_block.header.state_root` (hard error, not debug_assert), and `put_pbt_state(genesis_hash, state)`.
- `put_pbt_state` must be `pub`: it doubles as the offline-seeding API for nodes that cannot replay from genesis (an external tool installs the snapshot replay would have produced, under the appropriate block hash). Document this on the method.
- Genesis fixture `fixtures/genesis/l1-binarytree.json`: clone `fixtures/genesis/l1-bal.json`, add `"enableBinaryTreeAtGenesis": true` to its config, and audit alloc balances: any account with balance ≥ 2^128 must be reduced below the cap (l1 fixtures often use huge test balances — check and adjust; note changed balances in the commit message).

**Step 4:** green: `cargo test -p ethrex-common`, `cargo test -p ethrex-storage` (or wherever store unit tests run — check), plus a store-level test: `Store::new(in-memory) + add_initial_state(l1-binarytree genesis)` succeeds and `get_pbt_state(genesis_hash)` is `Some` with root == header state_root. Model on `store.rs:2058`'s existing test.

**Step 5: Commit:** `feat(binary-tree-fork): genesis state root through the binary trie`

---

## Task 6: Block import and payload building

**Files:**
- Modify: `crates/blockchain/blockchain.rs` (`store_block` `:2163-2184` + its callers `add_block` `:2186-2221`, `add_block_pipeline_inner` `:2272-2390`, witness path `:1782`; `add_blocks_in_batch` internals `:2789-2801`)
- Modify: `crates/blockchain/payload.rs` (`finalize_payload` `:979-992`)

This is the riskiest task — read each call site fully before editing.

**Step 1: Failing test** — end-to-end, in `test/tests/blockchain/binary_tree_tests.rs` (register in `test/tests/blockchain/mod.rs`). Model directly on `test/tests/blockchain/batch_tests.rs` (`setup_store` `:37-66`, `build_block` `:70-88`):

```rust
// Test 1: build + import a chain of 3 blocks under BinaryTree-at-genesis.
//   - setup_store variant loading fixtures/genesis/l1-binarytree.json
//   - build each payload via blockchain.build_payload (this exercises
//     finalize_payload's binary root), import via blockchain.add_block
//     (exercises store_block validation)
//   - after each import: store.get_pbt_state(block_hash) is Some, and
//     block.header.state_root == that state's compute_root()
//   - include at least one value-transfer tx so state actually changes.
// Test 2: corrupted root is rejected — take a valid built block, flip a
//   byte in header.state_root, assert add_block returns
//   ChainError::InvalidBlock(StateRootMismatch-ish) (match on the actual
//   error shape).
// Test 3: batch import under the fork — add_blocks_in_batch over the same
//   3 blocks must ALSO work (via the per-block fallback added below).
```

**Step 2:** red — under the fork the built payload's header carries the MPT root today, so even Test 1 fails at validation (or produces an MPT-root header — assert catches it).

**Step 3: Implement:**

1. **Thread `&[AccountUpdate]` into `store_block`.** Change `Blockchain::store_block(&self, block, account_updates_list, execution_result)` to also take `account_updates: &[AccountUpdate]`. Update the three callers — each already has the updates in scope (`add_block` computes them at `:2192`; for `add_block_pipeline_inner` and the witness path `:1782`, FIND where the update vec lives in those flows and pass it through; if a caller genuinely lacks them, stop and reassess rather than reconstructing them).
2. **Branch in `store_block`** (`:2170` area), where `block`, chain config, and now updates are all in scope:
   ```rust
   let cfg = self.storage.get_chain_config();
   if cfg.enable_binary_tree_at_genesis {
       // Every block extends the parent's snapshot (genesis snapshot
       // seeded at add_initial_state).
       let parent = self.storage.get_pbt_state(block.header.parent_hash)
           .ok_or_else(|| ChainError::Custom(
               "missing PbtState for parent (experimental BinaryTree fork, \
                in-memory only) — restart requires re-import from genesis, \
                or seed a snapshot via put_pbt_state".into()))?;
       let mut state = (*parent).clone();
       state.apply_account_updates(account_updates);
       let root = state.compute_root().map_err(/* -> ChainError */)?;
       validate_state_root(&block.header, root)?;
       self.storage.put_pbt_state(block.hash(), state);
       // fall through: persist MPT updates as usual, but the header
       // comparison above replaces the MPT-root check
   } else {
       validate_state_root(&block.header, account_updates_list.state_trie_hash)?;
   }
   ```
   Read the existing body first — the comparison may be phrased differently; preserve all other behavior (receipts, canonicality, etc.). Check the exact error conversion for `PbtStateError` → `ChainError` (add a variant or use an existing wrapping — look at how `StoreError` maps at `:2183`).
3. **Batch path** (`add_blocks_in_batch`, `:2789-2801`): the batch merkleizes once for the whole range, which cannot produce per-block snapshots. At the top of the batch method (chain config is local at `:2756`): if `chain_config.enable_binary_tree_at_genesis` (every block needs a per-block snapshot), fall back to importing sequentially via `self.add_block(...)` per block and return. Keep it blunt and documented — the fork is experimental.
4. **Payload building** (`finalize_payload`, `payload.rs:979-992`): after `state_trie_hash` is set, branch on `context.chain_config().enable_binary_tree_at_genesis` (check the accessor name at `:962-968`): fetch the parent PbtState (missing → error with the same message as import — extract the fetch-or-error into a small shared helper on `Blockchain` or `Store` rather than duplicating it). Then clone, apply the payload's account updates (find where the update vec is in `PayloadBuildContext` — the merkleization at `:987` consumed it, so it's in scope), `compute_root`, and set `context.payload.header.state_root` to it. (The built block's snapshot is NOT stored here — it's written when the block comes back through store_block on import.)

**Step 4:** green — all three tests. Also re-run the whole existing blockchain test suite (`cargo test -p ethrex-blockchain` and `cd test && cargo test blockchain` — check the actual invocation in `test/`'s CI or Makefile) to prove non-fork paths are untouched.

**Step 5: Commit:** `feat(binary-tree-fork): block import and payload building commit via binary trie`

---

## Task 7: End-to-end polish tests + failure-mode coverage

**Files:**
- Modify: `test/tests/blockchain/binary_tree_tests.rs`

Add the failure/edge cases (each a bite-sized test):
1. **Restart simulation**: import blocks 1-2 under fork-at-genesis, drop and recreate the `Blockchain` over a FRESH store initialized from the same genesis (genesis snapshot present, block-1/2 snapshots gone), try importing block 3 → expect the "missing PbtState for parent" error. Then **seed recovery**: `put_pbt_state(block2_hash, <snapshot captured from the first run>)` and import block 3 successfully — proving a seeded snapshot is indistinguishable from a replayed one.
2. **Storage-zeroing block**: a tx that sets a previously non-zero slot to zero (contract with SSTORE(k,0) — reuse whatever contract-deploy helper the existing blockchain tests use, or pre-seed the slot via genesis alloc storage) → root validates, `get_pbt_state(hash)` shows the slot gone.
3. **MPT unaffected off-fork**: import the same tx-chain against the plain `l1-bal.json` genesis and assert behavior identical to before (guards the threading changes in store_block/payload didn't disturb the default path) — if Test 4/existing suites already cover this, note it and skip.
4. **Balance-cap surfacing**: unit-level is enough — a `PbtState` with balance `2^128` fails `compute_root` with `BinaryTrieError::BalanceTooLarge` wrapped in `PbtStateError` (may already exist from Task 4; if so skip with a note).

Run the full relevant suites; commit: `test(binary-tree-fork): failure-mode and edge coverage`

---

## Task 8: Docs, lint, wrap-up

**Files:**
- Modify: `crates/common/binary-trie/README.md` (the "non-goals" section: state-commitment integration now EXISTS behind `enableBinaryTreeAtGenesis`; update pointers)
- Create/verify nothing else pending.

1. README updates: crate README's non-goals now link to the integration (fork name, `PbtState` location, in-memory/experimental caveats). Keep honest: persistence, witness path, sync, proofs still out.
2. Full verification: `cargo fmt --check` (workspace or per touched crate per repo convention), `cargo clippy -p ethrex-common -p ethrex-storage -p ethrex-blockchain -p ethrex-binary-trie --all-targets -- -D warnings` (plus the repo's `make lint` if practical — it runs release clippy over l1+l2), `cargo test -p ethrex-common -p ethrex-storage -p ethrex-blockchain -p ethrex-binary-trie`, `cd test && cargo test` (or the repo's canonical integration-test invocation), `cargo check --workspace`.
3. Commit: `docs(binary-tree-fork): README and doc updates for state commitment integration`

---

## Out of scope (deliberately, again)

- Witness/guest (`GuestProgramState`) and zkVM: the binary root is not computed statelessly; `Crypto`-trait blake3 deferred with it.
- Snap sync, eth_getProof, and any real-network scheduling.
- EEST fixture consumption (`BinaryTree` fork fills) — its own follow-up once spec-side fills exist; the tooling maps the fixture fork name to "latest schedule + enableBinaryTreeAtGenesis".
- The snapshot export/seeding TOOL itself: this plan only provides the seeding seam (`put_pbt_state`, exercised by the restart-recovery test with a captured snapshot).
- Persistence of `PbtState` (survives neither restart nor pruning), snapshot pruning (memory is O(blocks x state) — keep-last-N is the obvious follow-up for long-lived devnets), incremental root maintenance (the `BinaryTrie` insert path exists but deletion/caching don't — re-embed is the spec-faithful cut), and a persisted preimage/flat-address table (would let restarted or snap-synced nodes materialize the shadow state without genesis replay). All of these are pure speed/robustness upgrades: none may change committed roots. **See "Phase 2 roadmap" below for how each one slots into the architecture — Phase 1's job is to leave those seams clean.**

---

## Phase 2 roadmap: how "make it better" fits the architecture

Not tasks — design context. Phase 1 deliberately hides everything behind **two seams**, and every Phase 2 upgrade swaps internals behind one of them without moving a single call site:

- **Seam A — the snapshot registry**: `Store::{get_pbt_state, put_pbt_state}` (+ the shared fetch-or-error helper from Task 6). Everything about *where state lives and how long* is behind this.
- **Seam B — root computation**: `PbtState::compute_root()`. Everything about *how the root is obtained* is behind this.

The non-negotiable invariant for every upgrade: **committed roots are bit-identical before and after.** The enforcement tooling already exists — the Task 2/4 spec vectors pin absolute roots, and `trie::rebuild::rebuild_root` stays permanently as the differential oracle (any optimized path must agree with a from-scratch re-embed; extend the crate's differential test to cover each new path as it lands).

**Upgrade 1 — snapshot pruning (Seam A, trivial).** Keep-last-N canonical snapshots plus any snapshot still reachable by a live fork tip; evict the rest inside the registry. Callers never know. Only design point: eviction must never drop the latest canonical snapshot (that's the restart-recovery seed once Upgrade 2 lands). Do this first — it's an afternoon and makes long-lived devnets viable.

**Upgrade 2 — persist the flat state (Seam A).** Replace per-block full clones with the normalized form: backend tables for the *current* flat state (`PBT_ACCOUNTS`: address -> nonce/balance/code_hash; `PBT_STORAGE`: address ‖ slot -> value; code already lives in `ACCOUNT_CODES`) plus a small per-block **undo log** (the inverse of each block's diff) for reorg rewind — the same current-state+undo pattern ethrex's flat KV layers use. This is also *the* preimage table: the flat tables are keyed by real addresses/slots, so a restarted node materializes the shadow state by reading them instead of replaying from genesis, and an exported copy of these tables IS the offline-seeding artifact for snap-style joins. `get_pbt_state(hash)` becomes "current tables rewound/advanced to `hash`" for recent blocks. Solves restarts and memory in one move.

**Transition machinery — mid-chain activation via shadow tracking (its own phase; consensus-visible, unlike the numbered upgrades). STATUS: DONE except mainnet scale** — shipped on `kw/bin-trie-integration` per `docs/plans/2026-07-26-binary-tree-transition.md` (see "As-built: the binaryTreeTime transition" below); the persistence/seed-artifact story for real networks still rides on Upgrade 2 — unchanged. One divergence from the paragraph below: NO `Fork::BinaryTree` variant was added (rationale in the as-built section). Historical design text follows. This is where the real `Fork::BinaryTree` variant and `binaryTreeTime` config field land (timestamp activation is what fork variants are for; the full enum-plumbing map is in the appendix below) and the boolean flag is subsumed. The design is settled, deferred only for scoping: when `binaryTreeTime` is scheduled later than genesis, the node maintains `PbtState` from genesis anyway — alloc seed, per-block update application, NO root computation — and from the first block with `timestamp >= binaryTreeTime` the header commitment flips to the shadow state's root. Full-state commitment at any activation point, derivable from block history by any full-syncing node, spec-conformant, with genesis activation as the degenerate case (meaning Phase 1's code is a strict subset — the change is removing the genesis-only guard, running the snapshot loop pre-activation without validation, and adding boundary tests). Two things it must respect: carry-over is **consensus data** (all nodes shadow-track by rule; an empty-start overlay variant would be a different consensus rule, deliberately not built), and it sequences best AFTER Upgrade 2 — persisted flat tables make transition seeds for non-replaying nodes self-serve instead of hand-built artifacts.

**Upgrade 3 — incremental root maintenance (Seam B).** Stop re-embedding the world per block. Prerequisites in `ethrex-binary-trie` (all flagged in that crate's docs): deletion in `BinaryTrie`, hash caching with dirty-path recomputation (the reviewer-recommended `&mut Node` insert rewrite lands here), and `TrieDB`-backed node storage for persistence. Then `compute_root` changes shape: the embedding layer maps each block's `AccountUpdate` diff to **tree-key-level operations** (inserts/updates/deletes of embedded keys — deletion of an account expands to its header-stem keys, its storage-zone keys, and reference-counted or rechecked overflow code chunks: the one semantic sharp edge, since content-addressed chunks are shared across accounts; the re-embed oracle is what keeps this honest), applied to a retained per-head trie. Per-block cost drops from O(state) to O(touched keys x depth). This is the point where the experimental fork could actually track a busy chain.

**Upgrade 4 — stateless/witness + `Crypto`-trait blake3.** Once roots are incrementally maintained over a node store, the witness path can carry binary-trie nodes, `GuestProgramState` gets the PBT branch, and blake3 moves behind `crates/common/crypto/provider.rs` so zkVM guests substitute accelerated implementations. Depends on Upgrade 3's node store and on EIP-8297's proof format settling — last in line by design.

**Ordering rationale**: 1 and 2 are robustness (devnets survive time and restarts) and touch only Seam A; transition machinery slots in after 2, when its seeding story is self-serve; 3 is the big perf jump behind Seam B with the oracle as a safety net; 4 rides on 3. Among the numbered upgrades no consumer above the seams changes and no root may move; transition is the one deliberate exception — it extends *which chains are expressible*, not what any existing chain commits to.

---

## Appendix: `Fork::BinaryTree` enum plumbing (deferred to the transition phase)

Fully mapped during planning (line refs from `bad1f85c`); kept here so the transition phase starts from a checklist instead of re-exploration. Adding `BinaryTree = 27` after `Hegota = 26` in `crates/common/types/genesis.rs` touches:

- Enum `:313-344` (`#[repr(u8)]`, `PartialOrd`-by-discriminant — ordering gates like `fork >= Fork::X` stay correct).
- `impl From<Fork> for &str` `:346-378` — exhaustive, compile error until the arm is added.
- `ChainConfig`: `binary_tree_time: Option<u64>` next to `hegota_time` `:277-283`; camelCase serde.
- `is_binary_tree_activated` predicate next to `:381-383`.
- Ordering lists: `display_config` `:443-451`; `get_fork` chain `:469-495` (new fork checked FIRST); `get_fork_blob_schedule` `:497-543` (inherit `blob_schedule.amsterdam`, mirror Hegota `:500-504`); `next_fork` array `:558-570` (comment mandates every timestamp fork present); `get_last_scheduled_fork` `:582-606`; `get_activation_timestamp_for_fork` `:608-635` (silent `_ => None` — don't rely on it); `get_blob_schedule_for_fork` `:637-653`; `gather_forks` `:685-701` (**ForkId input** — unscheduled `None` is dropped and changes nothing; once scheduled it MUST be listed or peers reject the fork hash).
- Discriminant-ordering tests modeled on `test_hegota_after_amsterdam` `:1275-1327`.
- Outside `genesis.rs`: `tooling/ef_tests/state/runner/revm_runner.rs:688-718` `fork_to_spec_id` (exhaustive — add `=> SpecId::OSAKA`); the exact-JSON ChainConfig assertion in `crates/networking/rpc/rpc.rs:1813` gains `"binaryTreeTime": null`; string→fork maps worth extending: `tooling/ef_tests/engine/src/fixture.rs:245-268,315`, `tooling/ef_tests/state/deserialize.rs:309-325`; `tooling/ef_tests/blockchain/fork.rs:167-168` has its own separate Hive fork enum.
- Non-breaking `Fork::Hegota` ordering gates that automatically extend (verify only): `crates/vm/system_contracts.rs:113`, `crates/vm/backends/mod.rs:193`, `crates/vm/backends/levm/mod.rs:3508`, `crates/vm/levm/src/opcodes.rs:427,434,657`, `crates/blockchain/blockchain.rs:3247`, `crates/blockchain/payload.rs:726`, `crates/vm/levm/src/vm.rs:138-142`.
- Migration note: when the variant lands, `enable_binary_tree_at_genesis: true` becomes sugar for (or is replaced by) `binaryTreeTime: <= genesis.timestamp`; experimental genesis fixtures updated in the same change.

---

## Implementation notes (as-built)

Recorded at the end of Task 8 (branch `kw/bin-trie-integration`). The plan
above is history; this section records what actually shipped, where it
diverged, and the known limitations.

**Update (2026-07-26): `enableBinaryTreeAtGenesis` removed.** The boolean
was consolidated away; `binaryTreeTime` is the single activation field, and
genesis activation is spelled as a time at or before the genesis timestamp
(canonically `binaryTreeTime: 0` — `fixtures/genesis/l1-binarytree.json`
now says exactly that). The CLI sugar `--experimental.binary-tree` sets
`binaryTreeTime = genesis.timestamp`. Mentions of the flag below are
historical.

**Shipped.** Genesis seeding, block import (single, batch-via-fallback, and
pipeline paths) and payload building all commit and validate binary-trie
(PBT) roots under `enable_binary_tree_at_genesis`; the MPT remains the
lookup structure. `Genesis::compute_state_root` returns the PBT root under
the flag; `Genesis::compute_mpt_state_root` exposes the flag-off
computation for the lookup side.

**Divergence: the `mpt_lookup_roots` side registry.** Unplanned. The plan
assumed the MPT could keep being addressed by `header.state_root`; under
the flag that field carries the PBT root, which addresses no MPT, so
headers can no longer name their own lookup structure. `Store` grew an
in-memory registry (`mpt_lookup_roots`, companion to `pbt_states`)
recording, per block hash, the MPT root the block's state is stored under,
resolved via `Store::mpt_state_root_for_header`. Every MPT consumer that
starts from a header routes through it (`state_trie`, `storage_trie`,
`get_storage_at`, ancestor iteration, the safe-commit gate
`compute_safe_commit_root`). Flag off, the helper returns
`header.state_root` untouched.

**Divergence: pipeline update collection.** `add_block_pipeline` only
accumulated raw account updates when building witnesses. Under the flag
the merkleizer must always accumulate them (the snapshot extension needs
the per-block diff), so the condition generalized to
`collect_updates = collect_witness || enable_binary_tree_at_genesis`
(`crates/blockchain/blockchain.rs`). Flag off this is behaviorally
identical to the old `collect_witness`.

**Limitation LIFTED: engine API SYNCING degradation.** The FCU/newPayload/
startup reachability probes used to feed `header.state_root` straight into
`has_state_root`, which no MPT layer ever matches under the flag, so a
flag-on node answered every FCU with SYNCING and `--dev` died at startup
("Unknown state found in DB"). They now resolve through the registry via
`Store::has_reconstructible_state(&BlockHeader)` (built on
`mpt_state_root_for_header_opt`; a missing registry entry counts as
"state not reconstructible", same as a missing root, never an error).
Converted probes: `regenerate_head_state` (cmd/ethrex/initializers.rs),
FCU (`crates/blockchain/fork_choice.rs`), the newPayload parent-state
SYNCING guard (`crates/networking/rpc/engine/payload.rs`), the
`eth_syncing` head probe (`rpc/eth/client.rs`), all four full-sync
resume-point/parent probes (`crates/networking/p2p/sync/full.rs`), the
tracing parent-walk (`crates/blockchain/tracing.rs:279` — tracing
re-execution now resolves under the flag instead of erroring out at the
re-exec cap), and the L2 committer walk-back
(`crates/l2/sequencer/l1_committer.rs`, flag-off identical). Flag off,
the helper returns `has_state_root(header.state_root)` bit-identically.
A `--dev` devnet on `fixtures/genesis/l1-binarytree.json` now boots and
produces blocks end-to-end through the engine API (this also required
teaching the dev block producer FCUv4/getPayloadV6 for Amsterdam — a
fork-version gap independent of the flag; the unflagged Amsterdam twin
fixture failed identically).

**Limitation LIFTED: `eth_getProof`.** Under the flag the method now
serves per-tree-key binary-trie proofs (experimental `pbt-getproof-v1`
shape) generated from the block's `PbtState` snapshot via the Seam B
API `PbtState::build_trie` and verifiable statelessly with
`ethrex_binary_trie::trie::verify_proof`. See
`docs/eip-draft-pbt-eth-getproof.md` (format) and
`docs/binary-trie-getproof-investigation.md` (design record). Blocks
whose in-memory snapshot is gone (restart, future pruning) error
clearly rather than proving against the wrong trie; flag-off the MPT
proof path is untouched.

**Limitation: in-memory registries.** Both registries (`pbt_states`,
`mpt_lookup_roots`) are in-memory only:

- Lost on restart. The rocksdb restart test
  (`binary_tree_restart_loses_registries_and_replay_recovers`) documents
  the recovery contract: reopening the datadir re-seeds the GENESIS
  entries automatically (`add_initial_state`'s matching-genesis path
  re-derives them from the genesis file), and everything past genesis is
  recovered by replaying blocks from genesis; `put_pbt_state` /
  `put_mpt_lookup_root` remain the offline-seeding seam for nodes that
  cannot replay. The skip-validation boot path seeds nothing (its alloc
  does not describe the stored state) and requires offline seeding.
- Never evicted: memory is O(blocks x state). Acceptable for short-lived
  experimental devnets only; keep-last-N pruning is the first Phase 2
  upgrade (Seam A).

**Harness discovery: EIP-8037 state gas.** The fixture is Amsterdam at
genesis, so transactions pay EIP-8037 state gas on top of execution gas
(e.g. `STATE_BYTES_PER_NEW_ACCOUNT (120) * cost_per_state_byte (1530) =
183_600` for a transfer that materializes a new account, spilled from the
tx gas limit). A 100k gas limit made every transfer fail-in-block; the
binary-tree tests use `TEST_GAS_LIMIT = 400_000`
(`test/tests/blockchain/binary_tree_tests.rs`).

**Phase 2.** The roadmap above ("Phase 2 roadmap") is unchanged by any of
this: all upgrades still slot in behind Seam A (the snapshot registry) and
Seam B (`PbtState::compute_root`), with bit-identical committed roots as
the invariant.

---

## As-built: the `binaryTreeTime` transition (2026-07-26)

The transition machinery from the roadmap above shipped
(`docs/plans/2026-07-26-binary-tree-transition.md` is the plan; this
section is the record). Verified live on a merged-from-genesis kurtosis
devnet — see "Fast devnet" below.

**Shipped semantics.** `binaryTreeTime` (camelCase in genesis JSON) is
the SINGLE activation field — the `enableBinaryTreeAtGenesis` boolean
was consolidated away in the same series (a time at or before the
genesis timestamp, canonically `binaryTreeTime: 0`, is the
genesis-activation spelling; the CLI sugar `--experimental.binary-tree`
sets it to the genesis timestamp). Two predicates on `ChainConfig`
carry the whole rule:

- `binary_tree_scheduled()` — the field is set. Scheduled nodes
  shadow-track `PbtState` from genesis: snapshot seeding at genesis,
  per-block clone/apply/store, `mpt_lookup_roots` registration — the
  identical loop genesis-activation runs, just without header
  commitment or validation.
- `is_binary_tree_active(ts)` — `binary_tree_time <= ts`. From the
  first block at/after the time, `header.state_root` commits the shadow
  state's PBT root (validated on import, produced by payload building)
  and `eth_getProof` serves `pbt-getproof-v1`. Carry-over is the
  consensus rule: the first active block commits the FULL state, not an
  empty-start overlay.

`--experimental.binary-tree-delay <seconds>` injects
`binaryTreeTime = genesis.timestamp + delay` after genesis load — a
relative delay (not an absolute time) is what a kurtosis yaml can
express before genesis exists; every node given the same genesis and
delay derives the same schedule. The scheduled time joins `gather_forks`
(the `verkle_time` pattern), so it is part of the fork id: mismatched
delays split at the flip, by design.

**Per-header MPT resolution rule** (the key correctness subtlety):
`mpt_state_root_for_header_opt` resolves through the
`mpt_lookup_roots` registry ONLY when
`is_binary_tree_active(header.timestamp)`; pre-activation headers
return `header.state_root` directly — those roots genuinely ARE MPT
roots. Consequences: pre-flip blocks stay readable across restarts
without any replay, `eth_getProof` on pre-flip targets takes the
untouched legacy MPT path, and an unscheduled chain is bit-identical
to before the feature existed.

**No `Fork::BinaryTree` enum variant (deliberate divergence from the
roadmap text above).** The commitment flip is orthogonal to EVM
semantics. A variant ordered after `Hegota` would make `get_fork()`
report "BinaryTree" for post-flip blocks on (say) a Fulu-era chain,
dragging wrong blob-schedule fallbacks and fork reporting along, and
would re-couple exactly what Phase 1 decoupled. `binary_tree_time` is
a standalone scheduled timestamp on `ChainConfig` — the exact
`verkle_time` precedent. The enum appendix above stays parked for the
day EEST fixture consumption needs a *named* fork (a tooling-level
mapping anyway).

**Restart contract, sharpened.** The registries are still in-memory
(see "Limitation: in-memory registries"), and for a scheduled chain
the recovery story has a hard edge: replay-from-genesis recovery
requires re-executing every block, which requires the pre-flip MPT
state still being addressable — but once a scheduled chain flushes
past `DB_COMMIT_THRESHOLD`, replay-from-genesis recovery is
impossible and only offline seeding (`put_pbt_state` /
`put_mpt_lookup_root`) remains. Short-lived devnets restart fine;
anything long-lived needs the Upgrade 2 persistence story.
Additionally, `--experimental.binary-tree-delay` is not persisted or
genesis-hash-enforced: every boot must re-supply the identical delay
(kurtosis `el_extra_params` does this naturally), or the node reopens
unscheduled and fails loudly at the first post-flip block.

**Transition modes — scope boundary.** Three distinct meanings of
"transition", with different status:
1. **Commitment flip over dual-tracked state (SHIPPED):** shadow
   tracking accumulates the flat state from genesis, so the flip block
   commits the full state with no conversion event. Requires the node
   to have processed the chain from genesis (devnets, full sync).
2. **Offline conversion/seeding (SEAMED, tool pending):** for nodes
   that cannot replay, `put_pbt_state`/`put_mpt_lookup_root` accept an
   externally materialized flat state (exercised by the restart
   recovery tests); Phase 2 Upgrade 2's persisted flat tables become
   the exportable artifact. The conversion tool itself is not built.
3. **In-protocol gradual conversion (NOT DESIGNED — upstream gap):**
   the mainnet-credible mechanism (cf. verkle's EIP-7748: bounded
   per-block conversion batches as consensus, dual-tree reads) is
   unspecified by EIP-7864/8297 and absent from EELS. Deliberately not
   built ahead of the EIP. Compatibility note: any future conversion
   mechanism's correctness target is already pinned here — the
   converted state's root must equal what shadow tracking would have
   computed (`PbtState::compute_root`, spec-conformance-locked), so
   this implementation doubles as the oracle for that future work.

Corollary guard: `--syncmode snap` (the L1 default) is refused at
startup on any scheduled chain (`validate_sync_mode` in
`cmd/ethrex/initializers.rs`, after the CLI overrides finalize the
schedule) — snap sync is MPT-shaped, and a post-flip pivot root
addresses no MPT; the error names the fix (`--syncmode full`) rather
than silently switching modes. Lifted when PBT snap sync (planned
separately) lands. Consequence: every scheduled-chain launch config
must pin the mode — both devnet yamls now carry `--syncmode=full` in
`el_extra_params` (the prior verified run predated the guard and
never exercised syncmode).

**Fast devnet — the payoff.**
`fixtures/networks/binary-tree-devnet-fast.yaml` is a
merged-from-genesis config (package defaults: altair..fulu all at
epoch 0 — verified at the pinned ethereum-package revision; no fork
ladder, no TTD games, stock lighthouse v8.1.3) with
`--experimental.binary-tree-delay=30` as the only activation input.
The generator's embedded MPT genesis hash is CORRECT because genesis
genuinely is MPT-committed; the flip happens ~30s in. Contrast
`binary-tree-devnet.yaml` (genesis activation), which needs the
pre-merge TTD ladder precisely because its genesis hash differs from
the generator's — that config stays for genesis-activation testing.
Measured on the verification run (3x ethrex + lighthouse, 3s slots):
first block ~26s after enclave-up (vs ~8 minutes of fork ladder on
the slow variant); flip landed at block 10 (timestamp == genesis+30
exactly); state roots identical across all 3 nodes at every height
through and past the boundary; `eth_getProof` flipped shape at the
boundary (legacy MPT at block 9, `pbt-getproof-v1` at block 10) and
a live post-flip proof verified OFFLINE against the block-10 header
root via the `verify_live_proof` example; a post-flip EIP-1559
transfer mined with identical reads on all nodes; zero invalid
fork-choice lines in EL logs.

**Re-verification with the snap guard + restart catch-up
(2026-07-26, image `575eb1c8`).** Same fast config re-run after the
snap-sync startup guard landed (`ce75e8b1`) and the scheduled devnet
yamls pinned `--syncmode=full` (`575eb1c8`). All prior checks
reproduced: flip at block 10 exactly, state roots identical across
all 3 nodes at six sampled heights spanning the boundary, getProof
shape flip (legacy at 9, `pbt-getproof-v1` post-flip), post-flip
transfer mined with an agreed receipt (gas limit 500k, over the
EIP-8037 floor); the guard stayed silent on every node (validating
the yaml pin) and each EL logged the `BinaryTree: @<flip-ts>`
schedule. New coverage — the restart contract, live: one EL stopped
at post-flip height 36, survivors advanced 22 blocks, restart
re-supplied the delay flag via kurtosis, the node logged the
schedule WARN again, replayed blocks 0-37 in ~150ms (in-memory
registries re-derived), then full-synced to head in 12s with exact
root parity at the flip block, the stop height, and head; zero
panic/"Unknown state"/invalid-fork-choice/ERROR lines post-restart.
