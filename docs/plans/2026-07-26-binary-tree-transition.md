# Binary Tree Transition (`binaryTreeTime` + Shadow Tracking) Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Update (2026-07-26): `enableBinaryTreeAtGenesis` removed post-planning.**
In a user-approved consolidation after this plan was written, the boolean
config field was removed; `binaryTreeTime` is the single activation field,
with a time at or before the genesis timestamp (canonically
`binaryTreeTime: 0`) as the genesis-activation spelling. The two-field
predicate definitions and bool mentions in the plan text below are
historical.

**Goal:** Mid-chain activation of the EIP-8297 binary-tree commitment: a `binaryTreeTime` timestamp in the chain config schedules the flip, nodes shadow-track `PbtState` from genesis, and the first block at/after the timestamp commits the *full* state to the PBT — making merged-from-genesis (Fulu-at-epoch-0) devnets work with a stock genesis generator.

**Architecture:** Shadow carry-over as the consensus rule, exactly as designed in the Phase 2 roadmap of `docs/plans/2026-07-25-binary-trie-state-commitment.md`: when the commitment is *scheduled*, every node maintains the `PbtState` snapshot chain from genesis (the identical clone/apply/store loop `store_block` already runs when flagged — no new machinery), and once *active* it additionally computes/validates PBT roots in headers. Genesis-activation (`enableBinaryTreeAtGenesis`) remains as the degenerate case and stays fully supported. Pre-activation blocks keep MPT roots in headers and stay addressable WITHOUT registries (restart-friendly); post-activation headers resolve the MPT through the existing lookup-root registry.

**Design decision — NO `Fork::BinaryTree` enum variant (divergence from the earlier roadmap note, deliberate):** the commitment flip is orthogonal to EVM semantics. Adding a variant ordered after `Hegota` would make `get_fork()` report "BinaryTree" for post-flip blocks on (say) a Fulu-era chain, dragging wrong blob-schedule fallbacks and fork reporting with it, and would re-couple exactly what Phase 1 deliberately decoupled. `binary_tree_time` is instead a standalone scheduled timestamp on `ChainConfig` — the exact `verkle_time` precedent (`genesis.rs`: field + `display_config` row + `gather_forks` entry, no enum variant). The plan's fork-enum appendix stays parked for the day EEST fixture consumption genuinely needs a *named* fork, which is a tooling-level mapping anyway.

**Tech Stack:** everything already on `kw/bin-trie-integration` (HEAD `af69a480`): `PbtState`, the snapshot + `mpt_lookup_roots` registries, `extended_pbt_state`, the flagged RPC/getProof paths, the kurtosis devnet config, and the binary-tree test suites.

**Constraints settled up front:**
- **Consensus rule:** `scheduled ⇒ shadow-track from genesis; active(block.timestamp) ⇒ header commits the shadow state's root.` Carry-over is the only rule; empty-start is not built.
- **Predicates** (the load-bearing definitions — everything branches through these two):
  - `binary_tree_scheduled()` = `enable_binary_tree_at_genesis || binary_tree_time.is_some()`
  - `is_binary_tree_active(ts)` = `enable_binary_tree_at_genesis || binary_tree_time.is_some_and(|t| t <= ts)`
  Setting BOTH the bool and a time is rejected at genesis load (ambiguous intent — the bool means "active from genesis," which a time contradicts unless equal; keep it simple: hard error).
- **MPT addressability rule (per-header, not per-chain):** `mpt_state_root_for_header*` resolves through the registry ONLY when `is_binary_tree_active(header.timestamp)`; pre-activation headers return `header.state_root` directly. This keeps pre-flip blocks readable across restarts without replay and is the key correctness subtlety of this plan.
- **CLI injection is a DELAY, not an absolute time:** `--experimental.binary-tree-delay <seconds>` sets `binary_tree_time = genesis.timestamp + delay` after genesis load. An absolute timestamp is unusable in kurtosis configs (genesis time isn't known when the yaml is written); a delay is identical on every node given the shared genesis. Mutually exclusive with `--experimental.binary-tree`.
- **ForkId:** `binary_tree_time` joins `gather_forks` (mirroring `verkle_time`) so scheduled networks advertise it; `None` is dropped, so unscheduled configs are unaffected.
- `eth_getProof` becomes per-block: binary handler when the TARGET block's header is active, legacy MPT path otherwise.

**Reference (symbols, not line numbers — the tree has moved since the exploration):** `ChainConfig`/`gather_forks`/`display_config` and `verkle_time` in `crates/common/types/genesis.rs`; `Genesis::compute_state_root` + `compute_mpt_state_root`; `Store::{add_initial_state_inner, seed_genesis_pbt_snapshot, mpt_state_root_for_header, mpt_state_root_for_header_opt, has_reconstructible_state, get/put_pbt_state, put_mpt_lookup_root}` in `crates/storage/store.rs`; `Blockchain::{store_block, extended_pbt_state, add_blocks_in_batch}` in `crates/blockchain/blockchain.rs`; `finalize_payload` in `crates/blockchain/payload.rs`; `GetProofRequest::handle`/`handle_binary_tree` in `crates/networking/rpc/eth/account.rs`; CLI flag + injection in `cmd/ethrex/cli.rs` / `cmd/ethrex/initializers.rs` (`init_store`); tests in `test/tests/blockchain/binary_tree_tests.rs`, `test/tests/rpc/fork_choice_tests.rs`.

---

## Task 1: `binary_tree_time` config field + unified predicates

**Files:**
- Modify: `crates/common/types/genesis.rs`
- Modify: `crates/networking/rpc/rpc.rs` (exact-JSON config test — run it, patch expected JSON only if it fails)

**Step 1 — failing tests** (next to `test_enable_binary_tree_at_genesis_flag`):

```rust
#[test]
fn binary_tree_time_schedules_and_activates() {
    let mut config = ChainConfig::default();
    assert!(!config.binary_tree_scheduled());
    assert!(!config.is_binary_tree_active(u64::MAX));

    config.binary_tree_time = Some(1000);
    assert!(config.binary_tree_scheduled());
    assert!(!config.is_binary_tree_active(999));
    assert!(config.is_binary_tree_active(1000));

    // bool implies both, regardless of timestamp
    let mut flagged = ChainConfig::default();
    flagged.enable_binary_tree_at_genesis = true;
    assert!(flagged.binary_tree_scheduled());
    assert!(flagged.is_binary_tree_active(0));
}

#[test]
fn binary_tree_time_serde_camel_case() {
    // model construction on the existing flag test's JSON pattern
    // (depositContractAddress is required)
    let parsed: ChainConfig = /* json with "binaryTreeTime": 1000 */;
    assert_eq!(parsed.binary_tree_time, Some(1000));
    // absent -> None
}

#[test]
fn binary_tree_time_joins_fork_id_when_scheduled() {
    // gather_forks: verify a scheduled binary_tree_time > genesis ts
    // appears in the fork-id inputs and None does not. Model on how
    // verkle_time is covered (check existing gather_forks tests; if
    // none exist for verkle_time, assert via ForkId::new equality/
    // inequality between scheduled and unscheduled configs).
}
```

**Step 2:** red (no field/methods).

**Step 3 — implement:**
- Field, directly below `enable_binary_tree_at_genesis`, mirroring `verkle_time`'s serde style (camelCase ⇒ `binaryTreeTime`):
  ```rust
  /// Experimental EIP-8297 commitment activation timestamp. From the
  /// first block with `timestamp >= binary_tree_time`, headers commit
  /// Partitioned-Binary-Tree state roots instead of MPT roots; nodes
  /// shadow-track the flat state from genesis so the flip commits the
  /// FULL state (consensus rule: carry-over, not empty-start). Not an
  /// EVM fork: deliberately NOT a `Fork` variant (commitment is
  /// orthogonal to execution semantics; cf. `verkle_time`).
  pub binary_tree_time: Option<u64>,
  ```
- The two predicates on `ChainConfig` as specified in the constraints (doc comments carrying the consensus rule).
- `display_config`: a row alongside the fork table or the verkle line — follow `verkle_time`'s placement.
- `gather_forks`: add `self.binary_tree_time` exactly where `verkle_time` sits.
- Migrate ALL existing `enable_binary_tree_at_genesis` call sites *outside* genesis.rs to the predicates in later tasks — in THIS task only add the API (grep now, list the sites in your report so Task 2 has the inventory: expect `store.rs`, `blockchain.rs`, `payload.rs`, `account.rs`, `initializers.rs`, plus tests).

**Step 4:** `cargo test -p ethrex-common` green; `cargo check --workspace`; run the RPC exact-JSON test and patch only on observed failure.

**Step 5:** Commit: `feat(config): binaryTreeTime scheduled activation for the EIP-8297 commitment`

---

## Task 2: Bool+time validation, scheduled-vs-active split in genesis + store + import + payload + RPC

This is the core task. Every branch that today asks "is the flag on?" must now ask the RIGHT one of two questions: *scheduled* (do I track?) or *active at this timestamp* (do I commit/validate/resolve-via-registry?). Work from Task 1's call-site inventory; the rules per site:

**Files:** `crates/common/types/genesis.rs`, `crates/storage/store.rs`, `crates/blockchain/blockchain.rs`, `crates/blockchain/payload.rs`, `crates/networking/rpc/eth/account.rs`.

**Step 1 — failing tests.** Two levels:

(a) Unit (genesis.rs): `Genesis::compute_state_root` uses PBT iff active AT GENESIS timestamp: a genesis with `binary_tree_time = genesis.timestamp + 100` must produce the MPT root (assert equals `compute_mpt_state_root()`), while `binary_tree_time <= timestamp` or the bool produce the PBT root. Plus: constructing/validating a config with BOTH bool and time set errors (decide the surfacing point: `Genesis::try_from`-adjacent validation or `add_initial_state` — pick where existing config validation lives, e.g. next to the blob-schedule warning, and note it in the report).

(b) Integration — the boundary test (new file `test/tests/blockchain/binary_tree_transition_tests.rs`, registered in mod.rs; model helpers on `binary_tree_tests.rs`, and reuse them via a shared module rather than copying — the reviewer flagged copy-drift there before):

```text
transition_boundary_commits_full_state:
  genesis: l1-bal.json-based, bool OFF, binary_tree_time = genesis_ts + N
  chosen so blocks 1..2 are pre-activation and block 3 is the first
  active block (compute N from the block-timestamp pattern the test
  harness produces — read build_block; timestamps are parent+1 slot).
  - blocks 1,2: headers carry MPT roots (assert equals the MPT root the
    store computes); snapshots EXIST for both (shadow tracking ran);
    get_pbt_state(hash).is_some().
  - block 3: header.state_root == snapshot.compute_root() AND != any
    MPT root; the snapshot contains a genesis-alloc account UNTOUCHED
    by blocks 1-3 (full-state carry-over — the whole point).
  - block 4: continues normally (extends block 3's snapshot).
  - payload building produced those headers (build via build_payload
    as the existing tests do — this exercises finalize_payload's
    active check with a pre-activation parent).
pre_activation_blocks_validate_mpt:
  corrupt an MPT header root on block 1 -> rejected; corrupt the PBT
  root on block 3 -> rejected (StateRootMismatch both).
pre_activation_headers_resolve_without_registry:
  after importing the chain, clear nothing — instead assert
  mpt_state_root_for_header_opt(block1.header) == Some(block1.header.state_root)
  (documents the per-header rule; the restart-flavored version is in Task 4).
```

**Step 2:** red — today the time field does nothing (blocks 1-2 would get PBT roots under `scheduled`… actually today `binary_tree_time` doesn't exist for these paths at all, so test (b) fails at genesis construction; record whatever red you get).

**Step 3 — implement, site by site:**
- `Genesis::compute_state_root`: branch on `config.is_binary_tree_active(self.timestamp)` (was: the bool).
- Bool+time conflict: hard error at the chosen validation point with a message naming both fields.
- `Store::add_initial_state_inner`: seed snapshot + genesis MPT lookup root when `binary_tree_scheduled()` (both fresh and reopen paths — the reseed helper's condition changes identically). The funnel-consistency root check runs only when active at genesis (pre-activation genesis headers hold MPT roots — the check would be comparing PBT root to MPT header, guaranteed mismatch).
- `Store::mpt_state_root_for_header_opt` (and thus `mpt_state_root_for_header` + `has_reconstructible_state`): the per-header rule — registry only when `is_binary_tree_active(header.timestamp)`; otherwise `Ok(Some(header.state_root))`. THIS is where flag-off equivalence and pre-activation restart-friendliness both live; the doc comment must state the per-header rule and why (pre-flip blocks stay addressable without replay).
- `Blockchain::store_block`: restructure to the two-level branch:
  ```rust
  if cfg.binary_tree_scheduled() {
      let (state, root) = self.extended_pbt_state(block.header.parent_hash, account_updates)?;
      if cfg.is_binary_tree_active(block.header.timestamp) {
          validate_state_root(&block.header, root)?;
      }
      self.storage.put_pbt_state(block.hash(), state)?;
      self.storage.put_mpt_lookup_root(block.hash(), account_updates_list.state_trie_hash)?;
  }
  if !cfg.is_binary_tree_active(block.header.timestamp) {
      validate_state_root(&block.header, account_updates_list.state_trie_hash)?;
  }
  ```
  (Note `extended_pbt_state` computes the root unconditionally — O(state) per pre-activation block. For devnet-scale that's accepted; IF you find it trivially avoidable — e.g. split the helper into extend vs root — do it, but do NOT contort the seam; note the choice either way.)
- `add_blocks_in_batch` fallback condition: `binary_tree_scheduled()`.
- `finalize_payload`: `is_binary_tree_active(payload timestamp)` for the header-root swap (parent snapshot fetch stays behind the same check — a pre-activation build needs nothing).
- `GetProofRequest::handle`: route to `handle_binary_tree` only when `is_binary_tree_active(target_header.timestamp)`; pre-activation blocks take the untouched MPT path (works because of the per-header resolution rule).
- Sweep the Task 1 inventory for any remaining raw bool uses; each must justify itself as genuinely genesis-only or convert.

**Step 4:** all suites green: `cargo test -p ethrex-common -p ethrex-storage -p ethrex-blockchain -p ethrex-rpc`, `cd test && cargo test --test ethrex_tests` (884 + new), rocksdb variant, `cargo check --workspace`, clippy `-D warnings` + fmt on touched crates. The existing binary-tree suite (bool path) must pass UNCHANGED — the degenerate case proves itself.

**Step 5:** Commit: `feat(binary-tree): scheduled activation via binaryTreeTime with shadow carry-over`

---

## Task 3: CLI `--experimental.binary-tree-delay`

**Files:** `cmd/ethrex/cli.rs`, `cmd/ethrex/initializers.rs`.

**Step 1 — failing test:** clap-level parse test if the repo has CLI parse tests (grep `Options::try_parse` usage in cmd/ethrex tests); otherwise TDD at the injection function level if `init_store`'s genesis mutation is testable — if neither is cheap, the devnet run in Task 5 is the system test; note which.

**Step 2/3 — implement:** mirror the existing flag exactly:
- `--experimental.binary-tree-delay <SECONDS>` (env `ETHREX_EXPERIMENTAL_BINARY_TREE_DELAY`), doc: sets `binaryTreeTime = genesis.timestamp + delay` on the loaded genesis; every node given the same genesis and delay derives the same activation; mutually exclusive with `--experimental.binary-tree` (use clap `conflicts_with`).
- Injection in `init_store` beside the existing one: mutate `genesis.config.binary_tree_time` BEFORE `display_chain_initialization`; same warn! style. Remember `impl Default for Options` (the E0063 lesson from last time).

**Step 4:** `cargo build --release --bin ethrex` (full binary — same lesson), crate tests, clippy/fmt.

**Step 5:** Commit: `feat(cli): --experimental.binary-tree-delay for scheduled PBT activation`

---

## Task 4: Failure-mode and restart tests

**Files:** `test/tests/blockchain/binary_tree_transition_tests.rs`.

Bite-sized additions, each red-first where meaningful:
1. **Restart across the boundary (rocksdb-gated, model on the existing restart test):** import blocks 1(pre)..3(active), capture states, shutdown, reopen same datadir. Assert: genesis registries reseeded (existing behavior, now under `scheduled`); pre-activation block 1 is READABLE without replay (`get_storage_at`/account reads through its MPT header root — the per-header rule's payoff); importing block 4 fails with the missing-snapshot error; replaying 1-3 re-derives identical registries; block 4 then imports.
2. **Boundary determinism:** replay the same chain on a fresh store; block 3's root identical (shadow carry-over is deterministic).
3. **Scheduled-but-never-active chain behaves observably like unscheduled** for headers/reads (snapshots exist but nothing consensus-visible differs): import a chain whose `binary_tree_time` is far future; assert headers/MPT reads/getProof all match a twin unscheduled chain.
4. **Conflict rejection:** genesis with bool AND time → the Task 2 error, surfaced through `add_initial_state` (or wherever Task 2 put it).

Run full suites incl. rocksdb. Commit: `test(binary-tree): transition boundary, restart, and conflict coverage`

---

## Task 5: Fast devnet config + live verification

**Files:**
- Create: `fixtures/networks/binary-tree-devnet-fast.yaml`
- Modify: `fixtures/networks/binary-tree-devnet.yaml` (pointer comment), `docs/plans/2026-07-25-binary-trie-state-commitment.md` (as-built note), README pointers.

**Step 1 — the config** (this is the payoff artifact):

```yaml
# EIP-8297 PBT devnet, FAST variant: merged-from-genesis (all forks at
# epoch 0 — a bone-stock generator config), with the commitment
# scheduled via --experimental.binary-tree-delay instead of a flagged
# genesis. The generator's embedded (MPT) genesis hash is CORRECT here
# because genesis genuinely is MPT-committed; the flip happens ~30s in
# and shadow tracking carries the full state across. No fork ladder,
# no TTD transition, no preset games — cf. binary-tree-devnet.yaml for
# why the genesis-flag variant needs all of those.
participants:
  - el_type: ethrex
    el_image: ethrex:local
    cl_type: lighthouse
    cl_image: sigp/lighthouse:v8.1.3
    validator_count: 32
    count: 3
    supernode: true
    el_extra_params:
      - "--experimental.binary-tree-delay=30"
      - "--http.api=eth,net,web3,debug,admin,txpool"
ethereum_metrics_exporter_enabled: true
network_params:
  seconds_per_slot: 3
additional_services:
  - dora
  - spamoor
spamoor_params:
  spammers:
    - scenario: eoatx
      config:
        throughput: 20
```

(No fork_epoch overrides at all — package defaults, which are all-at-genesis. Verify the package defaults still include fulu at 0 with this pin; adjust the comment if defaults changed.)

**Step 2 — system verification** (rebuild image first: `make build-image`):
- `kurtosis run` the fast config. Assert, scripted like the prior batteries:
  - EL blocks flow within ~1 minute of enclave-up (no ladder wait) — record time-to-first-block.
  - Find the boundary block (first with `timestamp >= genesis+30`): headers BEFORE it match MPT roots, AT/after it carry PBT roots (compare across all 3 nodes; roots agree at every sampled height).
  - A pre-boundary block's storage/account reads work over RPC; `eth_getProof` on a PRE-boundary block returns the legacy MPT shape, on a POST-boundary block returns `pbt-getproof-v1` — verify the latter offline with the `verify_live_proof` example (it takes the post-boundary header root).
  - A transfer submitted post-boundary mines and reads identically on all nodes.
- Tear the enclave down or leave per operator choice; record results in the report.

**Step 3 — docs:** as-built appendix gains the transition section (shipped semantics, per-header resolution rule, the no-enum-variant decision + rationale, fast-devnet story); the slow yaml gets a one-line pointer to the fast one; update the Phase 2 roadmap's transition entry to DONE-except-mainnet-scale (persistence/seed-artifact story still pending for real networks — unchanged).

**Step 4:** Commit(s): `feat(binary-tree): merged-genesis fast devnet via binary-tree-delay` + `docs(binary-tree): transition as-built notes`

---

## Task 6: Wrap-up

- Full verification: fmt, clippy `-D warnings` (all touched crates), all crate suites, integration default + rocksdb, `cargo check --workspace`. Note (don't run) `make lint` for CI.
- Update the memory file per session convention (transition shipped; fast devnet verified; enum variant deliberately still absent; mainnet-scale seeding still open).

---

## Out of scope (unchanged from the Phase 2 roadmap)

- Persistence of the registries / flat-state tables + the exportable seed artifact (mainnet-scale transition needs them; devnets replay from genesis).
- Snapshot pruning; incremental root maintenance (Seam B); witness/zkVM; snap sync.
- `Fork::BinaryTree` enum variant + EEST fixture consumption — parked until spec-side fills exist; the appendix checklist in the Phase 1 plan remains the map if/when a named fork is required.
