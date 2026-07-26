//! Boundary tests for the scheduled EIP-8297 binary-tree transition
//! (`ChainConfig::binary_tree_time`).
//!
//! Consensus rule under test: `scheduled ⇒ shadow-track from genesis;
//! active(block.timestamp) ⇒ header commits the shadow state's root`.
//! Blocks before the activation timestamp keep MPT roots in their headers
//! (and stay addressable WITHOUT the lookup registry), while shadow
//! tracking maintains the `PbtState` snapshot chain; the first block
//! at/after `binary_tree_time` commits the binary-trie root of the FULL
//! carried-over state (carry-over, not empty-start).

use bytes::Bytes;
use ethrex_blockchain::{
    Blockchain,
    error::{ChainError, InvalidBlockError},
};
use ethrex_common::{
    Address, H256, U256,
    types::{Block, Genesis, GenesisAccount},
};
use ethrex_l2_rpc::signer::{LocalSigner, Signer};
use ethrex_storage::Store;
// Only the rocksdb-gated restart test opens a store by engine type; the
// in-memory stores come from the shared helpers.
#[cfg(feature = "rocksdb")]
use ethrex_storage::EngineType;

use super::binary_tree_helpers::{
    assert_binary_snapshots, build_and_import_transfers, load_genesis_fixture, sender_from_key,
    setup_store_from_genesis, test_recipient, test_secret_key,
};
// Only the rocksdb-gated restart test builds a block by hand.
#[cfg(feature = "rocksdb")]
use super::binary_tree_helpers::{build_block, transfer_tx};

/// `build_block` stamps `parent.timestamp + 12` on every block, so with
/// activation at `genesis.timestamp + 36` blocks 1-2 (`+12`, `+24`) are
/// pre-activation and block 3 (`+36`, `timestamp == binary_tree_time`) is
/// the first active block.
const ACTIVATION_DELAY: u64 = 36;

/// Genesis-alloc account never touched by any transaction in these tests —
/// the carry-over witness: it can only appear in a post-flip snapshot if
/// shadow tracking carried the full genesis state across the boundary.
fn untouched_account() -> Address {
    Address::from_low_u64_be(0xCAFE)
}
const UNTOUCHED_BALANCE: u64 = 0xDEAD_BEEF;

/// `l1-bal.json` (no `binaryTreeTime` schedule) with the untouched
/// carry-over witness account injected into the alloc — the unscheduled base
/// every scheduled variant below derives from, so twin chains share the alloc.
fn unscheduled_genesis(sender: Address) -> Genesis {
    let genesis = load_genesis_fixture(
        "l1-bal.json",
        sender,
        &[(
            untouched_account(),
            GenesisAccount {
                balance: U256::from(UNTOUCHED_BALANCE),
                code: Bytes::new(),
                storage: Default::default(),
                nonce: 0,
            },
        )],
    );
    assert!(
        genesis.config.binary_tree_time.is_none(),
        "fixture must not schedule the binary tree — the scheduled variants derive from this unscheduled base"
    );
    genesis
}

/// [`unscheduled_genesis`] with `binary_tree_time = genesis.timestamp + delay`.
fn scheduled_genesis_with_delay(sender: Address, delay: u64) -> Genesis {
    let mut genesis = unscheduled_genesis(sender);
    genesis.config.binary_tree_time = Some(genesis.timestamp + delay);
    genesis
}

/// The standard boundary genesis: activation at `genesis.timestamp +
/// ACTIVATION_DELAY` (blocks 1-2 pre-flip, block 3 first active).
fn scheduled_genesis(sender: Address) -> Genesis {
    scheduled_genesis_with_delay(sender, ACTIVATION_DELAY)
}

/// Build and import `n` transfer blocks on a fresh in-memory store seeded
/// with `genesis`, every block built via the payload builder.
async fn build_chain_from_genesis(genesis: Genesis, n: u64) -> (Store, Blockchain, Vec<Block>) {
    let sk = test_secret_key();
    let signer: Signer = LocalSigner::new(sk).into();

    let chain_id = genesis.config.chain_id;
    let store = setup_store_from_genesis(genesis).await;
    let blockchain = Blockchain::default_with_store(store.clone());

    let blocks = build_and_import_transfers(&store, &blockchain, chain_id, &signer, n).await;
    (store, blockchain, blocks)
}

/// Build and import `n` transfer blocks on a fresh in-memory store seeded
/// with the scheduled genesis, every block built via the payload builder
/// (exercises `finalize_payload` on both sides of the boundary).
async fn build_scheduled_chain(n: u64) -> (Store, Blockchain, Vec<Block>) {
    let sender = sender_from_key(&test_secret_key());
    build_chain_from_genesis(scheduled_genesis(sender), n).await
}

/// `eth_getProof` through the real RPC dispatch (`map_eth_requests`) at an
/// explicit block number, returning the raw JSON response.
async fn get_proof_at(
    context: &ethrex_rpc::RpcApiContext,
    address: Address,
    slots: &str,
    block: &str,
) -> serde_json::Value {
    let body = format!(
        r#"{{"jsonrpc":"2.0","method":"eth_getProof","params":["{address:#x}", {slots}, "{block}"],"id":1}}"#
    );
    let request: ethrex_rpc::utils::RpcRequest = serde_json::from_str(&body).unwrap();
    ethrex_rpc::map_eth_requests(&request, context.clone())
        .await
        .expect("eth_getProof should succeed")
}

/// Return `block` with its header `state_root` corrupted (and the block
/// hash recomputed to match the corrupted header).
fn corrupt_state_root(block: &Block) -> Block {
    let mut header = block.header.clone();
    let mut root_bytes = header.state_root.0;
    root_bytes[0] ^= 0xFF;
    header.state_root = H256(root_bytes);
    Block::new(header, block.body.clone())
}

/// The core boundary test: a chain crossing `binary_tree_time` keeps MPT
/// roots in pre-activation headers (while shadow-tracking snapshots), then
/// commits the FULL carried-over state's binary root from the first active
/// block on, and keeps extending it afterwards.
#[tokio::test]
async fn transition_boundary_commits_full_state() {
    let (store, _blockchain, blocks) = build_scheduled_chain(4).await;
    assert_eq!(blocks.len(), 4);

    let genesis_header = store.get_block_header(0).unwrap().unwrap();
    let activation = genesis_header.timestamp + ACTIVATION_DELAY;
    // Boundary placement sanity: 1-2 pre, 3 first active.
    assert!(blocks[1].header.timestamp < activation);
    assert_eq!(blocks[2].header.timestamp, activation);

    // Genesis itself is pre-activation: its header carries the MPT root.
    assert_eq!(
        genesis_header.state_root,
        store
            .get_mpt_lookup_root(genesis_header.hash())
            .unwrap()
            .expect("scheduled chains record the genesis MPT lookup root"),
        "scheduled-later genesis must commit the MPT root"
    );

    // Blocks 1-2: headers carry the MPT root the store computed (the
    // registry entry recorded under `scheduled` IS that MPT root), and
    // shadow tracking stored a snapshot whose binary root the header does
    // NOT commit.
    for block in &blocks[..2] {
        let number = block.header.number;
        let mpt_root = store
            .get_mpt_lookup_root(block.hash())
            .unwrap()
            .expect("shadow tracking must record the MPT lookup root pre-activation");
        assert_eq!(
            block.header.state_root, mpt_root,
            "pre-activation header must carry the MPT root (block {number})"
        );

        let snapshot = store
            .get_pbt_state(block.hash())
            .unwrap()
            .expect("shadow tracking must snapshot every pre-activation block");
        assert_ne!(
            block.header.state_root,
            snapshot.compute_root().unwrap(),
            "pre-activation header must NOT commit the binary root (block {number})"
        );
    }

    // Block 3 (first active): the header commits the snapshot's binary
    // root, which is not an MPT root.
    let snapshot3 = store
        .get_pbt_state(blocks[2].hash())
        .unwrap()
        .expect("first active block must have a snapshot");
    assert_eq!(
        blocks[2].header.state_root,
        snapshot3.compute_root().unwrap(),
        "first active header must commit the shadow state's binary root"
    );
    assert_ne!(
        blocks[2].header.state_root,
        store
            .get_mpt_lookup_root(blocks[2].hash())
            .unwrap()
            .unwrap(),
        "the first active header's root must differ from the block's MPT root"
    );

    // Carry-over proof: the snapshot behind the first active header holds a
    // genesis-alloc account UNTOUCHED by blocks 1-3 — the flip committed
    // the full shadow-tracked state, not an empty restart.
    assert_eq!(
        snapshot3
            .accounts
            .get(&untouched_account())
            .map(|account| account.balance),
        Some(U256::from(UNTOUCHED_BALANCE)),
        "first active block's snapshot must carry over untouched genesis state"
    );

    // Block 4 continues normally, extending block 3's snapshot.
    assert_binary_snapshots(&store, &blocks[2..]);
}

/// Validation is per-block across the boundary: a corrupted MPT root on a
/// pre-activation block and a corrupted binary root on the first active
/// block are both rejected with `StateRootMismatch`.
#[tokio::test]
async fn validation_is_per_block_across_the_boundary() {
    let (_store, _blockchain, blocks) = build_scheduled_chain(3).await;

    // Import into a fresh store from the same scheduled genesis.
    let sk = test_secret_key();
    let sender = sender_from_key(&sk);
    let blockchain =
        Blockchain::default_with_store(setup_store_from_genesis(scheduled_genesis(sender)).await);

    // Block 1 (pre-activation, MPT-rooted header): corrupt -> rejected.
    let err = blockchain
        .add_block(corrupt_state_root(&blocks[0]))
        .expect_err("corrupted pre-activation MPT root must be rejected");
    assert!(
        matches!(
            err,
            ChainError::InvalidBlock(InvalidBlockError::StateRootMismatch)
        ),
        "expected StateRootMismatch for the corrupted MPT root, got: {err:?}"
    );

    for block in &blocks[..2] {
        blockchain
            .add_block(block.clone())
            .expect("intact pre-activation blocks should import");
    }

    // Block 3 (first active, PBT-rooted header): corrupt -> rejected.
    let err = blockchain
        .add_block(corrupt_state_root(&blocks[2]))
        .expect_err("corrupted first-active binary root must be rejected");
    assert!(
        matches!(
            err,
            ChainError::InvalidBlock(InvalidBlockError::StateRootMismatch)
        ),
        "expected StateRootMismatch for the corrupted binary root, got: {err:?}"
    );

    // The intact block 3 still imports.
    blockchain
        .add_block(blocks[2].clone())
        .expect("intact first active block should import");
}

/// The per-header MPT addressability rule: pre-activation headers resolve
/// to their own `state_root` directly — no registry entry needed — while
/// active headers resolve only through the registry. This is what keeps
/// pre-flip blocks readable across restarts without replay.
#[tokio::test]
async fn pre_activation_headers_resolve_without_registry() {
    let (store, _blockchain, blocks) = build_scheduled_chain(3).await;

    // On the importing store, the pre-activation header resolves to its own
    // state root.
    assert_eq!(
        store
            .mpt_state_root_for_header_opt(&blocks[0].header)
            .unwrap(),
        Some(blocks[0].header.state_root),
        "pre-activation header must resolve to its own (MPT) state root"
    );

    // Sharper (restart-flavored): a fresh store that never imported these
    // blocks has NO registry entries for them, yet the pre-activation
    // header still resolves — while the active header does not.
    let sk = test_secret_key();
    let sender = sender_from_key(&sk);
    let fresh = setup_store_from_genesis(scheduled_genesis(sender)).await;
    assert!(
        fresh
            .get_mpt_lookup_root(blocks[0].hash())
            .unwrap()
            .is_none(),
        "precondition: the fresh store has no registry entry for block 1"
    );
    assert_eq!(
        fresh
            .mpt_state_root_for_header_opt(&blocks[0].header)
            .unwrap(),
        Some(blocks[0].header.state_root),
        "pre-activation headers must resolve WITHOUT a registry entry"
    );
    assert_eq!(
        fresh
            .mpt_state_root_for_header_opt(&blocks[2].header)
            .unwrap(),
        None,
        "active headers must resolve only through the registry"
    );
}

/// True restart simulation across the activation boundary (RocksDB, model
/// of `binary_tree_restart_loses_registries_and_replay_recovers` for the
/// scheduled path): after a clean shutdown + reopen, the in-memory
/// registries are gone — but the per-header MPT rule keeps PRE-FLIP blocks
/// addressable through their own header roots, no registry needed, while
/// active blocks are unaddressable until replay re-derives the registries.
/// Whether an addressable pre-flip block is also *readable* is then purely
/// the baseline MPT durability question (recent diff-layers are dropped on
/// shutdown on any chain); the durable pre-flip state (genesis here) reads
/// back with zero replay.
#[cfg(feature = "rocksdb")]
#[tokio::test]
async fn restart_across_boundary_preserves_durable_preflip_reads_and_recovers_by_replay() {
    let sk = test_secret_key();
    let sender = sender_from_key(&sk);
    let signer: Signer = LocalSigner::new(sk).into();

    let genesis = scheduled_genesis(sender);
    let chain_id = genesis.config.chain_id;
    let activation = genesis.timestamp + ACTIVATION_DELAY;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().to_str().unwrap();

    // Session 1: import blocks 1-2 (pre-flip) and 3 (first active), build
    // (but do not import) block 4, capture the registry entries replay must
    // re-derive, then shut down cleanly.
    let (blocks, block4, genesis_hash, captured) = {
        let mut store = Store::new(path, EngineType::RocksDB).expect("rocksdb store");
        store
            .add_initial_state(genesis.clone())
            .await
            .expect("genesis init");
        let blockchain = Blockchain::default_with_store(store.clone());
        let genesis_hash = store.get_block_header(0).unwrap().unwrap().hash();

        let blocks = build_and_import_transfers(&store, &blockchain, chain_id, &signer, 3).await;
        // Boundary placement sanity: 1-2 pre, 3 first active.
        assert!(blocks[1].header.timestamp < activation);
        assert_eq!(blocks[2].header.timestamp, activation);

        let tx = transfer_tx(
            chain_id,
            3,
            test_recipient(),
            U256::from(1_000_000u64),
            &signer,
        )
        .await;
        blockchain.add_transaction_to_pool(tx).await.unwrap();
        let block4 = build_block(&store, &blockchain, &blocks[2].header).await;
        assert_eq!(block4.body.transactions.len(), 1);

        // (snapshot binary root, MPT lookup root) for genesis + blocks 1-3.
        let captured: Vec<(H256, H256)> = std::iter::once(genesis_hash)
            .chain(blocks.iter().map(|block| block.hash()))
            .map(|hash| {
                (
                    store
                        .get_pbt_state(hash)
                        .unwrap()
                        .expect("scheduled chains snapshot every block")
                        .compute_root()
                        .unwrap(),
                    store
                        .get_mpt_lookup_root(hash)
                        .unwrap()
                        .expect("scheduled chains record every MPT lookup root"),
                )
            })
            .collect();

        store.shutdown().await.expect("clean shutdown");
        (blocks, block4, genesis_hash, captured)
    };

    // Session 2: reopen the same datadir through the real boot entry point.
    let mut store = Store::new(path, EngineType::RocksDB).expect("reopen");
    store
        .add_initial_state(genesis)
        .await
        .expect("boot on existing datadir");
    let blockchain = Blockchain::default_with_store(store.clone());

    // The genesis registry entries are re-seeded by the reopen (the
    // `scheduled` predicate) while the per-block entries stayed in memory
    // and are gone.
    assert_eq!(
        store
            .get_pbt_state(genesis_hash)
            .unwrap()
            .expect("reopen must re-seed the genesis PbtState snapshot when scheduled")
            .compute_root()
            .unwrap(),
        captured[0].0,
        "the re-seeded genesis snapshot must match the pre-restart one"
    );
    assert_eq!(
        store.get_mpt_lookup_root(genesis_hash).unwrap(),
        Some(captured[0].1),
        "reopen must re-seed the genesis MPT lookup root when scheduled"
    );
    for block in &blocks {
        assert!(
            store.get_pbt_state(block.hash()).unwrap().is_none(),
            "per-block snapshots must not survive a restart (block {})",
            block.header.number
        );
        assert!(
            store.get_mpt_lookup_root(block.hash()).unwrap().is_none(),
            "per-block MPT lookup roots must not survive a restart (block {})",
            block.header.number
        );
    }

    // THE per-header rule's payoff, without replaying anything: pre-flip
    // headers stay ADDRESSABLE through their own (MPT) state roots — no
    // registry entry needed — so a pre-flip block whose MPT state is
    // durable is fully readable. On this short chain the only durable MPT
    // version is genesis (recent diff-layers are dropped on shutdown below
    // DB_COMMIT_THRESHOLD depth, on ANY chain — see `Store::shutdown`), and
    // genesis IS a pre-flip block here: the read succeeds with zero replay.
    let info = store
        .get_account_info(0, untouched_account())
        .await
        .expect("pre-flip genesis reads must not require the lost per-block registries")
        .expect("genesis-alloc account must be readable at block 0 after restart");
    assert_eq!(
        info.balance,
        U256::from(UNTOUCHED_BALANCE),
        "block-0 read must serve the durable pre-flip MPT state"
    );

    // Block 1 (pre-flip, recent): resolution works without a registry
    // entry...
    assert_eq!(
        store
            .mpt_state_root_for_header_opt(&blocks[0].header)
            .unwrap(),
        Some(blocks[0].header.state_root),
        "pre-flip headers must resolve without a registry entry after restart"
    );
    // ...and the read fails ONLY for the baseline reason every MPT chain
    // shares: the recent diff-layer was dropped at shutdown (soft miss, not
    // a registry error). Characterization of current layer persistence —
    // if recent layers ever become durable, block 1 becomes fully readable
    // and this flips.
    assert!(
        !store.has_reconstructible_state(&blocks[0].header).unwrap(),
        "recent pre-flip state is not durable across restarts (baseline MPT behavior)"
    );
    assert_eq!(
        store.get_account_info(1, test_recipient()).await.unwrap(),
        None,
        "the recent pre-flip read misses softly, exactly like an unscheduled chain"
    );

    // Contrast: the active block 3 fails HARD with the binary-tree-specific
    // missing-registry error — its MPT is addressable only through the lost
    // registry, so only replay (or offline seeding) can restore it.
    let err = store
        .get_account_info(3, test_recipient())
        .await
        .expect_err("active-block reads must fail while the registry entry is missing");
    assert!(
        format!("{err}").contains("missing MPT lookup root"),
        "expected the missing-registry error for the active block, got: {err:?}"
    );

    // Importing block 4 on top of the pre-restart active parent fails with
    // the documented missing-registry error.
    let err = blockchain
        .add_block(block4.clone())
        .expect_err("import on a registry-less active parent must fail after restart");
    assert!(
        format!("{err}").contains("missing MPT lookup root"),
        "expected the missing-registry restart error, got: {err:?}"
    );

    // Recovery = replay 1-3 from the re-seeded genesis: the registries are
    // re-derived block by block, identical to the pre-restart ones
    // (boundary determinism across a real restart).
    for (block, (snapshot_root, lookup_root)) in blocks.iter().zip(&captured[1..]) {
        blockchain
            .add_block(block.clone())
            .expect("replay of pre-restart blocks should succeed");
        assert_eq!(
            store
                .get_pbt_state(block.hash())
                .unwrap()
                .expect("replay must restore the snapshot")
                .compute_root()
                .unwrap(),
            *snapshot_root,
            "replayed snapshot root must match the pre-restart one (block {})",
            block.header.number
        );
        assert_eq!(
            store.get_mpt_lookup_root(block.hash()).unwrap(),
            Some(*lookup_root),
            "replayed MPT lookup root must match the pre-restart one (block {})",
            block.header.number
        );
    }

    // Replay also re-derived the execution layers: the block-1 read that
    // missed softly above now serves the transfer.
    assert_eq!(
        store
            .get_account_info(1, test_recipient())
            .await
            .unwrap()
            .map(|info| info.balance),
        Some(U256::from(1_000_000u64)),
        "block-1 read must reflect the first transfer after replay"
    );

    // With the registries reconstructed, block 4 imports and extends the
    // post-flip snapshot chain.
    blockchain
        .add_block(block4.clone())
        .expect("block 4 should import after replay recovery");
    assert_binary_snapshots(&store, std::slice::from_ref(&block4));
}

/// Boundary determinism without a restart in the way: replaying the same
/// blocks on a fresh store re-derives the identical registries, and in
/// particular the first active block's committed binary root — shadow
/// carry-over is a deterministic function of (genesis, blocks).
#[tokio::test]
async fn boundary_replay_on_fresh_store_rederives_identical_roots() {
    let (store_a, _blockchain_a, blocks) = build_scheduled_chain(3).await;
    let captured: Vec<(H256, H256)> = blocks
        .iter()
        .map(|block| {
            (
                store_a
                    .get_pbt_state(block.hash())
                    .unwrap()
                    .expect("snapshot must exist on the original store")
                    .compute_root()
                    .unwrap(),
                store_a
                    .get_mpt_lookup_root(block.hash())
                    .unwrap()
                    .expect("lookup root must exist on the original store"),
            )
        })
        .collect();

    let sender = sender_from_key(&test_secret_key());
    let store_b = setup_store_from_genesis(scheduled_genesis(sender)).await;
    let blockchain_b = Blockchain::default_with_store(store_b.clone());
    for (block, (snapshot_root, lookup_root)) in blocks.iter().zip(&captured) {
        blockchain_b
            .add_block(block.clone())
            .expect("replay on a fresh store should succeed");
        assert_eq!(
            store_b
                .get_pbt_state(block.hash())
                .unwrap()
                .expect("replay must store a snapshot")
                .compute_root()
                .unwrap(),
            *snapshot_root,
            "replayed snapshot root must match the original (block {})",
            block.header.number
        );
        assert_eq!(
            store_b.get_mpt_lookup_root(block.hash()).unwrap(),
            Some(*lookup_root),
            "replayed MPT lookup root must match the original (block {})",
            block.header.number
        );
    }

    // The explicit determinism claim: the fresh store re-derived exactly
    // the binary root the first active header committed.
    assert_eq!(
        store_b
            .get_pbt_state(blocks[2].hash())
            .unwrap()
            .unwrap()
            .compute_root()
            .unwrap(),
        blocks[2].header.state_root,
        "the first active block's binary root must be identical across stores"
    );
}

/// `eth_getProof` is per-block across the boundary ON THE SAME CHAIN:
/// pre-flip target blocks serve the legacy MPT shape (their headers carry
/// MPT roots the proofs verify against), while active target blocks serve
/// the experimental `pbt-getproof-v1` shape.
#[tokio::test]
async fn get_proof_shape_flips_at_the_boundary() {
    use ethrex_rpc::test_utils::default_context_with_storage;
    use serde_json::Value;

    let (store, _blockchain, blocks) = build_scheduled_chain(3).await;
    let genesis_ts = store.get_block_header(0).unwrap().unwrap().timestamp;
    assert!(blocks[0].header.timestamp < genesis_ts + ACTIVATION_DELAY);
    let context = default_context_with_storage(store).await;

    // Block 1 (pre-flip target): the untouched legacy MPT shape.
    let legacy = get_proof_at(&context, test_recipient(), r#"["0x0"]"#, "0x1").await;
    assert!(
        legacy["format"].is_null(),
        "pre-flip getProof must not carry the pbt format marker: {legacy}"
    );
    assert!(
        legacy["accountProof"].is_array(),
        "pre-flip getProof must serve the legacy accountProof node list"
    );
    assert!(
        legacy["storageHash"].is_string(),
        "pre-flip getProof must serve the legacy per-account storageHash"
    );
    assert!(
        legacy["binaryAccountProof"].is_null(),
        "pre-flip getProof must not serve binary leaf proofs"
    );

    // Block 3 (first active target): the pbt-getproof-v1 shape.
    let pbt = get_proof_at(&context, test_recipient(), r#"["0x0"]"#, "0x3").await;
    assert_eq!(
        pbt["format"], "pbt-getproof-v1",
        "active getProof must serve the pbt shape: {pbt}"
    );
    assert!(
        pbt["binaryAccountProof"]["basicData"]["proof"].is_array(),
        "active getProof must serve binary leaf proofs"
    );
    assert!(
        pbt["storageHash"].is_null(),
        "no per-account storage root exists in the unified binary tree"
    );
    assert_eq!(
        pbt["storageProof"].as_array().map(Vec::len),
        Some(1),
        "active getProof must answer every requested slot"
    );
    assert!(matches!(
        &pbt["storageProof"][0]["treeKey"],
        Value::String(_)
    ));
}

/// A scheduled-but-never-active chain is OBSERVABLY an unscheduled chain:
/// with `binary_tree_time` in the far future, every header (hash-identical
/// blocks), every MPT read, and every getProof response matches a twin
/// chain built from the same genesis with the schedule removed. Shadow
/// tracking (the snapshots) is the only difference, and it is invisible to
/// consensus. In particular the GENESIS HASHES are equal: the chain config
/// is not part of the header and a scheduled-later genesis commits the
/// same MPT root.
#[tokio::test]
async fn scheduled_but_never_active_is_observably_unscheduled() {
    use ethrex_rpc::test_utils::default_context_with_storage;

    /// Comfortably beyond any timestamp a 3-block chain reaches.
    const NEVER_DELAY: u64 = 1_000_000;

    let sender = sender_from_key(&test_secret_key());
    let (sched_store, _sched_bc, sched_blocks) =
        build_chain_from_genesis(scheduled_genesis_with_delay(sender, NEVER_DELAY), 3).await;
    let (plain_store, _plain_bc, plain_blocks) =
        build_chain_from_genesis(unscheduled_genesis(sender), 3).await;

    // Genesis hashes equal (config differences don't reach the header).
    let sched_genesis = sched_store.get_block_header(0).unwrap().unwrap();
    let plain_genesis = plain_store.get_block_header(0).unwrap().unwrap();
    assert_eq!(
        sched_genesis.hash(),
        plain_genesis.hash(),
        "a scheduled-later genesis must hash identically to the unscheduled twin"
    );

    for (number, (sched, plain)) in (1u64..).zip(sched_blocks.iter().zip(&plain_blocks)) {
        // Full header identity, not just the state root: the chains are
        // block-for-block the same chain.
        assert_eq!(
            sched.hash(),
            plain.hash(),
            "block {number} must be hash-identical across the twin chains"
        );

        // MPT reads agree through the public path.
        let sched_info = sched_store
            .get_account_info(number, test_recipient())
            .await
            .unwrap()
            .expect("recipient must be readable on the scheduled chain");
        let plain_info = plain_store
            .get_account_info(number, test_recipient())
            .await
            .unwrap()
            .expect("recipient must be readable on the unscheduled chain");
        assert_eq!(
            sched_info.balance, plain_info.balance,
            "account reads must agree at block {number}"
        );

        // The one (invisible) difference: shadow tracking ran only on the
        // scheduled chain.
        assert!(
            sched_store.get_pbt_state(sched.hash()).unwrap().is_some(),
            "the scheduled chain must shadow-track block {number}"
        );
        assert!(
            plain_store.get_pbt_state(plain.hash()).unwrap().is_none(),
            "the unscheduled chain must not snapshot block {number}"
        );
    }

    // getProof: legacy shape on the scheduled chain (pre-flip targets), and
    // byte-identical to the unscheduled twin's response.
    let sched_context = default_context_with_storage(sched_store).await;
    let plain_context = default_context_with_storage(plain_store).await;
    for number in 1u64..=3 {
        let block = format!("{number:#x}");
        let sched_proof = get_proof_at(&sched_context, sender, r#"["0x0"]"#, &block).await;
        let plain_proof = get_proof_at(&plain_context, sender, r#"["0x0"]"#, &block).await;
        assert!(
            sched_proof["format"].is_null() && sched_proof["accountProof"].is_array(),
            "scheduled-but-never-active getProof must serve the legacy shape at block {number}"
        );
        assert_eq!(
            sched_proof, plain_proof,
            "getProof must be identical across the twin chains at block {number}"
        );
    }
}
