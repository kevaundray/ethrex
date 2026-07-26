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

use super::binary_tree_helpers::{
    assert_binary_snapshots, build_and_import_transfers, load_genesis_fixture, sender_from_key,
    setup_store_from_genesis, test_secret_key,
};

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

/// `l1-bal.json` (bool OFF) with `binary_tree_time = genesis.timestamp +
/// ACTIVATION_DELAY` and the untouched carry-over witness account injected
/// into the alloc.
fn scheduled_genesis(sender: Address) -> Genesis {
    let mut genesis = load_genesis_fixture(
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
        !genesis.config.enable_binary_tree_at_genesis,
        "fixture must not carry the genesis-activation flag (bool+time is rejected)"
    );
    genesis.config.binary_tree_time = Some(genesis.timestamp + ACTIVATION_DELAY);
    genesis
}

/// Build and import `n` transfer blocks on a fresh in-memory store seeded
/// with the scheduled genesis, every block built via the payload builder
/// (exercises `finalize_payload` on both sides of the boundary).
async fn build_scheduled_chain(n: u64) -> (Store, Blockchain, Vec<Block>) {
    let sk = test_secret_key();
    let sender = sender_from_key(&sk);
    let signer: Signer = LocalSigner::new(sk).into();

    let genesis = scheduled_genesis(sender);
    let chain_id = genesis.config.chain_id;
    let store = setup_store_from_genesis(genesis).await;
    let blockchain = Blockchain::default_with_store(store.clone());

    let blocks = build_and_import_transfers(&store, &blockchain, chain_id, &signer, n).await;
    (store, blockchain, blocks)
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
async fn pre_activation_blocks_validate_mpt() {
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
