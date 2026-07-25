//! End-to-end tests for the experimental EIP-8297 binary-tree state
//! commitment (`ChainConfig::enable_binary_tree_at_genesis`).
//!
//! Under the flag, payload building must put the binary-trie (PBT) root in
//! `header.state_root`, and block import must validate that root against a
//! freshly extended `PbtState` snapshot and store the new snapshot under the
//! block's hash. The MPT is still persisted as the lookup structure.

use std::{fs::File, io::BufReader, path::PathBuf};

use bytes::Bytes;
use ethrex_blockchain::{
    Blockchain,
    error::{ChainError, InvalidBlockError},
    fork_choice::apply_fork_choice,
    payload::{BuildPayloadArgs, create_payload},
};
use ethrex_common::{
    Address, H160, H256, U256,
    types::{
        Block, BlockHeader, DEFAULT_BUILDER_GAS_CEIL, EIP1559Transaction, ELASTICITY_MULTIPLIER,
        Genesis, GenesisAccount, PbtAccount, Transaction, TxKind, Withdrawal,
    },
};
use ethrex_l2_rpc::signer::{LocalSigner, Signable, Signer};
use ethrex_storage::{EngineType, Store};
use secp256k1::SecretKey;
use tokio_util::sync::CancellationToken;

/// Test private key from fixtures/keys/private_keys_tests.txt.
const TEST_PRIVATE_KEY: &str = "850643a0224065ecce3882673c21f56bcf6eef86274cc21cadff15930b59fc8c";
/// Comfortably high max fee — well above any genesis base fee.
const TEST_MAX_FEE_PER_GAS: u64 = 10_000_000_000;
/// Must cover EIP-8037 state gas (the fixture is Amsterdam at genesis): a
/// value transfer that materializes a new account draws
/// `STATE_BYTES_PER_NEW_ACCOUNT (120) * cost_per_state_byte (1530) = 183_600`
/// gas on top of execution gas, spilled from the tx gas since small gas
/// limits carry no reservoir. 100k made every transfer here fail-in-block.
/// 400k gives comfortable headroom over that ~183.6k new-account floor and
/// over the storage-zeroing test's SSTORE storage-set state gas
/// (`64 * 1530 = 97_920`) plus execution gas.
const TEST_GAS_LIMIT: u64 = 400_000;

fn test_secret_key() -> SecretKey {
    SecretKey::from_slice(&hex::decode(TEST_PRIVATE_KEY).unwrap()).unwrap()
}

fn sender_from_key(sk: &SecretKey) -> Address {
    LocalSigner::new(*sk).address
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// Recipient of the value transfers built by the chain helpers.
fn test_recipient() -> Address {
    Address::from_low_u64_be(0xD00D)
}

/// Load the given genesis fixture, inject `sender` with a large balance
/// plus any `extra_accounts`, and return the genesis.
///
/// `fixtures/genesis/l1-binarytree.json` is `l1-bal.json` plus
/// `enableBinaryTreeAtGenesis`, so the same chain id / fork schedule /
/// timestamps apply to both and blocks built on each are comparable.
fn load_genesis_fixture(
    fixture: &str,
    sender: Address,
    extra_accounts: &[(Address, GenesisAccount)],
) -> Genesis {
    let file = File::open(workspace_root().join("fixtures/genesis").join(fixture))
        .expect("Failed to open genesis file");
    let reader = BufReader::new(file);
    let mut genesis: Genesis =
        serde_json::from_reader(reader).expect("Failed to deserialize genesis file");

    // Give the sender a large balance so it can fund the transactions.
    genesis.alloc.insert(
        sender,
        GenesisAccount {
            balance: U256::from(10).pow(U256::from(20)), // 100 ETH
            code: Bytes::new(),
            storage: Default::default(),
            nonce: 0,
        },
    );
    for (address, account) in extra_accounts {
        genesis.alloc.insert(*address, account.clone());
    }
    genesis
}

/// Build an in-memory store seeded with `genesis`.
async fn setup_store_from_genesis(genesis: Genesis) -> Store {
    let mut store =
        Store::new("store.db", EngineType::InMemory).expect("Failed to build DB for testing");
    store
        .add_initial_state(genesis)
        .await
        .expect("Failed to add genesis state");
    store
}

/// Load the given genesis fixture, inject `sender` with a large balance,
/// and return an in-memory store together with the chain id.
async fn setup_store_from_fixture(fixture: &str, sender: Address) -> (Store, u64) {
    let genesis = load_genesis_fixture(fixture, sender, &[]);
    let chain_id = genesis.config.chain_id;
    (setup_store_from_genesis(genesis).await, chain_id)
}

/// Build a block on top of `parent_header` using the payload builder,
/// including whatever transactions are currently in the mempool.
async fn build_block(store: &Store, blockchain: &Blockchain, parent_header: &BlockHeader) -> Block {
    // Use fixed values instead of random ones for deterministic, reproducible tests.
    let args = BuildPayloadArgs {
        parent: parent_header.hash(),
        timestamp: parent_header.timestamp + 12,
        fee_recipient: H160::zero(),
        random: H256::zero(),
        withdrawals: Some(Vec::new()),
        beacon_root: Some(H256::zero()),
        // EIP-7843: Amsterdam headers must carry a slot_number, else header
        // validation rejects the block before import.
        slot_number: Some(parent_header.number + 1),
        version: 1,
        elasticity_multiplier: ELASTICITY_MULTIPLIER,
        gas_ceil: DEFAULT_BUILDER_GAS_CEIL,
    };

    let block = create_payload(&args, store, Bytes::new()).unwrap();
    let result = blockchain.build_payload(block).unwrap();
    result.payload
}

/// Build and sign an EIP-1559 call with the given value and calldata.
async fn signed_tx(
    chain_id: u64,
    nonce: u64,
    to: Address,
    value: U256,
    data: Bytes,
    signer: &Signer,
) -> Transaction {
    let mut tx = Transaction::EIP1559Transaction(EIP1559Transaction {
        chain_id,
        nonce,
        max_priority_fee_per_gas: 0,
        max_fee_per_gas: TEST_MAX_FEE_PER_GAS,
        gas_limit: TEST_GAS_LIMIT,
        to: TxKind::Call(to),
        value,
        data,
        ..Default::default()
    });
    tx.sign_inplace(signer).await.unwrap();
    tx
}

/// Build and sign a plain value-transfer transaction.
async fn transfer_tx(
    chain_id: u64,
    nonce: u64,
    to: Address,
    value: U256,
    signer: &Signer,
) -> Transaction {
    signed_tx(chain_id, nonce, to, value, Bytes::new(), signer).await
}

/// Build and import `n` transfer blocks on top of genesis on the given
/// store, one value transfer per block (sender nonces `0..n`), importing
/// each via `add_block` (exercises `store_block`) after building it via
/// the payload builder (exercises `finalize_payload`).
async fn build_and_import_transfers(
    store: &Store,
    blockchain: &Blockchain,
    chain_id: u64,
    signer: &Signer,
    n: u64,
) -> Vec<Block> {
    let mut parent = store.get_block_header(0).unwrap().unwrap();

    let mut blocks = Vec::new();
    for nonce in 0..n {
        let tx = transfer_tx(
            chain_id,
            nonce,
            test_recipient(),
            U256::from(1_000_000u64),
            signer,
        )
        .await;
        blockchain
            .add_transaction_to_pool(tx)
            .await
            .expect("transfer tx should enter pool");

        let block = build_block(store, blockchain, &parent).await;
        assert_eq!(
            block.body.transactions.len(),
            1,
            "block must include the value transfer"
        );

        blockchain
            .add_block(block.clone())
            .expect("block should import under the binary-tree flag");

        store
            .forkchoice_update(vec![], block.header.number, block.hash(), None, None)
            .await
            .unwrap();
        blockchain
            .remove_block_transactions_from_pool(&block)
            .expect("should remove included txs from pool");

        parent = block.header.clone();
        blocks.push(block);
    }

    blocks
}

/// Build a chain of `n` blocks under the binary-tree flag on a fresh
/// in-memory store. Returns the store and the built blocks.
async fn build_and_import_chain(n: u64) -> (Store, Blockchain, Vec<Block>) {
    let sk = test_secret_key();
    let sender = sender_from_key(&sk);
    let signer: Signer = LocalSigner::new(sk).into();

    let (store, chain_id) = setup_store_from_fixture("l1-binarytree.json", sender).await;
    let blockchain = Blockchain::default_with_store(store.clone());

    let blocks = build_and_import_transfers(&store, &blockchain, chain_id, &signer, n).await;
    (store, blockchain, blocks)
}

/// Assert the import-side postconditions for every block: a `PbtState`
/// snapshot exists under the block hash and the header's state root is that
/// snapshot's binary-trie root.
fn assert_binary_snapshots(store: &Store, blocks: &[Block]) {
    for block in blocks {
        let snapshot = store
            .get_pbt_state(block.hash())
            .expect("store read should succeed")
            .unwrap_or_else(|| {
                panic!(
                    "PbtState snapshot missing for block {}",
                    block.header.number
                )
            });
        assert_eq!(
            block.header.state_root,
            snapshot
                .compute_root()
                .expect("snapshot root computation should succeed"),
            "header state_root must be the binary-trie root of the stored snapshot (block {})",
            block.header.number
        );
    }
}

/// Chain of 3 under the flag: payload building commits the binary root and
/// import validates + snapshots it, block by block.
#[tokio::test]
async fn binary_tree_chain_of_three_commits_binary_roots() {
    let (store, _blockchain, blocks) = build_and_import_chain(3).await;
    assert_eq!(blocks.len(), 3);
    assert_binary_snapshots(&store, &blocks);

    // Cheapest honest "this is not an MPT root" assertion: run the identical
    // block-1 build on the same fixture without the flag (l1-bal.json differs
    // from l1-binarytree.json only by `enableBinaryTreeAtGenesis`; same chain
    // id, forks, timestamps and alloc, and the injected sender + tx are
    // identical), and require the committed roots to differ.
    let sk = test_secret_key();
    let sender = sender_from_key(&sk);
    let signer: Signer = LocalSigner::new(sk).into();
    let (mpt_store, chain_id) = setup_store_from_fixture("l1-bal.json", sender).await;
    let mpt_blockchain = Blockchain::default_with_store(mpt_store.clone());
    let mpt_genesis = mpt_store.get_block_header(0).unwrap().unwrap();

    let recipient = test_recipient();
    let tx = transfer_tx(chain_id, 0, recipient, U256::from(1_000_000u64), &signer).await;
    mpt_blockchain.add_transaction_to_pool(tx).await.unwrap();
    let mpt_block1 = build_block(&mpt_store, &mpt_blockchain, &mpt_genesis).await;
    assert_eq!(mpt_block1.body.transactions.len(), 1);

    assert_ne!(
        blocks[0].header.state_root, mpt_block1.header.state_root,
        "flagged header must commit to the binary-trie root, not the MPT root"
    );
}

/// A valid built block with a corrupted `state_root` must be rejected with
/// the state-root-mismatch error.
#[tokio::test]
async fn binary_tree_corrupted_state_root_rejected() {
    let sk = test_secret_key();
    let sender = sender_from_key(&sk);
    let signer: Signer = LocalSigner::new(sk).into();

    let (store, chain_id) = setup_store_from_fixture("l1-binarytree.json", sender).await;
    let blockchain = Blockchain::default_with_store(store.clone());
    let genesis_header = store.get_block_header(0).unwrap().unwrap();

    let recipient = test_recipient();
    let tx = transfer_tx(chain_id, 0, recipient, U256::from(1_000_000u64), &signer).await;
    blockchain.add_transaction_to_pool(tx).await.unwrap();

    let block = build_block(&store, &blockchain, &genesis_header).await;

    let mut corrupted_header = block.header.clone();
    let mut root_bytes = corrupted_header.state_root.0;
    root_bytes[0] ^= 0xFF;
    corrupted_header.state_root = H256(root_bytes);
    // Rebuild the block so the cached hash matches the corrupted header.
    let corrupted = Block::new(corrupted_header, block.body);

    let err = blockchain
        .add_block(corrupted)
        .expect_err("corrupted state root must be rejected");
    assert!(
        matches!(
            err,
            ChainError::InvalidBlock(InvalidBlockError::StateRootMismatch)
        ),
        "expected StateRootMismatch, got: {err:?}"
    );
}

/// `add_blocks_in_batch` under the flag must fall back to per-block imports
/// (the batch path merkleizes once for the whole range and cannot produce
/// the required per-block snapshots) with the same postconditions as the
/// single-block path.
#[tokio::test]
async fn binary_tree_batch_import_produces_per_block_snapshots() {
    let (_store_a, _blockchain_a, blocks) = build_and_import_chain(3).await;

    // Fresh store from the same genesis: only the genesis snapshot exists.
    let sk = test_secret_key();
    let sender = sender_from_key(&sk);
    let (store_b, _) = setup_store_from_fixture("l1-binarytree.json", sender).await;
    let blockchain_b = Blockchain::default_with_store(store_b.clone());

    let result = blockchain_b
        .add_blocks_in_batch(blocks.clone(), &[], CancellationToken::new())
        .await;
    assert!(
        result.is_ok(),
        "batch import under the binary-tree flag should succeed via the per-block fallback — got: {:?}",
        result.err()
    );

    assert_binary_snapshots(&store_b, &blocks);
}

/// The pipeline import path (`add_block_pipeline`, the engine-API route)
/// must also maintain per-block snapshots under the flag: the merkleizer is
/// forced to accumulate the raw account updates that `store_block` needs.
#[tokio::test]
async fn binary_tree_pipeline_import_produces_per_block_snapshots() {
    let (_store_a, _blockchain_a, blocks) = build_and_import_chain(3).await;

    let sk = test_secret_key();
    let sender = sender_from_key(&sk);
    let (store_b, _) = setup_store_from_fixture("l1-binarytree.json", sender).await;
    let blockchain_b = Blockchain::default_with_store(store_b.clone());

    for block in &blocks {
        blockchain_b
            .add_block_pipeline(block.clone(), None)
            .expect("pipeline import should succeed under the binary-tree flag");
    }

    assert_binary_snapshots(&store_b, &blocks);
}

/// Replaying the same blocks from genesis on a fresh store re-derives
/// registry entries identical to the original import — the "re-import from
/// genesis" recovery path the missing-registry error messages promise.
///
/// The `PbtState` snapshots and MPT lookup roots are in-memory only, so a
/// restart loses them; this proves the loss is recoverable because both
/// registries are deterministic functions of (genesis, blocks).
#[tokio::test]
async fn binary_tree_replay_from_genesis_rederives_registries() {
    let (store_a, _blockchain_a, blocks) = build_and_import_chain(2).await;

    // Capture what the original import derived.
    let captured: Vec<(H256, H256)> = blocks
        .iter()
        .map(|block| {
            let snapshot_root = store_a
                .get_pbt_state(block.hash())
                .unwrap()
                .expect("snapshot must exist on the original store")
                .compute_root()
                .expect("snapshot root computation should succeed");
            let lookup_root = store_a
                .get_mpt_lookup_root(block.hash())
                .unwrap()
                .expect("lookup root must exist on the original store");
            (snapshot_root, lookup_root)
        })
        .collect();

    // Fresh store from the same genesis: only the genesis registry entries
    // exist (the block-1/2 entries are "lost", as after a restart).
    let sk = test_secret_key();
    let sender = sender_from_key(&sk);
    let (store_b, _) = setup_store_from_fixture("l1-binarytree.json", sender).await;
    let blockchain_b = Blockchain::default_with_store(store_b.clone());
    for block in &blocks {
        assert!(
            store_b.get_pbt_state(block.hash()).unwrap().is_none(),
            "fresh store must not have a snapshot for block {}",
            block.header.number
        );
    }

    // Replay and require identical registry entries.
    for (block, (snapshot_root, lookup_root)) in blocks.iter().zip(&captured) {
        blockchain_b
            .add_block(block.clone())
            .expect("replay from genesis should succeed");
        let replayed_root = store_b
            .get_pbt_state(block.hash())
            .unwrap()
            .expect("replay must store a snapshot")
            .compute_root()
            .expect("snapshot root computation should succeed");
        assert_eq!(
            replayed_root, *snapshot_root,
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
}

/// `put_pbt_state` seeding is authoritative: import validates against
/// whatever snapshot is registered for the parent, and re-seeding
/// overwrites (last write wins).
///
/// A snapshot that differs from replay-equivalent state must surface as
/// `StateRootMismatch` on the next imported block (the exact contract
/// documented on `Store::put_pbt_state`), and seeding the correct snapshot
/// afterwards must let the same block import. This is the offline-seeding
/// recovery path for nodes that cannot replay from genesis, exercised as
/// far as it is honestly constructible on an in-memory store: parent block
/// data and MPT state come from a normal import of blocks 1-2, and the
/// overwrite semantics make the wrong/correct seeding real rather than
/// vacuous.
#[tokio::test]
async fn binary_tree_seeded_snapshot_gates_import_of_next_block() {
    // Blocks 1-3 from a reference chain; block 3 is the one gated on the
    // seeded snapshot of block 2.
    let (_store_a, _blockchain_a, blocks) = build_and_import_chain(3).await;

    let sk = test_secret_key();
    let sender = sender_from_key(&sk);
    let (store_b, _) = setup_store_from_fixture("l1-binarytree.json", sender).await;
    let blockchain_b = Blockchain::default_with_store(store_b.clone());
    for block in &blocks[..2] {
        blockchain_b
            .add_block(block.clone())
            .expect("blocks 1-2 should import");
    }
    let block2_hash = blocks[1].hash();
    let correct = store_b
        .get_pbt_state(block2_hash)
        .unwrap()
        .expect("block-2 snapshot must exist after import");

    // Seed a WRONG snapshot for block 2: a phantom account block 3 never
    // touches, so the perturbation survives the extension (block 3's own
    // updates overwrite touched accounts with absolute post-state values)
    // and the extended root cannot match block 3's header.
    let mut wrong = (*correct).clone();
    wrong.accounts.insert(
        Address::from_low_u64_be(0xDEAD),
        PbtAccount {
            balance: U256::one(),
            ..Default::default()
        },
    );
    store_b.put_pbt_state(block2_hash, wrong).unwrap();

    let err = blockchain_b
        .add_block(blocks[2].clone())
        .expect_err("import over a wrong seeded snapshot must be rejected");
    assert!(
        matches!(
            err,
            ChainError::InvalidBlock(InvalidBlockError::StateRootMismatch)
        ),
        "expected StateRootMismatch from the wrong seeded snapshot, got: {err:?}"
    );

    // Re-seed the correct snapshot: the same block must now import, and the
    // failed attempt must not have left partial registry state behind.
    store_b
        .put_pbt_state(block2_hash, (*correct).clone())
        .unwrap();
    blockchain_b
        .add_block(blocks[2].clone())
        .expect("import over the correct seeded snapshot should succeed");

    assert_binary_snapshots(&store_b, &blocks);
}

/// Storage zeroing must uphold the zero-slots-absent invariant end to end:
/// a slot written in block 1 and zeroed in block 2 (via a real SSTORE
/// contract) must be present in block 1's snapshot and absent from
/// block 2's, with both blocks' binary roots validating on import (the
/// builder committed them, `store_block` re-derived and checked them).
#[tokio::test]
async fn binary_tree_storage_zeroing_removes_slot_from_snapshot() {
    let sk = test_secret_key();
    let sender = sender_from_key(&sk);
    let signer: Signer = LocalSigner::new(sk).into();

    // PUSH0 CALLDATALOAD PUSH0 SSTORE STOP: stores calldata word 0 into
    // storage slot 0.
    let contract = Address::from_low_u64_be(0xC0DE);
    let contract_code = Bytes::from_static(&[0x5f, 0x35, 0x5f, 0x55, 0x00]);
    let genesis = load_genesis_fixture(
        "l1-binarytree.json",
        sender,
        &[(
            contract,
            GenesisAccount {
                balance: U256::zero(),
                code: contract_code,
                storage: Default::default(),
                nonce: 1,
            },
        )],
    );
    let chain_id = genesis.config.chain_id;
    let store = setup_store_from_genesis(genesis).await;
    let blockchain = Blockchain::default_with_store(store.clone());
    let mut parent = store.get_block_header(0).unwrap().unwrap();

    let slot = H256::zero();
    let slot_value = U256::from(0xBEEF);
    // Block 1 stores `slot_value` in slot 0; block 2 zeroes it again.
    let payloads = [H256(slot_value.to_big_endian()), H256::zero()];
    let mut imported = Vec::new();
    for (nonce, payload) in payloads.iter().enumerate() {
        let tx = signed_tx(
            chain_id,
            nonce as u64,
            contract,
            U256::zero(),
            Bytes::copy_from_slice(payload.as_bytes()),
            &signer,
        )
        .await;
        blockchain.add_transaction_to_pool(tx).await.unwrap();

        let block = build_block(&store, &blockchain, &parent).await;
        assert_eq!(
            block.body.transactions.len(),
            1,
            "block must include the contract call"
        );
        blockchain
            .add_block(block.clone())
            .expect("contract-call block should import under the binary-tree flag");
        store
            .forkchoice_update(vec![], block.header.number, block.hash(), None, None)
            .await
            .unwrap();
        blockchain
            .remove_block_transactions_from_pool(&block)
            .unwrap();

        parent = block.header.clone();
        imported.push(block);
    }

    // Block 1: the slot is present with the written value.
    let snapshot1 = store
        .get_pbt_state(imported[0].hash())
        .unwrap()
        .expect("block-1 snapshot must exist");
    assert_eq!(
        snapshot1
            .storage
            .get(&contract)
            .and_then(|slots| slots.get(&slot)),
        Some(&slot_value),
        "block-1 snapshot must hold the written slot"
    );

    // Block 2: zeroing removed the slot; since it was the contract's only
    // slot, the whole per-account storage map must be gone (zero means
    // absent, empty map is dropped). The account itself survives.
    let snapshot2 = store
        .get_pbt_state(imported[1].hash())
        .unwrap()
        .expect("block-2 snapshot must exist");
    assert!(
        !snapshot2.storage.contains_key(&contract),
        "zeroing the only slot must drop the contract's storage from the snapshot"
    );
    assert!(
        snapshot2.accounts.contains_key(&contract),
        "the contract account itself must survive storage zeroing"
    );

    // Both roots validated on import (`store_block` would have rejected a
    // mismatch); re-assert the header/snapshot linkage explicitly.
    assert_binary_snapshots(&store, &imported);

    // The public number-addressed storage read (`eth_getStorageAt`'s path)
    // must resolve the MPT through the side registry, not through the
    // header's (PBT) state root: the slot reads back at block 1 and is
    // gone at block 2.
    assert_eq!(
        store
            .get_storage_at(1, contract, slot)
            .expect("get_storage_at must resolve the MPT lookup root under the flag"),
        Some(slot_value),
        "block-1 storage read through the public path must return the SSTOREd value"
    );
    assert_eq!(
        store
            .get_storage_at(2, contract, slot)
            .expect("get_storage_at must resolve the MPT lookup root under the flag"),
        None,
        "block-2 storage read must reflect the zeroed (absent) slot"
    );
}

/// While headers carry binary-trie roots, the MPT must keep serving state
/// lookups through the side registry: per-block account reads through the
/// normal access path (`get_account_info` by block number) must reflect
/// the transfers, and the registered MPT lookup root must differ from the
/// header's (PBT) state root.
#[tokio::test]
async fn binary_tree_mpt_lookup_serves_account_state() {
    let (store, _blockchain, blocks) = build_and_import_chain(3).await;

    for (i, block) in blocks.iter().enumerate() {
        let number = i as u64 + 1;
        let info = store
            .get_account_info(number, test_recipient())
            .await
            .unwrap()
            .expect("recipient must be readable through the MPT lookup path");
        assert_eq!(
            info.balance,
            U256::from(1_000_000u64) * U256::from(number),
            "recipient balance at block {number} must reflect the transfers"
        );

        let lookup_root = store
            .get_mpt_lookup_root(block.hash())
            .unwrap()
            .expect("MPT lookup root must be registered for every imported block");
        assert_ne!(
            block.header.state_root, lookup_root,
            "the MPT lookup root must be addressed out of band, not by the header root (block {number})"
        );
    }

    let sk = test_secret_key();
    let sender_info = store
        .get_account_info(3, sender_from_key(&sk))
        .await
        .unwrap()
        .expect("sender must be readable through the MPT lookup path");
    assert_eq!(sender_info.nonce, 3, "sender nonce must reflect three txs");
}

/// True restart simulation (RocksDB): block data and the on-disk MPT base
/// survive a clean shutdown + reopen, but the in-memory `PbtState` /
/// MPT-lookup-root registries do not. `add_initial_state` on the reopened
/// datadir must re-seed the GENESIS registry entries itself (its
/// matching-genesis early return re-derives them from the genesis file),
/// while entries for blocks past genesis stay lost: importing a block on
/// top of a pre-restart parent must fail with the documented
/// missing-registry error, and recovery-by-replay from genesis (what a
/// re-import does) must reconstruct them and let the import proceed.
#[cfg(feature = "rocksdb")]
#[tokio::test]
async fn binary_tree_restart_loses_registries_and_replay_recovers() {
    let sk = test_secret_key();
    let sender = sender_from_key(&sk);
    let signer: Signer = LocalSigner::new(sk).into();

    let genesis = load_genesis_fixture("l1-binarytree.json", sender, &[]);
    let chain_id = genesis.config.chain_id;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().to_str().unwrap();

    // Session 1: import blocks 1-2, build (but do not import) block 3,
    // capture the registry entries a seeder/replayer would need, then shut
    // down cleanly. The scope drop releases the RocksDB handle.
    let (blocks, block3, genesis_hash, genesis_pbt, genesis_lookup, block2_root, block2_lookup) = {
        let mut store = Store::new(path, EngineType::RocksDB).expect("rocksdb store");
        store
            .add_initial_state(genesis.clone())
            .await
            .expect("genesis init");
        let blockchain = Blockchain::default_with_store(store.clone());
        let genesis_hash = store.get_block_header(0).unwrap().unwrap().hash();

        let blocks = build_and_import_transfers(&store, &blockchain, chain_id, &signer, 2).await;

        // Block 3, built via the payload builder on top of block 2.
        let tx = transfer_tx(
            chain_id,
            2,
            test_recipient(),
            U256::from(1_000_000u64),
            &signer,
        )
        .await;
        blockchain.add_transaction_to_pool(tx).await.unwrap();
        let block3 = build_block(&store, &blockchain, &blocks[1].header).await;
        assert_eq!(block3.body.transactions.len(), 1);

        let genesis_pbt = (*store.get_pbt_state(genesis_hash).unwrap().unwrap()).clone();
        let genesis_lookup = store.get_mpt_lookup_root(genesis_hash).unwrap().unwrap();
        let block2_root = store
            .get_pbt_state(blocks[1].hash())
            .unwrap()
            .unwrap()
            .compute_root()
            .unwrap();
        let block2_lookup = store
            .get_mpt_lookup_root(blocks[1].hash())
            .unwrap()
            .unwrap();

        store.shutdown().await.expect("clean shutdown");
        (
            blocks,
            block3,
            genesis_hash,
            genesis_pbt,
            genesis_lookup,
            block2_root,
            block2_lookup,
        )
    };

    // Session 2: reopen the same datadir through the real boot entry point.
    let mut store = Store::new(path, EngineType::RocksDB).expect("reopen");
    store
        .add_initial_state(genesis)
        .await
        .expect("boot on existing datadir");
    let blockchain = Blockchain::default_with_store(store.clone());

    // Block data survived the restart; the in-memory registries did not —
    // except the genesis entries, which `add_initial_state` re-derives from
    // the genesis file on its matching-genesis early return (exactly what a
    // fresh-datadir init would have seeded).
    assert!(
        store
            .get_block_header_by_hash(blocks[1].hash())
            .unwrap()
            .is_some(),
        "block 2 header must survive the restart on disk"
    );
    assert_eq!(
        store
            .get_pbt_state(genesis_hash)
            .unwrap()
            .expect("reopen must re-seed the genesis PbtState snapshot")
            .compute_root()
            .unwrap(),
        genesis_pbt.compute_root().unwrap(),
        "the re-seeded genesis snapshot must match the pre-restart one"
    );
    assert_eq!(
        store.get_mpt_lookup_root(genesis_hash).unwrap(),
        Some(genesis_lookup),
        "reopen must re-seed the genesis MPT lookup root"
    );
    assert!(
        store.get_pbt_state(blocks[1].hash()).unwrap().is_none(),
        "PbtState snapshots are in-memory only and must not survive a restart"
    );
    assert!(
        store
            .get_mpt_lookup_root(blocks[1].hash())
            .unwrap()
            .is_none(),
        "MPT lookup roots are in-memory only and must not survive a restart"
    );

    // Importing on top of a pre-restart parent fails with the documented
    // missing-registry error (the MPT lookup root is needed first, to set
    // up execution over the parent state).
    let err = blockchain
        .add_block(block3.clone())
        .expect_err("import on a registry-less parent must fail after restart");
    assert!(
        format!("{err}").contains("missing MPT lookup root"),
        "expected the missing-registry restart error, got: {err:?}"
    );

    // Recovery = re-import from genesis: the genesis entries are already
    // re-seeded by the reopen (asserted above), so replaying the chain is
    // all that is needed; the registries are re-derived block by block.
    for block in &blocks {
        blockchain
            .add_block(block.clone())
            .expect("replay of pre-restart blocks should succeed");
    }
    assert_eq!(
        store
            .get_pbt_state(blocks[1].hash())
            .unwrap()
            .expect("replay must restore the block-2 snapshot")
            .compute_root()
            .unwrap(),
        block2_root,
        "replayed block-2 snapshot root must match the pre-restart one"
    );
    assert_eq!(
        store.get_mpt_lookup_root(blocks[1].hash()).unwrap(),
        Some(block2_lookup),
        "replayed block-2 MPT lookup root must match the pre-restart one"
    );

    // With the registries reconstructed, block 3 imports.
    blockchain
        .add_block(block3.clone())
        .expect("block 3 should import after replay recovery");
    let snapshot3 = store
        .get_pbt_state(block3.hash())
        .unwrap()
        .expect("block-3 snapshot must exist after import");
    assert_eq!(
        block3.header.state_root,
        snapshot3.compute_root().unwrap(),
        "block-3 header must commit to the stored snapshot's binary root"
    );
}

/// Withdrawals are the one `AccountUpdate` source that bypasses transaction
/// execution (a consensus-layer credit applied at payload finalization), so
/// they must flow into the snapshot extension like any executed update: a
/// block whose only state change beyond the fee-recipient touch is a
/// non-empty withdrawal must validate on import, and the block's snapshot
/// must hold the credited balance (amount is denominated in Gwei).
#[tokio::test]
async fn binary_tree_withdrawal_credits_recipient_in_snapshot() {
    let sk = test_secret_key();
    let sender = sender_from_key(&sk);
    let (store, _chain_id) = setup_store_from_fixture("l1-binarytree.json", sender).await;
    let blockchain = Blockchain::default_with_store(store.clone());
    let genesis_header = store.get_block_header(0).unwrap().unwrap();

    let recipient = Address::from_low_u64_be(0x81D0);
    let amount_gwei = 1_000_000u64; // 0.001 ETH
    // Same fixed args as `build_block`, but with a non-empty withdrawal list.
    let args = BuildPayloadArgs {
        parent: genesis_header.hash(),
        timestamp: genesis_header.timestamp + 12,
        fee_recipient: H160::zero(),
        random: H256::zero(),
        withdrawals: Some(vec![Withdrawal {
            index: 0,
            validator_index: 0,
            address: recipient,
            amount: amount_gwei,
        }]),
        beacon_root: Some(H256::zero()),
        slot_number: Some(genesis_header.number + 1),
        version: 1,
        elasticity_multiplier: ELASTICITY_MULTIPLIER,
        gas_ceil: DEFAULT_BUILDER_GAS_CEIL,
    };
    let payload = create_payload(&args, &store, Bytes::new()).unwrap();
    let block = blockchain.build_payload(payload).unwrap().payload;
    assert!(
        block.body.transactions.is_empty(),
        "the withdrawal must be the block's only state change"
    );

    blockchain
        .add_block(block.clone())
        .expect("withdrawal-only block should import under the binary-tree flag");

    let snapshot = store
        .get_pbt_state(block.hash())
        .unwrap()
        .expect("snapshot must exist for the withdrawal block");
    assert_eq!(
        snapshot.accounts.get(&recipient).map(|a| a.balance),
        Some(U256::from(amount_gwei) * U256::from(1_000_000_000u64)),
        "the snapshot must credit the withdrawal recipient (Gwei -> wei)"
    );
    assert_eq!(
        block.header.state_root,
        snapshot
            .compute_root()
            .expect("snapshot root computation should succeed"),
        "the header must commit to the snapshot's binary root"
    );
}

/// Flag-variant of `canonical_commit_gate_tests::forkchoice_flushes_committable_backlog_and_prunes_genesis`:
/// the safe-commit gate compares against MPT layer roots, so under the flag
/// it must resolve the target block's root through the side registry — the
/// raw header root is a PBT root that matches no layer, which would leave
/// the committable backlog unflushed forever (and genesis never pruned).
///
/// Import `> DB_COMMIT_THRESHOLD` (128) blocks via `add_block` without any
/// forkchoice update, then canonicalize with a single FCU (the `import`
/// flow). The flush must advance the on-disk MPT past genesis: the genesis
/// MPT lookup root becomes unserveable while the head's stays available.
///
/// RocksDB-only for the same reason as the unflagged twin: the InMemory
/// commit threshold (10000) is unreachable with this few blocks.
#[cfg(feature = "rocksdb")]
#[tokio::test]
async fn binary_tree_forkchoice_flushes_backlog_through_mpt_lookup_roots() {
    // Strictly greater than DB_COMMIT_THRESHOLD so the canonical block at
    // `head - DB_COMMIT_THRESHOLD` exists and is a committable layer.
    const BLOCKS: u64 = ethrex_storage::DB_COMMIT_THRESHOLD as u64 + 2;

    let sk = test_secret_key();
    let sender = sender_from_key(&sk);
    let signer: Signer = LocalSigner::new(sk).into();

    let genesis = load_genesis_fixture("l1-binarytree.json", sender, &[]);
    let chain_id = genesis.config.chain_id;
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().to_str().unwrap();

    let mut store = Store::new(path, EngineType::RocksDB).expect("rocksdb store");
    store
        .add_initial_state(genesis)
        .await
        .expect("genesis init");
    let blockchain = Blockchain::default_with_store(store.clone());

    let genesis_header = store.get_block_header(0).unwrap().unwrap();
    let genesis_mpt_root = store
        .get_mpt_lookup_root(genesis_header.hash())
        .unwrap()
        .expect("genesis MPT lookup root must be registered");
    assert!(
        store.has_state_root(genesis_mpt_root).unwrap(),
        "precondition: the genesis MPT state must be present after init"
    );

    // Import BLOCKS blocks via `add_block`, WITHOUT any forkchoice_update
    // (mirrors the `import` command).
    let mut parent = genesis_header;
    let mut canonical: Vec<(u64, H256)> = Vec::with_capacity(BLOCKS as usize);
    for nonce in 0..BLOCKS {
        let tx = transfer_tx(
            chain_id,
            nonce,
            test_recipient(),
            U256::from(1_000_000u64),
            &signer,
        )
        .await;
        blockchain.add_transaction_to_pool(tx).await.unwrap();

        let block = build_block(&store, &blockchain, &parent).await;
        assert_eq!(block.body.transactions.len(), 1);
        blockchain
            .add_block(block.clone())
            .expect("block should import under the binary-tree flag");
        blockchain
            .remove_block_transactions_from_pool(&block)
            .unwrap();
        canonical.push((block.header.number, block.hash()));
        parent = block.header;
    }
    let head_mpt_root = store
        .get_mpt_lookup_root(parent.hash())
        .unwrap()
        .expect("head MPT lookup root must be registered");

    // Nothing flushed yet: no FCU ran, so the safe-commit cell is still zero.
    assert!(
        store.has_state_root(genesis_mpt_root).unwrap(),
        "before forkchoice_update nothing is flushed: genesis must still be present"
    );

    // Canonicalize the whole chain with one FCU, exactly like `import` does.
    let (head_number, head_hash) = canonical.pop().expect("at least one block imported");
    store
        .forkchoice_update(
            canonical,
            head_number,
            head_hash,
            Some(head_number),
            Some(head_number),
        )
        .await
        .expect("forkchoice_update");
    store
        .wait_for_persistence_idle()
        .await
        .expect("wait_for_persistence_idle");

    // The gate resolved the target block's MPT root through the registry and
    // flushed the backlog: the on-disk MPT advanced past genesis.
    assert!(
        !store.has_state_root(genesis_mpt_root).unwrap(),
        "after forkchoice_update the committable backlog must flush and prune genesis \
         (regression: a raw PBT header root matches no MPT layer, so nothing ever commits)"
    );
    assert!(
        store.has_state_root(head_mpt_root).unwrap(),
        "recent (head) MPT state must remain serveable after the flush"
    );
}

/// ENGINE-level fork choice under the flag: `apply_fork_choice` probes
/// whether the head's state is constructible before canonicalizing, and
/// under the flag the header's `state_root` is the binary-trie root — the
/// probe must resolve through the MPT lookup registry instead of feeding
/// the raw header root to `has_state_root` (which can never match an MPT
/// layer and would answer every FCU with `StateNotReachable`).
///
/// Chain of 2 canonicalized, block 3 imported but NOT canonicalized: the
/// FCU on block 3 must succeed and genuinely advance the canonical head.
#[tokio::test]
async fn binary_tree_apply_fork_choice_resolves_state_through_registry() {
    let (store, blockchain, blocks) = build_and_import_chain(2).await;

    // Import block 3 without canonicalizing it, so the fork choice below
    // has real work to do (head advances 2 -> 3 through the probe).
    let block3 = build_block(&store, &blockchain, &blocks[1].header).await;
    blockchain
        .add_block(block3.clone())
        .expect("block 3 should import under the binary-tree flag");

    let head = apply_fork_choice(&store, block3.hash(), H256::zero(), H256::zero())
        .await
        .expect(
            "fork choice must resolve state reachability through the MPT lookup registry \
             under the binary-tree flag (raw PBT header roots match no MPT layer)",
        );
    assert_eq!(head.hash(), block3.hash(), "FCU must return the new head");
    assert_eq!(
        store.get_latest_block_number().await.unwrap(),
        3,
        "canonical head must advance to block 3"
    );
    assert_eq!(
        store.get_canonical_block_hash(3).await.unwrap(),
        Some(block3.hash()),
        "block 3 must be the canonical block at height 3"
    );
}

// Deliberate coverage skips (recorded per the state-commitment plan):
//
// - Off-flag regression test: SKIPPED. Flag-off invariance is already proven
//   by the full flag-off integration suite (every non-binary-tree test runs
//   with the flag off), and the targeted MPT-vs-PBT divergence assert inside
//   `binary_tree_chain_of_three_commits_binary_roots` builds the identical
//   block on the unflagged `l1-bal.json` twin and requires the committed
//   roots to differ. A dedicated twin-chain test would be redundant.
//
// - Balance-cap (>= 2^128) integration test: SKIPPED. The cap is unit-covered
//   by `pbt_state.rs::balance_must_fit_the_basic_data_field`, and it is
//   unconstructible via valid execution here: the fixture's total genesis
//   supply (~1.95e29 wei) is ~9 orders of magnitude below 2^128, so no chain
//   of valid transactions can credit any account past the cap. A
//   malformed-genesis construction would only exercise the documented
//   `Genesis::compute_state_root` expect panic (a genesis-validation concern,
//   not the block-import cap surfacing).
