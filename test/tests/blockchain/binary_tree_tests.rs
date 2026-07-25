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
    payload::{BuildPayloadArgs, create_payload},
};
use ethrex_common::{
    Address, H160, H256, U256,
    types::{
        Block, BlockHeader, DEFAULT_BUILDER_GAS_CEIL, EIP1559Transaction, ELASTICITY_MULTIPLIER,
        GenesisAccount, Transaction, TxKind,
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
const TEST_GAS_LIMIT: u64 = 100_000;

fn test_secret_key() -> SecretKey {
    SecretKey::from_slice(&hex::decode(TEST_PRIVATE_KEY).unwrap()).unwrap()
}

fn sender_from_key(sk: &SecretKey) -> Address {
    LocalSigner::new(*sk).address
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// Load the given genesis fixture, inject `sender` with a large balance,
/// and return an in-memory store together with the chain id.
///
/// `fixtures/genesis/l1-binarytree.json` is `l1-bal.json` plus
/// `enableBinaryTreeAtGenesis`, so the same chain id / fork schedule /
/// timestamps apply to both and blocks built on each are comparable.
async fn setup_store_from_fixture(fixture: &str, sender: Address) -> (Store, u64) {
    let file = File::open(workspace_root().join("fixtures/genesis").join(fixture))
        .expect("Failed to open genesis file");
    let reader = BufReader::new(file);
    let mut genesis: ethrex_common::types::Genesis =
        serde_json::from_reader(reader).expect("Failed to deserialize genesis file");

    let chain_id = genesis.config.chain_id;

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

    let mut store =
        Store::new("store.db", EngineType::InMemory).expect("Failed to build DB for testing");

    store
        .add_initial_state(genesis)
        .await
        .expect("Failed to add genesis state");

    (store, chain_id)
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

/// Build and sign a plain value-transfer transaction.
async fn transfer_tx(
    chain_id: u64,
    nonce: u64,
    to: Address,
    value: U256,
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
        data: Bytes::new(),
        ..Default::default()
    });
    tx.sign_inplace(signer).await.unwrap();
    tx
}

/// Build a chain of `n` blocks under the binary-tree flag, one value
/// transfer per block, importing each via `add_block` (exercises
/// `store_block`) after building it via the payload builder (exercises
/// `finalize_payload`). Returns the store and the built blocks.
async fn build_and_import_chain(n: u64) -> (Store, Blockchain, Vec<Block>) {
    let sk = test_secret_key();
    let sender = sender_from_key(&sk);
    let signer: Signer = LocalSigner::new(sk).into();

    let (store, chain_id) = setup_store_from_fixture("l1-binarytree.json", sender).await;
    let blockchain = Blockchain::default_with_store(store.clone());
    let mut parent = store.get_block_header(0).unwrap().unwrap();

    let recipient = Address::from_low_u64_be(0xD00D);
    let mut blocks = Vec::new();
    for nonce in 0..n {
        let tx = transfer_tx(
            chain_id,
            nonce,
            recipient,
            U256::from(1_000_000u64),
            &signer,
        )
        .await;
        blockchain
            .add_transaction_to_pool(tx)
            .await
            .expect("transfer tx should enter pool");

        let block = build_block(&store, &blockchain, &parent).await;
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

    let recipient = Address::from_low_u64_be(0xD00D);
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

    let recipient = Address::from_low_u64_be(0xD00D);
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
