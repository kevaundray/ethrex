//! Shared helpers for the experimental EIP-8297 binary-tree suites
//! (`binary_tree_tests.rs`, `binary_tree_transition_tests.rs`): genesis
//! fixture loading, store setup, payload-built blocks, and signed
//! transfer/call transactions. Extracted into one module so the
//! genesis-flag suite and the scheduled-transition suite cannot drift
//! apart on chain construction.

use std::{fs::File, io::BufReader, path::PathBuf};

use bytes::Bytes;
use ethrex_blockchain::{
    Blockchain,
    payload::{BuildPayloadArgs, create_payload},
};
use ethrex_common::{
    Address, H160, H256, U256,
    types::{
        Block, BlockHeader, DEFAULT_BUILDER_GAS_CEIL, EIP1559Transaction, ELASTICITY_MULTIPLIER,
        Genesis, GenesisAccount, Transaction, TxKind,
    },
};
use ethrex_l2_rpc::signer::{LocalSigner, Signable, Signer};
use ethrex_storage::{EngineType, Store};
use secp256k1::SecretKey;

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

pub(crate) fn test_secret_key() -> SecretKey {
    SecretKey::from_slice(&hex::decode(TEST_PRIVATE_KEY).unwrap()).unwrap()
}

pub(crate) fn sender_from_key(sk: &SecretKey) -> Address {
    LocalSigner::new(*sk).address
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..")
}

/// Recipient of the value transfers built by the chain helpers.
pub(crate) fn test_recipient() -> Address {
    Address::from_low_u64_be(0xD00D)
}

/// Load the given genesis fixture, inject `sender` with a large balance
/// plus any `extra_accounts`, and return the genesis.
///
/// `fixtures/genesis/l1-binarytree.json` is `l1-bal.json` plus
/// `enableBinaryTreeAtGenesis`, so the same chain id / fork schedule /
/// timestamps apply to both and blocks built on each are comparable.
pub(crate) fn load_genesis_fixture(
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
pub(crate) async fn setup_store_from_genesis(genesis: Genesis) -> Store {
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
pub(crate) async fn setup_store_from_fixture(fixture: &str, sender: Address) -> (Store, u64) {
    let genesis = load_genesis_fixture(fixture, sender, &[]);
    let chain_id = genesis.config.chain_id;
    (setup_store_from_genesis(genesis).await, chain_id)
}

/// Build a block on top of `parent_header` using the payload builder,
/// including whatever transactions are currently in the mempool.
pub(crate) async fn build_block(
    store: &Store,
    blockchain: &Blockchain,
    parent_header: &BlockHeader,
) -> Block {
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
pub(crate) async fn signed_tx(
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
pub(crate) async fn transfer_tx(
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
pub(crate) async fn build_and_import_transfers(
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
            .expect("block should import");

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

/// Assert the import-side postconditions for every block that commits a
/// binary-trie root: a `PbtState` snapshot exists under the block hash and
/// the header's state root is that snapshot's binary-trie root.
pub(crate) fn assert_binary_snapshots(store: &Store, blocks: &[Block]) {
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
