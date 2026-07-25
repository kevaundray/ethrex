use serde_json::Value;
use tracing::debug;

use crate::rpc::{RpcApiContext, RpcHandler};
use crate::types::account_proof::{
    AccountProof, BINARY_ACCOUNT_PROOF_FORMAT, BinaryAccountLeafProofs, BinaryAccountProof,
    BinaryStorageProof, BinaryTreeKeyProof, StorageProof,
};
use crate::types::block_identifier::{BlockIdentifierOrHash, BlockTag};
use crate::utils::RpcErr;
use ethrex_binary_trie::embedding::{
    BASIC_DATA_VERSION, address20_to_address32, decode_basic_data, get_tree_key_for_basic_data,
    get_tree_key_for_code_hash, get_tree_key_for_storage_slot,
};
use ethrex_binary_trie::trie::BinaryTrie;
use ethrex_common::types::BlockHeader;
use ethrex_common::{Address, BigEndianHash, H256, U256, serde_utils};

pub struct GetBalanceRequest {
    pub address: Address,
    pub block: BlockIdentifierOrHash,
}

pub struct GetCodeRequest {
    pub address: Address,
    pub block: BlockIdentifierOrHash,
}

pub struct GetStorageAtRequest {
    pub address: Address,
    pub storage_slot: H256,
    pub block: BlockIdentifierOrHash,
}

pub struct GetTransactionCountRequest {
    pub address: Address,
    pub block: BlockIdentifierOrHash,
}

pub struct GetProofRequest {
    pub address: Address,
    pub storage_keys: Vec<H256>,
    pub block: BlockIdentifierOrHash,
}

impl RpcHandler for GetBalanceRequest {
    fn parse(params: &Option<Vec<Value>>) -> Result<GetBalanceRequest, RpcErr> {
        let params = params
            .as_ref()
            .ok_or(RpcErr::BadParams("No params provided".to_owned()))?;
        if params.len() != 2 {
            return Err(RpcErr::BadParams("Expected 2 params".to_owned()));
        };
        Ok(GetBalanceRequest {
            address: serde_json::from_value(params[0].clone())?,
            block: BlockIdentifierOrHash::parse(params[1].clone(), 1)?,
        })
    }
    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
        debug!(
            "Requested balance of account {} at block {}",
            self.address, self.block
        );

        let Some(block_number) = self.block.resolve_block_number(&context.storage).await? else {
            return Err(RpcErr::Internal(
                "Could not resolve block number".to_owned(),
            )); // Should we return Null here?
        };

        let account = context
            .storage
            .get_account_info(block_number, self.address)
            .await?;
        let balance = account.map(|acc| acc.balance).unwrap_or_default();

        serde_json::to_value(format!("{balance:#x}"))
            .map_err(|error| RpcErr::Internal(error.to_string()))
    }
}

impl RpcHandler for GetCodeRequest {
    fn parse(params: &Option<Vec<Value>>) -> Result<GetCodeRequest, RpcErr> {
        let params = params
            .as_ref()
            .ok_or(RpcErr::BadParams("No params provided".to_owned()))?;
        if params.len() != 2 {
            return Err(RpcErr::BadParams("Expected 2 params".to_owned()));
        };
        Ok(GetCodeRequest {
            address: serde_json::from_value(params[0].clone())?,
            block: BlockIdentifierOrHash::parse(params[1].clone(), 1)?,
        })
    }
    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
        debug!(
            "Requested code of account {} at block {}",
            self.address, self.block
        );

        let Some(block_number) = self.block.resolve_block_number(&context.storage).await? else {
            return Err(RpcErr::Internal(
                "Could not resolve block number".to_owned(),
            )); // Should we return Null here?
        };

        let code = context
            .storage
            .get_code_by_account_address(block_number, self.address)
            .await?
            .map(|c| c.code_bytes())
            .unwrap_or_default();

        serde_json::to_value(format!("0x{code:x}"))
            .map_err(|error| RpcErr::Internal(error.to_string()))
    }
}

impl RpcHandler for GetStorageAtRequest {
    fn parse(params: &Option<Vec<Value>>) -> Result<GetStorageAtRequest, RpcErr> {
        let params = params
            .as_ref()
            .ok_or(RpcErr::BadParams("No params provided".to_owned()))?;
        if params.len() != 3 {
            return Err(RpcErr::BadParams("Expected 3 params".to_owned()));
        };
        let storage_slot_u256 = serde_utils::u256::deser_hex_or_dec_str(params[1].clone())?;
        Ok(GetStorageAtRequest {
            address: serde_json::from_value(params[0].clone())?,
            storage_slot: H256::from_uint(&storage_slot_u256),
            block: BlockIdentifierOrHash::parse(params[2].clone(), 2)?,
        })
    }
    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
        debug!(
            "Requested storage slot {} of account {} at block {}",
            self.storage_slot, self.address, self.block
        );

        let Some(block_number) = self.block.resolve_block_number(&context.storage).await? else {
            return Err(RpcErr::Internal(
                "Could not resolve block number".to_owned(),
            )); // Should we return Null here?
        };

        let storage_value = context
            .storage
            .get_storage_at(block_number, self.address, self.storage_slot)?
            .unwrap_or_default();
        let storage_value = H256::from_uint(&storage_value);
        serde_json::to_value(format!("{storage_value:#x}"))
            .map_err(|error| RpcErr::Internal(error.to_string()))
    }
}

impl RpcHandler for GetTransactionCountRequest {
    fn parse(params: &Option<Vec<Value>>) -> Result<GetTransactionCountRequest, RpcErr> {
        let params = params
            .as_ref()
            .ok_or(RpcErr::BadParams("No params provided".to_owned()))?;
        if params.len() != 2 {
            return Err(RpcErr::BadParams("Expected 2 params".to_owned()));
        };
        Ok(GetTransactionCountRequest {
            address: serde_json::from_value(params[0].clone())?,
            block: BlockIdentifierOrHash::parse(params[1].clone(), 1)?,
        })
    }
    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
        debug!(
            "Requested nonce of account {} at block {}",
            self.address, self.block
        );

        // Resolve the canonical nonce for the requested block first. For the
        // `Pending` tag this resolves to the latest block.
        let Some(block_number) = self.block.resolve_block_number(&context.storage).await? else {
            return serde_json::to_value("0x0")
                .map_err(|error| RpcErr::Internal(error.to_string()));
        };
        let account_nonce = context
            .storage
            .get_nonce_by_account_address(block_number, self.address)
            .await?
            .unwrap_or_default();

        // For `Pending`, the mempool may advance the nonce past the on-chain
        // value, but it must never report a value below it. Stale txs left in
        // the pool can otherwise yield a pending nonce lower than `latest`.
        let nonce = if self.block == BlockTag::Pending {
            match context.blockchain.mempool.get_nonce(&self.address)? {
                Some(mempool_nonce) => mempool_nonce.max(account_nonce),
                None => account_nonce,
            }
        } else {
            account_nonce
        };

        serde_json::to_value(format!("0x{nonce:x}"))
            .map_err(|error| RpcErr::Internal(error.to_string()))
    }
}

impl RpcHandler for GetProofRequest {
    fn parse(params: &Option<Vec<Value>>) -> Result<Self, RpcErr> {
        let params = params
            .as_ref()
            .ok_or(RpcErr::BadParams("No params provided".to_owned()))?;
        if params.len() != 3 {
            return Err(RpcErr::BadParams("Expected 3 params".to_owned()));
        };
        let storage_keys: Vec<U256> = serde_json::from_value(params[1].clone())?;
        let storage_keys = storage_keys.iter().map(H256::from_uint).collect();
        Ok(GetProofRequest {
            address: serde_json::from_value(params[0].clone())?,
            storage_keys,
            block: BlockIdentifierOrHash::parse(params[2].clone(), 2)?,
        })
    }

    async fn handle(&self, context: RpcApiContext) -> Result<Value, RpcErr> {
        let storage = &context.storage;
        debug!(
            "Requested proof for account {} at block {} with storage keys: {:?}",
            self.address, self.block, self.storage_keys
        );
        let Some(block_number) = self.block.resolve_block_number(storage).await? else {
            return Ok(Value::Null);
        };
        let Some(header) = storage.get_block_header(block_number)? else {
            return Ok(Value::Null);
        };
        // Experimental EIP-8297: under the flag the header commits to the
        // binary tree, which the MPT proof below cannot prove against, so
        // the response switches to the pbt-getproof-v1 shape. Flag off,
        // everything past this point is untouched.
        if storage.get_chain_config().enable_binary_tree_at_genesis {
            return self.handle_binary_tree(&context, &header);
        }
        // Create account proof
        let Some(account_proof) = storage
            .get_account_proof(header.state_root, self.address, &self.storage_keys)
            .await?
        else {
            return Err(RpcErr::Internal("Could not get account proof".to_owned()));
        };
        let storage_proof = account_proof
            .storage_proof
            .into_iter()
            .map(|sp| StorageProof {
                key: sp.key.into_uint(),
                value: sp.value,
                proof: sp.proof,
            })
            .collect();
        let account = account_proof.account;
        let account_proof = AccountProof {
            account_proof: account_proof.proof,
            address: self.address,
            balance: account.balance,
            code_hash: account.code_hash,
            nonce: account.nonce,
            storage_hash: account.storage_root,
            storage_proof,
        };
        serde_json::to_value(account_proof).map_err(|error| RpcErr::Internal(error.to_string()))
    }
}

impl GetProofRequest {
    /// `eth_getProof` against the binary-tree commitment
    /// (`pbt-getproof-v1`, see `docs/eip-draft-pbt-eth-getproof.md`):
    /// materializes the block's `PbtState` snapshot into a trie and
    /// serves per-tree-key preimage proofs for the account-header
    /// leaves and every requested slot. Inclusion and exclusion come
    /// from the same walk; absent leaves report `value: null` (or a
    /// zero quantity for storage) alongside their exclusion proof.
    fn handle_binary_tree(
        &self,
        context: &RpcApiContext,
        header: &BlockHeader,
    ) -> Result<Value, RpcErr> {
        let block_hash = header.hash();
        // Snapshots are in-memory only (Seam A registry): blocks
        // imported before a restart, or beyond a future pruning
        // horizon, have none — error clearly instead of proving
        // against the wrong state.
        let Some(pbt_state) = context.storage.get_pbt_state(block_hash)? else {
            return Err(RpcErr::Internal(format!(
                "no binary-tree state snapshot for block {block_hash:#x}: the PbtState \
                 registry is in-memory (experimental EIP-8297) — re-import the chain from \
                 genesis or seed a snapshot via Store::put_pbt_state"
            )));
        };
        let trie = pbt_state
            .build_trie()
            .map_err(|e| RpcErr::Internal(format!("failed to build binary trie: {e}")))?;

        let address32 = address20_to_address32(self.address);
        let basic_data = prove_tree_key(&trie, get_tree_key_for_basic_data(&address32));
        let code_hash_leaf = prove_tree_key(&trie, get_tree_key_for_code_hash(&address32));

        // Decoded conveniences only; the proven leaf values are
        // authoritative (absent leaves -> zero defaults).
        let (nonce, balance) = match basic_data
            .value
            .as_ref()
            .map(|leaf| decode_basic_data(&leaf.0))
        {
            // An unknown layout version must not be misread positionally:
            // zero the conveniences and let consumers decode the proven leaf.
            Some(decoded) if decoded.version == BASIC_DATA_VERSION => {
                (decoded.nonce, decoded.balance)
            }
            _ => (0, U256::zero()),
        };
        let code_hash = code_hash_leaf.value.unwrap_or_default();

        let storage_proof = self
            .storage_keys
            .iter()
            .map(|slot| {
                let key = slot.into_uint();
                let leaf = prove_tree_key(&trie, get_tree_key_for_storage_slot(&address32, key));
                BinaryStorageProof {
                    key,
                    value: leaf
                        .value
                        .map(|v| U256::from_big_endian(v.as_bytes()))
                        .unwrap_or_default(),
                    tree_key: leaf.tree_key,
                    proof: leaf.proof,
                }
            })
            .collect();

        let response = BinaryAccountProof {
            format: BINARY_ACCOUNT_PROOF_FORMAT,
            address: self.address,
            balance,
            nonce,
            code_hash,
            storage_hash: None,
            binary_account_proof: BinaryAccountLeafProofs {
                basic_data,
                code_hash: code_hash_leaf,
            },
            storage_proof,
        };
        serde_json::to_value(response).map_err(|error| RpcErr::Internal(error.to_string()))
    }
}

/// Look up and prove one tree key against `trie`, pairing the leaf
/// value (`None` when absent) with the matching inclusion/exclusion
/// proof from the same walk.
fn prove_tree_key(trie: &BinaryTrie, tree_key: Vec<u8>) -> BinaryTreeKeyProof {
    BinaryTreeKeyProof {
        value: trie.get(&tree_key).map(H256),
        proof: trie.prove(&tree_key),
        tree_key,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_get_storage_at_request_parse_hex_slot() {
        let params = Some(vec![
            json!("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            // Storage slot can be provided as hex string
            json!("0x1"),
            json!("latest"),
        ]);
        let request = GetStorageAtRequest::parse(&params).unwrap();

        let expected_address = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
            .parse()
            .unwrap();
        assert_eq!(request.address, expected_address);
        assert_eq!(request.storage_slot, H256::from_uint(&U256::from(1u64)));
        assert_eq!(request.block, BlockTag::Latest);
    }

    #[test]
    fn test_get_storage_at_request_parse_number_slot() {
        let params = Some(vec![
            json!("0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"),
            // Storage slot can be provided as number
            json!("1"),
            json!("latest"),
        ]);
        let request = GetStorageAtRequest::parse(&params).unwrap();

        let expected_address = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
            .parse()
            .unwrap();
        assert_eq!(request.address, expected_address);
        assert_eq!(request.storage_slot, H256::from_uint(&U256::from(1u64)));
        assert_eq!(request.block, BlockTag::Latest);
    }

    /// Builds an in-memory store whose genesis pre-sets `address`'s nonce, and a
    /// context over it. Mirrors `setup_store` but lets the test fix the on-chain
    /// nonce without executing blocks.
    async fn context_with_account_nonce(address: Address, nonce: u64) -> RpcApiContext {
        use crate::test_utils::{TEST_GENESIS, default_context_with_storage};
        use ethrex_common::types::{Genesis, GenesisAccount};
        use ethrex_storage::{EngineType, Store};

        let mut genesis: Genesis = serde_json::from_str(TEST_GENESIS).unwrap();
        genesis.alloc.insert(
            address,
            GenesisAccount {
                code: Default::default(),
                storage: Default::default(),
                balance: U256::from(10u64).pow(U256::from(20u64)),
                nonce,
            },
        );
        let mut store = Store::new("", EngineType::InMemory).unwrap();
        store.add_initial_state(genesis).await.unwrap();
        default_context_with_storage(store).await
    }

    fn nonce_request(address: Address, tag: BlockTag) -> GetTransactionCountRequest {
        use crate::types::block_identifier::BlockIdentifier;
        GetTransactionCountRequest {
            address,
            block: BlockIdentifierOrHash::Identifier(BlockIdentifier::Tag(tag)),
        }
    }

    fn stale_mempool_tx(address: Address, nonce: u64, context: &RpcApiContext) {
        use ethrex_common::types::{LegacyTransaction, MempoolTransaction, Transaction, TxKind};
        let tx = Transaction::LegacyTransaction(LegacyTransaction {
            nonce,
            gas: 21000,
            to: TxKind::Create,
            ..Default::default()
        });
        context
            .blockchain
            .mempool
            .add_transaction(
                H256::random(),
                address,
                MempoolTransaction::new(tx, address),
                None,
                None,
            )
            .unwrap();
    }

    /// Regression: a stale tx left in the pool with a nonce below the account's
    /// on-chain nonce must not make `pending` report a value lower than `latest`.
    #[tokio::test]
    async fn pending_nonce_is_clamped_to_latest() {
        let address = Address::from_low_u64_be(0xabcd);
        let context = context_with_account_nonce(address, 0x59).await;
        stale_mempool_tx(address, 0x50, &context);

        let latest = nonce_request(address, BlockTag::Latest)
            .handle(context.clone())
            .await
            .unwrap();
        let pending = nonce_request(address, BlockTag::Pending)
            .handle(context.clone())
            .await
            .unwrap();

        assert_eq!(latest, json!("0x59"));
        assert_eq!(pending, json!("0x59"));
    }

    /// A pending tx above the on-chain nonce still advances `pending`.
    #[tokio::test]
    async fn pending_nonce_advances_past_latest() {
        let address = Address::from_low_u64_be(0xabcd);
        let context = context_with_account_nonce(address, 0x59).await;
        // Highest pending nonce is 0x59, so the next usable nonce is 0x5a.
        stale_mempool_tx(address, 0x59, &context);

        let pending = nonce_request(address, BlockTag::Pending)
            .handle(context.clone())
            .await
            .unwrap();

        assert_eq!(pending, json!("0x5a"));
    }
}
