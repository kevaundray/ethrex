use bytes::Bytes;
use ethereum_types::{Address, H256};
use ethrex_common::types::{ChainConfig, DEFAULT_BUILDER_GAS_CEIL};
use ethrex_rpc::clients::{EngineClient, EngineClientError};
use ethrex_rpc::types::fork_choice::{ForkChoiceState, PayloadAttributesV3, PayloadAttributesV4};
use sha2::{Digest, Sha256};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::time::sleep;

#[allow(clippy::too_many_arguments)]
pub async fn start_block_producer(
    execution_client_auth_url: String,
    jwt_secret: Bytes,
    head_block_hash: H256,
    head_block_number: u64,
    chain_config: ChainConfig,
    max_tries: u32,
    block_production_interval_ms: u64,
    coinbase_address: Address,
) -> Result<(), EngineClientError> {
    let engine_client = EngineClient::new(&execution_client_auth_url, jwt_secret);

    // Sleep for one slot to avoid timestamp collision with the genesis block.
    sleep(Duration::from_millis(block_production_interval_ms)).await;

    let mut head_block_hash: H256 = head_block_hash;
    let parent_beacon_block_root = H256::zero();
    // EIP-7843: Amsterdam headers carry a slot number; with one block per
    // dev slot, block N sits in slot N. Only advanced when a block is
    // actually produced, so skipped slots reuse the number — the header
    // validation only requires the field to be present.
    let mut slot_number = head_block_number + 1;
    let mut tries = 0;
    while tries < max_tries {
        tracing::info!("Producing block");
        tracing::debug!("Head block hash: {head_block_hash:#x}");
        let fork_choice_state = ForkChoiceState {
            head_block_hash,
            safe_block_hash: head_block_hash,
            finalized_block_hash: head_block_hash,
        };

        let timestamp = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let is_amsterdam = chain_config.is_amsterdam_activated(timestamp);
        // Amsterdam payloads must be requested via FCU V4 (V3 attributes lack
        // the mandatory EIP-7843 slot number and execution-apis#796 target
        // gas limit, and the engine API rejects V3 for Amsterdam timestamps);
        // earlier forks must keep using V3, which V4 in turn rejects.
        let (fcu_endpoint, fork_choice_result) = if is_amsterdam {
            let payload_attributes = PayloadAttributesV4 {
                timestamp,
                prev_randao: H256::zero(),
                suggested_fee_recipient: coinbase_address,
                parent_beacon_block_root: Some(parent_beacon_block_root),
                withdrawals: Some(Vec::new()),
                slot_number,
                target_gas_limit: DEFAULT_BUILDER_GAS_CEIL,
            };
            (
                "engine_forkchoiceUpdatedV4",
                engine_client
                    .engine_forkchoice_updated_v4(fork_choice_state, Some(payload_attributes))
                    .await,
            )
        } else {
            let payload_attributes = PayloadAttributesV3 {
                timestamp,
                prev_randao: H256::zero(),
                suggested_fee_recipient: coinbase_address,
                parent_beacon_block_root: Some(parent_beacon_block_root),
                withdrawals: Some(Vec::new()),
            };
            (
                "engine_forkchoiceUpdatedV3",
                engine_client
                    .engine_forkchoice_updated_v3(fork_choice_state, Some(payload_attributes))
                    .await,
            )
        };
        let fork_choice_response = match fork_choice_result {
            Ok(response) => {
                tracing::debug!("{fcu_endpoint} response: {response:?}");
                response
            }
            Err(error) => {
                tracing::error!(
                    "Failed to produce block: error sending {fcu_endpoint} with PayloadAttributes: {error}"
                );
                sleep(Duration::from_millis(300)).await;
                tries += 1;
                continue;
            }
        };
        let Some(payload_id) = fork_choice_response.payload_id else {
            tracing::error!("Failed to produce block: payload_id is None in ForkChoiceResponse");
            sleep(Duration::from_millis(300)).await;
            tries += 1;
            continue;
        };

        // Wait to retrieve the payload.
        // Note that this makes getPayload failures result in skipped blocks.
        sleep(Duration::from_millis(block_production_interval_ms)).await;

        // Amsterdam payloads must be retrieved via getPayloadV6 (V5 rejects
        // Amsterdam timestamps); pre-Amsterdam forks keep using V5.
        let (get_payload_endpoint, get_payload_result) = if is_amsterdam {
            (
                "engine_getPayloadV6",
                engine_client.engine_get_payload_v6(payload_id).await,
            )
        } else {
            (
                "engine_getPayloadV5",
                engine_client.engine_get_payload_v5(payload_id).await,
            )
        };
        let execution_payload_response = match get_payload_result {
            Ok(response) => {
                tracing::debug!("{get_payload_endpoint} response: {response:?}");
                response
            }
            Err(error) => {
                tracing::error!(
                    "Failed to produce block: error sending {get_payload_endpoint}: {error}"
                );
                sleep(Duration::from_millis(300)).await;
                tries += 1;
                continue;
            }
        };
        let execution_payload = execution_payload_response.execution_payload;
        let versioned_hashes: Vec<H256> = execution_payload_response
            .blobs_bundle
            .unwrap_or_default()
            .commitments
            .iter()
            .map(|commitment| {
                let mut hasher = Sha256::new();
                hasher.update(commitment);
                let mut hash = hasher.finalize();
                // https://eips.ethereum.org/EIPS/eip-4844 -> kzg_to_versioned_hash
                hash[0] = 0x01;
                H256::from_slice(&hash)
            })
            .collect();

        // Amsterdam+ payloads carry a Block Access List and MUST use newPayloadV5;
        // earlier forks use V4, which rejects the BAL field.
        let is_amsterdam = execution_payload.block_access_list.is_some();
        let endpoint = if is_amsterdam {
            "engine_newPayloadV5"
        } else {
            "engine_newPayloadV4"
        };
        let new_payload_result = if is_amsterdam {
            engine_client
                .engine_new_payload_v5(
                    execution_payload,
                    versioned_hashes,
                    parent_beacon_block_root,
                )
                .await
        } else {
            engine_client
                .engine_new_payload_v4(
                    execution_payload,
                    versioned_hashes,
                    parent_beacon_block_root,
                )
                .await
        };
        let payload_status = match new_payload_result {
            Ok(response) => {
                tracing::debug!("{endpoint} response: {response:?}");
                response
            }
            Err(error) => {
                tracing::error!("Failed to produce block: error sending {endpoint}: {error}");
                sleep(Duration::from_millis(300)).await;
                tries += 1;
                continue;
            }
        };
        let produced_block_hash = if let Some(latest_valid_hash) = payload_status.latest_valid_hash
        {
            latest_valid_hash
        } else {
            tracing::error!(
                "Failed to produce block: latest_valid_hash is None in PayloadStatus: {payload_status:?}"
            );
            sleep(Duration::from_millis(300)).await;
            tries += 1;
            continue;
        };
        tracing::info!("Produced block {produced_block_hash:#x}");

        head_block_hash = produced_block_hash;
        slot_number += 1;
        // Reset the failure counter on success so `max_tries` bounds CONSECUTIVE failures,
        // not cumulative ones over the node's lifetime (otherwise a long-lived dev node
        // with occasional transient hiccups would eventually abort).
        tries = 0;
    }
    Err(EngineClientError::SystemFailed(format!("{max_tries}")))
}
