//! SSZ container types for decoding stateless test fixture bytes.
//!
//! These match the SSZ schema from ethereum/execution-specs (amsterdam/stateless_ssz.py).

use ssz_rs::prelude::*;

// Max sizes from execution-specs stateless_ssz.py
const MAX_EXTRA_DATA_BYTES: usize = 32;
const MAX_BYTES_PER_TRANSACTION: usize = 1 << 30; // 2^30
const MAX_TRANSACTIONS_PER_PAYLOAD: usize = 1 << 20; // 2^20
const MAX_WITHDRAWALS_PER_PAYLOAD: usize = 1 << 16; // 2^16
const MAX_BLOB_COMMITMENTS_PER_BLOCK: usize = 4096;
const MAX_EXECUTION_REQUESTS: usize = 16;
const MAX_BYTES_PER_REQUEST: usize = 1 << 20; // 2^20
const MAX_BLOCK_ACCESS_LIST_BYTES: usize = 1 << 24; // 2^24
const MAX_WITNESS_NODES: usize = 1 << 20; // 2^20
const MAX_WITNESS_CODES: usize = 1 << 16; // 2^16
const MAX_WITNESS_HEADERS: usize = 256;
const MAX_BYTES_PER_WITNESS_NODE: usize = 1 << 20; // 2^20
const MAX_BYTES_PER_CODE: usize = 1 << 24; // 2^24
const MAX_BYTES_PER_HEADER: usize = 1 << 10; // 2^10
const MAX_PUBLIC_KEYS: usize = 1 << 20; // 2^20
const MAX_BYTES_PER_PUBLIC_KEY: usize = 48;

// Fixed sizes
const BYTES32: usize = 32;
const ADDRESS_SIZE: usize = 20;
const LOGS_BLOOM_SIZE: usize = 256;

// --- Output ---

#[derive(Debug, Default, SimpleSerialize)]
pub struct SszChainConfig {
    pub chain_id: u64,
}

#[derive(Debug, Default, SimpleSerialize)]
pub struct SszStatelessValidationResult {
    pub new_payload_request_root: Vector<u8, BYTES32>,
    pub successful_validation: bool,
    pub chain_config: SszChainConfig,
}

// --- Input ---

#[derive(Debug, Default, SimpleSerialize)]
pub struct SszWithdrawal {
    pub index: u64,
    pub validator_index: u64,
    pub address: Vector<u8, ADDRESS_SIZE>,
    pub amount: U256,
}

#[derive(Debug, Default, SimpleSerialize)]
pub struct SszExecutionPayload {
    pub parent_hash: Vector<u8, BYTES32>,
    pub fee_recipient: Vector<u8, ADDRESS_SIZE>,
    pub state_root: Vector<u8, BYTES32>,
    pub receipts_root: Vector<u8, BYTES32>,
    pub logs_bloom: Vector<u8, LOGS_BLOOM_SIZE>,
    pub prev_randao: Vector<u8, BYTES32>,
    pub block_number: u64,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub timestamp: u64,
    pub extra_data: List<u8, MAX_EXTRA_DATA_BYTES>,
    pub base_fee_per_gas: U256,
    pub block_hash: Vector<u8, BYTES32>,
    pub transactions: List<List<u8, MAX_BYTES_PER_TRANSACTION>, MAX_TRANSACTIONS_PER_PAYLOAD>,
    pub withdrawals: List<SszWithdrawal, MAX_WITHDRAWALS_PER_PAYLOAD>,
    pub blob_gas_used: u64,
    pub excess_blob_gas: u64,
    pub block_access_list: List<u8, MAX_BLOCK_ACCESS_LIST_BYTES>,
}

#[derive(Debug, Default, SimpleSerialize)]
pub struct SszNewPayloadRequest {
    pub execution_payload: SszExecutionPayload,
    pub versioned_hashes: List<Vector<u8, BYTES32>, MAX_BLOB_COMMITMENTS_PER_BLOCK>,
    pub parent_beacon_block_root: Vector<u8, BYTES32>,
    pub execution_requests: List<List<u8, MAX_BYTES_PER_REQUEST>, MAX_EXECUTION_REQUESTS>,
}

#[derive(Debug, Default, SimpleSerialize)]
pub struct SszExecutionWitness {
    pub state: List<List<u8, MAX_BYTES_PER_WITNESS_NODE>, MAX_WITNESS_NODES>,
    pub codes: List<List<u8, MAX_BYTES_PER_CODE>, MAX_WITNESS_CODES>,
    pub headers: List<List<u8, MAX_BYTES_PER_HEADER>, MAX_WITNESS_HEADERS>,
}

#[derive(Debug, Default, SimpleSerialize)]
pub struct SszStatelessInput {
    pub new_payload_request: SszNewPayloadRequest,
    pub witness: SszExecutionWitness,
    pub chain_config: SszChainConfig,
    pub public_keys: List<List<u8, MAX_BYTES_PER_PUBLIC_KEY>, MAX_PUBLIC_KEYS>,
}
