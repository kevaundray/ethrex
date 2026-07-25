use ethrex_common::{Address, H256, U256, serde_utils};
use serde::{Serialize, Serializer, ser::SerializeSeq};

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountProof {
    #[serde(serialize_with = "serialize_proofs")]
    pub account_proof: Vec<Vec<u8>>,
    pub address: Address,
    pub balance: U256,
    pub code_hash: H256,
    #[serde(with = "serde_utils::u64::hex_str")]
    pub nonce: u64,
    pub storage_hash: H256,
    pub storage_proof: Vec<StorageProof>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StorageProof {
    pub key: U256,
    #[serde(serialize_with = "serialize_proofs")]
    pub proof: Vec<Vec<u8>>,
    pub value: U256,
}

pub fn serialize_proofs<S>(value: &Vec<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    let mut seq_serializer = serializer.serialize_seq(Some(value.len()))?;
    for encoded_node in value {
        seq_serializer.serialize_element(&format!("0x{}", hex::encode(encoded_node)))?;
    }
    seq_serializer.end()
}

fn serialize_hex_bytes<S>(value: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&format!("0x{}", hex::encode(value)))
}

/// Version tag of the experimental EIP-8297 `eth_getProof` response
/// shape served under `enableBinaryTreeAtGenesis`. Consumers MUST
/// reject unknown strings; EIP-8297's eventual canonical witness
/// format supersedes this via a new tag. Spec:
/// `docs/eip-draft-pbt-eth-getproof.md`.
pub const BINARY_ACCOUNT_PROOF_FORMAT: &str = "pbt-getproof-v1";

/// `eth_getProof` response for a Partitioned-Binary-Tree-committed
/// chain (`pbt-getproof-v1`). Replaces [`AccountProof`] under the
/// flag only; the MPT shape is untouched flag-off.
///
/// `balance`/`nonce`/`code_hash` are decoded *conveniences* — the
/// leaf values inside the proofs are authoritative, and account
/// nonexistence is signaled by `value: null` on both account leaves,
/// with their proofs then being exclusion proofs.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BinaryAccountProof {
    /// Always [`BINARY_ACCOUNT_PROOF_FORMAT`].
    pub format: &'static str,
    pub address: Address,
    /// From the basic-data leaf; zero when the account is absent.
    pub balance: U256,
    /// From the basic-data leaf; zero when the account is absent.
    #[serde(with = "serde_utils::u64::hex_str")]
    pub nonce: u64,
    /// The code-hash leaf value; `0x00…00` when the leaf is absent
    /// (no leaf attests to any code hash, not even the empty-code
    /// keccak).
    pub code_hash: H256,
    /// Always `null`: the unified tree has no per-account storage
    /// root. Kept (rather than dropped) so consumers fail loudly
    /// instead of misreading a stale field.
    pub storage_hash: Option<H256>,
    pub binary_account_proof: BinaryAccountLeafProofs,
    pub storage_proof: Vec<BinaryStorageProof>,
}

/// Proofs for the two account-header leaves that replace the MPT's
/// single RLP account record.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BinaryAccountLeafProofs {
    pub basic_data: BinaryTreeKeyProof,
    pub code_hash: BinaryTreeKeyProof,
}

/// One tree key's proof: the derived key (echoed so consumers can
/// cross-check the derivation), the 32-byte leaf value or `null` when
/// absent, and the ordered node preimages root→terminal.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BinaryTreeKeyProof {
    #[serde(serialize_with = "serialize_hex_bytes")]
    pub tree_key: Vec<u8>,
    pub value: Option<H256>,
    #[serde(serialize_with = "serialize_proofs")]
    pub proof: Vec<Vec<u8>>,
}

/// One requested storage slot's proof. `value` keeps the MPT
/// method's quantity semantics: zero means the leaf is absent (PBT
/// state never stores zero-valued slots) and `proof` is then an
/// exclusion proof; non-zero demands inclusion of the 32-byte
/// big-endian encoding of `value`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BinaryStorageProof {
    /// The requested slot key, echoed as given.
    pub key: U256,
    #[serde(serialize_with = "serialize_hex_bytes")]
    pub tree_key: Vec<u8>,
    pub value: U256,
    #[serde(serialize_with = "serialize_proofs")]
    pub proof: Vec<Vec<u8>>,
}
