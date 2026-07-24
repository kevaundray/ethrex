//! EIP-8297 Ethereum state embedding: maps accounts, storage slots and
//! contract code onto binary-tree keys and 32-byte leaf values.
//!
//! Account and storage tries are merged into the single key/value tree
//! implemented in [`crate::trie`], which also holds contract code.
//!
//! The first byte of every key is a **zone** identifier labeling the
//! category of state the key holds: account headers live in
//! [`ACCOUNT_ZONE`], content-addressed overflow code in [`CODE_ZONE`],
//! and overflow storage in [`STORAGE_ZONE`]. Keys are variable length,
//! but every key of a zone has the same length, keeping keys
//! prefix-free as the tree requires.
//!
//! A key's **stem** is every byte except its final sub-index byte.
//! Keys sharing a stem form one group of up to [`STEM_SUBTREE_WIDTH`]
//! co-located values, all reachable through the same branch of the
//! tree. This keeps data that is accessed together cheap to prove: an
//! account's header stem holds its basic data, code hash, first
//! storage slots, and first code chunks, so one proof path covers
//! them all.

use ethereum_types::{H160, H256, U256};

use crate::trie::node::blake3_hash;

/// Sub-index of the account header leaf packing version, code size,
/// nonce, and balance.
pub const BASIC_DATA_LEAF_KEY: u8 = 0;

/// Version of the basic data leaf layout, packed as the leaf's first
/// byte by [`encode_basic_data`]. A future change to the layout bumps
/// the version so readers can tell the encodings apart.
pub const BASIC_DATA_VERSION: u8 = 0;

/// Sub-index of the account header leaf holding the code hash.
pub const CODE_HASH_LEAF_KEY: u8 = 1;

/// Sub-index of storage slot `0` within the account header stem.
/// Slots `0` through `63` live in the header.
pub const HEADER_STORAGE_OFFSET: u64 = 64;

/// Sub-index of code chunk `0` within the account header stem.
/// Chunks `0` through `127` live in the header.
pub const CODE_OFFSET: u64 = 128;

/// Maximum number of values grouped under a single stem: the size of
/// the sub-index byte's space.
pub const STEM_SUBTREE_WIDTH: u64 = 256;

/// Zone byte of account header stems.
pub const ACCOUNT_ZONE: u8 = 0;

/// Zone byte of content-addressed overflow code stems.
pub const CODE_ZONE: u8 = 1;

/// Zone byte of overflow storage stems.
///
/// Storage sits at the far end of the zone byte, leaving zones `2`
/// through `254` reserved for future state categories.
pub const STORAGE_ZONE: u8 = 255;

/// Length of every account zone key: the zone byte, a full address
/// digest, and the sub-index byte.
pub const ACCOUNT_KEY_LENGTH: usize = 34;

/// Length of every code zone key: the zone byte, a full digest of the
/// code hash and group index, and the sub-index byte.
pub const CODE_KEY_LENGTH: usize = 34;

/// Length of every storage zone key: the zone byte, two full digests
/// binding the account and its group index, and the sub-index byte.
pub const STORAGE_KEY_LENGTH: usize = 66;

/// 32-byte address used to key the tree. Legacy 20-byte addresses are
/// converted by [`address20_to_address32`].
pub type Address32 = [u8; 32];

/// A binary-tree key derived by this embedding.
pub type Key = Vec<u8>;

/// Convert a legacy 20-byte address by prepending 12 zero bytes.
///
/// The embedding keys the tree by 32-byte addresses so that a future
/// address-space extension needs no re-keying.
pub fn address20_to_address32(address: H160) -> Address32 {
    let mut out = [0u8; 32];
    out[12..].copy_from_slice(address.as_bytes());
    out
}

/// Hash `data` for use in tree key derivation.
///
/// In practice this reuses the tree's own merkleization hash,
/// [`blake3_hash`].
fn key_hash(data: &[u8]) -> H256 {
    blake3_hash(data)
}

/// Build a key from its three parts: the `zone` byte, the
/// hash-derived `tree_position`, and the final `sub_index` byte.
fn get_tree_key(zone: u8, tree_position: &[u8], sub_index: u8) -> Key {
    let mut key = Vec::with_capacity(2 + tree_position.len());
    key.push(zone);
    key.extend_from_slice(tree_position);
    key.push(sub_index);
    key
}

/// Compute the key of the account header leaf at `sub_index`.
///
/// The header stem is in [`ACCOUNT_ZONE`] and is keyed by the address
/// alone, so each account has exactly one header stem. The header is
/// not one key: it is up to [`STEM_SUBTREE_WIDTH`] separate leaves
/// sharing that stem, and `sub_index` selects which one; basic data,
/// code hash, an early storage slot, or an early code chunk.
pub fn get_tree_key_for_header(address: &Address32, sub_index: u64) -> Key {
    debug_assert!(sub_index < STEM_SUBTREE_WIDTH);
    let key = get_tree_key(ACCOUNT_ZONE, key_hash(address).as_bytes(), sub_index as u8);
    debug_assert_eq!(key.len(), ACCOUNT_KEY_LENGTH);
    key
}

/// Compute the key of the account's basic data leaf.
pub fn get_tree_key_for_basic_data(address: &Address32) -> Key {
    get_tree_key_for_header(address, BASIC_DATA_LEAF_KEY as u64)
}

/// Compute the key of the account's code hash leaf.
pub fn get_tree_key_for_code_hash(address: &Address32) -> Key {
    get_tree_key_for_header(address, CODE_HASH_LEAF_KEY as u64)
}

/// Build the hash-derived position of an account's overflow storage
/// group at `tree_index`.
///
/// The position carries two full digests:
///
/// - `key_hash(address)` gathers all of an account's overflow storage
///   under one subtree, which future expiry and sync schemes could use
///   as their unit of work: a contract's whole storage is one
///   contiguous key range rather than locations scattered across the
///   whole tree.
/// - `key_hash(address ‖ tree_index)` spreads the account's groups
///   within that subtree.
///
/// Both digests depend on the address, so storage keys that an
/// attacker grinds to sit close together under one contract cannot be
/// reused against a different contract.
fn storage_tree_position(address: &Address32, tree_index: U256) -> Vec<u8> {
    let prefix = key_hash(address);
    let mut preimage = Vec::with_capacity(64);
    preimage.extend_from_slice(address);
    preimage.extend_from_slice(&tree_index.to_big_endian());
    let suffix = key_hash(&preimage);
    let mut position = Vec::with_capacity(64);
    position.extend_from_slice(prefix.as_bytes());
    position.extend_from_slice(suffix.as_bytes());
    position
}

/// Compute the key of a storage slot.
///
/// Slots `0` through `63` live in the account header stem at
/// sub-indices [`HEADER_STORAGE_OFFSET`] onward; all other slots live
/// in [`STORAGE_ZONE`], grouped [`STEM_SUBTREE_WIDTH`] consecutive
/// slots to a stem. This leaves group `0` (`tree_index == 0`) short:
/// its storage-zone leaves are only sub-indices `64`-`255`.
pub fn get_tree_key_for_storage_slot(address: &Address32, storage_key: U256) -> Key {
    if storage_key < U256::from(CODE_OFFSET - HEADER_STORAGE_OFFSET) {
        // `low_u64` cannot truncate: the slot is below 64.
        return get_tree_key_for_header(address, HEADER_STORAGE_OFFSET + storage_key.low_u64());
    }
    let width = U256::from(STEM_SUBTREE_WIDTH);
    let tree_index = storage_key / width;
    // `low_u64` cannot truncate: the remainder is below 256.
    let sub_index = (storage_key % width).low_u64() as u8;
    let key = get_tree_key(
        STORAGE_ZONE,
        &storage_tree_position(address, tree_index),
        sub_index,
    );
    debug_assert_eq!(key.len(), STORAGE_KEY_LENGTH);
    key
}

/// Compute the key of a code chunk.
///
/// Chunks `0` through `127` live in the account header stem: the start
/// of a contract's code (usually dispatchers and entry points) is its
/// most executed region, so the first chunks open with the same branch
/// as the account's basic data.
///
/// Chunks at index `128` and above live in [`CODE_ZONE`],
/// content-addressed by `code_hash` so contracts with identical
/// bytecode share leaves.
pub fn get_tree_key_for_code_chunk(
    address: &Address32,
    code_hash: &[u8; 32],
    chunk_id: u64,
) -> Key {
    let header_chunk_count = STEM_SUBTREE_WIDTH - CODE_OFFSET;
    if chunk_id < header_chunk_count {
        return get_tree_key_for_header(address, CODE_OFFSET + chunk_id);
    }
    let overflow = chunk_id - header_chunk_count;
    let tree_index = overflow / STEM_SUBTREE_WIDTH;
    let sub_index = (overflow % STEM_SUBTREE_WIDTH) as u8;
    let mut preimage = Vec::with_capacity(64);
    preimage.extend_from_slice(code_hash);
    preimage.extend_from_slice(&U256::from(tree_index).to_big_endian());
    let key = get_tree_key(CODE_ZONE, key_hash(&preimage).as_bytes(), sub_index);
    debug_assert_eq!(key.len(), CODE_KEY_LENGTH);
    key
}

#[cfg(test)]
mod tests {
    use super::*;
    use ethereum_types::{H160, U256};
    use hex_literal::hex;

    const ADDR20: H160 = H160(hex!("00112233445566778899aabbccddeeff00112233"));

    #[test]
    fn address32_prepends_twelve_zero_bytes() {
        let a32 = address20_to_address32(ADDR20);
        assert_eq!(&a32[..12], &[0u8; 12]);
        assert_eq!(&a32[12..], ADDR20.as_bytes());
    }

    #[test]
    fn basic_data_key_vector() {
        // fixture: embedding.basic_data_key
        assert_eq!(
            get_tree_key_for_basic_data(&address20_to_address32(ADDR20)),
            hex!("00f4e42504054ae2ba2c9aab59b7cafad1e3df583c385d10fcb8ab0a0ab82e7a0800").to_vec()
        );
    }

    #[test]
    fn header_key_layout() {
        let a32 = address20_to_address32(ADDR20);
        let key = get_tree_key_for_header(&a32, 255);
        assert_eq!(key.len(), ACCOUNT_KEY_LENGTH);
        assert_eq!(key[0], ACCOUNT_ZONE);
        assert_eq!(key[33], 255);
        assert_eq!(get_tree_key_for_code_hash(&a32)[..33], key[..33]);
        assert_eq!(get_tree_key_for_code_hash(&a32)[33], 1);
    }

    #[test]
    fn storage_slot_63_in_header_64_in_storage_zone() {
        let a32 = address20_to_address32(ADDR20);
        let slot63 = get_tree_key_for_storage_slot(&a32, U256::from(63));
        let slot64 = get_tree_key_for_storage_slot(&a32, U256::from(64));
        assert_eq!(slot63.len(), ACCOUNT_KEY_LENGTH);
        assert_eq!(slot63[0], ACCOUNT_ZONE);
        assert_eq!(slot63[33], 64 + 63);
        assert_eq!(slot64.len(), STORAGE_KEY_LENGTH);
        assert_eq!(slot64[0], STORAGE_ZONE);
        assert_eq!(slot64[65], 64);
    }

    #[test]
    fn storage_slot_group_zero_is_short() {
        let a32 = address20_to_address32(ADDR20);
        let k255 = get_tree_key_for_storage_slot(&a32, U256::from(255));
        let k256 = get_tree_key_for_storage_slot(&a32, U256::from(256));
        assert_eq!(
            k255[..65],
            get_tree_key_for_storage_slot(&a32, U256::from(64))[..65]
        );
        assert_ne!(k255[..65], k256[..65]);
    }

    #[test]
    fn huge_storage_key_does_not_overflow() {
        let a32 = address20_to_address32(ADDR20);
        let key = get_tree_key_for_storage_slot(&a32, U256::from(2).pow(U256::from(200)));
        assert_eq!(key.len(), STORAGE_KEY_LENGTH);
        assert_eq!(key[0], STORAGE_ZONE);
    }

    #[test]
    fn code_chunk_127_in_header_128_in_code_zone() {
        let a32 = address20_to_address32(ADDR20);
        let code_hash = [0x11u8; 32];
        let c127 = get_tree_key_for_code_chunk(&a32, &code_hash, 127);
        let c128 = get_tree_key_for_code_chunk(&a32, &code_hash, 128);
        assert_eq!(c127[0], ACCOUNT_ZONE);
        assert_eq!(c127[33], 128 + 127);
        assert_eq!(c128[0], CODE_ZONE);
        assert_eq!(c128.len(), CODE_KEY_LENGTH);
        assert_eq!(c128[33], 0);
    }

    #[test]
    fn overflow_code_is_content_addressed_not_per_account() {
        let a = address20_to_address32(ADDR20);
        let b = address20_to_address32(H160([0x99; 20]));
        let code_hash = [0x11u8; 32];
        assert_eq!(
            get_tree_key_for_code_chunk(&a, &code_hash, 128),
            get_tree_key_for_code_chunk(&b, &code_hash, 128)
        );
        assert_ne!(
            get_tree_key_for_code_chunk(&a, &code_hash, 0),
            get_tree_key_for_code_chunk(&b, &code_hash, 0)
        );
    }
}
