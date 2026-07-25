//! Flat state model for the experimental EIP-8297 binary-tree
//! commitment (`ChainConfig::enable_binary_tree_at_genesis`).
//!
//! The MPT is keyed by keccak(address) with no preimage table, so the
//! binary-tree commitment cannot be derived from the trie. This model
//! tracks state by real address instead: seeded from the genesis
//! alloc, advanced per block from the [`AccountUpdate`] stream, and
//! re-embedded + re-hashed from scratch for each root — mirroring the
//! spec's `state_pbt.py`. Correct under deletion (orphaned
//! content-addressed code chunks vanish on re-embed), O(state) per
//! block; experimental/test scale only.

use std::collections::BTreeMap;

use ethrex_binary_trie::embedding::{
    address20_to_address32, chunkify_code, encode_basic_data, get_tree_key_for_basic_data,
    get_tree_key_for_code_chunk, get_tree_key_for_code_hash, get_tree_key_for_storage_slot,
};
use ethrex_binary_trie::trie::rebuild::{Entries, rebuild_root};

use crate::constants::EMPTY_KECCAK_HASH;
use crate::types::{AccountUpdate, Code};
use crate::{Address, Bytes, H256, U256};

#[derive(Debug, thiserror::Error)]
pub enum PbtStateError {
    #[error(transparent)]
    Trie(#[from] ethrex_binary_trie::BinaryTrieError),
    #[error("bytecode for code hash {0:#x} not in the PbtState code store")]
    CodeMissing(H256),
}

/// Account record in the flat binary-tree state model. Bytecode is
/// held separately in [`PbtState::code`], keyed by `code_hash`.
#[derive(Debug, Clone, PartialEq)]
pub struct PbtAccount {
    pub nonce: u64,
    pub balance: U256,
    pub code_hash: H256,
}

impl Default for PbtAccount {
    fn default() -> Self {
        Self {
            nonce: 0,
            balance: U256::zero(),
            code_hash: *EMPTY_KECCAK_HASH,
        }
    }
}

#[derive(Debug, Clone, Default)]
pub struct PbtState {
    pub accounts: BTreeMap<Address, PbtAccount>,
    /// Unhashed slot key -> value. Zero-valued slots are absent.
    pub storage: BTreeMap<Address, BTreeMap<H256, U256>>,
    /// code_hash -> bytecode; self-contained so root computation
    /// needs no store access.
    pub code: BTreeMap<H256, Code>,
}

impl PbtState {
    /// Apply a block's [`AccountUpdate`] stream, mirroring the MPT
    /// apply order in `Store::apply_account_updates_from_trie_batch`:
    /// removal drops the account and its storage; `removed_storage`
    /// clears storage only; `info` overwrites the account fields
    /// (creating it if absent, as the MPT path loads-or-defaults);
    /// `code` lands in the code store; zero-valued storage writes
    /// remove the slot, and an emptied storage map is dropped.
    pub fn apply_account_updates(&mut self, updates: &[AccountUpdate]) {
        for update in updates {
            if update.removed {
                self.accounts.remove(&update.address);
                self.storage.remove(&update.address);
                continue;
            }
            let account = self.accounts.entry(update.address).or_default();
            if update.removed_storage {
                self.storage.remove(&update.address);
            }
            if let Some(info) = &update.info {
                account.nonce = info.nonce;
                account.balance = info.balance;
                account.code_hash = info.code_hash;
                if let Some(code) = &update.code {
                    self.code.insert(info.code_hash, code.clone());
                }
            }
            if !update.added_storage.is_empty() {
                let slots = self.storage.entry(update.address).or_default();
                for (slot, value) in &update.added_storage {
                    if value.is_zero() {
                        slots.remove(slot);
                    } else {
                        slots.insert(*slot, *value);
                    }
                }
                if slots.is_empty() {
                    self.storage.remove(&update.address);
                }
            }
        }
    }

    /// Re-embed the whole state into a fresh set of binary-trie entries
    /// and hash. The re-embed strategy is an implementation detail
    /// validated against the rebuild oracle — callers must not depend on
    /// it (Phase 2 swaps this for incremental maintenance behind the
    /// same signature).
    pub fn compute_root(&self) -> Result<H256, PbtStateError> {
        let mut entries = Entries::new();

        for (address, account) in &self.accounts {
            let address32 = address20_to_address32(*address);
            // The empty code hash resolves to empty bytes without a
            // store lookup, so EOAs never need a code-store entry.
            let code = if account.code_hash == *EMPTY_KECCAK_HASH {
                Bytes::new()
            } else {
                self.code
                    .get(&account.code_hash)
                    .ok_or(PbtStateError::CodeMissing(account.code_hash))?
                    .code_bytes()
            };

            entries.insert(
                get_tree_key_for_basic_data(&address32),
                encode_basic_data(code.len() as u32, account.nonce, account.balance)?,
            );
            entries.insert(get_tree_key_for_code_hash(&address32), account.code_hash.0);
            for (chunk_id, chunk) in chunkify_code(&code).into_iter().enumerate() {
                entries.insert(
                    get_tree_key_for_code_chunk(&address32, &account.code_hash.0, chunk_id as u64),
                    chunk,
                );
            }
        }

        for (address, slots) in &self.storage {
            // Storage belongs to an account; slots without one have no
            // place in the tree (mirrors the spec's embed_flat_state).
            if !self.accounts.contains_key(address) {
                continue;
            }
            let address32 = address20_to_address32(*address);
            for (slot, value) in slots {
                entries.insert(
                    get_tree_key_for_storage_slot(
                        &address32,
                        U256::from_big_endian(slot.as_bytes()),
                    ),
                    value.to_big_endian(),
                );
            }
        }

        Ok(rebuild_root(&entries))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::constants::EMPTY_KECCAK_HASH;
    use crate::types::{AccountInfo, AccountUpdate, Code};
    use crate::{Address, Bytes, H256, U256};
    use ethrex_crypto::NativeCrypto;

    fn addr(byte: u8) -> Address {
        Address::repeat_byte(byte)
    }

    fn code_of(bytes: &[u8]) -> Code {
        Code::from_bytecode(Bytes::copy_from_slice(bytes), &NativeCrypto)
    }

    fn info_update(address: Address, nonce: u64, balance: U256, code_hash: H256) -> AccountUpdate {
        AccountUpdate {
            info: Some(AccountInfo {
                code_hash,
                balance,
                nonce,
            }),
            ..AccountUpdate::new(address)
        }
    }

    #[test]
    fn apply_creates_account_and_second_apply_overwrites_balance() {
        let mut state = PbtState::default();
        let a = addr(1);
        state.apply_account_updates(&[info_update(a, 1, U256::from(100), *EMPTY_KECCAK_HASH)]);
        assert_eq!(state.accounts[&a].balance, U256::from(100));
        assert_eq!(state.accounts[&a].nonce, 1);

        state.apply_account_updates(&[info_update(a, 2, U256::from(250), *EMPTY_KECCAK_HASH)]);
        assert_eq!(state.accounts[&a].balance, U256::from(250));
        assert_eq!(state.accounts[&a].nonce, 2);
        assert_eq!(state.accounts.len(), 1);
    }

    #[test]
    fn zero_storage_write_removes_slot_and_empty_map_is_dropped() {
        let mut state = PbtState::default();
        let a = addr(2);
        let slot1 = H256::from_low_u64_be(1);
        let slot2 = H256::from_low_u64_be(2);

        let mut setup = AccountUpdate::new(a);
        setup.info = Some(AccountInfo::default());
        setup.added_storage.insert(slot1, U256::from(7));
        setup.added_storage.insert(slot2, U256::from(9));
        state.apply_account_updates(&[setup]);
        assert_eq!(state.storage[&a][&slot1], U256::from(7));
        assert_eq!(state.storage[&a][&slot2], U256::from(9));

        // Zeroing one slot removes just that slot.
        let mut zero_one = AccountUpdate::new(a);
        zero_one.added_storage.insert(slot1, U256::zero());
        state.apply_account_updates(&[zero_one]);
        assert!(!state.storage[&a].contains_key(&slot1));
        assert_eq!(state.storage[&a][&slot2], U256::from(9));

        // Zeroing the last slot drops the per-account map entirely.
        let mut zero_last = AccountUpdate::new(a);
        zero_last.added_storage.insert(slot2, U256::zero());
        state.apply_account_updates(&[zero_last]);
        assert!(!state.storage.contains_key(&a));
    }

    #[test]
    fn removed_drops_account_and_its_storage() {
        let mut state = PbtState::default();
        let a = addr(3);
        let mut setup = info_update(a, 1, U256::from(5), *EMPTY_KECCAK_HASH);
        setup
            .added_storage
            .insert(H256::from_low_u64_be(1), U256::from(11));
        state.apply_account_updates(&[setup]);
        assert!(state.accounts.contains_key(&a));
        assert!(state.storage.contains_key(&a));

        state.apply_account_updates(&[AccountUpdate::removed(a)]);
        assert!(!state.accounts.contains_key(&a));
        assert!(!state.storage.contains_key(&a));
    }

    #[test]
    fn removed_storage_clears_storage_but_keeps_account() {
        let mut state = PbtState::default();
        let a = addr(4);
        let mut setup = info_update(a, 3, U256::from(5), *EMPTY_KECCAK_HASH);
        setup
            .added_storage
            .insert(H256::from_low_u64_be(1), U256::from(11));
        state.apply_account_updates(&[setup]);

        let clear = AccountUpdate {
            removed_storage: true,
            ..AccountUpdate::new(a)
        };
        state.apply_account_updates(&[clear]);
        assert!(!state.storage.contains_key(&a));
        assert_eq!(state.accounts[&a].nonce, 3);
        assert_eq!(state.accounts[&a].balance, U256::from(5));
    }

    #[test]
    fn code_update_lands_bytecode_in_code_store_keyed_by_hash() {
        let mut state = PbtState::default();
        let a = addr(5);
        let code = code_of(&[0x60, 0x01, 0x60, 0x02, 0x01]);
        let code_hash = code.hash;

        let update = AccountUpdate {
            code: Some(code.clone()),
            ..info_update(a, 1, U256::zero(), code_hash)
        };
        state.apply_account_updates(&[update]);

        assert_eq!(state.accounts[&a].code_hash, code_hash);
        assert_eq!(state.code[&code_hash].code(), code.code());
    }

    #[test]
    fn storage_only_update_keeps_existing_account_fields() {
        let mut state = PbtState::default();
        let a = addr(6);
        state.apply_account_updates(&[info_update(a, 9, U256::from(77), *EMPTY_KECCAK_HASH)]);

        let mut storage_only = AccountUpdate::new(a);
        storage_only
            .added_storage
            .insert(H256::from_low_u64_be(1), U256::from(1));
        state.apply_account_updates(&[storage_only]);

        assert_eq!(state.accounts[&a].nonce, 9);
        assert_eq!(state.accounts[&a].balance, U256::from(77));
        assert_eq!(state.accounts[&a].code_hash, *EMPTY_KECCAK_HASH);
    }

    #[test]
    fn storage_only_update_for_unknown_address_creates_default_account() {
        // Mirrors the MPT apply path (store.rs), which loads the account
        // from the trie or falls back to `AccountState::default()` before
        // applying storage: a storage write to an address the model has
        // never seen must still materialize the account (nonce 0,
        // balance 0, empty code hash) so both commitments stay in sync.
        let mut state = PbtState::default();
        let a = addr(7);

        let mut storage_only = AccountUpdate::new(a);
        storage_only
            .added_storage
            .insert(H256::from_low_u64_be(1), U256::from(42));
        state.apply_account_updates(&[storage_only]);

        let account = &state.accounts[&a];
        assert_eq!(account.nonce, 0);
        assert_eq!(account.balance, U256::zero());
        assert_eq!(account.code_hash, *EMPTY_KECCAK_HASH);
        assert_eq!(state.storage[&a][&H256::from_low_u64_be(1)], U256::from(42));
    }

    // ---- compute_root ----

    fn eoa_account(nonce: u64, balance: U256) -> PbtAccount {
        PbtAccount {
            nonce,
            balance,
            code_hash: *EMPTY_KECCAK_HASH,
        }
    }

    #[test]
    fn empty_state_root_is_zero() {
        assert_eq!(PbtState::default().compute_root().unwrap(), H256::zero());
    }

    #[test]
    fn eoa_only_root_is_nonzero_and_balance_sensitive() {
        let mut state = PbtState::default();
        state
            .accounts
            .insert(addr(1), eoa_account(1, U256::from(100)));
        let root_before = state.compute_root().unwrap();
        assert_ne!(root_before, H256::zero());

        state.accounts.get_mut(&addr(1)).unwrap().balance = U256::from(101);
        assert_ne!(state.compute_root().unwrap(), root_before);
    }

    #[test]
    fn balance_must_fit_the_basic_data_field() {
        let mut state = PbtState::default();
        state
            .accounts
            .insert(addr(1), eoa_account(0, U256::one() << 128));
        assert!(matches!(
            state.compute_root().unwrap_err(),
            PbtStateError::Trie(ethrex_binary_trie::BinaryTrieError::BalanceTooLarge)
        ));

        state.accounts.get_mut(&addr(1)).unwrap().balance = (U256::one() << 128) - 1;
        assert!(state.compute_root().is_ok());
    }

    #[test]
    fn missing_bytecode_for_nonempty_code_hash_is_an_error() {
        let mut state = PbtState::default();
        let dangling = H256::repeat_byte(0xab);
        state.accounts.insert(
            addr(1),
            PbtAccount {
                code_hash: dangling,
                ..Default::default()
            },
        );
        assert!(matches!(
            state.compute_root().unwrap_err(),
            PbtStateError::CodeMissing(h) if h == dangling
        ));
    }

    // ---- spec conformance (fixture generated from EELS state_pbt) ----

    #[derive(serde::Deserialize)]
    struct Fixture {
        pbt_state: PbtStateFixture,
    }

    #[derive(serde::Deserialize)]
    struct PbtStateFixture {
        eoa_address: String,
        contract_address: String,
        contract_code: String,
        pre: PreFixture,
        diff1: Diff1Fixture,
        post_diff1_root: String,
        post_delete_contract_root: String,
    }

    #[derive(serde::Deserialize)]
    struct PreFixture {
        eoa: AccountFixture,
        contract: AccountFixture,
        root: String,
    }

    #[derive(serde::Deserialize)]
    struct AccountFixture {
        nonce: u64,
        /// Hex string; balances can exceed `u64`.
        balance: String,
        /// Keyed by decimal slot number.
        #[serde(default)]
        storage: BTreeMap<String, String>,
    }

    #[derive(serde::Deserialize)]
    struct Diff1Fixture {
        eoa: AccountFixture,
        /// Keyed by decimal slot number.
        contract_storage: BTreeMap<String, String>,
    }

    fn load_fixture() -> PbtStateFixture {
        let fixture: Fixture = serde_json::from_str(include_str!(
            "../binary-trie/tests/vectors/binary_trie_vectors.json"
        ))
        .unwrap();
        fixture.pbt_state
    }

    fn unhex(s: &str) -> Vec<u8> {
        hex::decode(s.strip_prefix("0x").unwrap_or(s)).expect("fixture hex string")
    }

    fn fixture_h256(s: &str) -> H256 {
        H256::from_slice(&unhex(s))
    }

    fn fixture_address(s: &str) -> Address {
        Address::from_slice(&unhex(s))
    }

    fn fixture_u256(s: &str) -> U256 {
        U256::from_str_radix(s.trim_start_matches("0x"), 16).unwrap()
    }

    /// Fixture storage keys are decimal slot numbers; the model keys
    /// storage by the raw 32-byte big-endian slot key.
    fn fixture_slot(decimal: &str) -> H256 {
        H256(U256::from_dec_str(decimal).unwrap().to_big_endian())
    }

    fn fixture_storage(slots: &BTreeMap<String, String>) -> BTreeMap<H256, U256> {
        slots
            .iter()
            .map(|(k, v)| (fixture_slot(k), fixture_u256(v)))
            .collect()
    }

    #[test]
    fn conformance_pre_diff1_and_delete_roots_match_spec() {
        let f = load_fixture();
        let eoa = fixture_address(&f.eoa_address);
        let contract = fixture_address(&f.contract_address);
        let code = code_of(&unhex(&f.contract_code));
        // The deletion leg must exercise overflow (content-addressed)
        // code chunks, which start at chunk id 128: require more than
        // 128 chunks of 31 code bytes each.
        assert!(code.len() > 128 * 31, "fixture code has no overflow chunks");

        let mut state = PbtState::default();
        state.accounts.insert(
            eoa,
            eoa_account(f.pre.eoa.nonce, fixture_u256(&f.pre.eoa.balance)),
        );
        state.accounts.insert(
            contract,
            PbtAccount {
                nonce: f.pre.contract.nonce,
                balance: fixture_u256(&f.pre.contract.balance),
                code_hash: code.hash,
            },
        );
        state.code.insert(code.hash, code);
        state
            .storage
            .insert(contract, fixture_storage(&f.pre.contract.storage));

        assert_eq!(
            state.compute_root().unwrap(),
            fixture_h256(&f.pre.root),
            "pre-state root mismatch"
        );

        // diff1: EOA nonce/balance bump + contract storage writes
        // (a zeroing write and an overwrite), as AccountUpdates.
        let eoa_update = info_update(
            eoa,
            f.diff1.eoa.nonce,
            fixture_u256(&f.diff1.eoa.balance),
            *EMPTY_KECCAK_HASH,
        );
        let mut contract_update = AccountUpdate::new(contract);
        for (k, v) in &f.diff1.contract_storage {
            contract_update
                .added_storage
                .insert(fixture_slot(k), fixture_u256(v));
        }
        state.apply_account_updates(&[eoa_update, contract_update]);
        assert_eq!(
            state.compute_root().unwrap(),
            fixture_h256(&f.post_diff1_root),
            "post-diff1 root mismatch"
        );

        // diff2: delete the contract account. Its storage and all its
        // code chunks — including the orphaned content-addressed
        // overflow chunks — must vanish from the commitment.
        state.apply_account_updates(&[AccountUpdate::removed(contract)]);
        assert_eq!(
            state.compute_root().unwrap(),
            fixture_h256(&f.post_delete_contract_root),
            "post-delete root mismatch"
        );
    }
}
