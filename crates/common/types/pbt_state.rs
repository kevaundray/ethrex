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

use crate::constants::EMPTY_KECCAK_HASH;
use crate::types::{AccountUpdate, Code};
use crate::{Address, H256, U256};

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
}
