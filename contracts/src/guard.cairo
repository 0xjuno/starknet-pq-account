//! Guarded verifier switch for `HybridMigratableAccount`.
//!
//! A migrated account replaces its verifier with one hybrid-signed multicall:
//!
//!     [ account.set_verifier_class_hash(candidate),
//!       guard.assert_compatible(account, candidate) ]
//!
//! `assert_compatible` checks that this same transaction's hash and signature still verify
//! through the account's `is_valid_signature`, which by then library-calls the candidate in the
//! account's own storage. If not, it panics and the whole transaction reverts, so the old
//! verifier stays in place. The transaction hash commits to the account, chain, nonce and the
//! candidate in the calldata, so no separate proof is needed.
//!
//! Limits:
//! - One signature is checked. A candidate that only fails on rare inputs passes.
//! - Only this tooling path is guarded: `set_verifier_class_hash` and `upgrade` can still be
//!   called directly.
//! - The candidate runs as trusted code in the account's storage. The guard checks that the
//!   verifier pointer and the keys the account reports are unchanged, but it cannot see every
//!   storage slot; a hostile candidate is out of scope. Use reviewed, pinned class hashes.
//! - The signature is checked by the scheme of the old verifier (in `__validate__`) and of the
//!   candidate (here), so this only works between verifiers of the same scheme, such as two
//!   SHAKE-256 verifiers.
//!
//! EXPERIMENTAL AND UNAUDITED. Testnet / demo use only.

use starknet::{ClassHash, ContractAddress};

#[starknet::interface]
pub trait IVerifierSwitchGuard<TState> {
    /// Panics unless `account` is calling, points at `verifier_class_hash`, and accepts the
    /// current transaction's signature, with its keys and verifier pointer unchanged.
    fn assert_compatible(self: @TState, account: ContractAddress, verifier_class_hash: ClassHash);
}

#[starknet::contract]
pub mod VerifierSwitchGuard {
    use starknet::{ClassHash, ContractAddress, get_caller_address};
    use crate::migratable::{IMigratableDispatcher, IMigratableDispatcherTrait};
    use crate::utils::interface::{IHybridAccountDispatcher, IHybridAccountDispatcherTrait};

    pub const NOT_THE_ACCOUNT: felt252 = 'Guard: caller is not account';
    pub const WRONG_VERIFIER: felt252 = 'Guard: verifier not installed';
    pub const INCOMPATIBLE: felt252 = 'Guard: signature rejected';
    pub const STATE_CHANGED: felt252 = 'Guard: account state changed';

    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    impl GuardImpl of super::IVerifierSwitchGuard<ContractState> {
        fn assert_compatible(
            self: @ContractState, account: ContractAddress, verifier_class_hash: ClassHash,
        ) {
            assert(get_caller_address() == account, NOT_THE_ACCOUNT);
            let m = IMigratableDispatcher { contract_address: account };
            assert(m.get_verifier_class_hash() == verifier_class_hash, WRONG_VERIFIER);
            let ecdsa_public_key = m.get_ecdsa_public_key();
            let falcon_public_key = m.get_falcon_public_key();

            let tx = starknet::get_tx_info().unbox();
            let mut signature = array![];
            for felt in tx.signature {
                signature.append(*felt);
            }
            let result = IHybridAccountDispatcher { contract_address: account }
                .is_valid_signature(tx.transaction_hash, signature);
            assert(result == starknet::VALIDATED, INCOMPATIBLE);

            assert(m.get_verifier_class_hash() == verifier_class_hash, STATE_CHANGED);
            assert(m.get_ecdsa_public_key() == ecdsa_public_key, STATE_CHANGED);
            assert(m.get_falcon_public_key() == falcon_public_key, STATE_CHANGED);
        }
    }
}
