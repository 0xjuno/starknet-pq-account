//! In-place migration: an existing classical (ECDSA) account upgrades its class to this
//! hybrid ECDSA + Falcon-512 account WITHOUT changing its address or funds.
//!
//! Migration flow (one transaction, validated by the OLD account class):
//!   multicall [ self.upgrade(HybridMigratableAccount class hash),
//!               self.register_falcon_public_key(falcon_pk, verifier_class_hash) ]
//! `replace_class` takes effect for subsequent calls, so the second call already runs this
//! class and stores the Falcon key atomically. From the next transaction on, BOTH an ECDSA
//! and a Falcon signature are required.
//!
//! The ECDSA key stays under the storage name OpenZeppelin accounts use
//! (`Account_public_key`), so it carries over across the class replacement.
//!
//! Thin class: signature verification is delegated with a library call to an already
//! declared hybrid verifier class (`HybridPoseidonAccount`), which runs in THIS account's
//! storage context. The keys are therefore mirrored under that class's storage names
//! (`ecdsa_public_key`, `falcon_public_key`). Swapping the verifier (e.g. to an audited or
//! standard SHAKE-256 version) does not require migrating the account again.
//!
//! Fallback bootstrap: if the class was replaced without registering a Falcon key, the
//! account accepts an ECDSA-only transaction whose ONLY call is
//! `register_falcon_public_key` on itself. (In a post-quantum world that window could be
//! front-run, which is why the atomic flow above is the recommended path.)
//!
//! EXPERIMENTAL AND UNAUDITED. Testnet / demo use only.

use starknet::ClassHash;

#[starknet::interface]
pub trait IMigratable<TState> {
    fn register_falcon_public_key(
        ref self: TState, falcon_public_key: Array<felt252>, verifier_class_hash: ClassHash,
    );
    fn rotate_falcon_public_key(ref self: TState, falcon_public_key: Array<felt252>);
    fn rotate_ecdsa_public_key(ref self: TState, ecdsa_public_key: felt252);
    fn set_verifier_class_hash(ref self: TState, verifier_class_hash: ClassHash);
    fn upgrade(ref self: TState, new_class_hash: ClassHash);
    fn get_ecdsa_public_key(self: @TState) -> felt252;
    fn get_falcon_public_key(self: @TState) -> Array<felt252>;
    fn get_verifier_class_hash(self: @TState) -> ClassHash;
    fn is_falcon_registered(self: @TState) -> bool;
}

#[starknet::contract(account)]
pub mod HybridMigratableAccount {
    use core::num::traits::Zero;
    use pqbench_ecdsa_stark::EcdsaStarkVerifier;
    use pqbench_falcon_512::PUBKEY_FELTS;
    use starknet::account::Call;
    use starknet::storage::{
        MutableVecTrait, StoragePointerReadAccess, StoragePointerWriteAccess, Vec, VecTrait,
    };
    use starknet::{ClassHash, SyscallResultTrait, get_caller_address, get_contract_address};
    use crate::utils::execution;
    use crate::utils::interface::IHybridAccount;

    pub const ONLY_SELF: felt252 = 'Migratable: only self';
    pub const ALREADY_REGISTERED: felt252 = 'Migratable: already registered';
    pub const NOT_REGISTERED: felt252 = 'Migratable: not registered';
    pub const INVALID_FALCON_KEY: felt252 = 'Migratable: invalid falcon key';
    pub const INVALID_VERIFIER: felt252 = 'Migratable: invalid verifier';
    pub const NO_ECDSA_KEY: felt252 = 'Migratable: no ecdsa key';

    #[storage]
    struct Storage {
        // Same storage name as OpenZeppelin's AccountComponent, so the classical key
        // survives an in-place class replacement.
        Account_public_key: felt252,
        // Mirrors read by the verifier class through a library call. Names and types must
        // match `HybridAccountComponent::Storage` exactly.
        ecdsa_public_key: felt252,
        falcon_public_key: Vec<felt252>,
        Migratable_verifier_class_hash: ClassHash,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        FalconKeyRegistered: FalconKeyRegistered,
        FalconKeyRotated: FalconKeyRotated,
        EcdsaKeyRotated: EcdsaKeyRotated,
        VerifierChanged: VerifierChanged,
    }

    #[derive(Drop, starknet::Event)]
    struct FalconKeyRegistered {
        verifier_class_hash: ClassHash,
    }

    #[derive(Drop, starknet::Event)]
    struct FalconKeyRotated {}

    #[derive(Drop, starknet::Event)]
    struct EcdsaKeyRotated {
        ecdsa_public_key: felt252,
    }

    #[derive(Drop, starknet::Event)]
    struct VerifierChanged {
        verifier_class_hash: ClassHash,
    }

    /// Fresh deployment path (no migration): both keys and the verifier at construction.
    #[constructor]
    fn constructor(
        ref self: ContractState,
        ecdsa_public_key: felt252,
        falcon_public_key: Array<felt252>,
        verifier_class_hash: ClassHash,
    ) {
        self.Account_public_key.write(ecdsa_public_key);
        self._register(falcon_public_key, verifier_class_hash);
    }

    #[abi(embed_v0)]
    impl AccountImpl of IHybridAccount<ContractState> {
        fn __execute__(self: @ContractState, calls: Array<Call>) {
            execution::assert_protocol_caller();
            execution::assert_valid_tx_version();
            execution::execute_calls(calls.span());
        }

        fn __validate__(self: @ContractState, calls: Array<Call>) -> felt252 {
            let tx_info = starknet::get_tx_info().unbox();
            if self._falcon_registered() {
                return execution::assert_valid_signature(
                    self._verify(tx_info.transaction_hash, tx_info.signature),
                );
            }
            // Bootstrap: ECDSA-only, and only a single self-call registering the Falcon key.
            assert(calls.len() == 1, NOT_REGISTERED);
            let call = calls.at(0);
            assert(*call.to == get_contract_address(), NOT_REGISTERED);
            assert(*call.selector == selector!("register_falcon_public_key"), NOT_REGISTERED);
            execution::assert_valid_signature(
                EcdsaStarkVerifier::verify(
                    tx_info.transaction_hash,
                    array![self.Account_public_key.read()].span(),
                    tx_info.signature,
                ),
            )
        }

        fn __validate_declare__(self: @ContractState, class_hash: felt252) -> felt252 {
            let _ = class_hash;
            assert(self._falcon_registered(), NOT_REGISTERED);
            let tx_info = starknet::get_tx_info().unbox();
            execution::assert_valid_signature(
                self._verify(tx_info.transaction_hash, tx_info.signature),
            )
        }

        fn is_valid_signature(
            self: @ContractState, hash: felt252, signature: Array<felt252>,
        ) -> felt252 {
            if !self._falcon_registered() {
                return 0;
            }
            execution::signature_result(self._verify(hash, signature.span()))
        }

        fn supports_interface(self: @ContractState, interface_id: felt252) -> bool {
            execution::supports_account_interface(interface_id)
        }
    }

    #[abi(embed_v0)]
    impl MigratableImpl of super::IMigratable<ContractState> {
        /// One-time registration of the Falcon key after an in-place upgrade.
        fn register_falcon_public_key(
            ref self: ContractState,
            falcon_public_key: Array<felt252>,
            verifier_class_hash: ClassHash,
        ) {
            self._assert_only_self();
            assert(!self._falcon_registered(), ALREADY_REGISTERED);
            self._register(falcon_public_key, verifier_class_hash);
        }

        /// Replaces the Falcon key. Requires a hybrid-signed transaction (self-call).
        fn rotate_falcon_public_key(ref self: ContractState, falcon_public_key: Array<felt252>) {
            self._assert_only_self();
            assert(self._falcon_registered(), NOT_REGISTERED);
            assert(falcon_public_key.len() == PUBKEY_FELTS, INVALID_FALCON_KEY);
            let mut i: u64 = 0;
            for felt in falcon_public_key {
                self.falcon_public_key.at(i).write(felt);
                i += 1;
            }
            self.emit(FalconKeyRotated {});
        }

        /// Replaces the classical STARK-curve key. Requires a hybrid-signed transaction
        /// (self-call), so a forged ECDSA signature alone cannot rotate it.
        fn rotate_ecdsa_public_key(ref self: ContractState, ecdsa_public_key: felt252) {
            self._assert_only_self();
            assert(self._falcon_registered(), NOT_REGISTERED);
            assert(ecdsa_public_key != 0, NO_ECDSA_KEY);
            self.Account_public_key.write(ecdsa_public_key);
            self.ecdsa_public_key.write(ecdsa_public_key);
            self.emit(EcdsaKeyRotated { ecdsa_public_key });
        }

        /// Points verification at another declared verifier class (e.g. an audited one).
        /// Requires a hybrid-signed transaction (self-call).
        fn set_verifier_class_hash(ref self: ContractState, verifier_class_hash: ClassHash) {
            self._assert_only_self();
            assert(self._falcon_registered(), NOT_REGISTERED);
            assert(verifier_class_hash.is_non_zero(), INVALID_VERIFIER);
            self.Migratable_verifier_class_hash.write(verifier_class_hash);
            self.emit(VerifierChanged { verifier_class_hash });
        }

        /// Class upgrade (e.g. to a future PQ-only account). Hybrid-signed self-call.
        fn upgrade(ref self: ContractState, new_class_hash: ClassHash) {
            self._assert_only_self();
            starknet::syscalls::replace_class_syscall(new_class_hash).unwrap_syscall();
        }

        fn get_ecdsa_public_key(self: @ContractState) -> felt252 {
            self.Account_public_key.read()
        }

        fn get_falcon_public_key(self: @ContractState) -> Array<felt252> {
            let mut key = array![];
            let len = self.falcon_public_key.len();
            let mut i = 0;
            while i != len {
                key.append(self.falcon_public_key.at(i).read());
                i += 1;
            }
            key
        }

        fn get_verifier_class_hash(self: @ContractState) -> ClassHash {
            self.Migratable_verifier_class_hash.read()
        }

        fn is_falcon_registered(self: @ContractState) -> bool {
            self._falcon_registered()
        }
    }

    #[generate_trait]
    impl InternalImpl of InternalTrait {
        fn _assert_only_self(self: @ContractState) {
            assert(get_caller_address() == get_contract_address(), ONLY_SELF);
        }

        fn _falcon_registered(self: @ContractState) -> bool {
            self.falcon_public_key.len() == PUBKEY_FELTS.into()
        }

        fn _register(
            ref self: ContractState,
            falcon_public_key: Array<felt252>,
            verifier_class_hash: ClassHash,
        ) {
            let ecdsa_key = self.Account_public_key.read();
            assert(ecdsa_key != 0, NO_ECDSA_KEY);
            assert(falcon_public_key.len() == PUBKEY_FELTS, INVALID_FALCON_KEY);
            assert(verifier_class_hash.is_non_zero(), INVALID_VERIFIER);
            self.ecdsa_public_key.write(ecdsa_key);
            for felt in falcon_public_key {
                self.falcon_public_key.push(felt);
            }
            self.Migratable_verifier_class_hash.write(verifier_class_hash);
            self.emit(FalconKeyRegistered { verifier_class_hash });
        }

        /// Library-calls the verifier class's `is_valid_signature`, which reads the mirrored
        /// keys from this account's storage and checks ECDSA AND Falcon.
        fn _verify(self: @ContractState, hash: felt252, signature: Span<felt252>) -> bool {
            let mut calldata: Array<felt252> = array![hash];
            Serde::serialize(@signature, ref calldata);
            let result = starknet::syscalls::library_call_syscall(
                self.Migratable_verifier_class_hash.read(),
                selector!("is_valid_signature"),
                calldata.span(),
            )
                .unwrap_syscall();
            result.len() == 1 && *result.at(0) == starknet::VALIDATED
        }
    }
}

/// Minimal stand-in for an existing OpenZeppelin ECDSA account in tests: same
/// `Account_public_key` storage name and a self-only `upgrade`. Test-only.
#[cfg(test)]
#[starknet::contract]
pub mod LegacyOzLikeAccount {
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use starknet::{ClassHash, SyscallResultTrait, get_caller_address, get_contract_address};

    #[storage]
    struct Storage {
        Account_public_key: felt252,
    }

    #[constructor]
    fn constructor(ref self: ContractState, public_key: felt252) {
        self.Account_public_key.write(public_key);
    }

    #[starknet::interface]
    pub trait ILegacy<TState> {
        fn upgrade(ref self: TState, new_class_hash: ClassHash);
        fn get_public_key(self: @TState) -> felt252;
    }

    #[abi(embed_v0)]
    impl LegacyImpl of ILegacy<ContractState> {
        fn upgrade(ref self: ContractState, new_class_hash: ClassHash) {
            assert(get_caller_address() == get_contract_address(), 'only self');
            starknet::syscalls::replace_class_syscall(new_class_hash).unwrap_syscall();
        }

        fn get_public_key(self: @ContractState) -> felt252 {
            self.Account_public_key.read()
        }
    }
}
