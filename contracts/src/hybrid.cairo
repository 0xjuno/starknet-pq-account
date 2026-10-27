//! Hybrid ECDSA-STARK + Falcon-512 account.
//!
//! A transaction is valid only if BOTH signatures verify over the same transaction hash:
//! the classical STARK-curve ECDSA signature AND a post-quantum Falcon-512 signature.
//! If either scheme is broken (e.g. ECDSA by a future quantum computer), the other still
//! protects the account.
//!
//! Signature layout: `[ecdsa_r, ecdsa_s, falcon_signature...]` (2 + 60 felts for the
//! hint variants). Keys: one STARK-curve public key felt + a 29-felt packed Falcon key.
//!
//! EXPERIMENTAL AND UNAUDITED. Testnet / demo use only.

use pqbench_ecdsa_stark::EcdsaStarkVerifier;
use pqbench_falcon_512::PUBKEY_FELTS;
use pqbench_interface::PqSignatureVerifier;

/// Number of felts in the classical ECDSA part of the signature.
pub const ECDSA_SIG_FELTS: u32 = 2;

pub const INVALID_FALCON_KEY: felt252 = 'Hybrid: invalid falcon key';
pub const INVALID_ECDSA_KEY: felt252 = 'Hybrid: invalid ecdsa key';

/// Verifies the hybrid signature. Returns false on any malformed input.
pub fn verify_hybrid<impl Falcon: PqSignatureVerifier>(
    hash: felt252, ecdsa_public_key: felt252, falcon_public_key: Span<felt252>,
    signature: Span<felt252>,
) -> bool {
    if signature.len() <= ECDSA_SIG_FELTS {
        return false;
    }
    let ecdsa_ok = EcdsaStarkVerifier::verify(
        hash, array![ecdsa_public_key].span(), signature.slice(0, ECDSA_SIG_FELTS),
    );
    if !ecdsa_ok {
        return false;
    }
    Falcon::verify(
        hash,
        falcon_public_key,
        signature.slice(ECDSA_SIG_FELTS, signature.len() - ECDSA_SIG_FELTS),
    )
}

#[starknet::component]
pub mod HybridAccountComponent {
    use pqbench_interface::PqSignatureVerifier;
    use starknet::account::Call;
    use starknet::storage::{
        MutableVecTrait, StoragePointerReadAccess, StoragePointerWriteAccess, Vec, VecTrait,
    };
    use crate::utils::execution;
    use crate::utils::interface::{IHybridAccount, IHybridDeployable, IHybridPublicKeys};
    use super::{INVALID_ECDSA_KEY, INVALID_FALCON_KEY, PUBKEY_FELTS, verify_hybrid};

    #[storage]
    pub struct Storage {
        pub ecdsa_public_key: felt252,
        pub falcon_public_key: Vec<felt252>,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    pub enum Event {}

    #[embeddable_as(AccountImpl)]
    impl Account<
        TContractState,
        impl Falcon: PqSignatureVerifier,
        +HasComponent<TContractState>,
        +Drop<TContractState>,
    > of IHybridAccount<ComponentState<TContractState>> {
        fn __execute__(self: @ComponentState<TContractState>, calls: Array<Call>) {
            execution::assert_protocol_caller();
            execution::assert_valid_tx_version();
            execution::execute_calls(calls.span());
        }

        fn __validate__(self: @ComponentState<TContractState>, calls: Array<Call>) -> felt252 {
            let _ = calls;
            self.validate_transaction::<Falcon>()
        }

        fn __validate_declare__(
            self: @ComponentState<TContractState>, class_hash: felt252,
        ) -> felt252 {
            let _ = class_hash;
            self.validate_transaction::<Falcon>()
        }

        fn is_valid_signature(
            self: @ComponentState<TContractState>, hash: felt252, signature: Array<felt252>,
        ) -> felt252 {
            execution::signature_result(
                verify_hybrid::<
                    Falcon,
                >(
                    hash,
                    self.ecdsa_public_key.read(),
                    self.read_falcon_public_key().span(),
                    signature.span(),
                ),
            )
        }

        fn supports_interface(
            self: @ComponentState<TContractState>, interface_id: felt252,
        ) -> bool {
            execution::supports_account_interface(interface_id)
        }
    }

    #[embeddable_as(DeployableImpl)]
    impl Deployable<
        TContractState,
        impl Falcon: PqSignatureVerifier,
        +HasComponent<TContractState>,
        +Drop<TContractState>,
    > of IHybridDeployable<ComponentState<TContractState>> {
        fn __validate_deploy__(
            self: @ComponentState<TContractState>,
            class_hash: felt252,
            contract_address_salt: felt252,
            ecdsa_public_key: felt252,
            falcon_public_key: Array<felt252>,
        ) -> felt252 {
            let _ = class_hash;
            let _ = contract_address_salt;
            let _ = ecdsa_public_key;
            let _ = falcon_public_key;
            self.validate_transaction::<Falcon>()
        }
    }

    #[embeddable_as(PublicKeysImpl)]
    impl PublicKeys<
        TContractState, +HasComponent<TContractState>, +Drop<TContractState>,
    > of IHybridPublicKeys<ComponentState<TContractState>> {
        fn get_ecdsa_public_key(self: @ComponentState<TContractState>) -> felt252 {
            self.ecdsa_public_key.read()
        }

        fn get_falcon_public_key(self: @ComponentState<TContractState>) -> Array<felt252> {
            self.read_falcon_public_key()
        }
    }

    #[generate_trait]
    pub impl InternalImpl<
        TContractState, +HasComponent<TContractState>, +Drop<TContractState>,
    > of InternalTrait<TContractState> {
        /// Stores both public keys. Rejects malformed keys at deployment.
        fn initializer(
            ref self: ComponentState<TContractState>,
            ecdsa_public_key: felt252,
            falcon_public_key: Array<felt252>,
        ) {
            assert(ecdsa_public_key != 0, INVALID_ECDSA_KEY);
            assert(falcon_public_key.len() == PUBKEY_FELTS, INVALID_FALCON_KEY);
            self.ecdsa_public_key.write(ecdsa_public_key);
            for felt in falcon_public_key {
                self.falcon_public_key.push(felt);
            }
        }

        /// Validates the current transaction hash against the hybrid signature.
        fn validate_transaction<impl Falcon: PqSignatureVerifier>(
            self: @ComponentState<TContractState>,
        ) -> felt252 {
            let tx_info = starknet::get_tx_info().unbox();
            execution::assert_valid_signature(
                verify_hybrid::<
                    Falcon,
                >(
                    tx_info.transaction_hash,
                    self.ecdsa_public_key.read(),
                    self.read_falcon_public_key().span(),
                    tx_info.signature,
                ),
            )
        }

        fn read_falcon_public_key(self: @ComponentState<TContractState>) -> Array<felt252> {
            let mut key = array![];
            let len = self.falcon_public_key.len();
            let mut i = 0;
            while i != len {
                key.append(self.falcon_public_key.at(i).read());
                i += 1;
            }
            key
        }
    }
}

/// Hybrid account using the Falcon-512 native-Poseidon verifier (cheapest; needs a
/// matching Poseidon hash-to-point signer).
#[starknet::contract(account)]
pub mod HybridPoseidonAccount {
    use pqbench_falcon_512::Falcon512PoseidonVerifier;
    use super::HybridAccountComponent;

    component!(path: HybridAccountComponent, storage: account, event: AccountEvent);

    #[abi(embed_v0)]
    impl AccountImpl =
        HybridAccountComponent::AccountImpl<ContractState, Falcon512PoseidonVerifier>;
    #[abi(embed_v0)]
    impl DeployableImpl =
        HybridAccountComponent::DeployableImpl<ContractState, Falcon512PoseidonVerifier>;
    #[abi(embed_v0)]
    impl PublicKeysImpl = HybridAccountComponent::PublicKeysImpl<ContractState>;
    impl InternalImpl = HybridAccountComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        account: HybridAccountComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        AccountEvent: HybridAccountComponent::Event,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState, ecdsa_public_key: felt252, falcon_public_key: Array<felt252>,
    ) {
        self.account.initializer(ecdsa_public_key, falcon_public_key);
    }
}

/// Hybrid account using the round-three Falcon-512 verifier with SHAKE-256 hash-to-point
/// (interoperable with Falcon-512 signers using that hash-to-point, such as falcon.py and the
/// browser signer; ~4x the verification gas of Poseidon). Not FN-DSA (FIPS 206).
#[starknet::contract(account)]
pub mod HybridShakeAccount {
    use pqbench_falcon_512::Falcon512ShakeVerifier;
    use super::HybridAccountComponent;

    component!(path: HybridAccountComponent, storage: account, event: AccountEvent);

    #[abi(embed_v0)]
    impl AccountImpl =
        HybridAccountComponent::AccountImpl<ContractState, Falcon512ShakeVerifier>;
    #[abi(embed_v0)]
    impl DeployableImpl =
        HybridAccountComponent::DeployableImpl<ContractState, Falcon512ShakeVerifier>;
    #[abi(embed_v0)]
    impl PublicKeysImpl = HybridAccountComponent::PublicKeysImpl<ContractState>;
    impl InternalImpl = HybridAccountComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        account: HybridAccountComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        AccountEvent: HybridAccountComponent::Event,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState, ecdsa_public_key: felt252, falcon_public_key: Array<felt252>,
    ) {
        self.account.initializer(ecdsa_public_key, falcon_public_key);
    }
}
