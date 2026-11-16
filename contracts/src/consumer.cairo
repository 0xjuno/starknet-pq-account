//! A contract that checks another account's signature the SNIP-6 way: it hands the whole
//! signature to the account's `is_valid_signature` and never looks inside. That is what keeps it
//! working when the account moves to a hybrid ECDSA + Falcon-512 signature (62 felts instead of
//! 2) at the same address. `signer/consumer_sepolia.mjs` deploys it on Sepolia to measure what
//! such a check costs the caller.
//!
//! EXPERIMENTAL AND UNAUDITED. Testnet / demo use only.

use starknet::ContractAddress;

#[starknet::interface]
pub trait ISignatureConsumer<TState> {
    /// True when `account` accepts `signature` for `hash`, whatever the signature's length.
    fn check(
        self: @TState, account: ContractAddress, hash: felt252, signature: Array<felt252>,
    ) -> bool;
    /// Runs `check` `times` times and returns how many passed. Only for cost measurements.
    fn check_many(
        self: @TState,
        account: ContractAddress,
        hash: felt252,
        signature: Array<felt252>,
        times: u32,
    ) -> u32;
}

#[starknet::contract]
pub mod SignatureConsumer {
    use starknet::ContractAddress;
    use crate::utils::interface::{IHybridAccountDispatcher, IHybridAccountDispatcherTrait};

    #[storage]
    struct Storage {}

    fn passes(account: ContractAddress, hash: felt252, signature: Array<felt252>) -> bool {
        let account = IHybridAccountDispatcher { contract_address: account };
        account.is_valid_signature(hash, signature) == starknet::VALIDATED
    }

    #[abi(embed_v0)]
    impl SignatureConsumerImpl of super::ISignatureConsumer<ContractState> {
        fn check(
            self: @ContractState,
            account: ContractAddress,
            hash: felt252,
            signature: Array<felt252>,
        ) -> bool {
            passes(account, hash, signature)
        }

        fn check_many(
            self: @ContractState,
            account: ContractAddress,
            hash: felt252,
            signature: Array<felt252>,
            times: u32,
        ) -> u32 {
            let mut passed = 0;
            let mut i = 0;
            while i < times {
                if passes(account, hash, signature.clone()) {
                    passed += 1;
                }
                i += 1;
            }
            passed
        }
    }
}
