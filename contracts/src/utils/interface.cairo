//! Account interfaces and interface identifiers.
//!
//! Adapted from OpenZeppelin cairo-pq-verifiers, MIT License.

use starknet::account::Call;

/// SRC5 interface identifier.
pub const ISRC5_ID: felt252 = 0x3f918d17e5ee77373b56385708f855659a07f75997f365cf87748628532a055;

/// SNIP-6 account interface identifier.
pub const ISRC6_ID: felt252 = 0x2ceccef7f994940b3962a6c67e0ba4fcd37df7d131417c604f91e03caecc1cd;

/// Common account entrypoints for invoke, declare, signature checks, and SRC5 detection.
#[starknet::interface]
pub trait IHybridAccount<TState> {
    fn __execute__(self: @TState, calls: Array<Call>);
    fn __validate__(self: @TState, calls: Array<Call>) -> felt252;
    fn __validate_declare__(self: @TState, class_hash: felt252) -> felt252;
    fn is_valid_signature(self: @TState, hash: felt252, signature: Array<felt252>) -> felt252;
    fn supports_interface(self: @TState, interface_id: felt252) -> bool;
}

/// The one entrypoint `HybridMigratableAccount` library-calls on its verifier class. Same
/// selector and calldata as `IHybridAccount::is_valid_signature`.
#[starknet::interface]
pub trait IHybridVerifier<TState> {
    fn is_valid_signature(self: @TState, hash: felt252, signature: Array<felt252>) -> felt252;
}

/// Deploy-account validation for the hybrid key layout.
#[starknet::interface]
pub trait IHybridDeployable<TState> {
    fn __validate_deploy__(
        self: @TState,
        class_hash: felt252,
        contract_address_salt: felt252,
        ecdsa_public_key: felt252,
        falcon_public_key: Array<felt252>,
    ) -> felt252;
}

/// Public-key readers.
#[starknet::interface]
pub trait IHybridPublicKeys<TState> {
    fn get_ecdsa_public_key(self: @TState) -> felt252;
    fn get_falcon_public_key(self: @TState) -> Array<felt252>;
}
