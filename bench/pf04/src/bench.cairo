use pq_hybrid::migratable::{IMigratableDispatcher, IMigratableDispatcherTrait};
use pq_hybrid::utils::interface::{IHybridAccountDispatcher, IHybridAccountDispatcherTrait};
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_caller_address,
    start_cheat_signature, start_cheat_transaction_hash,
};
use starknet::{ClassHash, ContractAddress};
use crate::legacy::LegacyOzLikeAccount::{ILegacyDispatcher, ILegacyDispatcherTrait};

/// Verifier classes, as declared from contracts/.
pub const BASELINE: felt252 = 'baseline';
pub const COMPACT: felt252 = 'compact';
pub const RECORD: felt252 = 'record';
pub const SMALL: felt252 = 'small';
/// Small with the Falcon key's length read once (PF-11).
pub const SMALLKR: felt252 = 'smallkr';

pub fn class_hash(name: ByteArray) -> ClassHash {
    *declare(name).unwrap().contract_class().class_hash
}

pub fn verifier_class(verifier: felt252) -> ClassHash {
    if verifier == BASELINE {
        class_hash("HybridShakeAccount")
    } else if verifier == COMPACT {
        class_hash("HybridShakeVerifierPfCompact")
    } else if verifier == RECORD {
        class_hash("HybridShakeVerifierPfRecord")
    } else if verifier == SMALL {
        class_hash("HybridShakeVerifierPfSmall")
    } else {
        assert(verifier == SMALLKR, 'unknown verifier');
        class_hash("HybridShakeVerifierPfSmallKeyRead")
    }
}

pub fn hybrid(r: felt252, s: felt252, falcon: Span<felt252>) -> Array<felt252> {
    let mut sig = array![r, s];
    sig.append_span(falcon);
    sig
}

/// A `HybridMigratableAccount` deployed with both keys, validating through `verifier`'s
/// library call: the same storage a migrated wallet has.
pub fn migratable(
    verifier: felt252, ecdsa_public_key: felt252, falcon_public_key: Span<felt252>,
) -> IHybridAccountDispatcher {
    let verifier_class = verifier_class(verifier);
    let mut calldata = array![ecdsa_public_key];
    Serde::serialize(@falcon_public_key, ref calldata);
    calldata.append(verifier_class.into());
    deploy("HybridMigratableAccount", calldata)
}

/// A directly deployed `HybridShakeAccount` (baseline only: it has no candidate counterpart).
pub fn direct(
    ecdsa_public_key: felt252, falcon_public_key: Span<felt252>,
) -> IHybridAccountDispatcher {
    let mut calldata = array![ecdsa_public_key];
    Serde::serialize(@falcon_public_key, ref calldata);
    deploy("HybridShakeAccount", calldata)
}

fn deploy(name: ByteArray, calldata: Array<felt252>) -> IHybridAccountDispatcher {
    let (contract_address, _) = declare(name).unwrap().contract_class().deploy(@calldata).unwrap();
    IHybridAccountDispatcher { contract_address }
}

/// Makes `account` see `hash` and `signature` as the current transaction's.
pub fn as_transaction(account: ContractAddress, hash: felt252, signature: Span<felt252>) {
    start_cheat_transaction_hash(account, hash);
    start_cheat_signature(account, signature);
}

pub fn validate(account: IHybridAccountDispatcher) {
    assert_eq!(account.__validate__(array![]), starknet::VALIDATED);
}

pub fn validate_declare(account: IHybridAccountDispatcher) {
    assert_eq!(account.__validate_declare__(0x1234), starknet::VALIDATED);
}

/// A legacy ECDSA account holding `public_key`, with the migratable and verifier classes declared.
pub fn legacy(verifier: felt252, public_key: felt252) -> (ContractAddress, ClassHash, ClassHash) {
    let (account, _) = declare("LegacyOzLikeAccount")
        .unwrap()
        .contract_class()
        .deploy(@array![public_key])
        .unwrap();
    (account, class_hash("HybridMigratableAccount"), verifier_class(verifier))
}

/// The atomic migration as self-calls: `upgrade` to the migratable class, then `migrate` with the
/// key-possession proof (verified through `verifier_class`).
pub fn migrate(
    account: ContractAddress,
    migratable_class: ClassHash,
    ecdsa_public_key: felt252,
    falcon_public_key: Array<felt252>,
    verifier_class: ClassHash,
    proof: Array<felt252>,
) {
    start_cheat_caller_address(account, account);
    ILegacyDispatcher { contract_address: account }.upgrade(migratable_class);
    let migratable = IMigratableDispatcher { contract_address: account };
    migratable.migrate(ecdsa_public_key, falcon_public_key, verifier_class, proof);
}
