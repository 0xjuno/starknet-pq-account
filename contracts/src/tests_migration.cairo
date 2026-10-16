//! In-place migration tests: an OpenZeppelin-style ECDSA account upgrades to
//! `HybridMigratableAccount` at the SAME address, keeps its ECDSA key, registers a Falcon
//! key, and from then on only accepts hybrid (ECDSA + Falcon) signatures.

use pqbench_falcon_512::fixtures::poseidon;
use starknet::account::Call;
use starknet::syscalls::deploy_syscall;
use starknet::{ContractAddress, SyscallResultTrait};
use crate::hybrid::HybridPoseidonAccount;
use crate::migratable::LegacyOzLikeAccount::{ILegacyDispatcher, ILegacyDispatcherTrait};
use crate::migratable::{
    HybridMigratableAccount, IMigratableDispatcher, IMigratableDispatcherTrait,
    LegacyOzLikeAccount,
};
use crate::utils::interface::{IHybridAccountDispatcher, IHybridAccountDispatcherTrait};

// Same test-only STARK-curve ECDSA fixture as tests.cairo (signs poseidon::msg()).
const ECDSA_PK: felt252 = 0x1da8f79d6fd8ef4fb1b9afe8e861eb80b82ec0b022aa28220dad045dc9328a4;
const ECDSA_R: felt252 = 0x3b87908dab2a2c41cd7010c605f6d4aac97108e200e4c8838e1b465db549994;
const ECDSA_S: felt252 = 0x409708fbae771c0d93735659703ededebeb7c20a57226788b2b83d97646826d;

fn hybrid_sig() -> Array<felt252> {
    let mut sig = array![ECDSA_R, ECDSA_S];
    for f in poseidon::signature() {
        sig.append(f);
    }
    sig
}

fn tamper(mut sig: Array<felt252>, index: u32) -> Array<felt252> {
    let mut out = array![];
    let mut i = 0;
    while let Some(f) = sig.pop_front() {
        if i == index {
            out.append(f + 1);
        } else {
            out.append(f);
        }
        i += 1;
    }
    out
}

fn deploy_legacy() -> ContractAddress {
    let (address, _) = deploy_syscall(
        LegacyOzLikeAccount::TEST_CLASS_HASH, 0, array![ECDSA_PK].span(), false,
    )
        .unwrap_syscall();
    address
}

/// Runs the recommended atomic flow as self-calls: upgrade, then register.
fn migrate(address: ContractAddress) {
    starknet::testing::set_contract_address(address);
    ILegacyDispatcher { contract_address: address }
        .upgrade(HybridMigratableAccount::TEST_CLASS_HASH.try_into().unwrap());
    IMigratableDispatcher { contract_address: address }
        .register_falcon_public_key(
            poseidon::public_key(), HybridPoseidonAccount::TEST_CLASS_HASH.try_into().unwrap(),
        );
}

fn upgrade_only(address: ContractAddress) {
    starknet::testing::set_contract_address(address);
    ILegacyDispatcher { contract_address: address }
        .upgrade(HybridMigratableAccount::TEST_CLASS_HASH.try_into().unwrap());
}

#[test]
fn migration_keeps_address_and_ecdsa_key() {
    let address = deploy_legacy();
    assert_eq!(ILegacyDispatcher { contract_address: address }.get_public_key(), ECDSA_PK);
    migrate(address);
    let m = IMigratableDispatcher { contract_address: address };
    assert_eq!(m.get_ecdsa_public_key(), ECDSA_PK);
    assert!(m.is_falcon_registered());
    assert_eq!(m.get_falcon_public_key(), poseidon::public_key());
    assert_eq!(
        m.get_verifier_class_hash(), HybridPoseidonAccount::TEST_CLASS_HASH.try_into().unwrap(),
    );
}

#[test]
fn migrated_account_accepts_hybrid_signature() {
    let address = deploy_legacy();
    migrate(address);
    let account = IHybridAccountDispatcher { contract_address: address };
    assert_eq!(account.is_valid_signature(poseidon::msg(), hybrid_sig()), starknet::VALIDATED);
}

#[test]
fn migrated_account_rejects_ecdsa_only() {
    let address = deploy_legacy();
    migrate(address);
    let account = IHybridAccountDispatcher { contract_address: address };
    assert_eq!(account.is_valid_signature(poseidon::msg(), array![ECDSA_R, ECDSA_S]), 0);
}

#[test]
fn migrated_account_rejects_forged_ecdsa_with_bad_falcon() {
    let address = deploy_legacy();
    migrate(address);
    let account = IHybridAccountDispatcher { contract_address: address };
    assert_eq!(account.is_valid_signature(poseidon::msg(), tamper(hybrid_sig(), 2 + 29)), 0);
}

#[test]
fn migrated_validate_accepts_hybrid_transaction() {
    let address = deploy_legacy();
    migrate(address);
    let account = IHybridAccountDispatcher { contract_address: address };
    starknet::testing::set_transaction_hash(poseidon::msg());
    starknet::testing::set_signature(hybrid_sig().span());
    assert_eq!(account.__validate__(array![]), starknet::VALIDATED);
}

#[test]
#[should_panic]
fn migrated_validate_rejects_ecdsa_only_transaction() {
    let address = deploy_legacy();
    migrate(address);
    let account = IHybridAccountDispatcher { contract_address: address };
    starknet::testing::set_transaction_hash(poseidon::msg());
    starknet::testing::set_signature(array![ECDSA_R, ECDSA_S].span());
    account.__validate__(array![]);
}

#[test]
#[should_panic]
fn register_twice_fails() {
    let address = deploy_legacy();
    migrate(address);
    IMigratableDispatcher { contract_address: address }
        .register_falcon_public_key(
            poseidon::public_key(), HybridPoseidonAccount::TEST_CLASS_HASH.try_into().unwrap(),
        );
}

#[test]
#[should_panic]
fn register_from_outsider_fails() {
    let address = deploy_legacy();
    upgrade_only(address);
    starknet::testing::set_contract_address(0x1234.try_into().unwrap());
    IMigratableDispatcher { contract_address: address }
        .register_falcon_public_key(
            poseidon::public_key(), HybridPoseidonAccount::TEST_CLASS_HASH.try_into().unwrap(),
        );
}

#[test]
fn bootstrap_accepts_ecdsa_only_register_call() {
    let address = deploy_legacy();
    upgrade_only(address);
    let account = IHybridAccountDispatcher { contract_address: address };
    starknet::testing::set_transaction_hash(poseidon::msg());
    starknet::testing::set_signature(array![ECDSA_R, ECDSA_S].span());
    let call = Call {
        to: address, selector: selector!("register_falcon_public_key"), calldata: array![].span(),
    };
    assert_eq!(account.__validate__(array![call]), starknet::VALIDATED);
}

#[test]
#[should_panic]
fn bootstrap_rejects_any_other_call() {
    let address = deploy_legacy();
    upgrade_only(address);
    let account = IHybridAccountDispatcher { contract_address: address };
    starknet::testing::set_transaction_hash(poseidon::msg());
    starknet::testing::set_signature(array![ECDSA_R, ECDSA_S].span());
    let call = Call { to: address, selector: selector!("transfer"), calldata: array![].span() };
    account.__validate__(array![call]);
}

#[test]
fn unregistered_account_signature_check_returns_zero() {
    let address = deploy_legacy();
    upgrade_only(address);
    let account = IHybridAccountDispatcher { contract_address: address };
    assert_eq!(account.is_valid_signature(poseidon::msg(), hybrid_sig()), 0);
}
