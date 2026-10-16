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

// Second test-only key: STARK key of 0x5eed..02 and its signature over poseidon::msg().
const ECDSA_PK_2: felt252 = 0x1752840a181ce4108bf90d399aaca68c049b6f4c21ab9df838e250d03146d6d;
const ECDSA_R_2: felt252 = 0x262d03f1bd612441e7bcf7971e9ca52050d29eabef28499253bf71be6afc061;
const ECDSA_S_2: felt252 = 0x25900bff3c8ce0539fd09fbe16f2d388189c1a14daa0403b91a1cb0949cdec3;

fn outsider() -> ContractAddress {
    0x1234.try_into().unwrap()
}

#[test]
fn rotate_ecdsa_key_switches_the_classical_key() {
    let address = deploy_legacy();
    migrate(address);
    IMigratableDispatcher { contract_address: address }.rotate_ecdsa_public_key(ECDSA_PK_2);
    let account = IHybridAccountDispatcher { contract_address: address };
    // The old ECDSA half no longer verifies, the new one does (Falcon half unchanged).
    assert_eq!(account.is_valid_signature(poseidon::msg(), hybrid_sig()), 0);
    let mut sig = array![ECDSA_R_2, ECDSA_S_2];
    for f in poseidon::signature() {
        sig.append(f);
    }
    assert_eq!(account.is_valid_signature(poseidon::msg(), sig), starknet::VALIDATED);
    assert_eq!(IMigratableDispatcher { contract_address: address }.get_ecdsa_public_key(), ECDSA_PK_2);
}

#[test]
#[should_panic]
fn rotate_ecdsa_key_from_outsider_fails() {
    let address = deploy_legacy();
    migrate(address);
    starknet::testing::set_contract_address(outsider());
    IMigratableDispatcher { contract_address: address }.rotate_ecdsa_public_key(ECDSA_PK_2);
}

#[test]
#[should_panic]
fn rotate_ecdsa_key_to_zero_fails() {
    let address = deploy_legacy();
    migrate(address);
    IMigratableDispatcher { contract_address: address }.rotate_ecdsa_public_key(0);
}

#[test]
#[should_panic]
fn rotate_ecdsa_key_before_registration_fails() {
    let address = deploy_legacy();
    upgrade_only(address);
    IMigratableDispatcher { contract_address: address }.rotate_ecdsa_public_key(ECDSA_PK_2);
}

#[test]
#[should_panic]
fn set_verifier_from_outsider_fails() {
    let address = deploy_legacy();
    migrate(address);
    starknet::testing::set_contract_address(outsider());
    IMigratableDispatcher { contract_address: address }
        .set_verifier_class_hash(HybridPoseidonAccount::TEST_CLASS_HASH.try_into().unwrap());
}

#[test]
#[should_panic]
fn set_verifier_to_zero_fails() {
    let address = deploy_legacy();
    migrate(address);
    IMigratableDispatcher { contract_address: address }.set_verifier_class_hash(0.try_into().unwrap());
}

#[test]
#[should_panic]
fn upgrade_from_outsider_fails() {
    let address = deploy_legacy();
    migrate(address);
    starknet::testing::set_contract_address(outsider());
    IMigratableDispatcher { contract_address: address }
        .upgrade(HybridPoseidonAccount::TEST_CLASS_HASH.try_into().unwrap());
}

#[test]
#[should_panic]
fn register_short_falcon_key_fails() {
    let address = deploy_legacy();
    upgrade_only(address);
    let mut key = poseidon::public_key();
    let _ = key.pop_front();
    IMigratableDispatcher { contract_address: address }
        .register_falcon_public_key(key, HybridPoseidonAccount::TEST_CLASS_HASH.try_into().unwrap());
}

#[test]
#[should_panic]
fn rotate_short_falcon_key_fails() {
    let address = deploy_legacy();
    migrate(address);
    let mut key = poseidon::public_key();
    let _ = key.pop_front();
    IMigratableDispatcher { contract_address: address }.rotate_falcon_public_key(key);
}

#[test]
fn tampered_falcon_hint_is_rejected() {
    let address = deploy_legacy();
    migrate(address);
    let account = IHybridAccountDispatcher { contract_address: address };
    // Index 2 + 31 + 5 falls inside the multiplication hint (s2 * h).
    assert_eq!(account.is_valid_signature(poseidon::msg(), tamper(hybrid_sig(), 2 + 31 + 5)), 0);
}

#[test]
fn truncated_signature_is_rejected() {
    let address = deploy_legacy();
    migrate(address);
    let account = IHybridAccountDispatcher { contract_address: address };
    let mut sig = hybrid_sig();
    let mut short = array![];
    let mut i: u32 = 0;
    while let Some(f) = sig.pop_front() {
        if i < 61 {
            short.append(f);
        }
        i += 1;
    }
    assert_eq!(account.is_valid_signature(poseidon::msg(), short), 0);
}

#[test]
fn falcon_key_rotation_takes_effect() {
    let address = deploy_legacy();
    migrate(address);
    // Rotate to a different (valid-length) key: the old Falcon signature must stop verifying.
    let mut other = array![];
    for f in poseidon::public_key() {
        other.append(f + 1);
    }
    IMigratableDispatcher { contract_address: address }.rotate_falcon_public_key(other);
    let account = IHybridAccountDispatcher { contract_address: address };
    assert_eq!(account.is_valid_signature(poseidon::msg(), hybrid_sig()), 0);
}

#[test]
fn unregistered_account_signature_check_returns_zero() {
    let address = deploy_legacy();
    upgrade_only(address);
    let account = IHybridAccountDispatcher { contract_address: address };
    assert_eq!(account.is_valid_signature(poseidon::msg(), hybrid_sig()), 0);
}
