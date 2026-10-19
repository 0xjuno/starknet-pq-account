//! In-place migration tests: an OpenZeppelin-style ECDSA account upgrades to
//! `HybridMigratableAccount` at the SAME address, migrates with a key-possession proof, and
//! from then on only accepts hybrid (ECDSA + Falcon) signatures.
//!
//! Keys, proof and signatures come from the wallet fixture: the proof is a hybrid signature
//! over REGISTRATION_HASH, so the same hash and signature also serve as a signed "transaction".

use starknet::account::Call;
use starknet::syscalls::deploy_syscall;
use starknet::{ClassHash, ContractAddress, SyscallResultTrait};
use crate::hybrid::HybridShakeAccount;
use crate::migratable::LegacyOzLikeAccount::{ILegacyDispatcher, ILegacyDispatcherTrait};
use crate::migratable::{
    HybridMigratableAccount, IMigratableDispatcher, IMigratableDispatcherTrait,
    LegacyOzLikeAccount,
};
use crate::tests_wallets_fixture::{
    ECDSA_PK, ECDSA_R, ECDSA_S, REGISTRATION_HASH, WRONG_ECDSA_PK, WRONG_ECDSA_R, WRONG_ECDSA_S,
    falcon_pk, falcon_sig,
};
use crate::utils::interface::{IHybridAccountDispatcher, IHybridAccountDispatcherTrait};

const MSG: felt252 = REGISTRATION_HASH;

fn verifier() -> ClassHash {
    HybridShakeAccount::TEST_CLASS_HASH.try_into().unwrap()
}

fn sig_with(r: felt252, s: felt252) -> Array<felt252> {
    let mut sig = array![r, s];
    for f in falcon_sig() {
        sig.append(f);
    }
    sig
}

fn hybrid_sig() -> Array<felt252> {
    sig_with(ECDSA_R, ECDSA_S)
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

fn upgrade_only(address: ContractAddress) {
    starknet::testing::set_contract_address(address);
    ILegacyDispatcher { contract_address: address }
        .upgrade(HybridMigratableAccount::TEST_CLASS_HASH.try_into().unwrap());
}

/// The recommended atomic flow as self-calls: upgrade, then migrate with the proof.
fn migrate(address: ContractAddress) {
    upgrade_only(address);
    IMigratableDispatcher { contract_address: address }
        .migrate(ECDSA_PK, falcon_pk(), verifier(), hybrid_sig());
}

fn outsider() -> ContractAddress {
    0x1234.try_into().unwrap()
}

#[test]
fn migration_keeps_address_and_ecdsa_key() {
    let address = deploy_legacy();
    assert_eq!(ILegacyDispatcher { contract_address: address }.get_public_key(), ECDSA_PK);
    migrate(address);
    let m = IMigratableDispatcher { contract_address: address };
    assert_eq!(m.get_ecdsa_public_key(), ECDSA_PK);
    assert!(m.is_falcon_registered());
    assert_eq!(m.get_falcon_public_key(), falcon_pk());
    assert_eq!(m.get_verifier_class_hash(), verifier());
}

#[test]
fn migrated_account_accepts_hybrid_signature() {
    let address = deploy_legacy();
    migrate(address);
    let account = IHybridAccountDispatcher { contract_address: address };
    assert_eq!(account.is_valid_signature(MSG, hybrid_sig()), starknet::VALIDATED);
}

#[test]
fn migrated_account_rejects_ecdsa_only() {
    let address = deploy_legacy();
    migrate(address);
    let account = IHybridAccountDispatcher { contract_address: address };
    assert_eq!(account.is_valid_signature(MSG, array![ECDSA_R, ECDSA_S]), 0);
}

#[test]
fn migrated_account_rejects_forged_ecdsa_with_bad_falcon() {
    let address = deploy_legacy();
    migrate(address);
    let account = IHybridAccountDispatcher { contract_address: address };
    assert_eq!(account.is_valid_signature(MSG, tamper(hybrid_sig(), 2 + 29)), 0);
}

#[test]
fn migrated_validate_accepts_hybrid_transaction() {
    let address = deploy_legacy();
    migrate(address);
    let account = IHybridAccountDispatcher { contract_address: address };
    starknet::testing::set_transaction_hash(MSG);
    starknet::testing::set_signature(hybrid_sig().span());
    assert_eq!(account.__validate__(array![]), starknet::VALIDATED);
}

#[test]
#[should_panic]
fn migrated_validate_rejects_ecdsa_only_transaction() {
    let address = deploy_legacy();
    migrate(address);
    let account = IHybridAccountDispatcher { contract_address: address };
    starknet::testing::set_transaction_hash(MSG);
    starknet::testing::set_signature(array![ECDSA_R, ECDSA_S].span());
    account.__validate__(array![]);
}

#[test]
#[should_panic]
fn migrate_twice_fails() {
    let address = deploy_legacy();
    migrate(address);
    IMigratableDispatcher { contract_address: address }
        .migrate(ECDSA_PK, falcon_pk(), verifier(), hybrid_sig());
}

#[test]
#[should_panic]
fn migrate_from_outsider_fails() {
    let address = deploy_legacy();
    upgrade_only(address);
    starknet::testing::set_contract_address(outsider());
    IMigratableDispatcher { contract_address: address }
        .migrate(ECDSA_PK, falcon_pk(), verifier(), hybrid_sig());
}

#[test]
#[should_panic]
fn migrate_without_valid_proof_fails() {
    let address = deploy_legacy();
    upgrade_only(address);
    IMigratableDispatcher { contract_address: address }
        .migrate(ECDSA_PK, falcon_pk(), verifier(), sig_with(WRONG_ECDSA_R, WRONG_ECDSA_S));
}

#[test]
fn bootstrap_accepts_ecdsa_only_migrate_call() {
    let address = deploy_legacy();
    upgrade_only(address);
    let account = IHybridAccountDispatcher { contract_address: address };
    starknet::testing::set_transaction_hash(MSG);
    starknet::testing::set_signature(array![ECDSA_R, ECDSA_S].span());
    let call = Call { to: address, selector: selector!("migrate"), calldata: array![].span() };
    assert_eq!(account.__validate__(array![call]), starknet::VALIDATED);
}

#[test]
#[should_panic]
fn bootstrap_rejects_the_removed_register_call() {
    let address = deploy_legacy();
    upgrade_only(address);
    let account = IHybridAccountDispatcher { contract_address: address };
    starknet::testing::set_transaction_hash(MSG);
    starknet::testing::set_signature(array![ECDSA_R, ECDSA_S].span());
    let call = Call {
        to: address, selector: selector!("register_falcon_public_key"), calldata: array![].span(),
    };
    account.__validate__(array![call]);
}

#[test]
#[should_panic]
fn bootstrap_rejects_any_other_call() {
    let address = deploy_legacy();
    upgrade_only(address);
    let account = IHybridAccountDispatcher { contract_address: address };
    starknet::testing::set_transaction_hash(MSG);
    starknet::testing::set_signature(array![ECDSA_R, ECDSA_S].span());
    let call = Call { to: address, selector: selector!("transfer"), calldata: array![].span() };
    account.__validate__(array![call]);
}

#[test]
fn rotate_ecdsa_key_switches_the_classical_key() {
    let address = deploy_legacy();
    migrate(address);
    IMigratableDispatcher { contract_address: address }.rotate_ecdsa_public_key(WRONG_ECDSA_PK);
    let account = IHybridAccountDispatcher { contract_address: address };
    // The old ECDSA half no longer verifies, the new one does (Falcon half unchanged).
    assert_eq!(account.is_valid_signature(MSG, hybrid_sig()), 0);
    assert_eq!(
        account.is_valid_signature(MSG, sig_with(WRONG_ECDSA_R, WRONG_ECDSA_S)),
        starknet::VALIDATED,
    );
    assert_eq!(
        IMigratableDispatcher { contract_address: address }.get_ecdsa_public_key(), WRONG_ECDSA_PK,
    );
}

#[test]
#[should_panic]
fn rotate_ecdsa_key_from_outsider_fails() {
    let address = deploy_legacy();
    migrate(address);
    starknet::testing::set_contract_address(outsider());
    IMigratableDispatcher { contract_address: address }.rotate_ecdsa_public_key(WRONG_ECDSA_PK);
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
    IMigratableDispatcher { contract_address: address }.rotate_ecdsa_public_key(WRONG_ECDSA_PK);
}

#[test]
#[should_panic]
fn set_verifier_from_outsider_fails() {
    let address = deploy_legacy();
    migrate(address);
    starknet::testing::set_contract_address(outsider());
    IMigratableDispatcher { contract_address: address }.set_verifier_class_hash(verifier());
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
    IMigratableDispatcher { contract_address: address }.upgrade(verifier());
}

#[test]
#[should_panic]
fn migrate_with_short_falcon_key_fails() {
    let address = deploy_legacy();
    upgrade_only(address);
    let mut key = falcon_pk();
    let _ = key.pop_front();
    IMigratableDispatcher { contract_address: address }
        .migrate(ECDSA_PK, key, verifier(), hybrid_sig());
}

#[test]
#[should_panic]
fn rotate_short_falcon_key_fails() {
    let address = deploy_legacy();
    migrate(address);
    let mut key = falcon_pk();
    let _ = key.pop_front();
    IMigratableDispatcher { contract_address: address }.rotate_falcon_public_key(key);
}

#[test]
fn tampered_falcon_hint_is_rejected() {
    let address = deploy_legacy();
    migrate(address);
    let account = IHybridAccountDispatcher { contract_address: address };
    // Index 2 + 31 + 5 falls inside the multiplication hint (s2 * h).
    assert_eq!(account.is_valid_signature(MSG, tamper(hybrid_sig(), 2 + 31 + 5)), 0);
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
    assert_eq!(account.is_valid_signature(MSG, short), 0);
}

#[test]
fn falcon_key_rotation_takes_effect() {
    let address = deploy_legacy();
    migrate(address);
    // Rotate to a different (valid-length) key: the old Falcon signature must stop verifying.
    let mut other = array![];
    for f in falcon_pk() {
        other.append(f + 1);
    }
    IMigratableDispatcher { contract_address: address }.rotate_falcon_public_key(other);
    let account = IHybridAccountDispatcher { contract_address: address };
    assert_eq!(account.is_valid_signature(MSG, hybrid_sig()), 0);
}

#[test]
fn unregistered_account_signature_check_returns_zero() {
    let address = deploy_legacy();
    upgrade_only(address);
    let account = IHybridAccountDispatcher { contract_address: address };
    assert_eq!(account.is_valid_signature(MSG, hybrid_sig()), 0);
}
