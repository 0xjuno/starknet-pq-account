//! In-place migration tests: an OpenZeppelin-style ECDSA account upgrades to
//! `HybridMigratableAccount` at the SAME address, migrates with a key-possession proof, and
//! from then on only accepts hybrid (ECDSA + Falcon) signatures.
//!
//! Keys, proof and signatures come from the wallet fixture: the proof is a hybrid signature
//! over REGISTRATION_HASH, so the same hash and signature also serve as a signed "transaction".

use starknet::account::Call;
use starknet::syscalls::deploy_syscall;
use starknet::{ClassHash, ContractAddress, SyscallResultTrait};
use crate::hybrid::{HybridPoseidonAccount, HybridShakeAccount};
use crate::migratable::LegacyOzLikeAccount::{ILegacyDispatcher, ILegacyDispatcherTrait};
use crate::migratable::{
    HybridMigratableAccount, IMigratableDispatcher, IMigratableDispatcherTrait,
    LegacyOzLikeAccount, rotation_hash,
};
use crate::tests_rotation_fixture::{
    ECDSA_ROTATION_HASH, FALCON_ROTATION_HASH, ecdsa_rotation_proof, falcon_pk_b,
    falcon_rotation_proof,
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
fn rotation_hash_matches_off_chain_signer() {
    assert_eq!(rotation_hash(ECDSA_PK, falcon_pk_b().span()), FALCON_ROTATION_HASH);
    assert_eq!(rotation_hash(WRONG_ECDSA_PK, falcon_pk().span()), ECDSA_ROTATION_HASH);
}

#[test]
fn rotate_ecdsa_key_switches_the_classical_key() {
    let address = deploy_legacy();
    migrate(address);
    IMigratableDispatcher { contract_address: address }
        .rotate_ecdsa_public_key(WRONG_ECDSA_PK, ecdsa_rotation_proof());
    let account = IHybridAccountDispatcher { contract_address: address };
    // The old ECDSA half no longer verifies, the new one does (Falcon half unchanged).
    assert_eq!(account.is_valid_signature(MSG, hybrid_sig()), 0);
    assert_eq!(
        account.is_valid_signature(MSG, sig_with(WRONG_ECDSA_R, WRONG_ECDSA_S)),
        starknet::VALIDATED,
    );
    assert_eq!(
        account.is_valid_signature(ECDSA_ROTATION_HASH, ecdsa_rotation_proof()),
        starknet::VALIDATED,
    );
    assert_eq!(
        IMigratableDispatcher { contract_address: address }.get_ecdsa_public_key(), WRONG_ECDSA_PK,
    );
}

#[test]
#[should_panic(expected: ('Migratable: invalid key proof', 'ENTRYPOINT_FAILED'))]
fn rotate_ecdsa_key_without_proof_by_new_key_fails() {
    let address = deploy_legacy();
    migrate(address);
    // Signed by the current keys, not by the new ECDSA key.
    IMigratableDispatcher { contract_address: address }
        .rotate_ecdsa_public_key(WRONG_ECDSA_PK, hybrid_sig());
}

#[test]
#[should_panic(expected: ('Migratable: invalid key proof', 'ENTRYPOINT_FAILED'))]
fn rotate_ecdsa_key_with_proof_over_other_message_fails() {
    let address = deploy_legacy();
    migrate(address);
    // A valid hybrid signature by the new key pair, but over the registration hash.
    IMigratableDispatcher { contract_address: address }
        .rotate_ecdsa_public_key(WRONG_ECDSA_PK, sig_with(WRONG_ECDSA_R, WRONG_ECDSA_S));
}

#[test]
#[should_panic(expected: ('Migratable: invalid key proof', 'ENTRYPOINT_FAILED'))]
fn rotate_ecdsa_key_nobody_can_sign_for_fails() {
    let address = deploy_legacy();
    migrate(address);
    IMigratableDispatcher { contract_address: address }
        .rotate_ecdsa_public_key(ECDSA_PK + 1, ecdsa_rotation_proof());
}

#[test]
#[should_panic(expected: ('Migratable: only self', 'ENTRYPOINT_FAILED'))]
fn rotate_ecdsa_key_from_outsider_fails() {
    let address = deploy_legacy();
    migrate(address);
    starknet::testing::set_contract_address(outsider());
    IMigratableDispatcher { contract_address: address }
        .rotate_ecdsa_public_key(WRONG_ECDSA_PK, ecdsa_rotation_proof());
}

#[test]
#[should_panic(expected: ('Migratable: no ecdsa key', 'ENTRYPOINT_FAILED'))]
fn rotate_ecdsa_key_to_zero_fails() {
    let address = deploy_legacy();
    migrate(address);
    IMigratableDispatcher { contract_address: address }.rotate_ecdsa_public_key(0, array![]);
}

#[test]
#[should_panic(expected: ('Migratable: not registered', 'ENTRYPOINT_FAILED'))]
fn rotate_ecdsa_key_before_registration_fails() {
    let address = deploy_legacy();
    upgrade_only(address);
    IMigratableDispatcher { contract_address: address }
        .rotate_ecdsa_public_key(WRONG_ECDSA_PK, ecdsa_rotation_proof());
}

/// Self-call inside a transaction whose hash is MSG and whose signature is `signature`.
fn set_verifier_in_tx(address: ContractAddress, signature: Array<felt252>, class_hash: ClassHash) {
    starknet::testing::set_transaction_hash(MSG);
    starknet::testing::set_signature(signature.span());
    IMigratableDispatcher { contract_address: address }.set_verifier_class_hash(class_hash);
}

#[test]
fn set_verifier_accepting_the_transaction_signature_succeeds() {
    let address = deploy_legacy();
    migrate(address);
    set_verifier_in_tx(address, hybrid_sig(), verifier());
    let m = IMigratableDispatcher { contract_address: address };
    assert_eq!(m.get_verifier_class_hash(), verifier());
    let account = IHybridAccountDispatcher { contract_address: address };
    assert_eq!(account.is_valid_signature(MSG, hybrid_sig()), starknet::VALIDATED);
}

#[test]
#[should_panic(expected: ('Migratable: verifier rejects', 'ENTRYPOINT_FAILED'))]
fn set_verifier_of_another_scheme_fails() {
    let address = deploy_legacy();
    migrate(address);
    // The Poseidon verifier reads the same keys but hashes the message differently, so it
    // rejects this SHAKE-256 signature.
    set_verifier_in_tx(
        address, hybrid_sig(), HybridPoseidonAccount::TEST_CLASS_HASH.try_into().unwrap(),
    );
}

#[test]
#[should_panic]
fn set_verifier_to_a_class_that_is_not_a_verifier_fails() {
    let address = deploy_legacy();
    migrate(address);
    // No is_valid_signature entry point: the library call itself fails.
    set_verifier_in_tx(
        address, hybrid_sig(), LegacyOzLikeAccount::TEST_CLASS_HASH.try_into().unwrap(),
    );
}

#[test]
#[should_panic(expected: ('Migratable: verifier rejects', 'ENTRYPOINT_FAILED'))]
fn set_verifier_without_a_transaction_signature_fails() {
    let address = deploy_legacy();
    migrate(address);
    set_verifier_in_tx(address, array![], verifier());
}

#[test]
#[should_panic(expected: ('Migratable: only self', 'ENTRYPOINT_FAILED'))]
fn set_verifier_from_outsider_fails() {
    let address = deploy_legacy();
    migrate(address);
    starknet::testing::set_contract_address(outsider());
    set_verifier_in_tx(address, hybrid_sig(), verifier());
}

#[test]
#[should_panic(expected: ('Migratable: invalid verifier', 'ENTRYPOINT_FAILED'))]
fn set_verifier_to_zero_fails() {
    let address = deploy_legacy();
    migrate(address);
    set_verifier_in_tx(address, hybrid_sig(), 0.try_into().unwrap());
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
#[should_panic(expected: ('Migratable: invalid falcon key', 'ENTRYPOINT_FAILED'))]
fn rotate_short_falcon_key_fails() {
    let address = deploy_legacy();
    migrate(address);
    let mut key = falcon_pk_b();
    let _ = key.pop_front();
    IMigratableDispatcher { contract_address: address }
        .rotate_falcon_public_key(key, falcon_rotation_proof());
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
    IMigratableDispatcher { contract_address: address }
        .rotate_falcon_public_key(falcon_pk_b(), falcon_rotation_proof());
    let m = IMigratableDispatcher { contract_address: address };
    assert_eq!(m.get_falcon_public_key(), falcon_pk_b());
    assert_eq!(m.get_ecdsa_public_key(), ECDSA_PK);
    let account = IHybridAccountDispatcher { contract_address: address };
    // The old Falcon signature stops verifying, one by the new key verifies.
    assert_eq!(account.is_valid_signature(MSG, hybrid_sig()), 0);
    assert_eq!(
        account.is_valid_signature(FALCON_ROTATION_HASH, falcon_rotation_proof()),
        starknet::VALIDATED,
    );
}

#[test]
#[should_panic(expected: ('Migratable: invalid key proof', 'ENTRYPOINT_FAILED'))]
fn rotate_falcon_key_without_proof_by_new_key_fails() {
    let address = deploy_legacy();
    migrate(address);
    // Signed by the current Falcon key, not by key B.
    IMigratableDispatcher { contract_address: address }
        .rotate_falcon_public_key(falcon_pk_b(), hybrid_sig());
}

#[test]
#[should_panic(expected: ('Migratable: invalid key proof', 'ENTRYPOINT_FAILED'))]
fn rotate_falcon_key_nobody_can_sign_for_fails() {
    let address = deploy_legacy();
    migrate(address);
    // A valid-length key that nobody holds: before the proof check this locked the account.
    let mut other = array![];
    for f in falcon_pk() {
        other.append(f + 1);
    }
    IMigratableDispatcher { contract_address: address }
        .rotate_falcon_public_key(other, falcon_rotation_proof());
}

#[test]
#[should_panic(expected: ('Migratable: only self', 'ENTRYPOINT_FAILED'))]
fn rotate_falcon_key_from_outsider_fails() {
    let address = deploy_legacy();
    migrate(address);
    starknet::testing::set_contract_address(outsider());
    IMigratableDispatcher { contract_address: address }
        .rotate_falcon_public_key(falcon_pk_b(), falcon_rotation_proof());
}

#[test]
fn unregistered_account_signature_check_returns_zero() {
    let address = deploy_legacy();
    upgrade_only(address);
    let account = IHybridAccountDispatcher { contract_address: address };
    assert_eq!(account.is_valid_signature(MSG, hybrid_sig()), 0);
}
