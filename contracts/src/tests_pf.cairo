//! PF-02: the Provably Fast verifier classes accept the same keys, signatures and storage as
//! the baseline `HybridShakeAccount`, through `HybridMigratableAccount`'s library call.
//!
//! Every check runs on all four verifier classes (baseline, compact, record, small) so a difference
//! between them shows up as a failing index.

use pqbench_falcon_512::Falcon512ShakeVerifier as Baseline;
use pqbench_falcon_512::fixtures::shake as falcon_py;
use pqbench_falcon_512_pf_compact::Falcon512ShakeVerifier as Compact;
use pqbench_falcon_512_pf_record::Falcon512ShakeVerifier as Record;
use pqbench_falcon_512_pf_small::Falcon512ShakeVerifier as Small;
use starknet::syscalls::deploy_syscall;
use starknet::{ClassHash, ContractAddress, SyscallResultTrait};
use crate::hybrid::{
    HybridShakeAccount, HybridShakeVerifierPfCompact, HybridShakeVerifierPfRecord,
    HybridShakeVerifierPfSmall, HybridShakeVerifierPfSmallKeyRead, verify_hybrid,
};
use crate::migratable::LegacyOzLikeAccount::{ILegacyDispatcher, ILegacyDispatcherTrait};
use crate::migratable::{
    HybridMigratableAccount, IMigratableDispatcher, IMigratableDispatcherTrait,
    LegacyOzLikeAccount,
};
use crate::utils::interface::{
    IHybridAccountDispatcher, IHybridAccountDispatcherTrait, IHybridVerifierDispatcher,
    IHybridVerifierDispatcherTrait,
};
use crate::{tests_browser as browser, tests_wallets_fixture as wallet};

fn verifiers() -> Array<ClassHash> {
    array![
        HybridShakeAccount::TEST_CLASS_HASH.try_into().unwrap(),
        HybridShakeVerifierPfCompact::TEST_CLASS_HASH.try_into().unwrap(),
        HybridShakeVerifierPfRecord::TEST_CLASS_HASH.try_into().unwrap(),
        HybridShakeVerifierPfSmall::TEST_CLASS_HASH.try_into().unwrap(),
        HybridShakeVerifierPfSmallKeyRead::TEST_CLASS_HASH.try_into().unwrap(),
    ]
}

fn hybrid(r: felt252, s: felt252, falcon: Array<felt252>) -> Array<felt252> {
    let mut sig = array![r, s];
    for f in falcon {
        sig.append(f);
    }
    sig
}

fn wallet_sig() -> Array<felt252> {
    hybrid(wallet::ECDSA_R, wallet::ECDSA_S, wallet::falcon_sig())
}

fn browser_sig() -> Array<felt252> {
    hybrid(browser::ECDSA_R, browser::ECDSA_S, browser::falcon_sig())
}

fn tamper(sig: Span<felt252>, index: u32) -> Array<felt252> {
    let mut out = array![];
    let mut i = 0;
    for f in sig {
        out.append(if i == index {
            *f + 1
        } else {
            *f
        });
        i += 1;
    }
    out
}

/// An OpenZeppelin-style account at a fresh address, upgraded and migrated in place with the
/// wallet fixture's keys and key-possession proof, checked by `verifier`.
fn migrated(verifier: ClassHash, salt: felt252) -> ContractAddress {
    let (address, _) = deploy_syscall(
        LegacyOzLikeAccount::TEST_CLASS_HASH, salt, array![wallet::ECDSA_PK].span(), false,
    )
        .unwrap_syscall();
    starknet::testing::set_contract_address(address);
    ILegacyDispatcher { contract_address: address }
        .upgrade(HybridMigratableAccount::TEST_CLASS_HASH.try_into().unwrap());
    IMigratableDispatcher { contract_address: address }
        .migrate(wallet::ECDSA_PK, wallet::falcon_pk(), verifier, wallet_sig());
    address
}

/// A freshly deployed migratable account holding the browser fixture's keys.
fn browser_account(verifier: ClassHash, salt: felt252) -> ContractAddress {
    let mut calldata = array![browser::ECDSA_PK];
    Serde::serialize(@browser::falcon_pk(), ref calldata);
    calldata.append(verifier.into());
    let (address, _) = deploy_syscall(
        HybridMigratableAccount::TEST_CLASS_HASH, salt, calldata.span(), false,
    )
        .unwrap_syscall();
    address
}

#[test]
fn migration_proof_verifies_through_each_verifier() {
    let mut salt = 0;
    for verifier in verifiers() {
        let address = migrated(verifier, salt);
        let m = IMigratableDispatcher { contract_address: address };
        assert!(m.is_falcon_registered(), "verifier {salt}");
        assert_eq!(m.get_verifier_class_hash(), verifier);
        assert_eq!(m.get_ecdsa_public_key(), wallet::ECDSA_PK);
        assert_eq!(m.get_falcon_public_key(), wallet::falcon_pk());
        salt += 1;
    }
}

#[test]
fn each_verifier_accepts_the_wallet_signature() {
    let mut salt = 0;
    for verifier in verifiers() {
        let account = IHybridAccountDispatcher { contract_address: migrated(verifier, salt) };
        assert_eq!(
            account.is_valid_signature(wallet::REGISTRATION_HASH, wallet_sig()),
            starknet::VALIDATED,
            "verifier {salt}",
        );
        salt += 1;
    }
}

#[test]
fn each_verifier_validates_a_hybrid_transaction() {
    let mut salt = 0;
    for verifier in verifiers() {
        let account = IHybridAccountDispatcher { contract_address: migrated(verifier, salt) };
        starknet::testing::set_transaction_hash(wallet::REGISTRATION_HASH);
        starknet::testing::set_signature(wallet_sig().span());
        assert_eq!(account.__validate__(array![]), starknet::VALIDATED, "verifier {salt}");
        salt += 1;
    }
}

#[test]
fn each_verifier_validates_a_declare() {
    let mut salt = 0;
    for verifier in verifiers() {
        let account = IHybridAccountDispatcher { contract_address: migrated(verifier, salt) };
        starknet::testing::set_transaction_hash(wallet::REGISTRATION_HASH);
        starknet::testing::set_signature(wallet_sig().span());
        assert_eq!(account.__validate_declare__(0x1234), starknet::VALIDATED, "verifier {salt}");
        salt += 1;
    }
}

#[test]
#[should_panic]
fn ecdsa_only_declare_is_rejected_on_the_small_verifier() {
    let account = IHybridAccountDispatcher {
        contract_address: migrated(HybridShakeVerifierPfSmall::TEST_CLASS_HASH.try_into().unwrap(), 0),
    };
    starknet::testing::set_transaction_hash(wallet::REGISTRATION_HASH);
    starknet::testing::set_signature(array![wallet::ECDSA_R, wallet::ECDSA_S].span());
    account.__validate_declare__(0x1234);
}

#[test]
fn each_verifier_rejects_a_bad_ecdsa_or_a_bad_falcon_half() {
    let sig = wallet_sig();
    let bad_ecdsa = array![
        hybrid(wallet::WRONG_ECDSA_R, wallet::WRONG_ECDSA_S, wallet::falcon_sig()),
        tamper(sig.span(), 0), tamper(sig.span(), 1),
    ];
    // s1, both salt halves, and the hint.
    let bad_falcon = array![
        tamper(sig.span(), 2), tamper(sig.span(), 2 + 29), tamper(sig.span(), 2 + 30),
        tamper(sig.span(), 2 + 31), tamper(sig.span(), 2 + 59),
    ];
    let mut salt = 0;
    for verifier in verifiers() {
        let account = IHybridAccountDispatcher { contract_address: migrated(verifier, salt) };
        let hash = wallet::REGISTRATION_HASH;
        for s in bad_ecdsa.span() {
            assert_eq!(account.is_valid_signature(hash, s.clone()), 0, "verifier {salt}");
        }
        for s in bad_falcon.span() {
            assert_eq!(account.is_valid_signature(hash, s.clone()), 0, "verifier {salt}");
        }
        assert_eq!(account.is_valid_signature(hash + 1, sig.clone()), 0, "verifier {salt}");
        assert_eq!(
            account.is_valid_signature(hash, array![wallet::ECDSA_R, wallet::ECDSA_S]),
            0,
            "verifier {salt}",
        );
        assert_eq!(
            account.is_valid_signature(hash, sig.span().slice(0, 61).into()),
            0,
            "verifier {salt}",
        );
        salt += 1;
    }
}

#[test]
#[should_panic]
fn migration_with_a_wrong_key_proof_reverts_on_the_compact_verifier() {
    let (address, _) = deploy_syscall(
        LegacyOzLikeAccount::TEST_CLASS_HASH, 0, array![wallet::ECDSA_PK].span(), false,
    )
        .unwrap_syscall();
    starknet::testing::set_contract_address(address);
    ILegacyDispatcher { contract_address: address }
        .upgrade(HybridMigratableAccount::TEST_CLASS_HASH.try_into().unwrap());
    IMigratableDispatcher { contract_address: address }
        .migrate(
            wallet::ECDSA_PK,
            wallet::falcon_pk(),
            HybridShakeVerifierPfCompact::TEST_CLASS_HASH.try_into().unwrap(),
            hybrid(wallet::WRONG_ECDSA_R, wallet::WRONG_ECDSA_S, wallet::falcon_sig()),
        );
}

#[test]
#[should_panic]
fn migration_with_a_wrong_key_proof_reverts_on_the_record_verifier() {
    let (address, _) = deploy_syscall(
        LegacyOzLikeAccount::TEST_CLASS_HASH, 0, array![wallet::ECDSA_PK].span(), false,
    )
        .unwrap_syscall();
    starknet::testing::set_contract_address(address);
    ILegacyDispatcher { contract_address: address }
        .upgrade(HybridMigratableAccount::TEST_CLASS_HASH.try_into().unwrap());
    IMigratableDispatcher { contract_address: address }
        .migrate(
            wallet::ECDSA_PK,
            wallet::falcon_pk(),
            HybridShakeVerifierPfRecord::TEST_CLASS_HASH.try_into().unwrap(),
            hybrid(wallet::WRONG_ECDSA_R, wallet::WRONG_ECDSA_S, wallet::falcon_sig()),
        );
}

#[test]
#[should_panic]
fn migration_with_a_wrong_key_proof_reverts_on_the_small_verifier() {
    let (address, _) = deploy_syscall(
        LegacyOzLikeAccount::TEST_CLASS_HASH, 0, array![wallet::ECDSA_PK].span(), false,
    )
        .unwrap_syscall();
    starknet::testing::set_contract_address(address);
    ILegacyDispatcher { contract_address: address }
        .upgrade(HybridMigratableAccount::TEST_CLASS_HASH.try_into().unwrap());
    IMigratableDispatcher { contract_address: address }
        .migrate(
            wallet::ECDSA_PK,
            wallet::falcon_pk(),
            HybridShakeVerifierPfSmall::TEST_CLASS_HASH.try_into().unwrap(),
            hybrid(wallet::WRONG_ECDSA_R, wallet::WRONG_ECDSA_S, wallet::falcon_sig()),
        );
}

#[test]
fn each_verifier_accepts_the_browser_signature() {
    let mut salt = 0;
    for verifier in verifiers() {
        let account = IHybridAccountDispatcher { contract_address: browser_account(verifier, salt) };
        assert_eq!(
            account.is_valid_signature(browser::MSG, browser_sig()),
            starknet::VALIDATED,
            "verifier {salt}",
        );
        assert_eq!(account.is_valid_signature(browser::MSG + 1, browser_sig()), 0);
        salt += 1;
    }
}

#[test]
fn candidates_agree_with_the_baseline_on_the_falcon_py_fixture() {
    let msg = falcon_py::msg();
    let pk = falcon_py::public_key();
    let sig = falcon_py::signature();
    assert!(Baseline::verify(msg, pk.span(), sig.span()));
    assert!(Compact::verify(msg, pk.span(), sig.span()));
    assert!(Record::verify(msg, pk.span(), sig.span()));
    assert!(Small::verify(msg, pk.span(), sig.span()));
    for i in array![0_u32, 28, 29, 30, 31, 59] {
        let bad = tamper(sig.span(), i);
        assert!(!Baseline::verify(msg, pk.span(), bad.span()), "felt {i}");
        assert!(!Compact::verify(msg, pk.span(), bad.span()), "felt {i}");
        assert!(!Record::verify(msg, pk.span(), bad.span()), "felt {i}");
        assert!(!Small::verify(msg, pk.span(), bad.span()), "felt {i}");
    }
    assert!(!Compact::verify(msg + 1, pk.span(), sig.span()));
    assert!(!Record::verify(msg + 1, pk.span(), sig.span()));
    assert!(!Small::verify(msg + 1, pk.span(), sig.span()));
}

#[test]
fn candidates_accept_the_browser_signature_directly() {
    let sig = browser_sig();
    let pk = browser::falcon_pk();
    assert!(verify_hybrid::<Compact>(browser::MSG, browser::ECDSA_PK, pk.span(), sig.span()));
    assert!(verify_hybrid::<Record>(browser::MSG, browser::ECDSA_PK, pk.span(), sig.span()));
    assert!(verify_hybrid::<Small>(browser::MSG, browser::ECDSA_PK, pk.span(), sig.span()));
}

#[test]
fn a_deployed_verifier_class_has_no_keys_and_rejects() {
    // The classes are meant to be declared and library-called only. Deployed on their own they
    // hold no keys, so nothing verifies.
    let mut salt = 0;
    for class in array![
        HybridShakeVerifierPfCompact::TEST_CLASS_HASH, HybridShakeVerifierPfRecord::TEST_CLASS_HASH,
        HybridShakeVerifierPfSmall::TEST_CLASS_HASH,
        HybridShakeVerifierPfSmallKeyRead::TEST_CLASS_HASH,
    ] {
        let (address, _) = deploy_syscall(class, salt, array![].span(), false).unwrap_syscall();
        let verifier = IHybridVerifierDispatcher { contract_address: address };
        assert_eq!(verifier.is_valid_signature(wallet::REGISTRATION_HASH, wallet_sig()), 0);
        salt += 1;
    }
}
