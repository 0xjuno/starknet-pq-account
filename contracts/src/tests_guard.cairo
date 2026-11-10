//! PF-05: the guarded verifier switch, run as transactions: `__validate__` with the signature,
//! then `__execute__` with `[set_verifier_class_hash(candidate), guard.assert_compatible(..)]`.
//! `__execute__` is called through a raw syscall so a failed switch returns an error and the
//! test can check that nothing changed.

use starknet::account::Call;
use starknet::syscalls::{call_contract_syscall, deploy_syscall};
use starknet::{ClassHash, ContractAddress, SyscallResult, SyscallResultTrait};
use crate::guard::{IVerifierSwitchGuardDispatcher, IVerifierSwitchGuardDispatcherTrait, VerifierSwitchGuard};
use crate::hybrid::{
    HybridPoseidonAccount, HybridShakeAccount, HybridShakeVerifierPfCompact, HybridShakeVerifierPfSmall,
    HybridShakeVerifierPfSmallKeyRead,
};
use crate::migratable::LegacyOzLikeAccount::{ILegacyDispatcher, ILegacyDispatcherTrait};
use crate::migratable::{
    HybridMigratableAccount, IMigratableDispatcher, IMigratableDispatcherTrait,
    LegacyOzLikeAccount,
};
use crate::tests_wallets_fixture as wallet;
use crate::utils::interface::{IHybridAccountDispatcher, IHybridAccountDispatcherTrait};

/// Answers `is_valid_signature` with 1 instead of VALIDATED.
#[starknet::contract]
mod WrongAnswerVerifier {
    #[storage]
    struct Storage {}

    #[external(v0)]
    fn is_valid_signature(self: @ContractState, hash: felt252, signature: Array<felt252>) -> felt252 {
        1
    }
}

/// Accepts everything and, running in the account's storage, rewrites its classical key.
#[starknet::contract]
mod KeyRewritingVerifier {
    use starknet::storage::StoragePointerWriteAccess;

    #[storage]
    struct Storage {
        Account_public_key: felt252,
    }

    #[external(v0)]
    fn is_valid_signature(
        ref self: ContractState, hash: felt252, signature: Array<felt252>,
    ) -> felt252 {
        self.Account_public_key.write('attacker');
        starknet::VALIDATED
    }
}

fn class(hash: felt252) -> ClassHash {
    hash.try_into().unwrap()
}

fn baseline() -> ClassHash {
    HybridShakeAccount::TEST_CLASS_HASH.try_into().unwrap()
}

fn compact() -> ClassHash {
    HybridShakeVerifierPfCompact::TEST_CLASS_HASH.try_into().unwrap()
}

fn small() -> ClassHash {
    HybridShakeVerifierPfSmall::TEST_CLASS_HASH.try_into().unwrap()
}

fn small_key_read() -> ClassHash {
    HybridShakeVerifierPfSmallKeyRead::TEST_CLASS_HASH.try_into().unwrap()
}

fn hybrid(r: felt252, s: felt252) -> Array<felt252> {
    let mut sig = array![r, s];
    for f in wallet::falcon_sig() {
        sig.append(f);
    }
    sig
}

/// A migrated account on the baseline SHAKE verifier and a deployed guard.
fn setup() -> (ContractAddress, ContractAddress) {
    let (account, _) = deploy_syscall(
        LegacyOzLikeAccount::TEST_CLASS_HASH, 0, array![wallet::ECDSA_PK].span(), false,
    )
        .unwrap_syscall();
    starknet::testing::set_contract_address(account);
    ILegacyDispatcher { contract_address: account }
        .upgrade(HybridMigratableAccount::TEST_CLASS_HASH.try_into().unwrap());
    IMigratableDispatcher { contract_address: account }
        .migrate(wallet::ECDSA_PK, wallet::falcon_pk(), baseline(), hybrid(wallet::ECDSA_R, wallet::ECDSA_S));
    let (guard, _) = deploy_syscall(VerifierSwitchGuard::TEST_CLASS_HASH, 0, array![].span(), false)
        .unwrap_syscall();
    (account, guard)
}

fn switch_calls(account: ContractAddress, guard: ContractAddress, candidate: ClassHash) -> Array<Call> {
    array![
        Call {
            to: account, selector: selector!("set_verifier_class_hash"),
            calldata: array![candidate.into()].span(),
        },
        Call {
            to: guard, selector: selector!("assert_compatible"),
            calldata: array![account.into(), candidate.into()].span(),
        },
    ]
}

/// One transaction from `account`, signed with `signature` over the fixture hash: the protocol
/// runs `__validate__`, then `__execute__`.
fn transact(account: ContractAddress, calls: Array<Call>, signature: Array<felt252>) -> SyscallResult<Span<felt252>> {
    starknet::testing::set_contract_address(0.try_into().unwrap());
    starknet::testing::set_version(3);
    starknet::testing::set_transaction_hash(wallet::REGISTRATION_HASH);
    starknet::testing::set_signature(signature.span());
    let mut data = array![];
    Serde::serialize(@calls, ref data);
    call_contract_syscall(account, selector!("__validate__"), data.span())?;
    call_contract_syscall(account, selector!("__execute__"), data.span())
}

fn signed(account: ContractAddress, calls: Array<Call>) -> SyscallResult<Span<felt252>> {
    transact(account, calls, hybrid(wallet::ECDSA_R, wallet::ECDSA_S))
}

fn assert_unchanged(account: ContractAddress) {
    let m = IMigratableDispatcher { contract_address: account };
    assert_eq!(m.get_verifier_class_hash(), baseline());
    assert_eq!(m.get_ecdsa_public_key(), wallet::ECDSA_PK);
    assert_eq!(m.get_falcon_public_key(), wallet::falcon_pk());
}

/// The call failed, and `reason` is among the felts of its error.
fn assert_reverts_with(result: SyscallResult<Span<felt252>>, reason: felt252) {
    match result {
        Ok(_) => panic!("succeeded, expected a revert with {reason}"),
        Err(error) => {
            let mut found = false;
            for felt in error.span() {
                found = found || *felt == reason;
            }
            assert!(found, "reverted with {:?}, expected {reason}", error);
        },
    }
}

fn assert_switch_reverts(candidate: ClassHash, reason: felt252) {
    let (account, guard) = setup();
    assert_reverts_with(signed(account, switch_calls(account, guard, candidate)), reason);
    assert_unchanged(account);
}

#[test]
fn compatible_candidate_is_installed_and_then_validates() {
    let (account, guard) = setup();
    signed(account, switch_calls(account, guard, compact())).unwrap_syscall();
    assert_eq!(IMigratableDispatcher { contract_address: account }.get_verifier_class_hash(), compact());
    // The next transaction is validated by the candidate.
    signed(account, array![]).unwrap_syscall();
    assert_eq!(
        IHybridAccountDispatcher { contract_address: account }
            .is_valid_signature(wallet::REGISTRATION_HASH, hybrid(wallet::ECDSA_R, wallet::ECDSA_S)),
        starknet::VALIDATED,
    );
}

#[test]
fn switching_back_to_the_baseline_works() {
    let (account, guard) = setup();
    signed(account, switch_calls(account, guard, compact())).unwrap_syscall();
    signed(account, switch_calls(account, guard, baseline())).unwrap_syscall();
    assert_unchanged(account);
}

#[test]
fn baseline_to_small_is_installed_and_then_validates() {
    let (account, guard) = setup();
    signed(account, switch_calls(account, guard, small())).unwrap_syscall();
    assert_eq!(IMigratableDispatcher { contract_address: account }.get_verifier_class_hash(), small());
    signed(account, array![]).unwrap_syscall();
    // An ECDSA-only transaction is rejected by small in __validate__.
    assert!(transact(account, array![], array![wallet::ECDSA_R, wallet::ECDSA_S]).is_err());
}

#[test]
fn small_back_to_baseline_restores_the_pointer_and_keys() {
    let (account, guard) = setup();
    signed(account, switch_calls(account, guard, small())).unwrap_syscall();
    signed(account, array![]).unwrap_syscall();
    signed(account, switch_calls(account, guard, baseline())).unwrap_syscall();
    assert_unchanged(account);
    signed(account, array![]).unwrap_syscall();
}

#[test]
fn small_to_small_key_read_and_back_keeps_the_keys() {
    // PF-11: the route a deployed small-verifier account takes. Same storage layout, so the
    // keys read the same through either class.
    let (account, guard) = setup();
    signed(account, switch_calls(account, guard, small())).unwrap_syscall();
    signed(account, switch_calls(account, guard, small_key_read())).unwrap_syscall();
    assert_eq!(
        IMigratableDispatcher { contract_address: account }.get_verifier_class_hash(), small_key_read(),
    );
    signed(account, array![]).unwrap_syscall();
    assert!(transact(account, array![], array![wallet::ECDSA_R, wallet::ECDSA_S]).is_err());
    signed(account, switch_calls(account, guard, small())).unwrap_syscall();
    signed(account, switch_calls(account, guard, baseline())).unwrap_syscall();
    assert_unchanged(account);
}

#[test]
fn incompatible_scheme_reverts_the_whole_transaction() {
    // Same key, Poseidon hash-to-point: rejects the SHAKE signature.
    assert_switch_reverts(HybridPoseidonAccount::TEST_CLASS_HASH.try_into().unwrap(), VerifierSwitchGuard::INCOMPATIBLE);
}

#[test]
fn zero_class_hash_reverts() {
    assert_switch_reverts(class(0), HybridMigratableAccount::INVALID_VERIFIER);
}

#[test]
fn undeclared_class_hash_reverts() {
    assert_switch_reverts(class(0x1234), 'CLASS_HASH_NOT_DECLARED');
}

#[test]
fn class_without_is_valid_signature_reverts() {
    assert_switch_reverts(LegacyOzLikeAccount::TEST_CLASS_HASH.try_into().unwrap(), 'ENTRYPOINT_NOT_FOUND');
}

#[test]
fn class_with_a_wrong_answer_reverts() {
    assert_switch_reverts(WrongAnswerVerifier::TEST_CLASS_HASH.try_into().unwrap(), VerifierSwitchGuard::INCOMPATIBLE);
}

#[test]
fn candidate_that_rewrites_the_key_reverts_and_the_key_is_restored() {
    assert_switch_reverts(KeyRewritingVerifier::TEST_CLASS_HASH.try_into().unwrap(), VerifierSwitchGuard::STATE_CHANGED);
}

#[test]
fn guard_before_the_switch_reverts() {
    let (account, guard) = setup();
    let mut calls = switch_calls(account, guard, compact());
    let set = calls.pop_front().unwrap();
    calls.append(set);
    assert_reverts_with(signed(account, calls), VerifierSwitchGuard::WRONG_VERIFIER);
    assert_unchanged(account);
}

#[test]
fn guard_naming_another_class_reverts() {
    let (account, guard) = setup();
    let calls = array![
        Call {
            to: account, selector: selector!("set_verifier_class_hash"),
            calldata: array![compact().into()].span(),
        },
        Call {
            to: guard, selector: selector!("assert_compatible"),
            calldata: array![account.into(), baseline().into()].span(),
        },
    ];
    assert_reverts_with(signed(account, calls), VerifierSwitchGuard::WRONG_VERIFIER);
    assert_unchanged(account);
}

#[test]
fn ecdsa_only_switch_is_rejected_in_validate() {
    let (account, guard) = setup();
    let r = transact(
        account, switch_calls(account, guard, compact()), array![wallet::ECDSA_R, wallet::ECDSA_S],
    );
    assert_reverts_with(r, 'Account: invalid signature');
    assert_unchanged(account);
}

#[test]
fn falcon_only_switch_is_rejected_in_validate() {
    let (account, guard) = setup();
    let invalid = 'Account: invalid signature';
    assert_reverts_with(transact(account, switch_calls(account, guard, compact()), hybrid(0, 0)), invalid);
    assert_reverts_with(
        transact(account, switch_calls(account, guard, compact()), wallet::falcon_sig()), invalid,
    );
    assert_unchanged(account);
}

#[test]
fn wrong_ecdsa_key_switch_is_rejected_in_validate() {
    let (account, guard) = setup();
    let r = transact(
        account,
        switch_calls(account, guard, compact()),
        hybrid(wallet::WRONG_ECDSA_R, wallet::WRONG_ECDSA_S),
    );
    assert_reverts_with(r, 'Account: invalid signature');
    assert_unchanged(account);
}

#[test]
fn external_caller_cannot_execute_or_switch() {
    let (account, guard) = setup();
    starknet::testing::set_contract_address(0x1234.try_into().unwrap());
    let mut data = array![];
    Serde::serialize(@switch_calls(account, guard, compact()), ref data);
    assert_reverts_with(
        call_contract_syscall(account, selector!("__execute__"), data.span()),
        'Account: invalid caller',
    );
    assert_reverts_with(
        call_contract_syscall(
            account, selector!("set_verifier_class_hash"), array![compact().into()].span(),
        ),
        HybridMigratableAccount::ONLY_SELF,
    );
    assert_unchanged(account);
}

#[test]
#[should_panic(expected: ('Guard: caller is not account', 'ENTRYPOINT_FAILED'))]
fn guard_called_by_someone_else_panics() {
    let (account, guard) = setup();
    starknet::testing::set_contract_address(0x1234.try_into().unwrap());
    IVerifierSwitchGuardDispatcher { contract_address: guard }.assert_compatible(account, baseline());
}
