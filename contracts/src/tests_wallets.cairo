//! Migration of accounts that keep the classical key outside `Account_public_key`:
//! - Argent-style `upgrade(class_hash, data)`: checks SRC6 on the new class, then library-calls
//!   its `perform_upgrade` (argent-contracts-starknet src/upgrade.cairo); Argent 0.3.x replaces
//!   the class first and library-calls `execute_after_upgrade` instead.
//! - Braavos-style `upgrade(class_hash)`: checks SRC6, replaces the class; `migrate` follows in
//!   the same multicall (braavos-account-cairo src/upgradable/upgradable.cairo).
//! Both paths need a proof that the owner holds both keys.

use starknet::syscalls::deploy_syscall;
use starknet::{ClassHash, ContractAddress, SyscallResultTrait};
use crate::hybrid::{HybridShakeAccount, HybridShakeVerifierPfSmall};
use crate::migratable::HybridMigratableAccount::{ALREADY_REGISTERED, INVALID_DATA, INVALID_PROOF, ONLY_SELF};
use crate::migratable::LegacyOzLikeAccount::{ILegacyDispatcher, ILegacyDispatcherTrait};
use crate::migratable::{
    HybridMigratableAccount, IMigratableDispatcher, IMigratableDispatcherTrait,
    IMigratableSafeDispatcher, IMigratableSafeDispatcherTrait, LegacyOzLikeAccount, MigrationData,
    registration_hash,
};
use crate::tests_wallets_fixture::{
    ECDSA_PK, ECDSA_R, ECDSA_S, REGISTRATION_HASH, WRONG_ECDSA_R, WRONG_ECDSA_S, falcon_pk,
    falcon_sig,
};
use crate::utils::interface::{IHybridAccountDispatcher, IHybridAccountDispatcherTrait};

#[starknet::interface]
pub trait IArgentLike<TState> {
    fn upgrade(ref self: TState, new_implementation: ClassHash, data: Array<felt252>);
}

#[starknet::interface]
pub trait IBraavosLike<TState> {
    fn upgrade(ref self: TState, upgrade_to: ClassHash);
}

#[starknet::interface]
pub trait IArgent03Like<TState> {
    fn upgrade(ref self: TState, new_implementation: ClassHash, calldata: Array<felt252>) -> Array<felt252>;
}

/// Stand-in for an Argent 0.3.x account: checks SRC6, replaces the class, then library-calls
/// `execute_after_upgrade(calldata)` on the new class (argent-contracts-starknet account-0.3.1).
#[starknet::contract]
pub mod Argent03LikeAccount {
    use starknet::storage::StoragePointerWriteAccess;
    use starknet::{ClassHash, SyscallResultTrait, get_caller_address, get_contract_address};
    use crate::utils::interface::ISRC6_ID;

    #[storage]
    struct Storage {
        _signer: felt252,
    }

    #[constructor]
    fn constructor(ref self: ContractState, owner: felt252) {
        self._signer.write(owner);
    }

    #[abi(embed_v0)]
    impl UpgradeImpl of super::IArgent03Like<ContractState> {
        fn upgrade(
            ref self: ContractState, new_implementation: ClassHash, calldata: Array<felt252>,
        ) -> Array<felt252> {
            assert(get_caller_address() == get_contract_address(), 'only self');
            let supported = starknet::syscalls::library_call_syscall(
                new_implementation, selector!("supports_interface"), array![ISRC6_ID].span(),
            )
                .unwrap_syscall();
            assert(*supported.at(0) == 1, 'argent/invalid-implementation');
            starknet::syscalls::replace_class_syscall(new_implementation).unwrap_syscall();
            let mut args = array![];
            Serde::serialize(@calldata, ref args);
            let ret = starknet::syscalls::library_call_syscall(
                new_implementation, selector!("execute_after_upgrade"), args.span(),
            )
                .unwrap_syscall();
            let mut ret = ret;
            Serde::deserialize(ref ret).unwrap()
        }
    }
}

/// Stand-in for an Argent account: own storage name for the key, Argent's upgrade sequence.
#[starknet::contract]
pub mod ArgentLikeAccount {
    use starknet::storage::StoragePointerWriteAccess;
    use starknet::{ClassHash, SyscallResultTrait, get_caller_address, get_contract_address};
    use crate::utils::interface::ISRC6_ID;

    #[storage]
    struct Storage {
        owner: felt252,
    }

    #[constructor]
    fn constructor(ref self: ContractState, owner: felt252) {
        self.owner.write(owner);
    }

    #[abi(embed_v0)]
    impl UpgradeImpl of super::IArgentLike<ContractState> {
        fn upgrade(ref self: ContractState, new_implementation: ClassHash, data: Array<felt252>) {
            assert(get_caller_address() == get_contract_address(), 'only self');
            let supported = starknet::syscalls::library_call_syscall(
                new_implementation, selector!("supports_interface"), array![ISRC6_ID].span(),
            )
                .unwrap_syscall();
            assert(*supported.at(0) == 1, 'argent/invalid-implementation');
            let mut calldata = array![new_implementation.into()];
            Serde::serialize(@data.span(), ref calldata);
            starknet::syscalls::library_call_syscall(
                new_implementation, selector!("perform_upgrade"), calldata.span(),
            )
                .unwrap_syscall();
        }
    }
}

/// Stand-in for a Braavos account: own storage name for the key, Braavos's upgrade sequence.
#[starknet::contract]
pub mod BraavosLikeAccount {
    use starknet::storage::StoragePointerWriteAccess;
    use starknet::{ClassHash, SyscallResultTrait, get_caller_address, get_contract_address};
    use crate::utils::interface::ISRC6_ID;

    const ISTORAGE_MIGRATION_ID: felt252 =
        0x11b3a49796b9a26cb8541143be5abfd2522a0769ad2f464915a39a4910b908b;

    #[storage]
    struct Storage {
        stark_signer: felt252,
    }

    #[constructor]
    fn constructor(ref self: ContractState, stark_signer: felt252) {
        self.stark_signer.write(stark_signer);
    }

    #[abi(embed_v0)]
    impl UpgradeImpl of super::IBraavosLike<ContractState> {
        fn upgrade(ref self: ContractState, upgrade_to: ClassHash) {
            assert(get_caller_address() == get_contract_address(), 'only self');
            let src6 = starknet::syscalls::library_call_syscall(
                upgrade_to, selector!("supports_interface"), array![ISRC6_ID].span(),
            )
                .unwrap_syscall();
            assert(*src6.at(0) == 1, 'CLASS_HASH_NOT_SRC6');
            let migration = starknet::syscalls::library_call_syscall(
                upgrade_to, selector!("supports_interface"), array![ISTORAGE_MIGRATION_ID].span(),
            )
                .unwrap_syscall();
            assert(*migration.at(0) == 0, 'unexpected storage migration');
            starknet::syscalls::replace_class_syscall(upgrade_to).unwrap_syscall();
        }
    }
}

fn migratable() -> ClassHash {
    HybridMigratableAccount::TEST_CLASS_HASH.try_into().unwrap()
}

fn verifier() -> ClassHash {
    HybridShakeAccount::TEST_CLASS_HASH.try_into().unwrap()
}

/// The Provably Fast verifier PF-04 selected (bench/pf04).
fn small() -> ClassHash {
    HybridShakeVerifierPfSmall::TEST_CLASS_HASH.try_into().unwrap()
}

fn proof_with(r: felt252, s: felt252) -> Array<felt252> {
    let mut proof = array![r, s];
    for f in falcon_sig() {
        proof.append(f);
    }
    proof
}

fn proof() -> Array<felt252> {
    proof_with(ECDSA_R, ECDSA_S)
}

/// `proof()` with a valid ECDSA half and felt 2 + 31 + 5 (inside the Falcon hint) changed.
fn tampered_falcon_proof() -> Array<felt252> {
    let mut tampered = array![];
    let mut i: u32 = 0;
    for f in proof() {
        tampered.append(if i == 2 + 31 + 5 {
            f + 1
        } else {
            f
        });
        i += 1;
    }
    tampered
}

fn argent_data(proof: Array<felt252>) -> Array<felt252> {
    argent_data_for(verifier(), proof)
}

fn argent_data_for(verifier: ClassHash, proof: Array<felt252>) -> Array<felt252> {
    let m = MigrationData {
        ecdsa_public_key: ECDSA_PK,
        falcon_public_key: falcon_pk(),
        verifier_class_hash: verifier,
        proof,
    };
    let mut data = array![];
    m.serialize(ref data);
    data
}

fn deploy(class_hash: ClassHash, key: felt252) -> ContractAddress {
    let (address, _) = deploy_syscall(class_hash, 0, array![key].span(), false).unwrap_syscall();
    starknet::testing::set_contract_address(address);
    address
}

fn deploy_argent() -> ContractAddress {
    deploy(ArgentLikeAccount::TEST_CLASS_HASH, ECDSA_PK)
}

fn deploy_braavos() -> ContractAddress {
    deploy(BraavosLikeAccount::TEST_CLASS_HASH, ECDSA_PK)
}

fn assert_migrated(address: ContractAddress) {
    assert_migrated_to(address, verifier());
}

fn assert_migrated_to(address: ContractAddress, verifier: ClassHash) {
    assert_eq!(starknet::syscalls::get_class_hash_at_syscall(address).unwrap_syscall(), migratable());
    let m = IMigratableDispatcher { contract_address: address };
    assert!(m.is_falcon_registered());
    assert_eq!(m.get_ecdsa_public_key(), ECDSA_PK);
    assert_eq!(m.get_falcon_public_key(), falcon_pk());
    assert_eq!(m.get_verifier_class_hash(), verifier);
    let account = IHybridAccountDispatcher { contract_address: address };
    assert_eq!(account.is_valid_signature(REGISTRATION_HASH, proof()), starknet::VALIDATED);
    assert_eq!(account.is_valid_signature(REGISTRATION_HASH, array![ECDSA_R, ECDSA_S]), 0);
}

fn first(err: Array<felt252>) -> felt252 {
    *err.at(0)
}

#[test]
fn registration_hash_matches_off_chain_signer() {
    assert_eq!(registration_hash(ECDSA_PK, falcon_pk().span()), REGISTRATION_HASH);
}

#[test]
fn argent_upgrade_migrates_in_one_call() {
    let address = deploy_argent();
    IArgentLikeDispatcher { contract_address: address }.upgrade(migratable(), argent_data(proof()));
    assert_migrated(address);
}

#[test]
#[feature("safe_dispatcher")]
fn argent_upgrade_with_wrong_ecdsa_proof_reverts() {
    let address = deploy_argent();
    let err = IArgentLikeSafeDispatcher { contract_address: address }
        .upgrade(migratable(), argent_data(proof_with(WRONG_ECDSA_R, WRONG_ECDSA_S)))
        .unwrap_err();
    assert_eq!(first(err), INVALID_PROOF);
}

#[test]
#[feature("safe_dispatcher")]
fn argent_upgrade_with_tampered_falcon_proof_reverts() {
    let address = deploy_argent();
    let err = IArgentLikeSafeDispatcher { contract_address: address }
        .upgrade(migratable(), argent_data(tampered_falcon_proof()))
        .unwrap_err();
    assert_eq!(first(err), INVALID_PROOF);
}

#[test]
#[feature("safe_dispatcher")]
fn argent_upgrade_with_trailing_data_reverts() {
    let address = deploy_argent();
    let mut data = argent_data(proof());
    data.append(0);
    let err = IArgentLikeSafeDispatcher { contract_address: address }
        .upgrade(migratable(), data)
        .unwrap_err();
    assert_eq!(first(err), INVALID_DATA);
}

#[test]
fn argent_0_3_upgrade_migrates_in_one_call() {
    let address = deploy(Argent03LikeAccount::TEST_CLASS_HASH, ECDSA_PK);
    let ret = IArgent03LikeDispatcher { contract_address: address }
        .upgrade(migratable(), argent_data(proof()));
    assert_eq!(ret.len(), 0);
    assert_migrated(address);
}

#[test]
#[feature("safe_dispatcher")]
fn argent_0_3_upgrade_with_wrong_ecdsa_proof_reverts() {
    let address = deploy(Argent03LikeAccount::TEST_CLASS_HASH, ECDSA_PK);
    let err = IArgent03LikeSafeDispatcher { contract_address: address }
        .upgrade(migratable(), argent_data(proof_with(WRONG_ECDSA_R, WRONG_ECDSA_S)))
        .unwrap_err();
    assert_eq!(first(err), INVALID_PROOF);
}

#[test]
#[feature("safe_dispatcher")]
fn execute_after_upgrade_after_migration_reverts() {
    let address = deploy(Argent03LikeAccount::TEST_CLASS_HASH, ECDSA_PK);
    IArgent03LikeDispatcher { contract_address: address }.upgrade(migratable(), argent_data(proof()));
    let err = IMigratableSafeDispatcher { contract_address: address }
        .execute_after_upgrade(argent_data(proof()))
        .unwrap_err();
    assert_eq!(first(err), ALREADY_REGISTERED);
}

#[test]
fn braavos_upgrade_then_migrate() {
    let address = deploy_braavos();
    IBraavosLikeDispatcher { contract_address: address }.upgrade(migratable());
    IMigratableDispatcher { contract_address: address }
        .migrate(ECDSA_PK, falcon_pk(), verifier(), proof());
    assert_migrated(address);
}

#[test]
#[feature("safe_dispatcher")]
fn braavos_migrate_with_wrong_ecdsa_proof_reverts() {
    let address = deploy_braavos();
    IBraavosLikeDispatcher { contract_address: address }.upgrade(migratable());
    let err = IMigratableSafeDispatcher { contract_address: address }
        .migrate(ECDSA_PK, falcon_pk(), verifier(), proof_with(WRONG_ECDSA_R, WRONG_ECDSA_S))
        .unwrap_err();
    assert_eq!(first(err), INVALID_PROOF);
}

#[test]
#[feature("safe_dispatcher")]
fn braavos_migrate_from_outsider_reverts() {
    let address = deploy_braavos();
    IBraavosLikeDispatcher { contract_address: address }.upgrade(migratable());
    starknet::testing::set_contract_address(0x1234.try_into().unwrap());
    let err = IMigratableSafeDispatcher { contract_address: address }
        .migrate(ECDSA_PK, falcon_pk(), verifier(), proof())
        .unwrap_err();
    assert_eq!(first(err), ONLY_SELF);
}

#[test]
#[feature("safe_dispatcher")]
fn migrate_twice_reverts() {
    let address = deploy_braavos();
    IBraavosLikeDispatcher { contract_address: address }.upgrade(migratable());
    let m = IMigratableDispatcher { contract_address: address };
    m.migrate(ECDSA_PK, falcon_pk(), verifier(), proof());
    let err = IMigratableSafeDispatcher { contract_address: address }
        .migrate(ECDSA_PK, falcon_pk(), verifier(), proof())
        .unwrap_err();
    assert_eq!(first(err), ALREADY_REGISTERED);
}

#[test]
#[feature("safe_dispatcher")]
fn perform_upgrade_after_migration_reverts() {
    let address = deploy_argent();
    IArgentLikeDispatcher { contract_address: address }.upgrade(migratable(), argent_data(proof()));
    let err = IMigratableSafeDispatcher { contract_address: address }
        .perform_upgrade(migratable(), argent_data(proof()).span())
        .unwrap_err();
    assert_eq!(first(err), ALREADY_REGISTERED);
}

#[test]
fn openzeppelin_account_can_migrate_with_proof() {
    let address = deploy(LegacyOzLikeAccount::TEST_CLASS_HASH, 0x123);
    ILegacyDispatcher { contract_address: address }.upgrade(migratable());
    IMigratableDispatcher { contract_address: address }
        .migrate(ECDSA_PK, falcon_pk(), verifier(), proof());
    assert_migrated(address);
}

#[test]
fn argent_upgrade_migrates_to_the_small_verifier() {
    let address = deploy_argent();
    IArgentLikeDispatcher { contract_address: address }
        .upgrade(migratable(), argent_data_for(small(), proof()));
    assert_migrated_to(address, small());
}

#[test]
fn argent_0_3_upgrade_migrates_to_the_small_verifier() {
    let address = deploy(Argent03LikeAccount::TEST_CLASS_HASH, ECDSA_PK);
    let ret = IArgent03LikeDispatcher { contract_address: address }
        .upgrade(migratable(), argent_data_for(small(), proof()));
    assert_eq!(ret.len(), 0);
    assert_migrated_to(address, small());
}

#[test]
fn braavos_upgrade_then_migrate_to_the_small_verifier() {
    let address = deploy_braavos();
    IBraavosLikeDispatcher { contract_address: address }.upgrade(migratable());
    IMigratableDispatcher { contract_address: address }
        .migrate(ECDSA_PK, falcon_pk(), small(), proof());
    assert_migrated_to(address, small());
}

// A valid ECDSA half with a bad Falcon half is the only wrong proof that reaches the verifier:
// a bad ECDSA half fails before Falcon runs.
#[test]
#[feature("safe_dispatcher")]
fn argent_upgrade_to_small_with_tampered_falcon_proof_reverts() {
    let address = deploy_argent();
    let err = IArgentLikeSafeDispatcher { contract_address: address }
        .upgrade(migratable(), argent_data_for(small(), tampered_falcon_proof()))
        .unwrap_err();
    assert_eq!(first(err), INVALID_PROOF);
    // The failed call's class replacement is rolled back with it.
    assert_eq!(
        starknet::syscalls::get_class_hash_at_syscall(address).unwrap_syscall(),
        ArgentLikeAccount::TEST_CLASS_HASH.try_into().unwrap(),
    );
}

#[test]
#[feature("safe_dispatcher")]
fn argent_0_3_upgrade_to_small_with_tampered_falcon_proof_reverts() {
    let address = deploy(Argent03LikeAccount::TEST_CLASS_HASH, ECDSA_PK);
    let err = IArgent03LikeSafeDispatcher { contract_address: address }
        .upgrade(migratable(), argent_data_for(small(), tampered_falcon_proof()))
        .unwrap_err();
    assert_eq!(first(err), INVALID_PROOF);
    assert_eq!(
        starknet::syscalls::get_class_hash_at_syscall(address).unwrap_syscall(),
        Argent03LikeAccount::TEST_CLASS_HASH.try_into().unwrap(),
    );
}

#[test]
#[feature("safe_dispatcher")]
fn argent_0_3_upgrade_to_small_with_wrong_ecdsa_proof_reverts() {
    let address = deploy(Argent03LikeAccount::TEST_CLASS_HASH, ECDSA_PK);
    let err = IArgent03LikeSafeDispatcher { contract_address: address }
        .upgrade(migratable(), argent_data_for(small(), proof_with(WRONG_ECDSA_R, WRONG_ECDSA_S)))
        .unwrap_err();
    assert_eq!(first(err), INVALID_PROOF);
}

#[test]
#[feature("safe_dispatcher")]
fn braavos_migrate_to_small_with_tampered_falcon_proof_reverts() {
    let address = deploy_braavos();
    IBraavosLikeDispatcher { contract_address: address }.upgrade(migratable());
    let err = IMigratableSafeDispatcher { contract_address: address }
        .migrate(ECDSA_PK, falcon_pk(), small(), tampered_falcon_proof())
        .unwrap_err();
    assert_eq!(first(err), INVALID_PROOF);
}
