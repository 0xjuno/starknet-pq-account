//! A contract that checks signatures through the account's `is_valid_signature` keeps working
//! after the account migrates in place. A contract that reads the ECDSA key and checks it
//! itself accepts what the migrated account rejects.

use pqbench_ecdsa_stark::EcdsaStarkVerifier;
#[allow(unused_imports)]
use pqbench_interface::PqSignatureVerifier;
use starknet::syscalls::deploy_syscall;
use starknet::{ContractAddress, SyscallResultTrait};
use crate::consumer::{
    ISignatureConsumerDispatcher, ISignatureConsumerDispatcherTrait, SignatureConsumer,
};
use crate::migratable::{IMigratableDispatcher, IMigratableDispatcherTrait};
use crate::tests_migration::{deploy_legacy, hybrid_sig, migrate};
use crate::tests_wallets_fixture::{ECDSA_R, ECDSA_S, REGISTRATION_HASH};

const MSG: felt252 = REGISTRATION_HASH;

fn deploy_consumer() -> ISignatureConsumerDispatcher {
    let (address, _) = deploy_syscall(
        SignatureConsumer::TEST_CLASS_HASH, 0, array![].span(), false,
    )
        .unwrap_syscall();
    ISignatureConsumerDispatcher { contract_address: address }
}

fn migrated_account() -> ContractAddress {
    let address = deploy_legacy();
    migrate(address);
    address
}

#[test]
fn consumer_accepts_hybrid_signature_from_migrated_account() {
    let account = migrated_account();
    assert!(deploy_consumer().check(account, MSG, hybrid_sig()));
}

#[test]
fn consumer_rejects_ecdsa_only_from_migrated_account() {
    let account = migrated_account();
    assert!(!deploy_consumer().check(account, MSG, array![ECDSA_R, ECDSA_S]));
}

#[test]
fn consumer_counts_repeated_checks() {
    let account = migrated_account();
    let consumer = deploy_consumer();
    assert_eq!(consumer.check_many(account, MSG, hybrid_sig(), 2), 2);
    assert_eq!(consumer.check_many(account, MSG, array![ECDSA_R, ECDSA_S], 2), 0);
}

/// The pattern to avoid: read the account's ECDSA key and run the check yourself. It still says
/// yes to an ECDSA-only signature that the migrated account rejects.
#[test]
fn checking_the_ecdsa_key_yourself_accepts_what_the_account_rejects() {
    let account = migrated_account();
    let key = IMigratableDispatcher { contract_address: account }.get_ecdsa_public_key();
    let ecdsa_only = array![ECDSA_R, ECDSA_S];
    assert!(EcdsaStarkVerifier::verify(MSG, array![key].span(), ecdsa_only.span()));
    assert!(!deploy_consumer().check(account, MSG, ecdsa_only));
}
