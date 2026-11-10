/// Stand-in for an existing OpenZeppelin ECDSA account: the same `Account_public_key` storage name
/// and a self-only `upgrade` (copy of the test-only `LegacyOzLikeAccount` in contracts/). Real
/// wallet classes are measured on Sepolia.
#[starknet::contract]
pub mod LegacyOzLikeAccount {
    use starknet::storage::StoragePointerWriteAccess;
    use starknet::{ClassHash, SyscallResultTrait, get_caller_address, get_contract_address};

    #[storage]
    struct Storage {
        Account_public_key: felt252,
    }

    #[constructor]
    fn constructor(ref self: ContractState, public_key: felt252) {
        self.Account_public_key.write(public_key);
    }

    #[starknet::interface]
    pub trait ILegacy<TState> {
        fn upgrade(ref self: TState, new_class_hash: ClassHash);
    }

    #[abi(embed_v0)]
    impl LegacyImpl of ILegacy<ContractState> {
        fn upgrade(ref self: ContractState, new_class_hash: ClassHash) {
            assert(get_caller_address() == get_contract_address(), 'only self');
            starknet::syscalls::replace_class_syscall(new_class_hash).unwrap_syscall();
        }
    }
}
