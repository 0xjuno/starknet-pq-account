//! pq_recovery: quantum emergency recovery for Starknet accounts (research prototype).
//!
//! A STARK proof of this program shows: "I know a BIP39 seed from which a wallet derives the
//! STARK key `public_key`", without revealing the seed. A quantum attacker who computed the
//! private key from the public key does not know the seed, so only the owner can produce it.
//! `binding` (for example a hash of the owner's new post-quantum key) is echoed into the public
//! output so a proof cannot be reused to hand the account to someone else.
//!
//! EXPERIMENTAL AND UNAUDITED.

pub mod bip32;
pub mod constants;
pub mod secp256k1;
pub mod sha2;

#[cfg(test)]
mod tests;

/// profile: 'pq', 'braavos' or 'argentx'; seed: the 64-byte BIP39 seed as 8 big-endian u64 words.
#[executable]
fn main(profile: felt252, index: u32, seed: Array<u64>, binding: felt252) -> Array<felt252> {
    assert(seed.len() == 8, 'seed must be 64 bytes');
    let seed_bytes = sha2::words64_to_bytes(seed.span());
    let public_key = bip32::account_stark_key(profile, index, seed_bytes.span());
    array![profile, index.into(), public_key, binding]
}
