//! BIP32 derivation and Starknet key grinding, reproducing what wallets do with a seed:
//!   "pq" / Braavos: BIP39 seed -> m/44'/9004'/0'/0/i -> grindKey -> STARK key
//!   "argentx":      BIP39 seed -> m/44'/60'/0'/0/0 (Ethereum key) -> that key, leading zero
//!                   bytes dropped, as BIP32 seed -> m/44'/9004'/0'/0/i -> grindKey -> STARK key

use core::ec::{EcPointTrait, NonZeroEcPoint, stark_curve};
use crate::constants::{GRIND_LIMIT, STARK_ORDER};
use crate::secp256k1::{N, add_mod, compressed_pubkey};
use crate::sha2::{bytes_to_u256, hmac_sha512, sha256, u256_to_bytes, u32_to_bytes};

const HARDENED: u32 = 0x80000000;

#[derive(Drop)]
struct ExtKey {
    k: u256,
    chain: Array<u8>,
}

fn split(i: Array<u8>) -> (u256, Array<u8>) {
    let s = i.span();
    let il = bytes_to_u256(s.slice(0, 32));
    let mut chain: Array<u8> = array![];
    for b in s.slice(32, 32) {
        chain.append(*b);
    }
    (il, chain)
}

fn master(seed: Span<u8>) -> ExtKey {
    // HMAC key "Bitcoin seed"
    let key: Array<u8> = array![0x42, 0x69, 0x74, 0x63, 0x6f, 0x69, 0x6e, 0x20, 0x73, 0x65, 0x65, 0x64];
    let (k, chain) = split(hmac_sha512(key.span(), seed));
    assert(k != 0 && k < N, 'bip32: invalid master');
    ExtKey { k, chain }
}

fn child(parent: @ExtKey, index: u32) -> ExtKey {
    let mut data: Array<u8> = array![];
    if index >= HARDENED {
        data.append(0);
        for b in u256_to_bytes(*parent.k) {
            data.append(b);
        }
    } else {
        for b in compressed_pubkey(*parent.k) {
            data.append(b);
        }
    }
    for b in u32_to_bytes(index) {
        data.append(b);
    }
    let (il, chain) = split(hmac_sha512(parent.chain.span(), data.span()));
    assert(il < N, 'bip32: invalid child');
    let k = add_mod(il, *parent.k, N);
    assert(k != 0, 'bip32: zero child');
    ExtKey { k, chain }
}

/// m/44'/coin'/0'/0/index
fn derive(seed: Span<u8>, coin: u32, index: u32) -> u256 {
    let m = master(seed);
    let a = child(@m, 44 + HARDENED);
    let b = child(@a, coin + HARDENED);
    let c = child(@b, HARDENED);
    let d = child(@c, 0);
    let e = child(@d, index);
    e.k
}

/// Starknet grindKey: sha256(key || i) until below the rejection bound, then mod the curve order.
fn grind_key(k: u256) -> felt252 {
    let base = u256_to_bytes(k);
    let mut i: u8 = 0;
    loop {
        let mut data: Array<u8> = array![];
        for b in base.span() {
            data.append(*b);
        }
        data.append(i);
        let h = bytes_to_u256(sha256(data.span()).span());
        if h < GRIND_LIMIT {
            let order: NonZero<u256> = STARK_ORDER.try_into().unwrap();
            let (_, r) = DivRem::div_rem(h, order);
            break r.try_into().unwrap();
        }
        assert(i < 255, 'grind: too many rounds');
        i += 1;
    }
}

fn stark_public_key(private_key: felt252) -> felt252 {
    let g = EcPointTrait::new(stark_curve::GEN_X, stark_curve::GEN_Y).unwrap();
    let p: NonZeroEcPoint = g.mul(private_key).try_into().unwrap();
    p.x()
}

fn strip_leading_zeros(b: Span<u8>) -> Array<u8> {
    let mut out: Array<u8> = array![];
    let mut started = false;
    for x in b {
        if started || *x != 0 {
            started = true;
            out.append(*x);
        }
    }
    out
}

pub fn account_stark_key(profile: felt252, index: u32, seed: Span<u8>) -> felt252 {
    let k = if profile == 'argentx' {
        let eth = derive(seed, 60, 0);
        let secret = strip_leading_zeros(u256_to_bytes(eth).span());
        derive(secret.span(), 9004, index)
    } else {
        assert(profile == 'pq' || profile == 'braavos', 'unknown profile');
        derive(seed, 9004, index)
    };
    stark_public_key(grind_key(k))
}
