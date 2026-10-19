//! BIP32 derivation and Starknet key grinding, reproducing what wallets do with a seed:
//!   "pq" / Braavos: BIP39 seed -> m/44'/9004'/0'/0/i -> grindKey -> STARK key
//!   "argentx":      BIP39 seed -> m/44'/60'/0'/0/0 (Ethereum key) -> that key, leading zero
//!                   bytes dropped, as BIP32 seed -> m/44'/9004'/0'/0/i -> grindKey -> STARK key
//!
//! Everything stays in 64-bit words (held in u128): messages are built directly as padded SHA-512
//! blocks, and the HMAC key "Bitcoin seed" has its inner and outer pad states precomputed, so a
//! master key costs two compressions and a child key four.

use core::ec::{EcPointTrait, NonZeroEcPoint, stark_curve};
use crate::constants::{GRIND_LIMIT, STARK_ORDER};
use crate::secp256k1::{N, add_mod, mul_g};
use crate::sha2::{
    bytes_to_words64, compress256, compress512, digest_block, h256, hmac_key32, u128_of,
};

const HARDENED: u32 = 0x80000000;
/// 44', 60', 9004'
const PURPOSE_H: u32 = 0x8000002c;
const ETH_H: u32 = 0x8000003c;
const STARK_H: u32 = 0x8000232c;
const M64: u128 = 0xffffffffffffffff;
const M32: u128 = 0xffffffff;
const TWO64: felt252 = 0x10000000000000000;
const TWO32: felt252 = 0x100000000;
const INV2_8: felt252 = 0x7f8000000000010ef0000000000000000000000000000000000000000000001;
const INV2_32: felt252 = 0x7fffffff8000010ffffffef0000000000000000000000000000000000000001;
const INV2_64: felt252 = 0x800000000000010f7ffffffffffffef00000000000000000000000000000001;
const INV2_72: felt252 = 0x800000000000010fff7ffffffffffffef000000000000000000000000000001;
const INV2_96: felt252 = 0x800000000000010fffffffff7ffffffffffffef000000000000000000000001;
const INV2_120: felt252 = 0x800000000000010fffffffffffffff7ffffffffffffef000000000000000001;

/// SHA-512 states after compressing ("Bitcoin seed" zero-padded to 128 bytes) xor 0x36.. / 0x5c..
/// (tools/gen_tables.py checks them against hashlib's HMAC).
const BTC_IPAD_STATE: [u128; 8] = [
    0x2e2af459060c1873, 0x7894b868dc88433a, 0xdd1a797ef1a1933a, 0xe6486d04fcb412a7,
    0xfbcc67b9a396caa0, 0xa2970b146f49b65e, 0xfdf1daabc66f6248, 0x2ff99c812ada6dc3,
];
const BTC_OPAD_STATE: [u128; 8] = [
    0xbbd27bac212e9dbd, 0xdd0bc55e7e4037c1, 0xdfdd3d6890bd6424, 0x2902de663032b34c,
    0xa30f8aa6f67899fc, 0x69a566c30f88378f, 0x500247985ecb694, 0xf6d70307c6b2d337,
];

#[derive(Copy, Drop)]
struct ExtKey {
    k: u256,
    chain: [u128; 4],
}

/// (x >> 64, x & (2^64 - 1)) for x < 2^128.
#[inline(always)]
fn split_64(x: u128) -> (u128, u128) {
    let lo = x & M64;
    (u128_of((x.into() - lo.into()) * INV2_64), lo)
}

/// Splits x < 2^128 into (x >> 72, (x >> 8) & (2^64 - 1), x & 0xff) as felts.
#[inline(always)]
fn split_72_8(x: u128) -> (felt252, felt252, felt252) {
    let lo8: felt252 = (x & 0xff).into();
    let lo72: felt252 = (x & 0xffffffffffffffffff).into();
    ((x.into() - lo72) * INV2_72, (lo72 - lo8) * INV2_8, lo8)
}

/// Padded block of the 37-byte child message prefix || ser256(x) || ser32(index), after the
/// 128-byte HMAC key block: 165 bytes = 1320 bits.
#[inline(always)]
fn child_block(prefix: felt252, x: u256, index: u32) -> [u128; 16] {
    let (h_top, h_mid, h_lo) = split_72_8(x.high);
    let (l_top, l_mid, l_lo) = split_72_8(x.low);
    let w0 = u128_of(prefix * 0x100000000000000 + h_top);
    let w1 = u128_of(h_mid);
    let w2 = u128_of(h_lo * 0x100000000000000 + l_top);
    let w3 = u128_of(l_mid);
    let w4 = u128_of(l_lo * 0x100000000000000 + index.into() * 0x1000000 + 0x800000);
    [w0, w1, w2, w3, w4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1320]
}

/// HMAC output I -> (IL as u256, IR as chain words).
#[inline(never)]
fn split_i(i: [u128; 8]) -> (u256, [u128; 4]) {
    let [i0, i1, i2, i3, i4, i5, i6, i7] = i;
    let high = u128_of(i0.into() * TWO64 + i1.into());
    let low = u128_of(i2.into() * TWO64 + i3.into());
    (u256 { low, high }, [i4, i5, i6, i7])
}

/// Master key from the padded HMAC message block (key "Bitcoin seed").
#[inline(never)]
fn master(block: [u128; 16]) -> ExtKey {
    let inner = compress512(BTC_IPAD_STATE, block);
    let (k, chain) = split_i(compress512(BTC_OPAD_STATE, digest_block(inner)));
    assert(k != 0 && k < N, 'bip32: invalid master');
    ExtKey { k, chain }
}

#[inline(never)]
fn child(parent: ExtKey, index: u32) -> ExtKey {
    // hardened: 0x00 || ser256(k); normal: serP(k * G) = (2 + parity of y) || ser256(x)
    let (prefix, x) = if index >= HARDENED {
        (0, parent.k)
    } else {
        let (x, y) = mul_g(parent.k);
        (2 + (y.low & 1).into(), x)
    };
    let (il, chain) = split_i(hmac_key32(parent.chain, child_block(prefix, x, index)));
    assert(il < N, 'bip32: invalid child');
    let k = add_mod(il, parent.k, N);
    assert(k != 0, 'bip32: zero child');
    ExtKey { k, chain }
}

/// m/44'/coin'/0'/0/index (coin given hardened)
#[inline(never)]
fn derive(m: ExtKey, coin_h: u32, index: u32) -> u256 {
    let a = child(m, PURPOSE_H);
    let b = child(a, coin_h);
    let c = child(b, HARDENED);
    let d = child(c, 0);
    child(d, index).k
}

/// Master block for a 64-byte BIP39 seed given as 8 big-endian words.
#[inline(never)]
fn seed_block(seed: Span<u64>) -> [u128; 16] {
    let [s0, s1, s2, s3, s4, s5, s6, s7] = (*seed.try_into().unwrap()).unbox();
    [
        s0.into(), s1.into(), s2.into(), s3.into(), s4.into(), s5.into(), s6.into(), s7.into(),
        0x8000000000000000, 0, 0, 0, 0, 0, 0, 1536,
    ]
}

/// Master block for a 32-byte key with its leading zero bytes dropped (argentx): the remaining
/// L bytes left-aligned, then the 0x80 padding byte; the message is 128 + L bytes.
///
/// The key and the padding byte form the 264-bit value key * 256 + 0x80; it is shifted left one
/// byte per leading zero byte of the key (this cannot overflow), so its top 256 bits are words
/// 0..3 and its last byte opens word 4.
#[inline(never)]
fn stripped_key_block(key: u256) -> [u128; 16] {
    assert(key != 0, 'bip32: zero key');
    let mut hi = key.high;
    let mut lo = key.low;
    let mut tail: felt252 = 0x80;
    let mut zeros: felt252 = 0;
    while hi < 0x1000000000000000000000000000000 {
        let top: felt252 = (lo & 0xff000000000000000000000000000000).into();
        hi = u128_of(hi.into() * 256 + top * INV2_120);
        lo = u128_of((lo.into() - top) * 256 + tail);
        tail = 0;
        zeros += 1;
    }
    let (w0, w1) = split_64(hi);
    let (w2, w3) = split_64(lo);
    [w0, w1, w2, w3, u128_of(tail * 0x100000000000000), 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, u128_of((160 - zeros) * 8)]
}

/// Splits x < 2^128 into four big-endian 32-bit words.
#[inline(always)]
fn split_32(x: u128) -> (u128, u128, u128, u128) {
    let r32 = x & M32;
    let r64: felt252 = (x & M64).into();
    let r96: felt252 = (x & 0xffffffffffffffffffffffff).into();
    (
        u128_of((x.into() - r96) * INV2_96), u128_of((r96 - r64) * INV2_64),
        u128_of((r64 - r32.into()) * INV2_32), r32,
    )
}

/// Starknet grindKey: sha256(key || i) until below the rejection bound, then mod the curve order.
#[inline(never)]
fn grind_key(k: u256) -> felt252 {
    let (h0, h1, h2, h3) = split_32(k.high);
    let (l0, l1, l2, l3) = split_32(k.low);
    let mut i: felt252 = 0;
    loop {
        // 33-byte message key || i, then the 0x80 padding byte; 264 bits
        let w8 = u128_of(i * 0x1000000 + 0x800000);
        let block = [h0, h1, h2, h3, l0, l1, l2, l3, w8, 0, 0, 0, 0, 0, 0, 264];
        let [d0, d1, d2, d3, d4, d5, d6, d7] = compress256(h256(), block);
        let high = u128_of(((d0.into() * TWO32 + d1.into()) * TWO32 + d2.into()) * TWO32 + d3.into());
        let low = u128_of(((d4.into() * TWO32 + d5.into()) * TWO32 + d6.into()) * TWO32 + d7.into());
        let h = u256 { low, high };
        if h < GRIND_LIMIT {
            let order: NonZero<u256> = STARK_ORDER.try_into().unwrap();
            let (_, r) = DivRem::div_rem(h, order);
            break r.try_into().unwrap();
        }
        assert(i != 255, 'grind: too many rounds');
        i += 1;
    }
}

#[inline(never)]
fn stark_public_key(private_key: felt252) -> felt252 {
    let g = EcPointTrait::new(stark_curve::GEN_X, stark_curve::GEN_Y).unwrap();
    let p: NonZeroEcPoint = g.mul(private_key).try_into().unwrap();
    p.x()
}

/// profile: 'pq', 'braavos' or 'argentx'; seed: the 64-byte BIP39 seed as 8 big-endian words.
pub fn account_stark_key_words(profile: felt252, index: u32, seed: Span<u64>) -> felt252 {
    let k = if profile == 'argentx' {
        let eth = derive(master(seed_block(seed)), ETH_H, 0);
        derive(master(stripped_key_block(eth)), STARK_H, index)
    } else {
        assert(profile == 'pq' || profile == 'braavos', 'unknown profile');
        derive(master(seed_block(seed)), STARK_H, index)
    };
    stark_public_key(grind_key(k))
}

/// Byte interface: seed is the 64-byte BIP39 seed.
pub fn account_stark_key(profile: felt252, index: u32, seed: Span<u8>) -> felt252 {
    account_stark_key_words(profile, index, bytes_to_words64(seed).span())
}
