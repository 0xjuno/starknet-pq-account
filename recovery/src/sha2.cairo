//! SHA-256, SHA-512 and HMAC-SHA512 in plain Cairo (no syscalls), so they run inside a provable
//! executable.
//!
//! Words are u128 values below 2^64 (SHA-512) or 2^32 (SHA-256), so the bitwise builtin can be used
//! directly. A rotation of a word x is a window of the doubled word X = x * (2^w + 1): one AND cuts
//! the window out (shifted up by the rotation amount), one felt multiplication by a power of two
//! aligns the three terms of a sigma function at a common bit position P, and one felt-to-u128
//! conversion (a single range check) types the product again for the XORs. The XOR of the aligned
//! terms is sigma * 2^P, and multiplying by the field inverse of 2^P is an exact division. Sums are
//! accumulated as felts and reduced once per word with an AND.
//!
//! The derivation code works on words only; the byte interfaces at the end are kept for tests.

use crate::constants::{H256, H512, K256, K512};

extern fn bitwise(
    lhs: u128, rhs: u128,
) -> (u128, u128, u128) implicits(core::integer::Bitwise) nopanic;

const M32: u128 = 0xffffffff;
const D32: felt252 = 0x100000001;
const D64: felt252 = 0x10000000000000001;
// Field inverses of 2^k (exact division of multiples of 2^k).
const INV2_8: felt252 = 0x7f8000000000010ef0000000000000000000000000000000000000000000001;
const INV2_18: felt252 = 0x7fffe0000000010fffbc0000000000000000000000000000000000000000001;
const INV2_19: felt252 = 0x7ffff0000000010fffde0000000000000000000000000000000000000000001;
const INV2_22: felt252 = 0x7ffffe000000010ffffbc000000000000000000000000000000000000000001;
const INV2_25: felt252 = 0x7fffffc00000010fffff7800000000000000000000000000000000000000001;
const INV2_39: felt252 = 0x7fffffffff00010ffffffffde00000000000000000000000000000000000001;
const INV2_41: felt252 = 0x7fffffffffc0010fffffffff780000000000000000000000000000000000001;
const INV2_61: felt252 = 0x800000000000010bfffffffffffff7800000000000000000000000000000001;

/// felt252 -> u128 for values the caller knows are below 2^128 (hot paths: inline).
#[inline(always)]
pub fn to_u128(x: felt252) -> u128 {
    x.try_into().unwrap()
}

enum U128sFromFelt252 {
    Narrow: u128,
    Wide: (u128, u128),
}
extern fn u128s_from_felt252(a: felt252) -> U128sFromFelt252 implicits(core::RangeCheck) nopanic;

/// felt252 -> u128 for values below 2^128 by construction, out of line. Every inline conversion
/// carries ~20 felts of bytecode for the libfunc's other branch, and bytecode is hashed by the
/// bootloader, so code that runs rarely shares this one copy. The Wide branch (x >= 2^128, proven
/// by the libfunc) is unreachable for such values.
#[inline(never)]
pub fn u128_of(x: felt252) -> u128 nopanic {
    match u128s_from_felt252(x) {
        U128sFromFelt252::Narrow(v) => v,
        U128sFromFelt252::Wide(_) => 0,
    }
}

// ---------------------------------------------------------------- SHA-512

/// AND masks for SHA-512. They are read from MASKS512 at run time and carried through the round
/// loop, so every AND takes its mask from a frame cell instead of loading an immediate.
#[derive(Copy, Drop)]
struct Masks {
    w41: u128,
    w14: u128,
    w18: u128,
    w39: u128,
    w28: u128,
    w34: u128,
    m64: u128,
    w8: u128,
    w1: u128,
    s7: u128,
    w61: u128,
    w19: u128,
    s6: u128,
}

/// (2^64 - 1) << n for the rotation windows, then the shift masks of sigma0/sigma1.
const MASKS512: [u128; 13] = [
    0x1fffffffffffffffe0000000000, 0x3fffffffffffffffc000, 0x3fffffffffffffffc0000,
    0x7fffffffffffffff8000000000, 0xffffffffffffffff0000000, 0x3fffffffffffffffc00000000,
    0xffffffffffffffff, 0xffffffffffffffff00, 0x1fffffffffffffffe, 0xffffffffffffff80,
    0x1fffffffffffffffe000000000000000, 0x7fffffffffffffff80000, 0xffffffffffffffc0,
];

#[inline(always)]
fn masks512() -> Masks {
    let [w41, w14, w18, w39, w28, w34, m64, w8, w1, s7, w61, w19, s6] = (*MASKS512
        .span()
        .try_into()
        .unwrap())
        .unbox();
    Masks { w41, w14, w18, w39, w28, w34, m64, w8, w1, s7, w61, w19, s6 }
}

/// sigma0(x) = rotr1 ^ rotr8 ^ shr7, aligned at bit 8.
#[inline(always)]
fn ssig0(x: u128, m: @Masks) -> felt252 {
    let xx = to_u128(x.into() * D64);
    let y8 = xx & *m.w8;
    let y1 = to_u128((xx & *m.w1).into() * 0x80);
    let z7 = to_u128((x & *m.s7).into() * 2);
    (y1 ^ y8 ^ z7).into() * INV2_8
}

/// sigma1(x) = rotr19 ^ rotr61 ^ shr6, aligned at bit 61.
#[inline(always)]
fn ssig1(x: u128, m: @Masks) -> felt252 {
    let xx = to_u128(x.into() * D64);
    let y61 = xx & *m.w61;
    let y19 = to_u128((xx & *m.w19).into() * 0x40000000000);
    let z6 = to_u128((x & *m.s6).into() * 0x80000000000000);
    (y19 ^ y61 ^ z6).into() * INV2_61
}

/// Message schedule: W[t] from W[t-2], W[t-7], W[t-15], W[t-16].
#[inline(always)]
fn sched(w2: u128, w7: u128, w15: u128, w16: u128, m: @Masks) -> u128 {
    to_u128(ssig1(w2, m) + w7.into() + ssig0(w15, m) + w16.into()) & *m.m64
}

/// One SHA-512 round; returns (new a, new e).
#[inline(always)]
fn round(
    a: u128, b: u128, c: u128, d: u128, e: u128, f: u128, g: u128, h: u128, k: u64, w: u128, m: @Masks,
) -> (u128, u128) {
    // Sigma1(e) = rotr14 ^ rotr18 ^ rotr41, aligned at bit 41.
    let ee = to_u128(e.into() * D64);
    let y41 = ee & *m.w41;
    let y14 = to_u128((ee & *m.w14).into() * 0x8000000);
    let y18 = to_u128((ee & *m.w18).into() * 0x800000);
    let s1: felt252 = (y14 ^ y18 ^ y41).into() * INV2_41;
    // Ch(e, f, g) = (e & f) + (!e & g), the two terms have no common bits.
    let ch: felt252 = (e & f).into() + g.into() - (e & g).into();
    let t1 = h.into() + s1 + ch + k.into() + w.into();
    // Sigma0(a) = rotr28 ^ rotr34 ^ rotr39, aligned at bit 39.
    let aa = to_u128(a.into() * D64);
    let y39 = aa & *m.w39;
    let y28 = to_u128((aa & *m.w28).into() * 0x800);
    let y34 = to_u128((aa & *m.w34).into() * 0x20);
    let s0: felt252 = (y28 ^ y34 ^ y39).into() * INV2_39;
    // Maj(a, b, c) = (a & b) + (c & (a ^ b)), again without common bits.
    let (ab_and, ab_xor, _) = bitwise(a, b);
    let maj: felt252 = ab_and.into() + (c & ab_xor).into();
    (to_u128(t1 + s0 + maj) & *m.m64, to_u128(d.into() + t1) & *m.m64)
}

/// SHA-512 compression of one block. All words must be below 2^64.
#[inline(never)]
pub fn compress512(state: [u128; 8], block: [u128; 16]) -> [u128; 8] {
    let mk = masks512();
    let mut ks = K512.span();
    let [a0, b0, c0, d0, e0, f0, g0, h0] = state;
    let [
        mut w0,
        mut w1,
        mut w2,
        mut w3,
        mut w4,
        mut w5,
        mut w6,
        mut w7,
        mut w8,
        mut w9,
        mut w10,
        mut w11,
        mut w12,
        mut w13,
        mut w14,
        mut w15,
    ] =
        block;
    let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
    let (mut e, mut f, mut g, mut h) = (e0, f0, g0, h0);
    // 20 iterations of 4 rounds; w0..w15 is the sliding window W[4i .. 4i + 16].
    let mut i: usize = 0;
    while i != 20 {
        let [k0, k1, k2, k3] = (*ks.multi_pop_front::<4>().unwrap()).unbox();
        let (p1a, p1e) = round(a, b, c, d, e, f, g, h, k0, w0, @mk);
        let (p2a, p2e) = round(p1a, a, b, c, p1e, e, f, g, k1, w1, @mk);
        let (p3a, p3e) = round(p2a, p1a, a, b, p2e, p1e, e, f, k2, w2, @mk);
        let (p4a, p4e) = round(p3a, p2a, p1a, a, p3e, p2e, p1e, e, k3, w3, @mk);
        a = p4a;
        b = p3a;
        c = p2a;
        d = p1a;
        e = p4e;
        f = p3e;
        g = p2e;
        h = p1e;
        if i < 16 {
            let n0 = sched(w14, w9, w1, w0, @mk);
            let n1 = sched(w15, w10, w2, w1, @mk);
            let n2 = sched(n0, w11, w3, w2, @mk);
            let n3 = sched(n1, w12, w4, w3, @mk);
            w0 = w4;
            w1 = w5;
            w2 = w6;
            w3 = w7;
            w4 = w8;
            w5 = w9;
            w6 = w10;
            w7 = w11;
            w8 = w12;
            w9 = w13;
            w10 = w14;
            w11 = w15;
            w12 = n0;
            w13 = n1;
            w14 = n2;
            w15 = n3;
        } else {
            w0 = w4;
            w1 = w5;
            w2 = w6;
            w3 = w7;
            w4 = w8;
            w5 = w9;
            w6 = w10;
            w7 = w11;
            w8 = w12;
            w9 = w13;
            w10 = w14;
            w11 = w15;
        }
        i += 1;
    }
    let m64 = mk.m64;
    [
        (a + a0) & m64, (b + b0) & m64, (c + c0) & m64, (d + d0) & m64, (e + e0) & m64,
        (f + f0) & m64, (g + g0) & m64, (h + h0) & m64,
    ]
}

pub fn h512() -> [u128; 8] {
    let [a, b, c, d, e, f, g, h] = H512;
    [a.into(), b.into(), c.into(), d.into(), e.into(), f.into(), g.into(), h.into()]
}

// ---------------------------------------------------------------- HMAC-SHA512 on words

const IPAD64: u128 = 0x3636363636363636;
const OPAD64: u128 = 0x5c5c5c5c5c5c5c5c;

/// Final block of a hash whose message is 128 bytes of key block plus a 64-byte digest.
#[inline(always)]
pub fn digest_block(h: [u128; 8]) -> [u128; 16] {
    let [h0, h1, h2, h3, h4, h5, h6, h7] = h;
    [h0, h1, h2, h3, h4, h5, h6, h7, 0x8000000000000000, 0, 0, 0, 0, 0, 0, 1536]
}

/// HMAC-SHA512 with a 32-byte key (4 words) over one already padded message block.
#[inline(always)]
pub fn hmac_key32(key: [u128; 4], block: [u128; 16]) -> [u128; 8] {
    let [k0, k1, k2, k3] = key;
    let ip = IPAD64;
    let op = OPAD64;
    let istate = compress512(
        h512(), [k0 ^ ip, k1 ^ ip, k2 ^ ip, k3 ^ ip, ip, ip, ip, ip, ip, ip, ip, ip, ip, ip, ip, ip],
    );
    let inner = compress512(istate, block);
    let ostate = compress512(
        h512(), [k0 ^ op, k1 ^ op, k2 ^ op, k3 ^ op, op, op, op, op, op, op, op, op, op, op, op, op],
    );
    compress512(ostate, digest_block(inner))
}

// ---------------------------------------------------------------- SHA-256

#[inline(always)]
fn red32(x: felt252) -> u128 {
    to_u128(x) & M32
}

/// sigma0(x) = rotr7 ^ rotr18 ^ shr3, aligned at bit 18.
#[inline(always)]
fn ssig0_32(x: u128) -> felt252 {
    let xx = to_u128(x.into() * D32);
    let y18 = xx & 0x3fffffffc0000;
    let y7 = to_u128((xx & 0x7fffffff80).into() * 0x800);
    let z3 = to_u128((x & 0xfffffff8).into() * 0x8000);
    (y7 ^ y18 ^ z3).into() * INV2_18
}

/// sigma1(x) = rotr17 ^ rotr19 ^ shr10, aligned at bit 19.
#[inline(always)]
fn ssig1_32(x: u128) -> felt252 {
    let xx = to_u128(x.into() * D32);
    let y19 = xx & 0x7fffffff80000;
    let y17 = to_u128((xx & 0x1fffffffe0000).into() * 4);
    let z10 = to_u128((x & 0xfffffc00).into() * 0x200);
    (y17 ^ y19 ^ z10).into() * INV2_19
}

/// SHA-256 compression of one block. All words must be below 2^32.
///
/// One round per iteration over a sliding window w0..w15 = W[t .. t + 16]; each iteration also
/// appends W[t + 16] (the last 16 of these are never used, which is cheaper than a branch).
#[inline(never)]
pub fn compress256(state: [u128; 8], block: [u128; 16]) -> [u128; 8] {
    let [a0, b0, c0, d0, e0, f0, g0, h0] = state;
    let [
        mut w0,
        mut w1,
        mut w2,
        mut w3,
        mut w4,
        mut w5,
        mut w6,
        mut w7,
        mut w8,
        mut w9,
        mut w10,
        mut w11,
        mut w12,
        mut w13,
        mut w14,
        mut w15,
    ] =
        block;
    let (mut a, mut b, mut c, mut d) = (a0, b0, c0, d0);
    let (mut e, mut f, mut g, mut h) = (e0, f0, g0, h0);
    let mut ks = K256.span();
    while let Some(k) = ks.pop_front() {
        // Sigma1(e) = rotr6 ^ rotr11 ^ rotr25, aligned at bit 25.
        let ee = to_u128(e.into() * D32);
        let y25 = ee & 0x1fffffffe000000;
        let y6 = to_u128((ee & 0x3fffffffc0).into() * 0x80000);
        let y11 = to_u128((ee & 0x7fffffff800).into() * 0x4000);
        let s1: felt252 = (y6 ^ y11 ^ y25).into() * INV2_25;
        let ch: felt252 = (e & f).into() + g.into() - (e & g).into();
        let t1 = h.into() + s1 + ch + (*k).into() + w0.into();
        // Sigma0(a) = rotr2 ^ rotr13 ^ rotr22, aligned at bit 22.
        let aa = to_u128(a.into() * D32);
        let y22 = aa & 0x3fffffffc00000;
        let y2 = to_u128((aa & 0x3fffffffc).into() * 0x100000);
        let y13 = to_u128((aa & 0x1fffffffe000).into() * 0x200);
        let s0: felt252 = (y2 ^ y13 ^ y22).into() * INV2_22;
        let (ab_and, ab_xor, _) = bitwise(a, b);
        let maj: felt252 = ab_and.into() + (c & ab_xor).into();
        h = g;
        g = f;
        f = e;
        e = red32(d.into() + t1);
        d = c;
        c = b;
        b = a;
        a = red32(t1 + s0 + maj);
        let n = red32(ssig1_32(w14) + w9.into() + ssig0_32(w1) + w0.into());
        w0 = w1;
        w1 = w2;
        w2 = w3;
        w3 = w4;
        w4 = w5;
        w5 = w6;
        w6 = w7;
        w7 = w8;
        w8 = w9;
        w9 = w10;
        w10 = w11;
        w11 = w12;
        w12 = w13;
        w13 = w14;
        w14 = w15;
        w15 = n;
    };
    [
        (a + a0) & M32, (b + b0) & M32, (c + c0) & M32, (d + d0) & M32, (e + e0) & M32,
        (f + f0) & M32, (g + g0) & M32, (h + h0) & M32,
    ]
}
pub fn h256() -> [u128; 8] {
    let [a, b, c, d, e, f, g, h] = H256;
    [a.into(), b.into(), c.into(), d.into(), e.into(), f.into(), g.into(), h.into()]
}

// ---------------------------------------------------------------- byte interfaces (tests)

/// Big-endian words of `size` bytes from a padded message, starting at byte `off`.
fn load_words(data: Span<u8>, off: usize, size: usize) -> [u128; 16] {
    let mut out: Array<u128> = array![];
    let mut j: usize = 0;
    while j != 16 {
        let mut v: felt252 = 0;
        let mut b: usize = 0;
        while b != size {
            v = v * 256 + (*data[off + j * size + b]).into();
            b += 1;
        }
        out.append(to_u128(v));
        j += 1;
    }
    (*out.span().try_into().unwrap()).unbox()
}

/// Message padding: 0x80, zeros, then the bit length in `len_bytes` bytes.
fn pad(data: Span<u8>, block: usize, len_bytes: usize) -> Array<u8> {
    let mut out: Array<u8> = array![];
    for x in data {
        out.append(*x);
    }
    out.append(0x80);
    while (out.len() + len_bytes) % block != 0 {
        out.append(0);
    }
    let mut z = 0;
    while z != len_bytes - 4 {
        out.append(0);
        z += 1;
    }
    for b in u32_to_bytes(data.len() * 8) {
        out.append(b);
    }
    out
}

fn words_to_bytes(words: Span<u128>, size: usize) -> Array<u8> {
    let mut out: Array<u8> = array![];
    for w in words {
        let mut rev: Array<u8> = array![];
        let mut v: u128 = *w;
        let mut i = 0;
        while i != size {
            let (q, r) = DivRem::div_rem(v, 256);
            rev.append(r.try_into().unwrap());
            v = q;
            i += 1;
        }
        let mut j = size;
        while j != 0 {
            j -= 1;
            out.append(*rev[j]);
        }
    }
    out
}

pub fn sha512(data: Span<u8>) -> Array<u8> {
    let padded = pad(data, 128, 16);
    let mut state = h512();
    let mut off: usize = 0;
    while off != padded.len() {
        state = compress512(state, load_words(padded.span(), off, 8));
        off += 128;
    }
    words_to_bytes(state.span(), 8)
}

/// HMAC-SHA512 with a key of at most 128 bytes.
pub fn hmac_sha512(key: Span<u8>, data: Span<u8>) -> Array<u8> {
    assert(key.len() <= 128, 'hmac: key too long');
    let mut inner: Array<u8> = array![];
    let mut outer: Array<u8> = array![];
    let mut i: usize = 0;
    while i != 128 {
        let k: u8 = if i < key.len() {
            *key[i]
        } else {
            0
        };
        inner.append(k ^ 0x36);
        outer.append(k ^ 0x5c);
        i += 1;
    }
    for x in data {
        inner.append(*x);
    }
    for x in sha512(inner.span()) {
        outer.append(x);
    }
    sha512(outer.span())
}

pub fn sha256(data: Span<u8>) -> Array<u8> {
    let padded = pad(data, 64, 8);
    let mut state = h256();
    let mut off: usize = 0;
    while off != padded.len() {
        state = compress256(state, load_words(padded.span(), off, 4));
        off += 64;
    }
    words_to_bytes(state.span(), 4)
}

pub fn u32_to_bytes(x: u32) -> Array<u8> {
    let w: u128 = x.into();
    words_to_bytes([w].span(), 4)
}

pub fn words64_to_bytes(words: Span<u64>) -> Array<u8> {
    let mut ws: Array<u128> = array![];
    for w in words {
        ws.append((*w).into());
    }
    words_to_bytes(ws.span(), 8)
}

/// 64 big-endian bytes to 8 words.
pub fn bytes_to_words64(b: Span<u8>) -> Array<u64> {
    assert(b.len() == 64, 'expected 64 bytes');
    let mut out: Array<u64> = array![];
    let mut j: usize = 0;
    while j != 8 {
        let mut v: u64 = 0;
        let mut i: usize = 0;
        while i != 8 {
            v = v * 256 + (*b[j * 8 + i]).into();
            i += 1;
        }
        out.append(v);
        j += 1;
    }
    out
}
