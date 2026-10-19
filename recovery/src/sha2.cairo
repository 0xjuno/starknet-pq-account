//! SHA-256, SHA-512 and HMAC-SHA512 in plain Cairo (no syscalls), so they run inside a provable
//! executable. Rotations use one wide multiplication and a division by 2^64 (or 2^32).

use core::num::traits::WrappingAdd;
use crate::constants::{H256, H512, K256, K512};

const MASK64: u64 = 0xffffffffffffffff;
const MASK32: u32 = 0xffffffff;

// ---------------------------------------------------------------- SHA-512

#[inline]
fn rotr64(x: u64, m: u128, two64: NonZero<u128>) -> u64 {
    // m = 2^(64 - n): high part = x >> n, low part = (x << (64 - n)) mod 2^64
    let t: u128 = x.into() * m;
    let (hi, lo) = DivRem::div_rem(t, two64);
    (hi | lo).try_into().unwrap()
}

#[inline]
fn shr64(x: u64, d: NonZero<u64>) -> u64 {
    let (q, _) = DivRem::div_rem(x, d);
    q
}

fn compress512(state: Span<u64>, block: Span<u64>, two64: NonZero<u128>) -> Array<u64> {
    let d7: NonZero<u64> = 128_u64.try_into().unwrap();
    let d6: NonZero<u64> = 64_u64.try_into().unwrap();
    let mut w: Array<u64> = array![];
    for x in block {
        w.append(*x);
    }
    let mut t: usize = 16;
    while t != 80 {
        let x15 = *w[t - 15];
        let x2 = *w[t - 2];
        let s0 = rotr64(x15, 0x8000000000000000, two64)
            ^ rotr64(x15, 0x100000000000000, two64)
            ^ shr64(x15, d7);
        let s1 = rotr64(x2, 0x200000000000, two64) ^ rotr64(x2, 0x8, two64) ^ shr64(x2, d6);
        w.append(s1.wrapping_add(*w[t - 7]).wrapping_add(s0).wrapping_add(*w[t - 16]));
        t += 1;
    }
    let k = K512.span();
    let (mut a, mut b, mut c, mut d) = (*state[0], *state[1], *state[2], *state[3]);
    let (mut e, mut f, mut g, mut h) = (*state[4], *state[5], *state[6], *state[7]);
    let mut i: usize = 0;
    while i != 80 {
        let big_s1 = rotr64(e, 0x4000000000000, two64)
            ^ rotr64(e, 0x400000000000, two64)
            ^ rotr64(e, 0x800000, two64);
        let ch = (e & f) ^ ((e ^ MASK64) & g);
        let t1 = h.wrapping_add(big_s1).wrapping_add(ch).wrapping_add(*k[i]).wrapping_add(*w[i]);
        let big_s0 = rotr64(a, 0x1000000000, two64)
            ^ rotr64(a, 0x40000000, two64)
            ^ rotr64(a, 0x2000000, two64);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = big_s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
        i += 1;
    }
    array![
        a.wrapping_add(*state[0]), b.wrapping_add(*state[1]), c.wrapping_add(*state[2]),
        d.wrapping_add(*state[3]), e.wrapping_add(*state[4]), f.wrapping_add(*state[5]),
        g.wrapping_add(*state[6]), h.wrapping_add(*state[7]),
    ]
}

fn pad(data: Span<u8>, block: usize, len_bytes: usize) -> Array<u8> {
    let mut out: Array<u8> = array![];
    for x in data {
        out.append(*x);
    }
    out.append(0x80);
    while (out.len() + len_bytes) % block != 0 {
        out.append(0);
    }
    // message length in bits, big-endian (messages here are far below 2^32 bits)
    let mut z = 0;
    while z != len_bytes - 4 {
        out.append(0);
        z += 1;
    }
    let bits: u32 = data.len() * 8;
    for b in u32_to_bytes(bits) {
        out.append(b);
    }
    out
}

pub fn sha512(data: Span<u8>) -> Array<u8> {
    let two64: NonZero<u128> = 0x10000000000000000_u128.try_into().unwrap();
    let padded = pad(data, 128, 16);
    let mut state: Array<u64> = array![];
    for x in H512.span() {
        state.append(*x);
    }
    let mut off: usize = 0;
    while off != padded.len() {
        let mut block: Array<u64> = array![];
        let mut j: usize = 0;
        while j != 16 {
            let mut v: u64 = 0;
            let mut b: usize = 0;
            while b != 8 {
                v = v * 256 + (*padded[off + j * 8 + b]).into();
                b += 1;
            }
            block.append(v);
            j += 1;
        }
        state = compress512(state.span(), block.span(), two64);
        off += 128;
    }
    let mut out: Array<u8> = array![];
    for x in state {
        for b in u64_to_bytes(x) {
            out.append(b);
        }
    }
    out
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

// ---------------------------------------------------------------- SHA-256

#[inline]
fn rotr32(x: u32, m: u64, two32: NonZero<u64>) -> u32 {
    let t: u64 = x.into() * m;
    let (hi, lo) = DivRem::div_rem(t, two32);
    (hi | lo).try_into().unwrap()
}

#[inline]
fn shr32(x: u32, d: NonZero<u32>) -> u32 {
    let (q, _) = DivRem::div_rem(x, d);
    q
}

fn compress256(state: Span<u32>, block: Span<u32>, two32: NonZero<u64>) -> Array<u32> {
    let d3: NonZero<u32> = 8_u32.try_into().unwrap();
    let d10: NonZero<u32> = 1024_u32.try_into().unwrap();
    let mut w: Array<u32> = array![];
    for x in block {
        w.append(*x);
    }
    let mut t: usize = 16;
    while t != 64 {
        let x15 = *w[t - 15];
        let x2 = *w[t - 2];
        let s0 = rotr32(x15, 0x2000000, two32) ^ rotr32(x15, 0x4000, two32) ^ shr32(x15, d3);
        let s1 = rotr32(x2, 0x8000, two32) ^ rotr32(x2, 0x2000, two32) ^ shr32(x2, d10);
        w.append(s1.wrapping_add(*w[t - 7]).wrapping_add(s0).wrapping_add(*w[t - 16]));
        t += 1;
    }
    let k = K256.span();
    let (mut a, mut b, mut c, mut d) = (*state[0], *state[1], *state[2], *state[3]);
    let (mut e, mut f, mut g, mut h) = (*state[4], *state[5], *state[6], *state[7]);
    let mut i: usize = 0;
    while i != 64 {
        let big_s1 = rotr32(e, 0x4000000, two32) ^ rotr32(e, 0x200000, two32) ^ rotr32(e, 0x80, two32);
        let ch = (e & f) ^ ((e ^ MASK32) & g);
        let t1 = h.wrapping_add(big_s1).wrapping_add(ch).wrapping_add(*k[i]).wrapping_add(*w[i]);
        let big_s0 = rotr32(a, 0x40000000, two32) ^ rotr32(a, 0x80000, two32) ^ rotr32(a, 0x400, two32);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = big_s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
        i += 1;
    }
    array![
        a.wrapping_add(*state[0]), b.wrapping_add(*state[1]), c.wrapping_add(*state[2]),
        d.wrapping_add(*state[3]), e.wrapping_add(*state[4]), f.wrapping_add(*state[5]),
        g.wrapping_add(*state[6]), h.wrapping_add(*state[7]),
    ]
}

pub fn sha256(data: Span<u8>) -> Array<u8> {
    let two32: NonZero<u64> = 0x100000000_u64.try_into().unwrap();
    let padded = pad(data, 64, 8);
    let mut state: Array<u32> = array![];
    for x in H256.span() {
        state.append(*x);
    }
    let mut off: usize = 0;
    while off != padded.len() {
        let mut block: Array<u32> = array![];
        let mut j: usize = 0;
        while j != 16 {
            let mut v: u32 = 0;
            let mut b: usize = 0;
            while b != 4 {
                v = v * 256 + (*padded[off + j * 4 + b]).into();
                b += 1;
            }
            block.append(v);
            j += 1;
        }
        state = compress256(state.span(), block.span(), two32);
        off += 64;
    }
    let mut out: Array<u8> = array![];
    for x in state {
        for b in u32_to_bytes(x) {
            out.append(b);
        }
    }
    out
}

// ---------------------------------------------------------------- byte helpers

pub fn u32_to_bytes(x: u32) -> Array<u8> {
    let d: NonZero<u32> = 256_u32.try_into().unwrap();
    let (q1, b3) = DivRem::div_rem(x, d);
    let (q2, b2) = DivRem::div_rem(q1, d);
    let (b0, b1) = DivRem::div_rem(q2, d);
    array![
        b0.try_into().unwrap(), b1.try_into().unwrap(), b2.try_into().unwrap(),
        b3.try_into().unwrap(),
    ]
}

pub fn u64_to_bytes(x: u64) -> Array<u8> {
    let d: NonZero<u64> = 256_u64.try_into().unwrap();
    let mut rev: Array<u8> = array![];
    let mut v = x;
    let mut i = 0;
    while i != 8 {
        let (q, r) = DivRem::div_rem(v, d);
        rev.append(r.try_into().unwrap());
        v = q;
        i += 1;
    }
    let mut out: Array<u8> = array![];
    let mut j: usize = 8;
    while j != 0 {
        j -= 1;
        out.append(*rev[j]);
    }
    out
}

pub fn words64_to_bytes(words: Span<u64>) -> Array<u8> {
    let mut out: Array<u8> = array![];
    for w in words {
        for b in u64_to_bytes(*w) {
            out.append(b);
        }
    }
    out
}

/// 32 big-endian bytes to u256.
pub fn bytes_to_u256(b: Span<u8>) -> u256 {
    let mut high: u128 = 0;
    let mut low: u128 = 0;
    let mut i: usize = 0;
    while i != 16 {
        high = high * 256 + (*b[i]).into();
        low = low * 256 + (*b[i + 16]).into();
        i += 1;
    }
    u256 { low, high }
}

fn u128_to_bytes(x: u128) -> Array<u8> {
    let d: NonZero<u128> = 256_u128.try_into().unwrap();
    let mut rev: Array<u8> = array![];
    let mut v = x;
    let mut i = 0;
    while i != 16 {
        let (q, r) = DivRem::div_rem(v, d);
        rev.append(r.try_into().unwrap());
        v = q;
        i += 1;
    }
    let mut out: Array<u8> = array![];
    let mut j: usize = 16;
    while j != 0 {
        j -= 1;
        out.append(*rev[j]);
    }
    out
}

/// u256 to 32 big-endian bytes.
pub fn u256_to_bytes(v: u256) -> Array<u8> {
    let mut out = u128_to_bytes(v.high);
    for b in u128_to_bytes(v.low) {
        out.append(b);
    }
    out
}
