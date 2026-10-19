//! secp256k1 public key from a private key (k * G), in plain Cairo: Jacobian coordinates,
//! u256 field arithmetic mod p, one inversion at the end. Needed for BIP32 non-hardened steps.

use core::math::{u256_inv_mod, u256_mul_mod_n};
use core::num::traits::{OverflowingAdd, WrappingSub};
use crate::sha2::u256_to_bytes;

pub const P: u256 = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f;
pub const N: u256 = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;
const GX: u256 = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798;
const GY: u256 = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8;
const TOP_BIT: u128 = 0x80000000000000000000000000000000;

#[derive(Copy, Drop)]
struct Jac {
    x: u256,
    y: u256,
    z: u256,
}

/// (a + b) mod m for a, b < m.
pub fn add_mod(a: u256, b: u256, m: u256) -> u256 {
    let (s, overflow) = a.overflowing_add(b);
    if overflow || s >= m {
        s.wrapping_sub(m)
    } else {
        s
    }
}

/// (a - b) mod m for a, b < m.
fn sub_mod(a: u256, b: u256, m: u256) -> u256 {
    if a >= b {
        a - b
    } else {
        m - (b - a)
    }
}

#[inline]
fn fadd(a: u256, b: u256) -> u256 {
    add_mod(a, b, P)
}

#[inline]
fn fsub(a: u256, b: u256) -> u256 {
    sub_mod(a, b, P)
}

#[inline]
fn fmul(a: u256, b: u256, p: NonZero<u256>) -> u256 {
    u256_mul_mod_n(a, b, p)
}

// dbl-2009-l (a = 0)
fn dbl(q: Jac, p: NonZero<u256>) -> Jac {
    let a = fmul(q.x, q.x, p);
    let b = fmul(q.y, q.y, p);
    let c = fmul(b, b, p);
    let xb = fadd(q.x, b);
    let t = fsub(fsub(fmul(xb, xb, p), a), c);
    let d = fadd(t, t);
    let e = fadd(fadd(a, a), a);
    let f = fmul(e, e, p);
    let x3 = fsub(f, fadd(d, d));
    let c2 = fadd(c, c);
    let c4 = fadd(c2, c2);
    let c8 = fadd(c4, c4);
    let y3 = fsub(fmul(e, fsub(d, x3), p), c8);
    let yz = fmul(q.y, q.z, p);
    Jac { x: x3, y: y3, z: fadd(yz, yz) }
}

// madd-2007-bl: Jacobian + affine (GX, GY)
fn add_g(q: Jac, p: NonZero<u256>) -> Jac {
    let z1z1 = fmul(q.z, q.z, p);
    let u2 = fmul(GX, z1z1, p);
    let s2 = fmul(fmul(GY, q.z, p), z1z1, p);
    let h = fsub(u2, q.x);
    let hh = fmul(h, h, p);
    let h2 = fadd(hh, hh);
    let i = fadd(h2, h2);
    let j = fmul(h, i, p);
    let r0 = fsub(s2, q.y);
    let r = fadd(r0, r0);
    let v = fmul(q.x, i, p);
    let x3 = fsub(fsub(fmul(r, r, p), j), fadd(v, v));
    let y1j = fmul(q.y, j, p);
    let y3 = fsub(fmul(r, fsub(v, x3), p), fadd(y1j, y1j));
    let zh = fadd(q.z, h);
    let z3 = fsub(fsub(fmul(zh, zh, p), z1z1), hh);
    Jac { x: x3, y: y3, z: z3 }
}

/// Affine (x, y) of k * G for 0 < k < N. Double-and-add from the top bit; for a uniformly random
/// key the intermediate point never equals +-G, which the mixed addition does not handle.
pub fn mul_g(k: u256) -> (u256, u256) {
    assert(k != 0 && k < N, 'secp: bad scalar');
    let p: NonZero<u256> = P.try_into().unwrap();
    let mut acc = Jac { x: GX, y: GY, z: 1 };
    let mut started = false;
    let words = array![k.high, k.low];
    for word in words {
        let mut w = word;
        let mut i = 0;
        while i != 128 {
            let bit = w >= TOP_BIT;
            w = if bit {
                (w - TOP_BIT) * 2
            } else {
                w * 2
            };
            if started {
                acc = dbl(acc, p);
                if bit {
                    acc = add_g(acc, p);
                }
            } else if bit {
                started = true;
            }
            i += 1;
        }
    }
    let zinv: u256 = u256_inv_mod(acc.z, p).unwrap().into();
    let zinv2 = fmul(zinv, zinv, p);
    (fmul(acc.x, zinv2, p), fmul(acc.y, fmul(zinv2, zinv, p), p))
}

/// 33-byte compressed public key (SEC1).
pub fn compressed_pubkey(k: u256) -> Array<u8> {
    let (x, y) = mul_g(k);
    let parity: u8 = if y.low % 2 == 0 {
        2
    } else {
        3
    };
    let mut out = array![parity];
    for b in u256_to_bytes(x) {
        out.append(b);
    }
    out
}
