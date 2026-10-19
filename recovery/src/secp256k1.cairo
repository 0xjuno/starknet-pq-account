//! secp256k1 public key from a private key (k * G), in plain Cairo. Needed for BIP32 non-hardened
//! steps.
//!
//! Fixed-base signed comb: an odd scalar is rewritten with digits +-1 at every bit position,
//! k = sum_i s_i 2^i, and the digits are grouped in 32 columns of 8 teeth spaced 32 bits apart.
//! Column c contributes D_c = sum_j s_(c + 32 j) 2^(32 j), which is +- one of the 128 points in
//! `secp_table` (the sign of the top tooth is factored out). k * G = sum_c 2^c * D_c * G costs 31
//! doublings and 31 additions (instead of 255 doublings and ~128 additions), and the table is half
//! the size of an unsigned comb's.
//!
//! Points are affine: a field inversion (u256_inv_mod, a hint plus verification) costs about as
//! much as two multiplications, which is less than the extra multiplications of Jacobian formulas.
//! Multiplication mod p works on 64-bit limbs held in felts (products and column sums fit in a
//! felt without carries) and uses p = 2^256 - (2^32 + 977) for the reduction. Subtractions are
//! folded into the multiplications by adding 4p, so a point operation is one inversion and three
//! multiply-reduce calls.

use core::math::u256_inv_mod;
use core::num::traits::{OverflowingAdd, OverflowingSub, WrappingAdd, WrappingSub};
use crate::secp_table::SECP_COMB;
use crate::sha2::u128_of;

pub const P: u256 = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f;
pub const N: u256 = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141;

const P_LOW: u128 = 0xfffffffffffffffffffffffefffffc2f;
const P_HIGH: u128 = 0xffffffffffffffffffffffffffffffff;
const M64: u128 = 0xffffffffffffffff;
/// 2^256 mod p
const C: felt252 = 0x1000003d1;
const TWO64: felt252 = 0x10000000000000000;
const TWO123: felt252 = 0x8000000000000000000000000000000;
const INV2_64: felt252 = 0x800000000000010f7ffffffffffffef00000000000000000000000000000001;
const INV2_5: felt252 = 0x7c0000000000010780000000000000000000000000000000000000000000001;
const INV2: felt252 = 0x400000000000008800000000000000000000000000000000000000000000001;
const TWO127: felt252 = 0x80000000000000000000000000000000;
/// 4p as low and high 128-bit halves.
const FOUR_P_LO: felt252 = 0x3fffffffffffffffffffffffbfffff0bc;
const FOUR_P_HI: felt252 = 0x3fffffffffffffffffffffffffffffffc;
/// 4p = Q0 + Q1 2^64 + Q2 2^128 + Q3 2^192 with every Q_i in [2^64, 2^67).
const Q0: felt252 = 0x1fffffffbfffff0bc;
const Q1: felt252 = 0x1fffffffffffffffe;
const Q2: felt252 = 0x1fffffffffffffffe;
const Q3: felt252 = 0x3fffffffffffffffe;
/// 2^32 * (1 + 2^32 + 2^64 + 2^96): halved before each column c = 31..0 it selects bit c of each
/// 32-bit chunk of a u128.
const COL_MASK_32: felt252 = 0x100000001000000010000000100000000;
/// (2^128 + 2^97 + 2^66 + 2^35) / 2^32: doubled before each column c it becomes the factor that
/// moves bit c of the four chunks (masked) to bits 128..132 of the product.
const GATHER_32: felt252 = 0x1000000020000000400000008;

/// Four 64-bit-ish limbs (felts), least significant first.
type Limbs = (felt252, felt252, felt252, felt252);

/// (a + b) mod m for a, b < m.
#[inline(never)]
pub fn add_mod(a: u256, b: u256, m: u256) -> u256 {
    let (s, overflow) = a.overflowing_add(b);
    if overflow || s >= m {
        s.wrapping_sub(m)
    } else {
        s
    }
}

/// (a - b) mod p for a, b < p.
#[inline(never)]
fn fsub(a: u256, b: u256) -> u256 {
    let (r, borrow) = a.overflowing_sub(b);
    if borrow {
        r.wrapping_add(P)
    } else {
        r
    }
}

/// 64-bit limbs of a u256.
#[inline(always)]
fn limbs(a: u256) -> Limbs {
    let l: felt252 = (a.low & M64).into();
    let h: felt252 = (a.high & M64).into();
    (l, (a.low.into() - l) * INV2_64, h, (a.high.into() - h) * INV2_64)
}

/// Limbs of a + 4p - b for a, b < 2^256, each in [0, 2^67): congruent to a - b.
#[inline(always)]
fn limbs_diff(a: u256, b: u256) -> Limbs {
    let (a0, a1, a2, a3) = limbs(a);
    let (b0, b1, b2, b3) = limbs(b);
    (a0 + Q0 - b0, a1 + Q1 - b1, a2 + Q2 - b2, a3 + Q3 - b3)
}

/// (a * b + s_lo + s_hi * 2^128) mod p, for limbs below 2^67 and 0 <= s_lo, s_hi < 2^131.
///
/// Column sums c_k are below 2^136; 2^256 = C (mod p) folds c4..c6 down, leaving
/// lo + hi * 2^128 with lo < 2^236 and hi < 2^202, which is then carried into two u128 halves.
#[inline(never)]
fn mul_red(a: Limbs, b: Limbs, s_lo: felt252, s_hi: felt252) -> u256 {
    let (a0, a1, a2, a3) = a;
    let (b0, b1, b2, b3) = b;
    let c0 = a0 * b0;
    let c1 = a0 * b1 + a1 * b0;
    let c2 = a0 * b2 + a1 * b1 + a2 * b0;
    let c3 = a0 * b3 + a1 * b2 + a2 * b1 + a3 * b0;
    let c4 = a1 * b3 + a2 * b2 + a3 * b1;
    let c5 = a2 * b3 + a3 * b2;
    let c6 = a3 * b3;
    let l: u256 = (c0 + c1 * TWO64 + C * (c4 + c5 * TWO64) + s_lo).into();
    let h: u256 = (c2 + c3 * TWO64 + C * c6 + s_hi + l.high.into()).into();
    // value = l.low + h.low * 2^128 + h.high * 2^256 = l.low + h.high * C + h.low * 2^128 (mod p)
    let m: u256 = (l.low.into() + h.high.into() * C).into();
    let (high, carry) = h.low.overflowing_add(m.high);
    let r: u256 = if carry {
        // high wrapped to 0: value = m.low + 2^256 = m.low + C (mod p)
        (m.low.into() + C).into()
    } else {
        u256 { low: m.low, high }
    };
    if r.high == P_HIGH && r.low >= P_LOW {
        u256 { low: r.low - P_LOW, high: 0 }
    } else {
        r
    }
}

/// The point after (x1, y1) on the line of slope lam = num / den through it and the point with
/// x-coordinate x2: x3 = lam^2 - x1 - x2, y3 = lam * (x1 - x3) - y1. Shared by addition and
/// doubling. den must be nonzero and below p.
#[inline(never)]
fn step(num: Limbs, den: u256, x1: u256, y1: u256, x2: u256, p: NonZero<u256>) -> (u256, u256) {
    let inv: u256 = u256_inv_mod(den, p).unwrap().into();
    let lam = limbs(mul_red(num, limbs(inv), 0, 0));
    // x3 = lam^2 + 4p - x1 - x2
    let x3_lo = FOUR_P_LO - x1.low.into() - x2.low.into();
    let x3_hi = FOUR_P_HI - x1.high.into() - x2.high.into();
    let x3 = mul_red(lam, lam, x3_lo, x3_hi);
    // y3 = lam * (x1 + 4p - x3) + 4p - y1
    let y3 = mul_red(
        lam, limbs_diff(x1, x3), FOUR_P_LO - y1.low.into(), FOUR_P_HI - y1.high.into(),
    );
    (x3, y3)
}

/// Bit c of each 32-bit chunk of x as a 4-bit number, for mask = 2^c * (1 + 2^32 + 2^64 + 2^96)
/// and gather = (2^128 + 2^97 + 2^66 + 2^35) / 2^c. Masked, the bits sit at c + 32 j; times
/// gather, bit j lands on 128 + j and every cross term below 100 or at 160 and above.
#[inline(always)]
fn column_bits(x: u128, mask: u128, gather: felt252) -> felt252 {
    let v: felt252 = (x & mask).into();
    let g: u256 = (v * gather).into();
    (g.high & 0xf).into()
}

/// Table point i in 0..128, unpacked from its row (see secp_table).
#[inline(always)]
fn table_point(table: Span<[felt252; 3]>, i: usize) -> (u256, u256) {
    let [f0, f1, f2] = *table[i];
    let u0: u256 = f0.into();
    let u1: u256 = f1.into();
    let top = u128_of(f2);
    let xt: felt252 = (top & 31).into();
    let yt = (top.into() - xt) * INV2_5;
    let xh = u128_of(u0.high.into() + xt * TWO123);
    let yh = u128_of(u1.high.into() + yt * TWO123);
    (u256 { low: u0.low, high: xh }, u256 { low: u1.low, high: yh })
}

/// p - y for 0 < y < p.
#[inline(always)]
fn neg(y: u256) -> u256 {
    let (low, borrow) = P_LOW.overflowing_sub(y.low);
    let b: felt252 = if borrow {
        1
    } else {
        0
    };
    u256 { low, high: u128_of(P_HIGH.into() - y.high.into() - b) }
}

/// Affine 2 * (x, y): lam = 3 x^2 / (2 y) (y != 0: secp256k1 has no point of order 2).
#[inline(never)]
fn dbl(x: u256, y: u256, p: NonZero<u256>) -> (u256, u256) {
    let xl = limbs(x);
    let (a0, a1, a2, a3) = xl;
    let x2_3 = mul_red((3 * a0, 3 * a1, 3 * a2, 3 * a3), xl, 0, 0);
    step(limbs(x2_3), add_mod(y, y, P), x, y, x, p)
}

/// Affine (x, y) of k * G for 0 < k < N.
///
/// Recoding: for odd k' and m = (k' + 2^256 - 1) / 2, k' = sum_i (2 m_i - 1) 2^i, so digit i is
/// +1 exactly when bit i of m is set. Even k uses k' = N - k and negates the result.
///
/// Exceptional cases. Let V_c = sum_{c' >= c} 2^(c' - c) D_c'; the accumulator holds 2 V_(c+1) * G
/// when D_c is added and V_c * G after. In base 2^32 the lowest block of V_c is odd (its lowest
/// digit is +-1), so V_c != 0, and |V_c| < 2^(256 - c) <= 2^255 < N for c >= 1 while V_0 = k' < N:
/// the two points are never opposite. They are equal when 2 V_(c+1) - D_c = V_c - 2 D_c = 0
/// (mod N); its lowest block is odd as well, and |V_c - 2 D_c| < N for c >= 1, so this needs
/// c = 0 and k' = N + 2 D_0, which holds for exactly one odd k' (just below N). That addition is
/// handled as a doubling. The accumulator itself is never the point at infinity.
#[inline(never)]
pub fn mul_g(k: u256) -> (u256, u256) {
    assert(k != 0 && k < N, 'secp: bad scalar');
    let p: NonZero<u256> = P.try_into().unwrap();
    let table = SECP_COMB.span();
    let odd = k.low & 1 == 1;
    let ko = if odd {
        k
    } else {
        N - k
    };
    // m = (ko - 1) / 2 + 2^255
    let hb: felt252 = (ko.high & 1).into();
    let m_low = u128_of((ko.low.into() - 1) * INV2 + hb * TWO127);
    let m_high = u128_of((ko.high.into() - hb) * INV2 + TWO127);
    let mut maskf = COL_MASK_32 * INV2;
    let mut gather = GATHER_32 * 2;
    let (mut x, mut y) = column_point(table, m_low, m_high, maskf, gather);
    let mut c: usize = 31;
    while c != 0 {
        c -= 1;
        maskf = maskf * INV2;
        gather = gather * 2;
        let (px, py) = column_point(table, m_low, m_high, maskf, gather);
        let (x2, y2) = dbl(x, y, p);
        let dx = fsub(px, x2);
        let (nx, ny) = if dx == 0 {
            // same point (see above)
            dbl(px, py, p)
        } else {
            // lam = (py - y2) / (px - x2)
            step(limbs_diff(py, y2), dx, x2, y2, px, p)
        };
        x = nx;
        y = ny;
    }
    if odd {
        (x, y)
    } else {
        (x, neg(y))
    }
}

/// D_c * G for the column selected by maskf = 2^c * (1 + 2^32 + 2^64 + 2^96) and the matching
/// gather factor: bit 7 (top tooth) of the column is the sign, the other teeth index the table
/// relative to it.
#[inline(never)]
fn column_point(
    table: Span<[felt252; 3]>, m_low: u128, m_high: u128, maskf: felt252, gather: felt252,
) -> (u256, u256) {
    let mask = u128_of(maskf);
    let bits = column_bits(m_low, mask, gather) + 16 * column_bits(m_high, mask, gather);
    let j: usize = bits.try_into().unwrap();
    if j >= 128 {
        table_point(table, j - 128)
    } else {
        let (px, py) = table_point(table, 127 - j);
        (px, neg(py))
    }
}