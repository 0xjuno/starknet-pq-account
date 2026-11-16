//! Falcon-512 signature verification.
//!
//! Hint variant: verifies `s1 * h == mul_hint` via two forward NTTs and a pointwise
//! product check (the NTT is a bijection, so the check binds `mul_hint` to exactly
//! `s1 * h mod (q, phi)`), then accepts iff
//! `||msg_point - mul_hint||^2 + ||s1||^2 <= SIG_BOUND_512` over centered
//! representatives. Since `msg_point - s1*h = s0`, this is the Falcon verification
//! equation with the polynomial multiplication delegated to a signer-supplied hint;
//! a bad hint yields `false`. Both transforms use the generated fixed-parameter
//! Falcon-512 path, and the pointwise check tests `s1n*h == hn (mod q)`.
//!
//! Direct variant: computes `s1 * h` on-chain as `INTT(NTT(s1) ∘ h_ntt)` — the
//! generated forward transform's reduced pointwise products feed the generic inverse
//! engine with their exact bound.
//!
//! The verifier path decodes packed coefficients into canonical `u16` values and keeps
//! that representation through the generated NTT and norm calculation. The public core
//! functions also accept validated felt coefficients for standalone callers.

use pqbench_ntt_pf_small::engine::intt;
use pqbench_ntt_pf_small::falcon512::{PRODUCT_BITS, PRODUCT_BOUND_FELT, config};
use pqbench_ntt_pf_small::{LazyCoeff, ntt_falcon512_fast_u16_lazy_unchecked, ntt_falcon512_fast_u16_unchecked};
use corelib_imports::integer::{U128sFromFelt252Result, u128s_from_felt252};
use crate::zq::{Q32, center_sq, centered_difference_sq};

/// Maximum allowed `||s0||^2 + ||s1||^2` for Falcon-512 (FIPS 206 / falcon.py sig_bound).
pub const SIG_BOUND_512: u64 = 34034726;

/// The Falcon modulus as a u32 divisor.
const Q32_NZ: NonZero<u32> = 12289;

use corelib_imports::bounded_int::{
    AddHelper, BoundedInt, DivRemHelper, MulHelper, UnitInt, bounded_int, upcast,
};
#[feature("bounded-int-utils")]
use core::internal::bounded_int::SubHelper;

type QUnit = UnitInt<12289>;
const Q_NZ_B: NonZero<QUnit> = 12289;

/// The modulus as a cell rather than an immediate, so that the divisions in the fused
/// check loop use the loop parameter in place instead of first copying the constant.
#[inline(never)]
fn q_cell() -> NonZero<QUnit> {
    Q_NZ_B
}

/// The hint check's constants as cells (see [`q_cell`]).
#[derive(Copy, Drop)]
pub(crate) struct HintConsts {
    q: NonZero<QUnit>,
    offset: felt252,
    inv_q: felt252,
}

#[inline(never)]
pub(crate) fn hint_consts() -> HintConsts {
    HintConsts { q: Q_NZ_B, offset: LAZY_HINT_OFFSET, inv_q: INV_Q }
}
/// `u16 * u16`.
type U16Product = BoundedInt<0, 4294836225>;
/// `6q - c` for a `u16` `c`: 6q = 73734 >= 2^16 - 1, so never negative.
type SixQMinus = BoundedInt<8199, 73734>;
type HintCheck = BoundedInt<8199, 4294909959>;
type RemQ = BoundedInt<0, 12288>;
type U128B = BoundedInt<0, 340282366920938463463374607431768211455>;
/// The smallest multiple of q at or above 2^122, the bound on the lazy NTT outputs.
const LAZY_HINT_OFFSET: felt252 = 5316911983139663491615228241121380889;
/// `6144 + 5q - t` for a `u16` `t` (6144 + 5q = 67589 >= 2^16 - 1).
type CenterOffset = BoundedInt<2054, 67589>;
type CenterSum = BoundedInt<2054, 133124>;
type Centered = BoundedInt<-6144, 6144>;
type CenteredSq = BoundedInt<-37748736, 37748736>;

impl MulU16U16 of MulHelper<u16, u16> {
    type Result = U16Product;
}
impl SubSixQU16 of SubHelper<UnitInt<73734>, u16> {
    type Result = SixQMinus;
}
impl AddProductSixQ of AddHelper<U16Product, SixQMinus> {
    type Result = HintCheck;
}
impl DivRemHintCheckQ of DivRemHelper<HintCheck, QUnit> {
    type DivT = BoundedInt<0, 349492>;
    type RemT = RemQ;
}
impl DivRemU128Q of DivRemHelper<U128B, QUnit> {
    type DivT = BoundedInt<0, 27689996494502275487295516920153650>;
    type RemT = RemQ;
}
impl AddU16CenterOffsetFirst of AddHelper<u16, UnitInt<67589>> {
    type Result = BoundedInt<67589, 133124>;
}
impl SubCenterSumU16 of SubHelper<BoundedInt<67589, 133124>, u16> {
    type Result = CenterSum;
}
impl SubCenterOffsetU16 of SubHelper<UnitInt<67589>, u16> {
    type Result = CenterOffset;
}
impl AddU16CenterOffset of AddHelper<u16, CenterOffset> {
    type Result = CenterSum;
}
impl DivRemCenterSumQ of DivRemHelper<CenterSum, QUnit> {
    type DivT = BoundedInt<0, 10>;
    type RemT = RemQ;
}
impl SubRemHalf of SubHelper<RemQ, UnitInt<6144>> {
    type Result = Centered;
}
impl MulCentered of MulHelper<Centered, Centered> {
    type Result = CenteredSq;
}

/// `(a * b - c) mod q` as a remainder of a non-negative bounded value: `a * b + (6q - c)`,
/// built with no runtime check, then one bounded division by q.
#[inline(always)]
fn product_difference_rem(a: u16, b: u16, c: u16) -> felt252 {
    let six_q: UnitInt<73734> = 73734;
    let x = bounded_int::add(bounded_int::mul(a, b), bounded_int::sub(six_q, c));
    let (_, r) = bounded_int::div_rem(x, Q_NZ_B);
    r.into()
}

/// `(a*b - c) mod q` for a lazy NTT output `c` in `[0, 2^122)`: `a*b + K - c` is
/// non-negative and below `2^123`, so it converts to a `u128` exactly.
#[inline(always)]
fn lazy_product_difference_rem(a: u16, b: u16, c: LazyCoeff, q: NonZero<QUnit>) -> felt252 {
    let product: felt252 = bounded_int::mul(a, b).into();
    let x = product + (LAZY_HINT_OFFSET - c.value);
    let x: U128B = match u128s_from_felt252(x) {
        U128sFromFelt252Result::Narrow(low) => upcast(low),
        U128sFromFelt252Result::Wide(_) => panic!("lazy hint check out of range"),
    };
    let (_, r) = bounded_int::div_rem(x, q);
    r.into()
}

type CenterShift = BoundedInt<6144, 71679>;
impl AddU16Half of AddHelper<u16, UnitInt<6144>> {
    type Result = CenterShift;
}
impl DivRemCenterShiftQ of DivRemHelper<CenterShift, QUnit> {
    type DivT = BoundedInt<0, 5>;
    type RemT = RemQ;
}

type LazyProduct = BoundedInt<0, 4181389724724491839037947176121567782359040>;
/// The smallest multiple of q at or above 2^128 - 1, so that `K - c` is non-negative for
/// every `u128` `c`.
type LazyOffset2 = UnitInt<340282366920938463463374607431768217139>;
const LAZY_OFFSET2: LazyOffset2 = 340282366920938463463374607431768217139;
type LazyOffset2Minus = BoundedInt<5684, 340282366920938463463374607431768217139>;
type LazyCheck2 = BoundedInt<5684, 4181730007091412777501410550728999550576179>;
impl MulU128Zq of MulHelper<U128B, RemQ> {
    type Result = LazyProduct;
}
impl SubLazyOffset2 of SubHelper<LazyOffset2, U128B> {
    type Result = LazyOffset2Minus;
}
impl AddLazyCheck2 of AddHelper<LazyProduct, LazyOffset2Minus> {
    type Result = LazyCheck2;
}
/// Its quotient by q stays below 2^128, as `bounded_int_div_rem` requires.
impl DivRemLazyCheck2Q of DivRemHelper<LazyCheck2, QUnit> {
    type DivT = BoundedInt<0, 340282366920938463463374607431768211455>;
    type RemT = RemQ;
}

/// A lazy NTT output as a `u128`: canonical inputs keep it below 2^122.
#[inline(always)]
fn lazy_as_u128(c: LazyCoeff) -> U128B {
    match u128s_from_felt252(c.value) {
        U128sFromFelt252Result::Narrow(low) => upcast(low),
        U128sFromFelt252Result::Wide(_) => panic!("lazy NTT output out of range"),
    }
}

/// `(a*b - c) mod q` for lazy NTT outputs `a` and `c` and a reduced `b < q`:
/// `a*b + K - c` with `K = q * ceil((2^128 - 1) / q)` is a non-negative bounded integer
/// below `q * 2^128`, congruent to `a*b - c`, reduced by one division.
#[inline(always)]
fn lazy2_product_difference_rem(a: LazyCoeff, b: RemQ, c: LazyCoeff, q: NonZero<QUnit>) -> felt252 {
    let k: LazyOffset2 = LAZY_OFFSET2;
    let x = bounded_int::add(bounded_int::mul(lazy_as_u128(a), b), bounded_int::sub(k, lazy_as_u128(c)));
    let (_, r) = bounded_int::div_rem(x, q);
    r.into()
}

/// q^-1 in the Stark field.
pub(crate) const INV_Q: felt252 = 0x590625348ee7b13ed5063a897278482929cf2104a53c8ebd06ba86c7dbd6164;

/// Whether q divides `a*b - c`, for lazy NTT outputs `a`, `c` in `[0, 2^122)` and `b < q`.
/// `x = a*b + K - c` is an integer in `[0, 2^137)`. If `q` divides it, `x * q^-1` in the
/// field is the integer quotient, below 2^128. If not, `x * q^-1` is at least 2^128:
/// otherwise `q * y` and `x` would be integers below `2^142 < P` congruent mod `P`, so
/// equal, and `q` would divide `x`. One range check, no division.
#[inline(always)]
pub(crate) fn hint_quotient(a: LazyCoeff, b: RemQ, c: LazyCoeff, k: HintConsts) -> felt252 {
    let b: felt252 = b.into();
    (a.value * b + (k.offset - c.value)) * k.inv_q
}

/// [`hint_quotient`] with the offset already taken off the hint transform: `c` is the field
/// element `hn - K` (see `ntt_falcon512_fast_u16_lazy_minus_unchecked`), so
/// `a*b - c = a*b + K - hn` as field elements and the same bound argument applies.
#[inline(always)]
pub(crate) fn hint_quotient_pre(a: LazyCoeff, b: RemQ, c: LazyCoeff, k: HintConsts) -> felt252 {
    let b: felt252 = b.into();
    (a.value * b - c.value) * k.inv_q
}

/// [`hint_quotient_pre`] with q^-1 as an immediate (Q56): the fused check loop then
/// carries no `HintConsts` cells from one iteration to the next.
#[inline(always)]
pub(crate) fn hint_quotient_inv(a: LazyCoeff, b: RemQ, c: LazyCoeff) -> felt252 {
    let b: felt252 = b.into();
    (a.value * b - c.value) * INV_Q
}

/// Squared centered representative of a coefficient: `(v + 6144) mod q - 6144` lies in
/// [-6144, 6144] and is congruent to `v`; one division, no branch.
#[inline(always)]
fn center_sq_b(v: u16, q: NonZero<QUnit>) -> felt252 {
    let half: UnitInt<6144> = 6144;
    let (_, r) = bounded_int::div_rem(bounded_int::add(v, half), q);
    let c = bounded_int::sub(r, half);
    bounded_int::mul(c, c).into()
}

/// Squared centered representative of `a - b` mod q: `(a - b + 6144) mod q - 6144` lies in
/// [-6144, 6144] and is congruent to `a - b`, so its square is the centered square.
#[inline(always)]
fn centered_difference_sq_b(a: u16, b: u16, q: NonZero<QUnit>) -> felt252 {
    let offset: UnitInt<67589> = 67589;
    let half: UnitInt<6144> = 6144;
    // (a + offset) - b: the constant is added as an immediate, never copied.
    let (_, r) = bounded_int::div_rem(bounded_int::sub(bounded_int::add(a, offset), b), q);
    let c = bounded_int::sub(r, half);
    bounded_int::mul(c, c).into()
}



#[inline(always)]
fn felts_to_u16(mut values: Span<felt252>) -> Array<u16> {
    let mut out: Array<u16> = array![];
    while let Some(value) = values.pop_front() {
        out.append((*value).try_into().unwrap());
    }
    out
}

#[inline(always)]
fn product_difference(a: u16, b: u16, c: u16) -> u32 {
    let a: u32 = a.into();
    let b: u32 = b.into();
    let c: u32 = c.into();
    a * b + Q32 - c
}

#[inline(always)]
fn product_as_felt(a: u16, b: u16) -> felt252 {
    let a: u32 = a.into();
    let b: u32 = b.into();
    (a * b).into()
}

/// Verify with a signer-supplied product hint. All spans must have length 512 with
/// coefficients in `[0, Q)` — guaranteed by `packing::unpack_512` and
/// `hash_to_point::hash_to_point_512`.
pub fn verify_512_with_hint(
    s1: Span<felt252>, h_ntt: Span<felt252>, mul_hint: Span<felt252>, msg_point: Span<u16>,
) -> bool {
    assert(s1.len() == 512, 's1 must be 512 coeffs');
    assert(h_ntt.len() == 512, 'h_ntt must be 512 coeffs');
    assert(mul_hint.len() == 512, 'mul_hint must be 512 coeffs');
    assert(msg_point.len() == 512, 'msg_point must be 512 coeffs');

    let s1 = felts_to_u16(s1);
    let h_ntt = felts_to_u16(h_ntt);
    let mul_hint = felts_to_u16(mul_hint);
    verify_512_with_hint_u16(s1.span(), h_ntt.span(), mul_hint.span(), msg_point)
}

/// Verify the hint equation over canonical `u16` coefficients.
pub(crate) fn verify_512_with_hint_u16(
    s1: Span<u16>, h_ntt: Span<u16>, mul_hint: Span<u16>, msg_point: Span<u16>,
) -> bool {
    assert(s1.len() == 512, 's1 must be 512 coeffs');
    assert(h_ntt.len() == 512, 'h_ntt must be 512 coeffs');
    assert(mul_hint.len() == 512, 'mul_hint must be 512 coeffs');
    assert(msg_point.len() == 512, 'msg_point must be 512 coeffs');

    // Both spans came from canonical base-Q unpacking (or the public wrapper's documented
    // canonical-coefficient precondition), so the generated unchecked NTT is sound here.
    let s1_ntt = ntt_falcon512_fast_u16_unchecked(s1);
    let hint_ntt = ntt_falcon512_fast_u16_lazy_unchecked(mul_hint);

    let mut s1_ntt_iter = s1_ntt.span();
    let mut hint_ntt_iter = hint_ntt;
    let mut h_iter = h_ntt;
    let mut msg_iter = msg_point;
    let mut hint_iter = mul_hint;
    let mut s1_iter = s1;

    // Fused pass, 16-way unrolled (512 = 16 * 32, no remainder): hint check and
    // centered-norm accumulation per coefficient.
    // Max acc = 512 * 2 * 6144^2 < 2^36, so the felt252 accumulator cannot wrap
    // and always fits u64.
    let qb = q_cell();
    let mut acc: felt252 = 0;
    let mut ok = true;
    while let Some(s1n_c) = s1_ntt_iter.multi_pop_front::<16>() {
        let [
            s1n0,
            s1n1,
            s1n2,
            s1n3,
            s1n4,
            s1n5,
            s1n6,
            s1n7,
            s1n8,
            s1n9,
            s1n10,
            s1n11,
            s1n12,
            s1n13,
            s1n14,
            s1n15,
        ] =
            (*s1n_c)
            .unbox();
        let [hn0, hn1, hn2, hn3, hn4, hn5, hn6, hn7, hn8, hn9, hn10, hn11, hn12, hn13, hn14, hn15] =
            (*hint_ntt_iter
            .multi_pop_front::<16>()
            .unwrap())
            .unbox();
        let [h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15] = (*h_iter
            .multi_pop_front::<16>()
            .unwrap())
            .unbox();
        // s1n*h + q - hn has zero remainder iff the two NTT coordinates agree mod q,
        // which by bijectivity binds mul_hint to s1*h.
        let r0 = lazy_product_difference_rem(s1n0, h0, hn0, qb);
        let r1 = lazy_product_difference_rem(s1n1, h1, hn1, qb);
        let r2 = lazy_product_difference_rem(s1n2, h2, hn2, qb);
        let r3 = lazy_product_difference_rem(s1n3, h3, hn3, qb);
        let r4 = lazy_product_difference_rem(s1n4, h4, hn4, qb);
        let r5 = lazy_product_difference_rem(s1n5, h5, hn5, qb);
        let r6 = lazy_product_difference_rem(s1n6, h6, hn6, qb);
        let r7 = lazy_product_difference_rem(s1n7, h7, hn7, qb);
        let r8 = lazy_product_difference_rem(s1n8, h8, hn8, qb);
        let r9 = lazy_product_difference_rem(s1n9, h9, hn9, qb);
        let r10 = lazy_product_difference_rem(s1n10, h10, hn10, qb);
        let r11 = lazy_product_difference_rem(s1n11, h11, hn11, qb);
        let r12 = lazy_product_difference_rem(s1n12, h12, hn12, qb);
        let r13 = lazy_product_difference_rem(s1n13, h13, hn13, qb);
        let r14 = lazy_product_difference_rem(s1n14, h14, hn14, qb);
        let r15 = lazy_product_difference_rem(s1n15, h15, hn15, qb);
        // Remainders are non-negative, so the sum is zero iff all sixteen are.
        if r0
            + r1
            + r2
            + r3
            + r4
            + r5
            + r6
            + r7
            + r8
            + r9
            + r10
            + r11
            + r12
            + r13
            + r14
            + r15 != 0 {
            ok = false;
            break;
        }
        let [m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15] = (*msg_iter
            .multi_pop_front::<16>()
            .unwrap())
            .unbox();
        let [t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15] = (*hint_iter
            .multi_pop_front::<16>()
            .unwrap())
            .unbox();
        let [v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15] = (*s1_iter
            .multi_pop_front::<16>()
            .unwrap())
            .unbox();
        acc += centered_difference_sq_b(m0, t0, qb) + center_sq_b(v0, qb);
        acc += centered_difference_sq_b(m1, t1, qb) + center_sq_b(v1, qb);
        acc += centered_difference_sq_b(m2, t2, qb) + center_sq_b(v2, qb);
        acc += centered_difference_sq_b(m3, t3, qb) + center_sq_b(v3, qb);
        acc += centered_difference_sq_b(m4, t4, qb) + center_sq_b(v4, qb);
        acc += centered_difference_sq_b(m5, t5, qb) + center_sq_b(v5, qb);
        acc += centered_difference_sq_b(m6, t6, qb) + center_sq_b(v6, qb);
        acc += centered_difference_sq_b(m7, t7, qb) + center_sq_b(v7, qb);
        acc += centered_difference_sq_b(m8, t8, qb) + center_sq_b(v8, qb);
        acc += centered_difference_sq_b(m9, t9, qb) + center_sq_b(v9, qb);
        acc += centered_difference_sq_b(m10, t10, qb) + center_sq_b(v10, qb);
        acc += centered_difference_sq_b(m11, t11, qb) + center_sq_b(v11, qb);
        acc += centered_difference_sq_b(m12, t12, qb) + center_sq_b(v12, qb);
        acc += centered_difference_sq_b(m13, t13, qb) + center_sq_b(v13, qb);
        acc += centered_difference_sq_b(m14, t14, qb) + center_sq_b(v14, qb);
        acc += centered_difference_sq_b(m15, t15, qb) + center_sq_b(v15, qb);
    }
    if !ok {
        return false;
    }
    let norm: u64 = acc.try_into().unwrap();
    norm <= SIG_BOUND_512
}

/// [`verify_512_with_hint_u16`] with the public key's coefficients as bounded integers
/// below q, which lets the check take both transforms unreduced.
pub(crate) fn verify_512_with_hint_zq(
    s1: Span<u16>, norm: felt252, h_ntt: Span<RemQ>, mul_hint: Span<u16>, msg_point: Span<u16>,
) -> bool {
    assert(s1.len() == 512, 's1 must be 512 coeffs');
    assert(h_ntt.len() == 512, 'h_ntt must be 512 coeffs');
    assert(mul_hint.len() == 512, 'mul_hint must be 512 coeffs');
    assert(msg_point.len() == 512, 'msg_point must be 512 coeffs');

    // Both spans came from canonical base-Q unpacking (or the public wrapper's documented
    // canonical-coefficient precondition), so the generated unchecked NTT is sound here.
    let s1_ntt = ntt_falcon512_fast_u16_lazy_unchecked(s1);
    let hint_ntt = ntt_falcon512_fast_u16_lazy_unchecked(mul_hint);

    let mut s1_ntt_iter = s1_ntt;
    let mut hint_ntt_iter = hint_ntt;
    let mut h_iter = h_ntt;

    // Hint check, 16-way unrolled (512 = 16 * 32, no remainder). Both norm terms were
    // summed while unpacking s1 and the mul hint: at most 512 * 2 * 6144^2 < 2^36, so the
    // felt252 sum cannot wrap and always fits u64.
    let hk = hint_consts();
    let acc: felt252 = norm;
    let mut ok = true;
    while let Some(s1n_c) = s1_ntt_iter.multi_pop_front::<16>() {
        let [
            s1n0,
            s1n1,
            s1n2,
            s1n3,
            s1n4,
            s1n5,
            s1n6,
            s1n7,
            s1n8,
            s1n9,
            s1n10,
            s1n11,
            s1n12,
            s1n13,
            s1n14,
            s1n15,
        ] =
            (*s1n_c)
            .unbox();
        let [hn0, hn1, hn2, hn3, hn4, hn5, hn6, hn7, hn8, hn9, hn10, hn11, hn12, hn13, hn14, hn15] =
            (*hint_ntt_iter
            .multi_pop_front::<16>()
            .unwrap())
            .unbox();
        let [h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15] = (*h_iter
            .multi_pop_front::<16>()
            .unwrap())
            .unbox();
        // s1n*h + q - hn has zero remainder iff the two NTT coordinates agree mod q,
        // which by bijectivity binds mul_hint to s1*h.
        // q divides each s1n*h - hn exactly when the two NTT coordinates agree mod q,
        // which by bijectivity binds mul_hint to s1*h.
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient(s1n0, h0, hn0, hk)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient(s1n1, h1, hn1, hk)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient(s1n2, h2, hn2, hk)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient(s1n3, h3, hn3, hk)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient(s1n4, h4, hn4, hk)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient(s1n5, h5, hn5, hk)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient(s1n6, h6, hn6, hk)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient(s1n7, h7, hn7, hk)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient(s1n8, h8, hn8, hk)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient(s1n9, h9, hn9, hk)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient(s1n10, h10, hn10, hk)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient(s1n11, h11, hn11, hk)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient(s1n12, h12, hn12, hk)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient(s1n13, h13, hn13, hk)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient(s1n14, h14, hn14, hk)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient(s1n15, h15, hn15, hk)) {
            return false;
        }
    }
    if !ok {
        return false;
    }
    let norm: u64 = acc.try_into().unwrap();
    norm <= SIG_BOUND_512
}

/// The hint check of [`verify_512_with_hint_zq`] fused with unpacking the public key: both
/// transforms are taken unreduced, and each coefficient of `h` is checked against them as
/// soon as it is unpacked, so `h` is never stored. False if the key is not canonical or any
/// coordinate fails. `hint_ntt` is the hint transform minus K (`HINT_NTT_OFFSET`).
pub(crate) fn check_hint_zq(
    s1_ntt: (Span<[LazyCoeff; 72]>, Box<[LazyCoeff; 8]>), hint_ntt: (Span<[LazyCoeff; 72]>, Box<[LazyCoeff; 8]>), public_key: Span<felt252>,
) -> bool {
    crate::packing::unpack_512_zq_check(public_key, s1_ntt, hint_ntt)
}

/// The check's offset K, subtracted from the hint transform (see `hint_quotient_pre`).
pub(crate) const HINT_NTT_OFFSET: felt252 = LAZY_HINT_OFFSET;

/// Verify without a hint (direct variant): compute `s1 * h` on-chain as
/// `INTT(NTT(s1) ∘ h_ntt)` — 1 NTT + 1 INTT because the public key is already stored in
/// the NTT domain — then accept iff `||msg_point - s1*h||^2 + ||s1||^2 <= SIG_BOUND_512`.
/// Same trust surface as the textbook equation (no signer-supplied hint), 29 fewer
/// signature felts than [`verify_512_with_hint`], at the cost of the INTT.
pub fn verify_512_direct(s1: Span<felt252>, h_ntt: Span<felt252>, msg_point: Span<u16>) -> bool {
    assert(s1.len() == 512, 's1 must be 512 coeffs');
    assert(h_ntt.len() == 512, 'h_ntt must be 512 coeffs');
    assert(msg_point.len() == 512, 'msg_point must be 512 coeffs');

    let s1 = felts_to_u16(s1);
    let h_ntt = felts_to_u16(h_ntt);
    verify_512_direct_u16(s1.span(), h_ntt.span(), msg_point)
}

/// Verify the direct equation over canonical `u16` coefficients.
pub(crate) fn verify_512_direct_u16(s1: Span<u16>, h_ntt: Span<u16>, msg_point: Span<u16>) -> bool {
    assert(s1.len() == 512, 's1 must be 512 coeffs');
    assert(h_ntt.len() == 512, 'h_ntt must be 512 coeffs');
    assert(msg_point.len() == 512, 'msg_point must be 512 coeffs');

    let cfg = config();
    // `s1` is canonical by the same verifier/wrapper precondition as the hint path.
    let s1_ntt = ntt_falcon512_fast_u16_unchecked(s1);

    // Pointwise products of two reduced inputs are below q^2. They feed the inverse
    // engine unreduced under its exact product bound.
    let mut prods: Array<felt252> = array![];
    let mut s1n_iter = s1_ntt.span();
    let mut h_iter = h_ntt;
    while let Some(s1n_c) = s1n_iter.multi_pop_front::<16>() {
        let [
            s1n0,
            s1n1,
            s1n2,
            s1n3,
            s1n4,
            s1n5,
            s1n6,
            s1n7,
            s1n8,
            s1n9,
            s1n10,
            s1n11,
            s1n12,
            s1n13,
            s1n14,
            s1n15,
        ] =
            (*s1n_c)
            .unbox();
        let [h0, h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15] = (*h_iter
            .multi_pop_front::<16>()
            .unwrap())
            .unbox();
        prods.append(product_as_felt(s1n0, h0));
        prods.append(product_as_felt(s1n1, h1));
        prods.append(product_as_felt(s1n2, h2));
        prods.append(product_as_felt(s1n3, h3));
        prods.append(product_as_felt(s1n4, h4));
        prods.append(product_as_felt(s1n5, h5));
        prods.append(product_as_felt(s1n6, h6));
        prods.append(product_as_felt(s1n7, h7));
        prods.append(product_as_felt(s1n8, h8));
        prods.append(product_as_felt(s1n9, h9));
        prods.append(product_as_felt(s1n10, h10));
        prods.append(product_as_felt(s1n11, h11));
        prods.append(product_as_felt(s1n12, h12));
        prods.append(product_as_felt(s1n13, h13));
        prods.append(product_as_felt(s1n14, h14));
        prods.append(product_as_felt(s1n15, h15));
    }
    let s1h = intt(prods.span(), PRODUCT_BITS, PRODUCT_BOUND_FELT, @cfg);

    let mut s1h_iter = s1h.span();
    let mut msg_iter = msg_point;
    let mut s1_iter = s1;
    // Norm pass, 16-way unrolled (512 = 16 * 32, no remainder).
    // Same accumulator bound argument as in `verify_512_with_hint`.
    let mut acc: felt252 = 0;
    while let Some(pc) = s1h_iter.multi_pop_front::<16>() {
        let [p0, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10, p11, p12, p13, p14, p15] = (*pc).unbox();
        let [m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15] = (*msg_iter
            .multi_pop_front::<16>()
            .unwrap())
            .unbox();
        let [v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15] = (*s1_iter
            .multi_pop_front::<16>()
            .unwrap())
            .unbox();
        // INTT outputs are reduced, so their u16 downcasts cannot fail.
        acc += centered_difference_sq(m0, p0.try_into().unwrap()) + center_sq(v0);
        acc += centered_difference_sq(m1, p1.try_into().unwrap()) + center_sq(v1);
        acc += centered_difference_sq(m2, p2.try_into().unwrap()) + center_sq(v2);
        acc += centered_difference_sq(m3, p3.try_into().unwrap()) + center_sq(v3);
        acc += centered_difference_sq(m4, p4.try_into().unwrap()) + center_sq(v4);
        acc += centered_difference_sq(m5, p5.try_into().unwrap()) + center_sq(v5);
        acc += centered_difference_sq(m6, p6.try_into().unwrap()) + center_sq(v6);
        acc += centered_difference_sq(m7, p7.try_into().unwrap()) + center_sq(v7);
        acc += centered_difference_sq(m8, p8.try_into().unwrap()) + center_sq(v8);
        acc += centered_difference_sq(m9, p9.try_into().unwrap()) + center_sq(v9);
        acc += centered_difference_sq(m10, p10.try_into().unwrap()) + center_sq(v10);
        acc += centered_difference_sq(m11, p11.try_into().unwrap()) + center_sq(v11);
        acc += centered_difference_sq(m12, p12.try_into().unwrap()) + center_sq(v12);
        acc += centered_difference_sq(m13, p13.try_into().unwrap()) + center_sq(v13);
        acc += centered_difference_sq(m14, p14.try_into().unwrap()) + center_sq(v14);
        acc += centered_difference_sq(m15, p15.try_into().unwrap()) + center_sq(v15);
    }
    let norm: u64 = acc.try_into().unwrap();
    norm <= SIG_BOUND_512
}

#[cfg(test)]
mod tests {
    use pqbench_ntt_pf_small::engine::{intt, ntt};
    use pqbench_ntt_pf_small::falcon512::{PRODUCT_BITS, PRODUCT_BOUND_FELT, config};
    use crate::zq::add_mod;
    use super::{verify_512_direct, verify_512_with_hint};

    fn to_u16(mut vals: Span<felt252>) -> Array<u16> {
        let mut out: Array<u16> = array![];
        while let Some(v) = vals.pop_front() {
            out.append((*v).try_into().unwrap());
        }
        out
    }

    /// Negacyclic product in Z_q[x]/(x^512 + 1) (test helper).
    fn mul_zq(f: Span<felt252>, g: Span<felt252>) -> Array<felt252> {
        let cfg = config();
        let f_ntt = ntt(f, @cfg);
        let g_ntt = ntt(g, @cfg);
        let mut prods: Array<felt252> = array![];
        let mut fi = f_ntt.span();
        let mut gi = g_ntt.span();
        while let Some(a) = fi.pop_front() {
            prods.append(*a * *gi.pop_front().unwrap());
        }
        intt(prods.span(), PRODUCT_BITS, PRODUCT_BOUND_FELT, @cfg)
    }

    fn pseudorandom_coeffs(seed: u64) -> Array<felt252> {
        let mut f: Array<felt252> = array![];
        let mut state: u64 = seed;
        for _ in 0_u32..512 {
            state = (state * 1664525 + 1013904223) % 0x100000000;
            f.append((state % 12289).into());
        }
        f
    }

    fn small_coeffs(seed: u64) -> Array<felt252> {
        // Centered coefficients in [-16, 16]: comfortably inside the norm bound.
        let mut f: Array<felt252> = array![];
        let mut state: u64 = seed;
        for _ in 0_u32..512 {
            state = (state * 1664525 + 1013904223) % 0x100000000;
            let centered = state % 33;
            if centered <= 16 {
                f.append(centered.into());
            } else {
                f.append((12289 - (centered - 16)).into());
            }
        }
        f
    }

    /// msg_point = s0 + prod coefficient-wise, downcast to the norm side's u16 form.
    fn add_points(s0: Span<felt252>, prod: Span<felt252>) -> Array<u16> {
        let mut out: Array<u16> = array![];
        let mut s0_iter = to_u16(s0).span();
        let mut prod_iter = to_u16(prod).span();
        while let Some(a) = s0_iter.pop_front() {
            out.append(add_mod(*a, *prod_iter.pop_front().unwrap()));
        }
        out
    }

    // Synthetic instance built from the verification equation itself: pick small s1 and
    // small s0, any h, set mul_hint = s1*h and msg_point = s0 + s1*h. A correct verifier
    // must accept it, and reject once the hint or the norm side is broken.
    #[test]
    fn test_verify_synthetic_instance() {
        let s1 = small_coeffs(1);
        let s0 = small_coeffs(2);
        let h = pseudorandom_coeffs(3);
        let h_ntt = ntt(h.span(), @config());
        let mul_hint = mul_zq(s1.span(), h.span());
        let msg_point = add_points(s0.span(), mul_hint.span());
        assert!(verify_512_with_hint(s1.span(), h_ntt.span(), mul_hint.span(), msg_point.span()));
    }

    #[test]
    fn test_verify_rejects_bad_hint() {
        let s1 = small_coeffs(1);
        let h = pseudorandom_coeffs(3);
        let h_ntt = ntt(h.span(), @config());
        let good_hint = mul_zq(s1.span(), h.span());
        // Flip one coefficient of the hint.
        let mut hint_iter = good_hint.span();
        let first: u16 = (*hint_iter.pop_front().unwrap()).try_into().unwrap();
        let mut tampered: Array<felt252> = array![((first + 1) % 12289).into()];
        while let Some(c) = hint_iter.pop_front() {
            tampered.append(*c);
        }
        // msg_point = mul_hint would give norm ||s1||^2 only — accepted if hint passed.
        let msg_point = to_u16(mul_zq(s1.span(), h.span()).span());
        assert!(!verify_512_with_hint(s1.span(), h_ntt.span(), tampered.span(), msg_point.span()));
    }

    // The direct variant must agree with the hint variant on the same instances.
    #[test]
    fn test_verify_direct_synthetic_instance() {
        let s1 = small_coeffs(1);
        let s0 = small_coeffs(2);
        let h = pseudorandom_coeffs(3);
        let h_ntt = ntt(h.span(), @config());
        let prod = mul_zq(s1.span(), h.span());
        let msg_point = add_points(s0.span(), prod.span());
        assert!(verify_512_direct(s1.span(), h_ntt.span(), msg_point.span()));
        // Perturb one msg_point coefficient far from the lattice point: norm blows up.
        let mut bad_msg: Array<u16> = array![add_mod(*msg_point.span().at(0), 6144)];
        let mut rest = msg_point.span().slice(1, 511);
        while let Some(c) = rest.pop_front() {
            bad_msg.append(*c);
        }
        assert!(!verify_512_direct(s1.span(), h_ntt.span(), bad_msg.span()));
    }

    #[test]
    fn test_verify_direct_rejects_large_norm() {
        let s1 = pseudorandom_coeffs(9);
        let h = pseudorandom_coeffs(3);
        let h_ntt = ntt(h.span(), @config());
        // msg_point = s1*h so s0 = 0; ||s1||^2 alone is far above the bound.
        let msg_point = to_u16(mul_zq(s1.span(), h.span()).span());
        assert!(!verify_512_direct(s1.span(), h_ntt.span(), msg_point.span()));
    }

    #[test]
    fn test_verify_rejects_large_norm() {
        // s1 uniformly random in [0, Q): astronomically above the centered-norm bound,
        // with a consistent hint and msg_point = s1*h (so s0 = 0).
        let s1 = pseudorandom_coeffs(9);
        let h = pseudorandom_coeffs(3);
        let h_ntt = ntt(h.span(), @config());
        let mul_hint = mul_zq(s1.span(), h.span());
        let msg_point = to_u16(mul_hint.span());
        assert!(!verify_512_with_hint(s1.span(), h_ntt.span(), mul_hint.span(), msg_point.span()));
    }
}
