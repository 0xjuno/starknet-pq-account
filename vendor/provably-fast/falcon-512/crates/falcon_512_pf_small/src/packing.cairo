//! Base-Q packing of 512 Z_q coefficients into 29 felt252 slots.
//!
//! Each full slot carries two u128 halves; each half Horner-packs 9 coefficients in base
//! Q = 12289 (Q^9 < 2^128): `half = c0 + Q*(c1 + Q*(c2 + ...))`. 28 full slots hold 18
//! coefficients each; the last slot holds the remaining 8 in its low half.
//!
//! Unpacking is validating: every extracted base-Q digit is < Q by construction, and the
//! residual quotient after the last digit must be zero (each half < Q^9, the last slot
//! < Q^8). The accepted felt vectors are therefore in bijection with coefficient vectors
//! in [0, Q)^512 — no coefficient can be smuggled in a non-canonical encoding.

use corelib_imports::bounded_int::{
    AddHelper, BoundedInt, DivRemHelper, MulHelper, UnitInt, bounded_int, bounded_int_div_rem, downcast,
    upcast,
};
#[feature("bounded-int-utils")]
use core::internal::bounded_int::{ConstrainHelper, SubHelper, constrain};
use corelib_imports::integer::{U128sFromFelt252Result, u128s_from_felt252};
use pqbench_ntt_pf_small::LazyCoeff;
use crate::falcon::hint_quotient_inv;
use crate::zq::Q;

/// Coefficients per full felt252 slot (two u128 halves of 9).
pub const VALS_PER_FELT: u32 = 18;
/// felt252 slots for 512 coefficients: 28 full slots + 1 slot with 8.
pub const PACKED_SLOTS: u32 = 29;
/// Coefficients in the last slot: 512 - 28*18.
const LAST_SLOT_VALS: u32 = 8;

const TWO_POW_128: felt252 = 0x100000000000000000000000000000000;

pub(crate) type PackingZq = BoundedInt<0, 12288>;
type PackingQ = UnitInt<12289>;
type Acc1 = BoundedInt<0, 151019520>;
type Acc2 = BoundedInt<0, 1855878893568>;
type Acc3 = BoundedInt<0, 22806895723069440>;
type Acc4 = BoundedInt<0, 280273941540800360448>;
type Acc5 = BoundedInt<0, 3444286467594895629557760>;
type Acc6 = BoundedInt<0, 42326836400273672391635324928>;
type Acc7 = BoundedInt<0, 520154492522963160020806508052480>;
type Acc8 = BoundedInt<0, 6392178558614694273495691177456939008>;

const PACKING_Q_NZ: NonZero<PackingQ> = 12289;

/// The divisor as a cell rather than an immediate: inside the unpacking loop it is a loop
/// parameter, so each division uses it in place instead of first copying the constant.
#[inline(never)]
fn packing_q_cell() -> NonZero<PackingQ> {
    PACKING_Q_NZ
}

impl PackingDivRemAcc1Impl of DivRemHelper<Acc1, PackingQ> {
    type DivT = PackingZq;
    type RemT = PackingZq;
}

impl PackingDivRemAcc2Impl of DivRemHelper<Acc2, PackingQ> {
    type DivT = Acc1;
    type RemT = PackingZq;
}

impl PackingDivRemAcc3Impl of DivRemHelper<Acc3, PackingQ> {
    type DivT = Acc2;
    type RemT = PackingZq;
}

impl PackingDivRemAcc4Impl of DivRemHelper<Acc4, PackingQ> {
    type DivT = Acc3;
    type RemT = PackingZq;
}

impl PackingDivRemAcc5Impl of DivRemHelper<Acc5, PackingQ> {
    type DivT = Acc4;
    type RemT = PackingZq;
}

impl PackingDivRemAcc6Impl of DivRemHelper<Acc6, PackingQ> {
    type DivT = Acc5;
    type RemT = PackingZq;
}

impl PackingDivRemAcc7Impl of DivRemHelper<Acc7, PackingQ> {
    type DivT = Acc6;
    type RemT = PackingZq;
}

impl PackingDivRemAcc8Impl of DivRemHelper<Acc8, PackingQ> {
    type DivT = Acc7;
    type RemT = PackingZq;
}

/// Unpack 29 packed felts into 512 coefficients in [0, Q), as felts (each is a
/// base-Q digit, so the range holds by construction).
/// Returns `None` on wrong length or any non-canonical slot encoding.
pub fn unpack_512(packed: Span<felt252>) -> Option<Array<felt252>> {
    let coeffs_u16 = match unpack_512_u16(packed) {
        Some(v) => v,
        None => { return None; },
    };
    let mut coeffs_u16 = coeffs_u16.span();
    let mut coeffs: Array<felt252> = array![];
    while let Some(coeff) = coeffs_u16.pop_front() {
        coeffs.append((*coeff).into());
    }
    Some(coeffs)
}

/// Unpack the canonical 29-slot encoding directly into the verifier's `u16` form.
/// Returns `None` on wrong length or any non-canonical slot encoding.
pub(crate) fn unpack_512_u16(packed: Span<felt252>) -> Option<Array<u16>> {
    if packed.len() != PACKED_SLOTS {
        return None;
    }
    let mut coeffs: Array<u16> = array![];
    let q = packing_q_cell();
    let mut full_slots = packed.slice(0, PACKED_SLOTS - 1);
    while let Some(chunk) = full_slots.multi_pop_front::<7>() {
        let [f0, f1, f2, f3, f4, f5, f6] = (*chunk).unbox();
        if !unpack_full_slot_u16(f0, ref coeffs, q)
            || !unpack_full_slot_u16(f1, ref coeffs, q)
            || !unpack_full_slot_u16(f2, ref coeffs, q)
            || !unpack_full_slot_u16(f3, ref coeffs, q)
            || !unpack_full_slot_u16(f4, ref coeffs, q)
            || !unpack_full_slot_u16(f5, ref coeffs, q)
            || !unpack_full_slot_u16(f6, ref coeffs, q) {
            return None;
        }
    }
    let last: u256 = (*packed.at(PACKED_SLOTS - 1)).into();
    if last.high != 0 || !unpack_half8_u16(last.low, ref coeffs, q) {
        return None;
    }
    Some(coeffs)
}

#[inline(always)]
fn unpack_full_slot_u16(felt: felt252, ref coeffs: Array<u16>, q: NonZero<PackingQ>) -> bool {
    let value: u256 = felt.into();
    unpack_half9_u16(value.low, ref coeffs, q) && unpack_half9_u16(value.high, ref coeffs, q)
}

/// Extract nine base-Q digits from a u128 half. Values below Q^9 are canonical;
/// after eight divisions the remaining quotient is the ninth digit.
#[inline(always)]
fn unpack_half9_u16(value: u128, ref coeffs: Array<u16>, q: NonZero<PackingQ>) -> bool {
    let value: Acc8 = match downcast(value) {
        Some(v) => v,
        None => { return false; },
    };
    let (rest, d0) = bounded_int_div_rem(value, q);
    let (rest, d1) = bounded_int_div_rem(rest, q);
    let (rest, d2) = bounded_int_div_rem(rest, q);
    let (rest, d3) = bounded_int_div_rem(rest, q);
    let (rest, d4) = bounded_int_div_rem(rest, q);
    let (rest, d5) = bounded_int_div_rem(rest, q);
    let (rest, d6) = bounded_int_div_rem(rest, q);
    let (rest, d7) = bounded_int_div_rem(rest, q);
    coeffs.append(upcast(d0));
    coeffs.append(upcast(d1));
    coeffs.append(upcast(d2));
    coeffs.append(upcast(d3));
    coeffs.append(upcast(d4));
    coeffs.append(upcast(d5));
    coeffs.append(upcast(d6));
    coeffs.append(upcast(d7));
    coeffs.append(upcast(rest));
    true
}

/// Extract the final slot's eight digits after checking the value is below Q^8.
#[inline(always)]
fn unpack_half8_u16(value: u128, ref coeffs: Array<u16>, q: NonZero<PackingQ>) -> bool {
    let value: Acc7 = match downcast(value) {
        Some(v) => v,
        None => { return false; },
    };
    let (rest, d0) = bounded_int_div_rem(value, q);
    let (rest, d1) = bounded_int_div_rem(rest, q);
    let (rest, d2) = bounded_int_div_rem(rest, q);
    let (rest, d3) = bounded_int_div_rem(rest, q);
    let (rest, d4) = bounded_int_div_rem(rest, q);
    let (rest, d5) = bounded_int_div_rem(rest, q);
    let (rest, d6) = bounded_int_div_rem(rest, q);
    coeffs.append(upcast(d0));
    coeffs.append(upcast(d1));
    coeffs.append(upcast(d2));
    coeffs.append(upcast(d3));
    coeffs.append(upcast(d4));
    coeffs.append(upcast(d5));
    coeffs.append(upcast(d6));
    coeffs.append(upcast(rest));
    true
}

/// Pack 512 coefficients (each < Q) into 29 felts. Inverse of [`unpack_512`];
/// used by tests and off-chain tooling mirrors. Panics on bad length or coefficient.
pub fn pack_512(coeffs: Span<u16>) -> Array<felt252> {
    assert(coeffs.len() == 512, 'pack: need 512 coeffs');
    let mut packed: Array<felt252> = array![];
    let mut slot: u32 = 0;
    while slot != PACKED_SLOTS - 1 {
        let low = pack_half(coeffs.slice(slot * VALS_PER_FELT, 9));
        let high = pack_half(coeffs.slice(slot * VALS_PER_FELT + 9, 9));
        packed.append(low.into() + high.into() * TWO_POW_128);
        slot += 1;
    }
    packed.append(pack_half(coeffs.slice(504, LAST_SLOT_VALS)).into());
    packed
}

/// Horner-encode up to 9 coefficients into a u128: c0 + Q*(c1 + Q*(c2 + ...)).
fn pack_half(coeffs: Span<u16>) -> u128 {
    let mut acc: u128 = 0;
    let mut i = coeffs.len();
    while i != 0 {
        i -= 1;
        let c = *coeffs.at(i);
        assert(c < Q, 'pack: coeff >= Q');
        acc = acc * 12289 + c.into();
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::{PACKED_SLOTS, pack_512, unpack_512, unpack_512_u16};

    /// Q^9: the smallest non-canonical low-half value (all 9 digits zero, residue 1).
    const Q_POW_9: felt252 = 6392178558614694273495691177456939009;
    /// Q^8: the smallest non-canonical last-slot value.
    const Q_POW_8: felt252 = 520154492522963160020806508052481;
    const TWO_POW_128: felt252 = 0x100000000000000000000000000000000;

    fn pseudorandom_coeffs() -> Array<u16> {
        let mut f: Array<u16> = array![];
        let mut state: u64 = 7;
        for _ in 0_u32..512 {
            state = (state * 1664525 + 1013904223) % 0x100000000;
            f.append((state % 12289).try_into().unwrap());
        }
        f
    }

    fn as_felts(mut vals: Span<u16>) -> Array<felt252> {
        let mut out: Array<felt252> = array![];
        while let Some(v) = vals.pop_front() {
            out.append((*v).into());
        }
        out
    }

    #[test]
    fn test_pack_unpack_roundtrip() {
        let coeffs = pseudorandom_coeffs();
        let packed = pack_512(coeffs.span());
        assert_eq!(packed.len(), PACKED_SLOTS);
        let unpacked = unpack_512(packed.span()).unwrap();
        assert_eq!(unpacked.span(), as_felts(coeffs.span()).span());
        assert_eq!(unpack_512_u16(packed.span()).unwrap().span(), coeffs.span());
    }

    #[test]
    fn test_unpack_all_zero_and_max() {
        let mut zeros: Array<u16> = array![];
        let mut maxed: Array<u16> = array![];
        for _ in 0_u32..512 {
            zeros.append(0);
            maxed.append(12288);
        }
        let z = unpack_512(pack_512(zeros.span()).span()).unwrap();
        assert_eq!(z.span(), as_felts(zeros.span()).span());
        let m = unpack_512(pack_512(maxed.span()).span()).unwrap();
        assert_eq!(m.span(), as_felts(maxed.span()).span());
    }

    #[test]
    fn test_unpack_rejects_wrong_length() {
        let coeffs = pseudorandom_coeffs();
        let packed = pack_512(coeffs.span());
        assert!(unpack_512(packed.span().slice(0, 28)).is_none());
        assert!(unpack_512(array![].span()).is_none());
    }

    #[test]
    fn test_unpack_rejects_noncanonical_half() {
        // Q^9 in a low half: nine zero digits with a nonzero residue.
        let mut packed = pack_512(pseudorandom_coeffs().span());
        let mut tampered: Array<felt252> = array![Q_POW_9];
        let mut rest = packed.span().slice(1, 28);
        while let Some(f) = rest.pop_front() {
            tampered.append(*f);
        }
        assert!(unpack_512(tampered.span()).is_none());
        // Same overflow in a high half.
        let mut tampered2: Array<felt252> = array![Q_POW_9 * TWO_POW_128];
        let mut rest2 = packed.span().slice(1, 28);
        while let Some(f) = rest2.pop_front() {
            tampered2.append(*f);
        }
        assert!(unpack_512(tampered2.span()).is_none());
    }

    #[test]
    fn test_unpack_rejects_noncanonical_last_slot() {
        let packed = pack_512(pseudorandom_coeffs().span());
        // Non-zero high half in the last slot.
        let mut tampered: Array<felt252> = array![];
        let mut head = packed.span().slice(0, 28);
        while let Some(f) = head.pop_front() {
            tampered.append(*f);
        }
        tampered.append(TWO_POW_128);
        assert!(unpack_512(tampered.span()).is_none());
        // Q^8 in the last slot: eight zero digits with a nonzero residue.
        let mut tampered2: Array<felt252> = array![];
        let mut head2 = packed.span().slice(0, 28);
        while let Some(f) = head2.pop_front() {
            tampered2.append(*f);
        }
        tampered2.append(Q_POW_8);
        assert!(unpack_512(tampered2.span()).is_none());
    }
}

/// Unpack the canonical 29-slot encoding directly into the verifier's `u16` form.
/// Returns `None` on wrong length or any non-canonical slot encoding.
/// [`unpack_512_u16`] keeping the digits as bounded integers below q.
pub(crate) fn unpack_512_zq(packed: Span<felt252>) -> Option<Array<PackingZq>> {
    if packed.len() != PACKED_SLOTS {
        return None;
    }
    let mut coeffs: Array<PackingZq> = array![];
    let q = packing_q_cell();
    let mut full_slots = packed.slice(0, PACKED_SLOTS - 1);
    while let Some(chunk) = full_slots.multi_pop_front::<7>() {
        let [f0, f1, f2, f3, f4, f5, f6] = (*chunk).unbox();
        if !unpack_full_slot_zq(f0, ref coeffs, q)
            || !unpack_full_slot_zq(f1, ref coeffs, q)
            || !unpack_full_slot_zq(f2, ref coeffs, q)
            || !unpack_full_slot_zq(f3, ref coeffs, q)
            || !unpack_full_slot_zq(f4, ref coeffs, q)
            || !unpack_full_slot_zq(f5, ref coeffs, q)
            || !unpack_full_slot_zq(f6, ref coeffs, q) {
            return None;
        }
    }
    let last: u256 = (*packed.at(PACKED_SLOTS - 1)).into();
    if last.high != 0 || !unpack_half8_zq(last.low, ref coeffs, q) {
        return None;
    }
    Some(coeffs)
}

#[inline(always)]
fn unpack_full_slot_zq(felt: felt252, ref coeffs: Array<PackingZq>, q: NonZero<PackingQ>) -> bool {
    let value: u256 = felt.into();
    unpack_half9_zq(value.low, ref coeffs, q) && unpack_half9_zq(value.high, ref coeffs, q)
}

/// Extract nine base-Q digits from a u128 half. Values below Q^9 are canonical;
/// after eight divisions the remaining quotient is the ninth digit.
#[inline(always)]
fn unpack_half9_zq(value: u128, ref coeffs: Array<PackingZq>, q: NonZero<PackingQ>) -> bool {
    let value: Acc8 = match downcast(value) {
        Some(v) => v,
        None => { return false; },
    };
    let (rest, d0) = bounded_int_div_rem(value, q);
    let (rest, d1) = bounded_int_div_rem(rest, q);
    let (rest, d2) = bounded_int_div_rem(rest, q);
    let (rest, d3) = bounded_int_div_rem(rest, q);
    let (rest, d4) = bounded_int_div_rem(rest, q);
    let (rest, d5) = bounded_int_div_rem(rest, q);
    let (rest, d6) = bounded_int_div_rem(rest, q);
    let (rest, d7) = bounded_int_div_rem(rest, q);
    coeffs.append(d0);
    coeffs.append(d1);
    coeffs.append(d2);
    coeffs.append(d3);
    coeffs.append(d4);
    coeffs.append(d5);
    coeffs.append(d6);
    coeffs.append(d7);
    coeffs.append(rest);
    true
}

/// Extract the final slot's eight digits after checking the value is below Q^8.
#[inline(always)]
fn unpack_half8_zq(value: u128, ref coeffs: Array<PackingZq>, q: NonZero<PackingQ>) -> bool {
    let value: Acc7 = match downcast(value) {
        Some(v) => v,
        None => { return false; },
    };
    let (rest, d0) = bounded_int_div_rem(value, q);
    let (rest, d1) = bounded_int_div_rem(rest, q);
    let (rest, d2) = bounded_int_div_rem(rest, q);
    let (rest, d3) = bounded_int_div_rem(rest, q);
    let (rest, d4) = bounded_int_div_rem(rest, q);
    let (rest, d5) = bounded_int_div_rem(rest, q);
    let (rest, d6) = bounded_int_div_rem(rest, q);
    coeffs.append(d0);
    coeffs.append(d1);
    coeffs.append(d2);
    coeffs.append(d3);
    coeffs.append(d4);
    coeffs.append(d5);
    coeffs.append(d6);
    coeffs.append(rest);
    true
}

type CenterShiftZq = BoundedInt<6144, 18432>;
type CenteredZq = BoundedInt<-6144, 6144>;
impl AddZqHalf of AddHelper<PackingZq, UnitInt<6144>> {
    type Result = CenterShiftZq;
}
impl DivRemCenterShiftZq of DivRemHelper<CenterShiftZq, PackingQ> {
    type DivT = BoundedInt<0, 1>;
    type RemT = PackingZq;
}
impl SubZqHalf of SubHelper<PackingZq, UnitInt<6144>> {
    type Result = CenteredZq;
}
impl MulCenteredZq of MulHelper<CenteredZq, CenteredZq> {
    type Result = BoundedInt<-37748736, 37748736>;
}

/// The centered square of a digit: `(d + 6144) mod q - 6144` lies in [-6144, 6144] and is
/// congruent to `d`.
impl ConstrainZqHalf of ConstrainHelper<PackingZq, 6145> {
    type LowT = BoundedInt<0, 6144>;
    type HighT = BoundedInt<6145, 12288>;
}

#[inline(always)]
fn center_sq_zq(d: PackingZq, q: NonZero<PackingQ>) -> felt252 {
    // One range check: d <= 6144 is its own centered value, otherwise d - q is.
    let x: felt252 = match constrain::<PackingZq, 6145>(d) {
        Ok(low) => low.into(),
        Err(high) => high.into() - 12289,
    };
    x * x
}

type DiffShiftZq = BoundedInt<6145, 83968>;
impl AddU16DiffOffset of AddHelper<u16, UnitInt<18433>> {
    type Result = BoundedInt<18433, 83968>;
}
impl SubDiffZq of SubHelper<BoundedInt<18433, 83968>, PackingZq> {
    type Result = DiffShiftZq;
}
impl DivRemDiffShiftZq of DivRemHelper<DiffShiftZq, PackingQ> {
    type DivT = BoundedInt<0, 6>;
    type RemT = PackingZq;
}

/// The centered square of `m - t` mod q: `(m + 6144 + q - t) mod q - 6144` lies in
/// [-6144, 6144] and is congruent to `m - t`.
#[inline(always)]
fn center_diff_sq_zq(m: u16, t: PackingZq, q: NonZero<PackingQ>) -> felt252 {
    let offset: UnitInt<18433> = 18433;
    let half: UnitInt<6144> = 6144;
    let (_, r) = bounded_int_div_rem(bounded_int::sub(bounded_int::add(m, offset), t), q);
    let c = bounded_int::sub(r, half);
    bounded_int::mul(c, c).into()
}

/// Q57: two digits centred by one constrain tree (4 leaves) and merged once, so the
/// range-check pointer store and the branch jump are paid per pair, not per digit. Same
/// centered values as two `center_sq_zq` calls.
#[inline(always)]
fn center_pair_zq(a: PackingZq, b: PackingZq) -> (felt252, felt252) {
    match constrain::<PackingZq, 6145>(a) {
        Ok(la) => match constrain::<PackingZq, 6145>(b) {
            Ok(lb) => (la.into(), lb.into()),
            Err(hb) => (la.into(), hb.into() - 12289),
        },
        Err(ha) => match constrain::<PackingZq, 6145>(b) {
            Ok(lb) => (ha.into() - 12289, lb.into()),
            Err(hb) => (ha.into() - 12289, hb.into() - 12289),
        },
    }
}

// Q21 BEGIN (generated by data/artifacts/q21/gen_q21.py)
/// The nine (eight) digits of a half already known to be below q^9 (q^8), returned as
/// felts for the transform, with their centered squares (`_n`) or the centered squares
/// of `m - t` (`_d`) added to `norm`; no failure path.
#[inline(always)]
fn digits9_n(value: Acc8, ref norm: felt252, q: NonZero<PackingQ>) -> (felt252, felt252, felt252, felt252, felt252, felt252, felt252, felt252, felt252) {
    let (rest, d0) = bounded_int_div_rem(value, q);
    let (rest, d1) = bounded_int_div_rem(rest, q);
    let (rest, d2) = bounded_int_div_rem(rest, q);
    let (rest, d3) = bounded_int_div_rem(rest, q);
    let (rest, d4) = bounded_int_div_rem(rest, q);
    let (rest, d5) = bounded_int_div_rem(rest, q);
    let (rest, d6) = bounded_int_div_rem(rest, q);
    let (rest, d7) = bounded_int_div_rem(rest, q);
    norm += center_sq_zq(d0, q);
    norm += center_sq_zq(d1, q);
    norm += center_sq_zq(d2, q);
    norm += center_sq_zq(d3, q);
    norm += center_sq_zq(d4, q);
    norm += center_sq_zq(d5, q);
    norm += center_sq_zq(d6, q);
    norm += center_sq_zq(d7, q);
    norm += center_sq_zq(rest, q);
    (d0.into(), d1.into(), d2.into(), d3.into(), d4.into(), d5.into(), d6.into(), d7.into(), rest.into())
}

#[inline(always)]
fn digits9_np(value: Acc8, ref norm: felt252, q: NonZero<PackingQ>) -> (felt252, felt252, felt252, felt252, felt252, felt252, felt252, felt252, felt252) {
    let (rest, d0) = bounded_int_div_rem(value, q);
    let (rest, d1) = bounded_int_div_rem(rest, q);
    let (rest, d2) = bounded_int_div_rem(rest, q);
    let (rest, d3) = bounded_int_div_rem(rest, q);
    let (rest, d4) = bounded_int_div_rem(rest, q);
    let (rest, d5) = bounded_int_div_rem(rest, q);
    let (rest, d6) = bounded_int_div_rem(rest, q);
    let (rest, d7) = bounded_int_div_rem(rest, q);
    let (a, b) = center_pair_zq(d0, d1);
    norm += a * a;
    norm += b * b;
    let (a, b) = center_pair_zq(d2, d3);
    norm += a * a;
    norm += b * b;
    let (a, b) = center_pair_zq(d4, d5);
    norm += a * a;
    norm += b * b;
    let (a, b) = center_pair_zq(d6, d7);
    norm += a * a;
    norm += b * b;
    norm += center_sq_zq(rest, q);
    (d0.into(), d1.into(), d2.into(), d3.into(), d4.into(), d5.into(), d6.into(), d7.into(), rest.into())
}

#[inline(always)]
fn digits9_np8(value: Acc8, ref norm: felt252, q: NonZero<PackingQ>) -> (felt252, felt252, felt252, felt252, felt252, felt252, felt252, felt252, PackingZq) {
    let (rest, d0) = bounded_int_div_rem(value, q);
    let (rest, d1) = bounded_int_div_rem(rest, q);
    let (rest, d2) = bounded_int_div_rem(rest, q);
    let (rest, d3) = bounded_int_div_rem(rest, q);
    let (rest, d4) = bounded_int_div_rem(rest, q);
    let (rest, d5) = bounded_int_div_rem(rest, q);
    let (rest, d6) = bounded_int_div_rem(rest, q);
    let (rest, d7) = bounded_int_div_rem(rest, q);
    let (a, b) = center_pair_zq(d0, d1);
    norm += a * a;
    norm += b * b;
    let (a, b) = center_pair_zq(d2, d3);
    norm += a * a;
    norm += b * b;
    let (a, b) = center_pair_zq(d4, d5);
    norm += a * a;
    norm += b * b;
    let (a, b) = center_pair_zq(d6, d7);
    norm += a * a;
    norm += b * b;
    (d0.into(), d1.into(), d2.into(), d3.into(), d4.into(), d5.into(), d6.into(), d7.into(), rest)
}

#[inline(always)]
fn digits9_d(value: Acc8, m: [u16; 9], ref norm: felt252, q: NonZero<PackingQ>) -> (felt252, felt252, felt252, felt252, felt252, felt252, felt252, felt252, felt252) {
    let (rest, d0) = bounded_int_div_rem(value, q);
    let (rest, d1) = bounded_int_div_rem(rest, q);
    let (rest, d2) = bounded_int_div_rem(rest, q);
    let (rest, d3) = bounded_int_div_rem(rest, q);
    let (rest, d4) = bounded_int_div_rem(rest, q);
    let (rest, d5) = bounded_int_div_rem(rest, q);
    let (rest, d6) = bounded_int_div_rem(rest, q);
    let (rest, d7) = bounded_int_div_rem(rest, q);
    let [m0, m1, m2, m3, m4, m5, m6, m7, m8] = m;
    norm += center_diff_sq_zq(m0, d0, q);
    norm += center_diff_sq_zq(m1, d1, q);
    norm += center_diff_sq_zq(m2, d2, q);
    norm += center_diff_sq_zq(m3, d3, q);
    norm += center_diff_sq_zq(m4, d4, q);
    norm += center_diff_sq_zq(m5, d5, q);
    norm += center_diff_sq_zq(m6, d6, q);
    norm += center_diff_sq_zq(m7, d7, q);
    norm += center_diff_sq_zq(m8, rest, q);
    (d0.into(), d1.into(), d2.into(), d3.into(), d4.into(), d5.into(), d6.into(), d7.into(), rest.into())
}

#[inline(always)]
fn digits8_n(value: Acc7, ref norm: felt252, q: NonZero<PackingQ>) -> (felt252, felt252, felt252, felt252, felt252, felt252, felt252, felt252) {
    let (rest, d0) = bounded_int_div_rem(value, q);
    let (rest, d1) = bounded_int_div_rem(rest, q);
    let (rest, d2) = bounded_int_div_rem(rest, q);
    let (rest, d3) = bounded_int_div_rem(rest, q);
    let (rest, d4) = bounded_int_div_rem(rest, q);
    let (rest, d5) = bounded_int_div_rem(rest, q);
    let (rest, d6) = bounded_int_div_rem(rest, q);
    norm += center_sq_zq(d0, q);
    norm += center_sq_zq(d1, q);
    norm += center_sq_zq(d2, q);
    norm += center_sq_zq(d3, q);
    norm += center_sq_zq(d4, q);
    norm += center_sq_zq(d5, q);
    norm += center_sq_zq(d6, q);
    norm += center_sq_zq(rest, q);
    (d0.into(), d1.into(), d2.into(), d3.into(), d4.into(), d5.into(), d6.into(), rest.into())
}

#[inline(always)]
fn digits8_np(value: Acc7, ref norm: felt252, q: NonZero<PackingQ>) -> (felt252, felt252, felt252, felt252, felt252, felt252, felt252, felt252) {
    let (rest, d0) = bounded_int_div_rem(value, q);
    let (rest, d1) = bounded_int_div_rem(rest, q);
    let (rest, d2) = bounded_int_div_rem(rest, q);
    let (rest, d3) = bounded_int_div_rem(rest, q);
    let (rest, d4) = bounded_int_div_rem(rest, q);
    let (rest, d5) = bounded_int_div_rem(rest, q);
    let (rest, d6) = bounded_int_div_rem(rest, q);
    let (a, b) = center_pair_zq(d0, d1);
    norm += a * a;
    norm += b * b;
    let (a, b) = center_pair_zq(d2, d3);
    norm += a * a;
    norm += b * b;
    let (a, b) = center_pair_zq(d4, d5);
    norm += a * a;
    norm += b * b;
    let (a, b) = center_pair_zq(d6, rest);
    norm += a * a;
    norm += b * b;
    (d0.into(), d1.into(), d2.into(), d3.into(), d4.into(), d5.into(), d6.into(), rest.into())
}

#[inline(always)]
fn digits8_d(value: Acc7, m: [u16; 8], ref norm: felt252, q: NonZero<PackingQ>) -> (felt252, felt252, felt252, felt252, felt252, felt252, felt252, felt252) {
    let (rest, d0) = bounded_int_div_rem(value, q);
    let (rest, d1) = bounded_int_div_rem(rest, q);
    let (rest, d2) = bounded_int_div_rem(rest, q);
    let (rest, d3) = bounded_int_div_rem(rest, q);
    let (rest, d4) = bounded_int_div_rem(rest, q);
    let (rest, d5) = bounded_int_div_rem(rest, q);
    let (rest, d6) = bounded_int_div_rem(rest, q);
    let [m0, m1, m2, m3, m4, m5, m6, m7] = m;
    norm += center_diff_sq_zq(m0, d0, q);
    norm += center_diff_sq_zq(m1, d1, q);
    norm += center_diff_sq_zq(m2, d2, q);
    norm += center_diff_sq_zq(m3, d3, q);
    norm += center_diff_sq_zq(m4, d4, q);
    norm += center_diff_sq_zq(m5, d5, q);
    norm += center_diff_sq_zq(m6, d6, q);
    norm += center_diff_sq_zq(m7, rest, q);
    (d0.into(), d1.into(), d2.into(), d3.into(), d4.into(), d5.into(), d6.into(), rest.into())
}

// s1 and the mul hint get one generated copy each of the transform: a shared body needs a
// gas counter (or a 127-cell copy) at the merge of the two chunk calls, about 90K more gas.
/// Unpack s1, with the sum of its centered squares, and transform it without storing
/// the coefficients: the 512 digits come back from four out-of-line chunk calls plus the
/// last slot and feed the generated NTT body as its inputs directly. Returns the unreduced
/// transform (`LazyCoeff`).
/// `None` on wrong length or any non-canonical slot encoding: every digit is extracted
/// and range-checked exactly as by the q15 unpackers, so the accepted encodings are
/// unchanged.
#[inline(never)]
pub(crate) fn unpack_ntt_512_n(packed: @Box<[felt252; 29]>) -> Option<((Span<[LazyCoeff; 72]>, Box<[LazyCoeff; 8]>), felt252)> {
    // Q51: the caller pops the 29 slots off the signature; the chunks take their felts by value.
    let q = packing_q_cell();
    let mut norm: felt252 = 0;
    let [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15, s16, s17, s18, s19, s20, s21, s22, s23, s24, s25, s26, s27, s28] = (*packed).unbox();
    let [g0, g1, g2, g3, g4, g5, g6, g7, g8, g9, g10, g11, g12, g13, g14, g15, g16, g17, g18, g19, g20, g21, g22, g23, g24, g25, g26, g27, g28, g29, g30, g31, g32, g33, g34, g35, g36, g37, g38, g39, g40, g41, g42, g43, g44, g45, g46, g47, g48, g49, g50, g51, g52, g53, g54, g55, g56, g57, g58, g59, g60, g61, g62, g63, g64, g65, g66, g67, g68, g69, g70, g71] = match unpack_chunk_ntt_n4(s0, s1, s2, s3, ref norm, q) {
        Some(v) => v,
        None => { return None; },
    };
    let [g72, g73, g74, g75, g76, g77, g78, g79, g80, g81, g82, g83, g84, g85, g86, g87, g88, g89, g90, g91, g92, g93, g94, g95, g96, g97, g98, g99, g100, g101, g102, g103, g104, g105, g106, g107, g108, g109, g110, g111, g112, g113, g114, g115, g116, g117, g118, g119, g120, g121, g122, g123, g124, g125, g126, g127, g128, g129, g130, g131, g132, g133, g134, g135, g136, g137, g138, g139, g140, g141, g142, g143] = match unpack_chunk_ntt_n4(s4, s5, s6, s7, ref norm, q) {
        Some(v) => v,
        None => { return None; },
    };
    let [g144, g145, g146, g147, g148, g149, g150, g151, g152, g153, g154, g155, g156, g157, g158, g159, g160, g161, g162, g163, g164, g165, g166, g167, g168, g169, g170, g171, g172, g173, g174, g175, g176, g177, g178, g179, g180, g181, g182, g183, g184, g185, g186, g187, g188, g189, g190, g191, g192, g193, g194, g195, g196, g197, g198, g199, g200, g201, g202, g203, g204, g205, g206, g207, g208, g209, g210, g211, g212, g213, g214, g215] = match unpack_chunk_ntt_n4(s8, s9, s10, s11, ref norm, q) {
        Some(v) => v,
        None => { return None; },
    };
    let [g216, g217, g218, g219, g220, g221, g222, g223, g224, g225, g226, g227, g228, g229, g230, g231, g232, g233, g234, g235, g236, g237, g238, g239, g240, g241, g242, g243, g244, g245, g246, g247, g248, g249, g250, g251, g252, g253, g254, g255, g256, g257, g258, g259, g260, g261, g262, g263, g264, g265, g266, g267, g268, g269, g270, g271, g272, g273, g274, g275, g276, g277, g278, g279, g280, g281, g282, g283, g284, g285, g286, g287] = match unpack_chunk_ntt_n4(s12, s13, s14, s15, ref norm, q) {
        Some(v) => v,
        None => { return None; },
    };
    let [g288, g289, g290, g291, g292, g293, g294, g295, g296, g297, g298, g299, g300, g301, g302, g303, g304, g305, g306, g307, g308, g309, g310, g311, g312, g313, g314, g315, g316, g317, g318, g319, g320, g321, g322, g323, g324, g325, g326, g327, g328, g329, g330, g331, g332, g333, g334, g335, g336, g337, g338, g339, g340, g341, g342, g343, g344, g345, g346, g347, g348, g349, g350, g351, g352, g353, g354, g355, g356, g357, g358, g359] = match unpack_chunk_ntt_n4(s16, s17, s18, s19, ref norm, q) {
        Some(v) => v,
        None => { return None; },
    };
    let [g360, g361, g362, g363, g364, g365, g366, g367, g368, g369, g370, g371, g372, g373, g374, g375, g376, g377, g378, g379, g380, g381, g382, g383, g384, g385, g386, g387, g388, g389, g390, g391, g392, g393, g394, g395, g396, g397, g398, g399, g400, g401, g402, g403, g404, g405, g406, g407, g408, g409, g410, g411, g412, g413, g414, g415, g416, g417, g418, g419, g420, g421, g422, g423, g424, g425, g426, g427, g428, g429, g430, g431] = match unpack_chunk_ntt_n4(s20, s21, s22, s23, ref norm, q) {
        Some(v) => v,
        None => { return None; },
    };
    let [g432, g433, g434, g435, g436, g437, g438, g439, g440, g441, g442, g443, g444, g445, g446, g447, g448, g449, g450, g451, g452, g453, g454, g455, g456, g457, g458, g459, g460, g461, g462, g463, g464, g465, g466, g467, g468, g469, g470, g471, g472, g473, g474, g475, g476, g477, g478, g479, g480, g481, g482, g483, g484, g485, g486, g487, g488, g489, g490, g491, g492, g493, g494, g495, g496, g497, g498, g499, g500, g501, g502, g503] = match unpack_chunk_ntt_n4_inl(s24, s25, s26, s27, ref norm, q) {
        Some(v) => v,
        None => { return None; },
    };
    // Q51: the last slot must split Narrow (high half 0); no u256 merge, no zero test.
    let low = match u128s_from_felt252(s28) {
        U128sFromFelt252Result::Narrow(x) => x,
        U128sFromFelt252Result::Wide(_) => { return None; },
    };
    let value: Acc7 = match downcast(low) {
        Some(v) => v,
        None => { return None; },
    };
    let (e0, e1, e2, e3, e4, e5, e6, e7) = digits8_np(value, ref norm, q);
    let out = pqbench_ntt_pf_small::ntt_falcon512_fast_lazy_regs(
        [g0, g1, g2, g3, g4, g5, g6, g7, g8, g9, g10, g11, g12, g13, g14, g15, g16, g17, g18, g19, g20, g21, g22, g23, g24, g25, g26, g27, g28, g29, g30, g31, g32, g33, g34, g35, g36, g37, g38, g39, g40, g41, g42, g43, g44, g45, g46, g47, g48, g49, g50, g51, g52, g53, g54, g55, g56, g57, g58, g59, g60, g61, g62, g63, g64, g65, g66, g67, g68, g69, g70, g71, g72, g73, g74, g75, g76, g77, g78, g79, g80, g81, g82, g83, g84, g85, g86, g87, g88, g89, g90, g91, g92, g93, g94, g95, g96, g97, g98, g99, g100, g101, g102, g103, g104, g105, g106, g107, g108, g109, g110, g111, g112, g113, g114, g115, g116, g117, g118, g119, g120, g121, g122, g123, g124, g125, g126, g127, g128, g129, g130, g131, g132, g133, g134, g135, g136, g137, g138, g139, g140, g141, g142, g143, g144, g145, g146, g147, g148, g149, g150, g151, g152, g153, g154, g155, g156, g157, g158, g159, g160, g161, g162, g163, g164, g165, g166, g167, g168, g169, g170, g171, g172, g173, g174, g175, g176, g177, g178, g179, g180, g181, g182, g183, g184, g185, g186, g187, g188, g189, g190, g191, g192, g193, g194, g195, g196, g197, g198, g199, g200, g201, g202, g203, g204, g205, g206, g207, g208, g209, g210, g211, g212, g213, g214, g215, g216, g217, g218, g219, g220, g221, g222, g223, g224, g225, g226, g227, g228, g229, g230, g231, g232, g233, g234, g235, g236, g237, g238, g239, g240, g241, g242, g243, g244, g245, g246, g247, g248, g249, g250, g251, g252, g253, g254, g255, g256, g257, g258, g259, g260, g261, g262, g263, g264, g265, g266, g267, g268, g269, g270, g271, g272, g273, g274, g275, g276, g277, g278, g279, g280, g281, g282, g283, g284, g285, g286, g287, g288, g289, g290, g291, g292, g293, g294, g295, g296, g297, g298, g299, g300, g301, g302, g303, g304, g305, g306, g307, g308, g309, g310, g311, g312, g313, g314, g315, g316, g317, g318, g319, g320, g321, g322, g323, g324, g325, g326, g327, g328, g329, g330, g331, g332, g333, g334, g335, g336, g337, g338, g339, g340, g341, g342, g343, g344, g345, g346, g347, g348, g349, g350, g351, g352, g353, g354, g355, g356, g357, g358, g359, g360, g361, g362, g363, g364, g365, g366, g367, g368, g369, g370, g371, g372, g373, g374, g375, g376, g377, g378, g379, g380, g381, g382, g383, g384, g385, g386, g387, g388, g389, g390, g391, g392, g393, g394, g395, g396, g397, g398, g399, g400, g401, g402, g403, g404, g405, g406, g407, g408, g409, g410, g411, g412, g413, g414, g415, g416, g417, g418, g419, g420, g421, g422, g423, g424, g425, g426, g427, g428, g429, g430, g431, g432, g433, g434, g435, g436, g437, g438, g439, g440, g441, g442, g443, g444, g445, g446, g447, g448, g449, g450, g451, g452, g453, g454, g455, g456, g457, g458, g459, g460, g461, g462, g463, g464, g465, g466, g467, g468, g469, g470, g471, g472, g473, g474, g475, g476, g477, g478, g479, g480, g481, g482, g483, g484, g485, g486, g487, g488, g489, g490, g491, g492, g493, g494, g495, g496, g497, g498, g499, g500, g501, g502, g503, e0, e1, e2, e3, e4, e5, e6, e7],
        0,
    );
    Some((out, norm))
}

#[inline(never)]
fn unpack_chunk_ntt_d4(
    f0: felt252, f1: felt252, f2: felt252, f3: felt252, ref msg: Span<u16>, ref norm: felt252, q: NonZero<PackingQ>,
) -> Option<[felt252; 72]> {
    let [m0, m1, m2, m3, m4, m5, m6, m7, m8, m9, m10, m11, m12, m13, m14, m15, m16, m17, m18, m19, m20, m21, m22, m23, m24, m25, m26, m27, m28, m29, m30, m31, m32, m33, m34, m35, m36, m37, m38, m39, m40, m41, m42, m43, m44, m45, m46, m47, m48, m49, m50, m51, m52, m53, m54, m55, m56, m57, m58, m59, m60, m61, m62, m63, m64, m65, m66, m67, m68, m69, m70, m71] = match msg.multi_pop_front::<72>() {
        Some(b) => (*b).unbox(),
        None => { return None; },
    };
    let (high, low) = match u128s_from_felt252(f0) {
        U128sFromFelt252Result::Wide(x) => x,
        U128sFromFelt252Result::Narrow(x) => (0, x),
    };
    let half: Acc8 = match downcast(low) {
        Some(v) => v,
        None => { return None; },
    };
    let (x0, x1, x2, x3, x4, x5, x6, x7, x8) = digits9_d(half, [m0, m1, m2, m3, m4, m5, m6, m7, m8], ref norm, q);
    let half: Acc8 = match downcast(high) {
        Some(v) => v,
        None => { return None; },
    };
    let (x9, x10, x11, x12, x13, x14, x15, x16, x17) = digits9_d(half, [m9, m10, m11, m12, m13, m14, m15, m16, m17], ref norm, q);
    let (high, low) = match u128s_from_felt252(f1) {
        U128sFromFelt252Result::Wide(x) => x,
        U128sFromFelt252Result::Narrow(x) => (0, x),
    };
    let half: Acc8 = match downcast(low) {
        Some(v) => v,
        None => { return None; },
    };
    let (x18, x19, x20, x21, x22, x23, x24, x25, x26) = digits9_d(half, [m18, m19, m20, m21, m22, m23, m24, m25, m26], ref norm, q);
    let half: Acc8 = match downcast(high) {
        Some(v) => v,
        None => { return None; },
    };
    let (x27, x28, x29, x30, x31, x32, x33, x34, x35) = digits9_d(half, [m27, m28, m29, m30, m31, m32, m33, m34, m35], ref norm, q);
    let (high, low) = match u128s_from_felt252(f2) {
        U128sFromFelt252Result::Wide(x) => x,
        U128sFromFelt252Result::Narrow(x) => (0, x),
    };
    let half: Acc8 = match downcast(low) {
        Some(v) => v,
        None => { return None; },
    };
    let (x36, x37, x38, x39, x40, x41, x42, x43, x44) = digits9_d(half, [m36, m37, m38, m39, m40, m41, m42, m43, m44], ref norm, q);
    let half: Acc8 = match downcast(high) {
        Some(v) => v,
        None => { return None; },
    };
    let (x45, x46, x47, x48, x49, x50, x51, x52, x53) = digits9_d(half, [m45, m46, m47, m48, m49, m50, m51, m52, m53], ref norm, q);
    let (high, low) = match u128s_from_felt252(f3) {
        U128sFromFelt252Result::Wide(x) => x,
        U128sFromFelt252Result::Narrow(x) => (0, x),
    };
    let half: Acc8 = match downcast(low) {
        Some(v) => v,
        None => { return None; },
    };
    let (x54, x55, x56, x57, x58, x59, x60, x61, x62) = digits9_d(half, [m54, m55, m56, m57, m58, m59, m60, m61, m62], ref norm, q);
    let half: Acc8 = match downcast(high) {
        Some(v) => v,
        None => { return None; },
    };
    let (x63, x64, x65, x66, x67, x68, x69, x70, x71) = digits9_d(half, [m63, m64, m65, m66, m67, m68, m69, m70, m71], ref norm, q);
    Some([x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16, x17, x18, x19, x20, x21, x22, x23, x24, x25, x26, x27, x28, x29, x30, x31, x32, x33, x34, x35, x36, x37, x38, x39, x40, x41, x42, x43, x44, x45, x46, x47, x48, x49, x50, x51, x52, x53, x54, x55, x56, x57, x58, x59, x60, x61, x62, x63, x64, x65, x66, x67, x68, x69, x70, x71])
}

/// Unpack the mul hint t, with the sum of the centered squares of `msg - t` (the s2 norm), and transform it without storing
/// the coefficients: the 512 digits come back from four out-of-line chunk calls plus the
/// last slot and feed the generated NTT body as its inputs directly. Returns the unreduced
/// transform minus `offset` (see `ntt_falcon512_fast_lazy_regs`).
/// `None` on wrong length or any non-canonical slot encoding: every digit is extracted
/// and range-checked exactly as by the q15 unpackers, so the accepted encodings are
/// unchanged.
#[inline(never)]
pub(crate) fn unpack_ntt_512_d(chunk: @Box<[felt252; 29]>, mut msg: Span<u16>, offset: felt252) -> Option<((Span<[LazyCoeff; 72]>, Box<[LazyCoeff; 8]>), felt252)> {
    // Q51: the caller pops the 29 slots off the signature. Q56: all 512 message coefficients in one pop.
    let q = packing_q_cell();
    let mut norm: felt252 = 0;
    let [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, s12, s13, s14, s15, s16, s17, s18, s19, s20, s21, s22, s23, s24, s25, s26, s27, s28] = (*chunk).unbox();
    let [c0_0, c0_1, c0_2, c0_3, c0_4, c0_5, c0_6, c0_7, c0_8, c0_9, c0_10, c0_11, c0_12, c0_13, c0_14, c0_15, c0_16, c0_17, c0_18, c0_19, c0_20, c0_21, c0_22, c0_23, c0_24, c0_25, c0_26, c0_27, c0_28, c0_29, c0_30, c0_31, c0_32, c0_33, c0_34, c0_35, c0_36, c0_37, c0_38, c0_39, c0_40, c0_41, c0_42, c0_43, c0_44, c0_45, c0_46, c0_47, c0_48, c0_49, c0_50, c0_51, c0_52, c0_53, c0_54, c0_55, c0_56, c0_57, c0_58, c0_59, c0_60, c0_61, c0_62, c0_63, c0_64, c0_65, c0_66, c0_67, c0_68, c0_69, c0_70, c0_71] = match unpack_chunk_ntt_d4(s0, s1, s2, s3, ref msg, ref norm, q) {
        Some(v) => v,
        None => { return None; },
    };
    let [c0_72, c0_73, c0_74, c0_75, c0_76, c0_77, c0_78, c0_79, c0_80, c0_81, c0_82, c0_83, c0_84, c0_85, c0_86, c0_87, c0_88, c0_89, c0_90, c0_91, c0_92, c0_93, c0_94, c0_95, c0_96, c0_97, c0_98, c0_99, c0_100, c0_101, c0_102, c0_103, c0_104, c0_105, c0_106, c0_107, c0_108, c0_109, c0_110, c0_111, c0_112, c0_113, c0_114, c0_115, c0_116, c0_117, c0_118, c0_119, c0_120, c0_121, c0_122, c0_123, c0_124, c0_125, c0_126, c0_127, c0_128, c0_129, c0_130, c0_131, c0_132, c0_133, c0_134, c0_135, c0_136, c0_137, c0_138, c0_139, c0_140, c0_141, c0_142, c0_143] = match unpack_chunk_ntt_d4(s4, s5, s6, s7, ref msg, ref norm, q) {
        Some(v) => v,
        None => { return None; },
    };
    let [c0_144, c0_145, c0_146, c0_147, c0_148, c0_149, c0_150, c0_151, c0_152, c0_153, c0_154, c0_155, c0_156, c0_157, c0_158, c0_159, c0_160, c0_161, c0_162, c0_163, c0_164, c0_165, c0_166, c0_167, c0_168, c0_169, c0_170, c0_171, c0_172, c0_173, c0_174, c0_175, c0_176, c0_177, c0_178, c0_179, c0_180, c0_181, c0_182, c0_183, c0_184, c0_185, c0_186, c0_187, c0_188, c0_189, c0_190, c0_191, c0_192, c0_193, c0_194, c0_195, c0_196, c0_197, c0_198, c0_199, c0_200, c0_201, c0_202, c0_203, c0_204, c0_205, c0_206, c0_207, c0_208, c0_209, c0_210, c0_211, c0_212, c0_213, c0_214, c0_215] = match unpack_chunk_ntt_d4(s8, s9, s10, s11, ref msg, ref norm, q) {
        Some(v) => v,
        None => { return None; },
    };
    let [c0_216, c0_217, c0_218, c0_219, c0_220, c0_221, c0_222, c0_223, c0_224, c0_225, c0_226, c0_227, c0_228, c0_229, c0_230, c0_231, c0_232, c0_233, c0_234, c0_235, c0_236, c0_237, c0_238, c0_239, c0_240, c0_241, c0_242, c0_243, c0_244, c0_245, c0_246, c0_247, c0_248, c0_249, c0_250, c0_251, c0_252, c0_253, c0_254, c0_255, c0_256, c0_257, c0_258, c0_259, c0_260, c0_261, c0_262, c0_263, c0_264, c0_265, c0_266, c0_267, c0_268, c0_269, c0_270, c0_271, c0_272, c0_273, c0_274, c0_275, c0_276, c0_277, c0_278, c0_279, c0_280, c0_281, c0_282, c0_283, c0_284, c0_285, c0_286, c0_287] = match unpack_chunk_ntt_d4(s12, s13, s14, s15, ref msg, ref norm, q) {
        Some(v) => v,
        None => { return None; },
    };
    let [c0_288, c0_289, c0_290, c0_291, c0_292, c0_293, c0_294, c0_295, c0_296, c0_297, c0_298, c0_299, c0_300, c0_301, c0_302, c0_303, c0_304, c0_305, c0_306, c0_307, c0_308, c0_309, c0_310, c0_311, c0_312, c0_313, c0_314, c0_315, c0_316, c0_317, c0_318, c0_319, c0_320, c0_321, c0_322, c0_323, c0_324, c0_325, c0_326, c0_327, c0_328, c0_329, c0_330, c0_331, c0_332, c0_333, c0_334, c0_335, c0_336, c0_337, c0_338, c0_339, c0_340, c0_341, c0_342, c0_343, c0_344, c0_345, c0_346, c0_347, c0_348, c0_349, c0_350, c0_351, c0_352, c0_353, c0_354, c0_355, c0_356, c0_357, c0_358, c0_359] = match unpack_chunk_ntt_d4(s16, s17, s18, s19, ref msg, ref norm, q) {
        Some(v) => v,
        None => { return None; },
    };
    let [c0_360, c0_361, c0_362, c0_363, c0_364, c0_365, c0_366, c0_367, c0_368, c0_369, c0_370, c0_371, c0_372, c0_373, c0_374, c0_375, c0_376, c0_377, c0_378, c0_379, c0_380, c0_381, c0_382, c0_383, c0_384, c0_385, c0_386, c0_387, c0_388, c0_389, c0_390, c0_391, c0_392, c0_393, c0_394, c0_395, c0_396, c0_397, c0_398, c0_399, c0_400, c0_401, c0_402, c0_403, c0_404, c0_405, c0_406, c0_407, c0_408, c0_409, c0_410, c0_411, c0_412, c0_413, c0_414, c0_415, c0_416, c0_417, c0_418, c0_419, c0_420, c0_421, c0_422, c0_423, c0_424, c0_425, c0_426, c0_427, c0_428, c0_429, c0_430, c0_431] = match unpack_chunk_ntt_d4(s20, s21, s22, s23, ref msg, ref norm, q) {
        Some(v) => v,
        None => { return None; },
    };
    let [c0_432, c0_433, c0_434, c0_435, c0_436, c0_437, c0_438, c0_439, c0_440, c0_441, c0_442, c0_443, c0_444, c0_445, c0_446, c0_447, c0_448, c0_449, c0_450, c0_451, c0_452, c0_453, c0_454, c0_455, c0_456, c0_457, c0_458, c0_459, c0_460, c0_461, c0_462, c0_463, c0_464, c0_465, c0_466, c0_467, c0_468, c0_469, c0_470, c0_471, c0_472, c0_473, c0_474, c0_475, c0_476, c0_477, c0_478, c0_479, c0_480, c0_481, c0_482, c0_483, c0_484, c0_485, c0_486, c0_487, c0_488, c0_489, c0_490, c0_491, c0_492, c0_493, c0_494, c0_495, c0_496, c0_497, c0_498, c0_499, c0_500, c0_501, c0_502, c0_503] = match unpack_chunk_ntt_d4(s24, s25, s26, s27, ref msg, ref norm, q) {
        Some(v) => v,
        None => { return None; },
    };
    // Q51: the last slot must split Narrow (high half 0); no u256 merge, no zero test.
    let low = match u128s_from_felt252(s28) {
        U128sFromFelt252Result::Narrow(x) => x,
        U128sFromFelt252Result::Wide(_) => { return None; },
    };
    let value: Acc7 = match downcast(low) {
        Some(v) => v,
        None => { return None; },
    };
    let [m0, m1, m2, m3, m4, m5, m6, m7] = match msg.multi_pop_front::<8>() {
        Some(b) => (*b).unbox(),
        None => { return None; },
    };
    let (e0, e1, e2, e3, e4, e5, e6, e7) = digits8_d(value, [m0, m1, m2, m3, m4, m5, m6, m7], ref norm, q);
    let out = pqbench_ntt_pf_small::ntt_falcon512_fast_lazy_regs(
        [c0_0, c0_1, c0_2, c0_3, c0_4, c0_5, c0_6, c0_7, c0_8, c0_9, c0_10, c0_11, c0_12, c0_13, c0_14, c0_15, c0_16, c0_17, c0_18, c0_19, c0_20, c0_21, c0_22, c0_23, c0_24, c0_25, c0_26, c0_27, c0_28, c0_29, c0_30, c0_31, c0_32, c0_33, c0_34, c0_35, c0_36, c0_37, c0_38, c0_39, c0_40, c0_41, c0_42, c0_43, c0_44, c0_45, c0_46, c0_47, c0_48, c0_49, c0_50, c0_51, c0_52, c0_53, c0_54, c0_55, c0_56, c0_57, c0_58, c0_59, c0_60, c0_61, c0_62, c0_63, c0_64, c0_65, c0_66, c0_67, c0_68, c0_69, c0_70, c0_71, c0_72, c0_73, c0_74, c0_75, c0_76, c0_77, c0_78, c0_79, c0_80, c0_81, c0_82, c0_83, c0_84, c0_85, c0_86, c0_87, c0_88, c0_89, c0_90, c0_91, c0_92, c0_93, c0_94, c0_95, c0_96, c0_97, c0_98, c0_99, c0_100, c0_101, c0_102, c0_103, c0_104, c0_105, c0_106, c0_107, c0_108, c0_109, c0_110, c0_111, c0_112, c0_113, c0_114, c0_115, c0_116, c0_117, c0_118, c0_119, c0_120, c0_121, c0_122, c0_123, c0_124, c0_125, c0_126, c0_127, c0_128, c0_129, c0_130, c0_131, c0_132, c0_133, c0_134, c0_135, c0_136, c0_137, c0_138, c0_139, c0_140, c0_141, c0_142, c0_143, c0_144, c0_145, c0_146, c0_147, c0_148, c0_149, c0_150, c0_151, c0_152, c0_153, c0_154, c0_155, c0_156, c0_157, c0_158, c0_159, c0_160, c0_161, c0_162, c0_163, c0_164, c0_165, c0_166, c0_167, c0_168, c0_169, c0_170, c0_171, c0_172, c0_173, c0_174, c0_175, c0_176, c0_177, c0_178, c0_179, c0_180, c0_181, c0_182, c0_183, c0_184, c0_185, c0_186, c0_187, c0_188, c0_189, c0_190, c0_191, c0_192, c0_193, c0_194, c0_195, c0_196, c0_197, c0_198, c0_199, c0_200, c0_201, c0_202, c0_203, c0_204, c0_205, c0_206, c0_207, c0_208, c0_209, c0_210, c0_211, c0_212, c0_213, c0_214, c0_215, c0_216, c0_217, c0_218, c0_219, c0_220, c0_221, c0_222, c0_223, c0_224, c0_225, c0_226, c0_227, c0_228, c0_229, c0_230, c0_231, c0_232, c0_233, c0_234, c0_235, c0_236, c0_237, c0_238, c0_239, c0_240, c0_241, c0_242, c0_243, c0_244, c0_245, c0_246, c0_247, c0_248, c0_249, c0_250, c0_251, c0_252, c0_253, c0_254, c0_255, c0_256, c0_257, c0_258, c0_259, c0_260, c0_261, c0_262, c0_263, c0_264, c0_265, c0_266, c0_267, c0_268, c0_269, c0_270, c0_271, c0_272, c0_273, c0_274, c0_275, c0_276, c0_277, c0_278, c0_279, c0_280, c0_281, c0_282, c0_283, c0_284, c0_285, c0_286, c0_287, c0_288, c0_289, c0_290, c0_291, c0_292, c0_293, c0_294, c0_295, c0_296, c0_297, c0_298, c0_299, c0_300, c0_301, c0_302, c0_303, c0_304, c0_305, c0_306, c0_307, c0_308, c0_309, c0_310, c0_311, c0_312, c0_313, c0_314, c0_315, c0_316, c0_317, c0_318, c0_319, c0_320, c0_321, c0_322, c0_323, c0_324, c0_325, c0_326, c0_327, c0_328, c0_329, c0_330, c0_331, c0_332, c0_333, c0_334, c0_335, c0_336, c0_337, c0_338, c0_339, c0_340, c0_341, c0_342, c0_343, c0_344, c0_345, c0_346, c0_347, c0_348, c0_349, c0_350, c0_351, c0_352, c0_353, c0_354, c0_355, c0_356, c0_357, c0_358, c0_359, c0_360, c0_361, c0_362, c0_363, c0_364, c0_365, c0_366, c0_367, c0_368, c0_369, c0_370, c0_371, c0_372, c0_373, c0_374, c0_375, c0_376, c0_377, c0_378, c0_379, c0_380, c0_381, c0_382, c0_383, c0_384, c0_385, c0_386, c0_387, c0_388, c0_389, c0_390, c0_391, c0_392, c0_393, c0_394, c0_395, c0_396, c0_397, c0_398, c0_399, c0_400, c0_401, c0_402, c0_403, c0_404, c0_405, c0_406, c0_407, c0_408, c0_409, c0_410, c0_411, c0_412, c0_413, c0_414, c0_415, c0_416, c0_417, c0_418, c0_419, c0_420, c0_421, c0_422, c0_423, c0_424, c0_425, c0_426, c0_427, c0_428, c0_429, c0_430, c0_431, c0_432, c0_433, c0_434, c0_435, c0_436, c0_437, c0_438, c0_439, c0_440, c0_441, c0_442, c0_443, c0_444, c0_445, c0_446, c0_447, c0_448, c0_449, c0_450, c0_451, c0_452, c0_453, c0_454, c0_455, c0_456, c0_457, c0_458, c0_459, c0_460, c0_461, c0_462, c0_463, c0_464, c0_465, c0_466, c0_467, c0_468, c0_469, c0_470, c0_471, c0_472, c0_473, c0_474, c0_475, c0_476, c0_477, c0_478, c0_479, c0_480, c0_481, c0_482, c0_483, c0_484, c0_485, c0_486, c0_487, c0_488, c0_489, c0_490, c0_491, c0_492, c0_493, c0_494, c0_495, c0_496, c0_497, c0_498, c0_499, c0_500, c0_501, c0_502, c0_503, e0, e1, e2, e3, e4, e5, e6, e7],
        offset,
    );
    Some((out, norm))
}
/// Q45: chunk readers of other sizes for the unpack schedules above (same per-slot code).
#[inline(never)]
fn unpack_chunk_ntt_n4(
    f0: felt252, f1: felt252, f2: felt252, f3: felt252, ref norm: felt252, q: NonZero<PackingQ>,
) -> Option<[felt252; 72]> {
    let (high, low) = match u128s_from_felt252(f0) {
        U128sFromFelt252Result::Wide(x) => x,
        U128sFromFelt252Result::Narrow(x) => (0, x),
    };
    let half: Acc8 = match downcast(low) {
        Some(v) => v,
        None => { return None; },
    };
    let (x0, x1, x2, x3, x4, x5, x6, x7, r_x8) = digits9_np8(half, ref norm, q);
    let half: Acc8 = match downcast(high) {
        Some(v) => v,
        None => { return None; },
    };
    let (x9, x10, x11, x12, x13, x14, x15, x16, r_x17) = digits9_np8(half, ref norm, q);
    let (a, b) = center_pair_zq(r_x8, r_x17);
    norm += a * a;
    norm += b * b;
    let x8: felt252 = r_x8.into();
    let x17: felt252 = r_x17.into();
    let (high, low) = match u128s_from_felt252(f1) {
        U128sFromFelt252Result::Wide(x) => x,
        U128sFromFelt252Result::Narrow(x) => (0, x),
    };
    let half: Acc8 = match downcast(low) {
        Some(v) => v,
        None => { return None; },
    };
    let (x18, x19, x20, x21, x22, x23, x24, x25, r_x26) = digits9_np8(half, ref norm, q);
    let half: Acc8 = match downcast(high) {
        Some(v) => v,
        None => { return None; },
    };
    let (x27, x28, x29, x30, x31, x32, x33, x34, r_x35) = digits9_np8(half, ref norm, q);
    let (a, b) = center_pair_zq(r_x26, r_x35);
    norm += a * a;
    norm += b * b;
    let x26: felt252 = r_x26.into();
    let x35: felt252 = r_x35.into();
    let (high, low) = match u128s_from_felt252(f2) {
        U128sFromFelt252Result::Wide(x) => x,
        U128sFromFelt252Result::Narrow(x) => (0, x),
    };
    let half: Acc8 = match downcast(low) {
        Some(v) => v,
        None => { return None; },
    };
    let (x36, x37, x38, x39, x40, x41, x42, x43, r_x44) = digits9_np8(half, ref norm, q);
    let half: Acc8 = match downcast(high) {
        Some(v) => v,
        None => { return None; },
    };
    let (x45, x46, x47, x48, x49, x50, x51, x52, r_x53) = digits9_np8(half, ref norm, q);
    let (a, b) = center_pair_zq(r_x44, r_x53);
    norm += a * a;
    norm += b * b;
    let x44: felt252 = r_x44.into();
    let x53: felt252 = r_x53.into();
    let (high, low) = match u128s_from_felt252(f3) {
        U128sFromFelt252Result::Wide(x) => x,
        U128sFromFelt252Result::Narrow(x) => (0, x),
    };
    let half: Acc8 = match downcast(low) {
        Some(v) => v,
        None => { return None; },
    };
    let (x54, x55, x56, x57, x58, x59, x60, x61, r_x62) = digits9_np8(half, ref norm, q);
    let half: Acc8 = match downcast(high) {
        Some(v) => v,
        None => { return None; },
    };
    let (x63, x64, x65, x66, x67, x68, x69, x70, r_x71) = digits9_np8(half, ref norm, q);
    let (a, b) = center_pair_zq(r_x62, r_x71);
    norm += a * a;
    norm += b * b;
    let x62: felt252 = r_x62.into();
    let x71: felt252 = r_x71.into();
    Some([x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16, x17, x18, x19, x20, x21, x22, x23, x24, x25, x26, x27, x28, x29, x30, x31, x32, x33, x34, x35, x36, x37, x38, x39, x40, x41, x42, x43, x44, x45, x46, x47, x48, x49, x50, x51, x52, x53, x54, x55, x56, x57, x58, x59, x60, x61, x62, x63, x64, x65, x66, x67, x68, x69, x70, x71])
}

#[inline(always)]
fn unpack_chunk_ntt_n4_inl(
    f0: felt252, f1: felt252, f2: felt252, f3: felt252, ref norm: felt252, q: NonZero<PackingQ>,
) -> Option<[felt252; 72]> {
    let (high, low) = match u128s_from_felt252(f0) {
        U128sFromFelt252Result::Wide(x) => x,
        U128sFromFelt252Result::Narrow(x) => (0, x),
    };
    let half: Acc8 = match downcast(low) {
        Some(v) => v,
        None => { return None; },
    };
    let (x0, x1, x2, x3, x4, x5, x6, x7, r_x8) = digits9_np8(half, ref norm, q);
    let half: Acc8 = match downcast(high) {
        Some(v) => v,
        None => { return None; },
    };
    let (x9, x10, x11, x12, x13, x14, x15, x16, r_x17) = digits9_np8(half, ref norm, q);
    let (a, b) = center_pair_zq(r_x8, r_x17);
    norm += a * a;
    norm += b * b;
    let x8: felt252 = r_x8.into();
    let x17: felt252 = r_x17.into();
    let (high, low) = match u128s_from_felt252(f1) {
        U128sFromFelt252Result::Wide(x) => x,
        U128sFromFelt252Result::Narrow(x) => (0, x),
    };
    let half: Acc8 = match downcast(low) {
        Some(v) => v,
        None => { return None; },
    };
    let (x18, x19, x20, x21, x22, x23, x24, x25, r_x26) = digits9_np8(half, ref norm, q);
    let half: Acc8 = match downcast(high) {
        Some(v) => v,
        None => { return None; },
    };
    let (x27, x28, x29, x30, x31, x32, x33, x34, r_x35) = digits9_np8(half, ref norm, q);
    let (a, b) = center_pair_zq(r_x26, r_x35);
    norm += a * a;
    norm += b * b;
    let x26: felt252 = r_x26.into();
    let x35: felt252 = r_x35.into();
    let (high, low) = match u128s_from_felt252(f2) {
        U128sFromFelt252Result::Wide(x) => x,
        U128sFromFelt252Result::Narrow(x) => (0, x),
    };
    let half: Acc8 = match downcast(low) {
        Some(v) => v,
        None => { return None; },
    };
    let (x36, x37, x38, x39, x40, x41, x42, x43, r_x44) = digits9_np8(half, ref norm, q);
    let half: Acc8 = match downcast(high) {
        Some(v) => v,
        None => { return None; },
    };
    let (x45, x46, x47, x48, x49, x50, x51, x52, r_x53) = digits9_np8(half, ref norm, q);
    let (a, b) = center_pair_zq(r_x44, r_x53);
    norm += a * a;
    norm += b * b;
    let x44: felt252 = r_x44.into();
    let x53: felt252 = r_x53.into();
    let (high, low) = match u128s_from_felt252(f3) {
        U128sFromFelt252Result::Wide(x) => x,
        U128sFromFelt252Result::Narrow(x) => (0, x),
    };
    let half: Acc8 = match downcast(low) {
        Some(v) => v,
        None => { return None; },
    };
    let (x54, x55, x56, x57, x58, x59, x60, x61, r_x62) = digits9_np8(half, ref norm, q);
    let half: Acc8 = match downcast(high) {
        Some(v) => v,
        None => { return None; },
    };
    let (x63, x64, x65, x66, x67, x68, x69, x70, r_x71) = digits9_np8(half, ref norm, q);
    let (a, b) = center_pair_zq(r_x62, r_x71);
    norm += a * a;
    norm += b * b;
    let x62: felt252 = r_x62.into();
    let x71: felt252 = r_x71.into();
    Some([x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16, x17, x18, x19, x20, x21, x22, x23, x24, x25, x26, x27, x28, x29, x30, x31, x32, x33, x34, x35, x36, x37, x38, x39, x40, x41, x42, x43, x44, x45, x46, x47, x48, x49, x50, x51, x52, x53, x54, x55, x56, x57, x58, x59, x60, x61, x62, x63, x64, x65, x66, x67, x68, x69, x70, x71])
}

// Q21 END

/// Unpack the canonical 29-slot encoding directly into the verifier's `u16` form.
/// Returns `None` on wrong length or any non-canonical slot encoding.
/// Unpack the public key's coefficients (bounded below q) and check each against the two
/// unreduced transforms as it comes out (see `falcon::check_hint_zq`); `hn` is the hint
/// transform minus the check's offset K (see `falcon::hint_quotient_pre`).
#[inline(always)]
pub(crate) fn unpack_512_zq_check(
    packed: Span<felt252>, s1n_t: (Span<[LazyCoeff; 72]>, Box<[LazyCoeff; 8]>), hn_t: (Span<[LazyCoeff; 72]>, Box<[LazyCoeff; 8]>),
) -> bool {
    // Q52: no length test here; the only caller (`Falcon512ShakeVerifier::verify`) rejects any key
    // whose length is not PACKED_SLOTS before anything else runs.
    let (mut s1n, s1n_tail) = s1n_t;
    let (mut hn, hn_tail) = hn_t;
    let q = packing_q_cell();
    let mut slots = packed;
    loop {
        let [f0, f1, f2, f3] = match slots.multi_pop_front::<4>() {
            Some(chunk) => (*chunk).unbox(),
            None => { return false; },
        };
        let [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24, a25, a26, a27, a28, a29, a30, a31, a32, a33, a34, a35, a36, a37, a38, a39, a40, a41, a42, a43, a44, a45, a46, a47, a48, a49, a50, a51, a52, a53, a54, a55, a56, a57, a58, a59, a60, a61, a62, a63, a64, a65, a66, a67, a68, a69, a70, a71] = *s1n.pop_front().unwrap();
        let [c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19, c20, c21, c22, c23, c24, c25, c26, c27, c28, c29, c30, c31, c32, c33, c34, c35, c36, c37, c38, c39, c40, c41, c42, c43, c44, c45, c46, c47, c48, c49, c50, c51, c52, c53, c54, c55, c56, c57, c58, c59, c60, c61, c62, c63, c64, c65, c66, c67, c68, c69, c70, c71] = *hn.pop_front().unwrap();
        let (high, low) = match u128s_from_felt252(f0) {
            U128sFromFelt252Result::Wide(x) => x,
            U128sFromFelt252Result::Narrow(x) => (0, x),
        };
        let x: Acc8 = match downcast(low) {
            Some(x) => x,
            None => { return false; },
        };
        let (x, d0) = bounded_int_div_rem(x, q);
        let (x, d1) = bounded_int_div_rem(x, q);
        let (x, d2) = bounded_int_div_rem(x, q);
        let (x, d3) = bounded_int_div_rem(x, q);
        let (x, d4) = bounded_int_div_rem(x, q);
        let (x, d5) = bounded_int_div_rem(x, q);
        let (x, d6) = bounded_int_div_rem(x, q);
        let (x, d7) = bounded_int_div_rem(x, q);
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a0, d0, c0)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a1, d1, c1)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a2, d2, c2)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a3, d3, c3)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a4, d4, c4)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a5, d5, c5)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a6, d6, c6)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a7, d7, c7)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a8, x, c8)) {
            return false;
        }
        let x: Acc8 = match downcast(high) {
            Some(x) => x,
            None => { return false; },
        };
        let (x, d0) = bounded_int_div_rem(x, q);
        let (x, d1) = bounded_int_div_rem(x, q);
        let (x, d2) = bounded_int_div_rem(x, q);
        let (x, d3) = bounded_int_div_rem(x, q);
        let (x, d4) = bounded_int_div_rem(x, q);
        let (x, d5) = bounded_int_div_rem(x, q);
        let (x, d6) = bounded_int_div_rem(x, q);
        let (x, d7) = bounded_int_div_rem(x, q);
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a9, d0, c9)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a10, d1, c10)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a11, d2, c11)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a12, d3, c12)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a13, d4, c13)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a14, d5, c14)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a15, d6, c15)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a16, d7, c16)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a17, x, c17)) {
            return false;
        }
        let (high, low) = match u128s_from_felt252(f1) {
            U128sFromFelt252Result::Wide(x) => x,
            U128sFromFelt252Result::Narrow(x) => (0, x),
        };
        let x: Acc8 = match downcast(low) {
            Some(x) => x,
            None => { return false; },
        };
        let (x, d0) = bounded_int_div_rem(x, q);
        let (x, d1) = bounded_int_div_rem(x, q);
        let (x, d2) = bounded_int_div_rem(x, q);
        let (x, d3) = bounded_int_div_rem(x, q);
        let (x, d4) = bounded_int_div_rem(x, q);
        let (x, d5) = bounded_int_div_rem(x, q);
        let (x, d6) = bounded_int_div_rem(x, q);
        let (x, d7) = bounded_int_div_rem(x, q);
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a18, d0, c18)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a19, d1, c19)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a20, d2, c20)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a21, d3, c21)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a22, d4, c22)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a23, d5, c23)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a24, d6, c24)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a25, d7, c25)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a26, x, c26)) {
            return false;
        }
        let x: Acc8 = match downcast(high) {
            Some(x) => x,
            None => { return false; },
        };
        let (x, d0) = bounded_int_div_rem(x, q);
        let (x, d1) = bounded_int_div_rem(x, q);
        let (x, d2) = bounded_int_div_rem(x, q);
        let (x, d3) = bounded_int_div_rem(x, q);
        let (x, d4) = bounded_int_div_rem(x, q);
        let (x, d5) = bounded_int_div_rem(x, q);
        let (x, d6) = bounded_int_div_rem(x, q);
        let (x, d7) = bounded_int_div_rem(x, q);
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a27, d0, c27)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a28, d1, c28)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a29, d2, c29)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a30, d3, c30)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a31, d4, c31)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a32, d5, c32)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a33, d6, c33)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a34, d7, c34)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a35, x, c35)) {
            return false;
        }
        let (high, low) = match u128s_from_felt252(f2) {
            U128sFromFelt252Result::Wide(x) => x,
            U128sFromFelt252Result::Narrow(x) => (0, x),
        };
        let x: Acc8 = match downcast(low) {
            Some(x) => x,
            None => { return false; },
        };
        let (x, d0) = bounded_int_div_rem(x, q);
        let (x, d1) = bounded_int_div_rem(x, q);
        let (x, d2) = bounded_int_div_rem(x, q);
        let (x, d3) = bounded_int_div_rem(x, q);
        let (x, d4) = bounded_int_div_rem(x, q);
        let (x, d5) = bounded_int_div_rem(x, q);
        let (x, d6) = bounded_int_div_rem(x, q);
        let (x, d7) = bounded_int_div_rem(x, q);
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a36, d0, c36)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a37, d1, c37)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a38, d2, c38)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a39, d3, c39)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a40, d4, c40)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a41, d5, c41)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a42, d6, c42)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a43, d7, c43)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a44, x, c44)) {
            return false;
        }
        let x: Acc8 = match downcast(high) {
            Some(x) => x,
            None => { return false; },
        };
        let (x, d0) = bounded_int_div_rem(x, q);
        let (x, d1) = bounded_int_div_rem(x, q);
        let (x, d2) = bounded_int_div_rem(x, q);
        let (x, d3) = bounded_int_div_rem(x, q);
        let (x, d4) = bounded_int_div_rem(x, q);
        let (x, d5) = bounded_int_div_rem(x, q);
        let (x, d6) = bounded_int_div_rem(x, q);
        let (x, d7) = bounded_int_div_rem(x, q);
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a45, d0, c45)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a46, d1, c46)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a47, d2, c47)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a48, d3, c48)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a49, d4, c49)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a50, d5, c50)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a51, d6, c51)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a52, d7, c52)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a53, x, c53)) {
            return false;
        }
        let (high, low) = match u128s_from_felt252(f3) {
            U128sFromFelt252Result::Wide(x) => x,
            U128sFromFelt252Result::Narrow(x) => (0, x),
        };
        let x: Acc8 = match downcast(low) {
            Some(x) => x,
            None => { return false; },
        };
        let (x, d0) = bounded_int_div_rem(x, q);
        let (x, d1) = bounded_int_div_rem(x, q);
        let (x, d2) = bounded_int_div_rem(x, q);
        let (x, d3) = bounded_int_div_rem(x, q);
        let (x, d4) = bounded_int_div_rem(x, q);
        let (x, d5) = bounded_int_div_rem(x, q);
        let (x, d6) = bounded_int_div_rem(x, q);
        let (x, d7) = bounded_int_div_rem(x, q);
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a54, d0, c54)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a55, d1, c55)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a56, d2, c56)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a57, d3, c57)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a58, d4, c58)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a59, d5, c59)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a60, d6, c60)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a61, d7, c61)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a62, x, c62)) {
            return false;
        }
        let x: Acc8 = match downcast(high) {
            Some(x) => x,
            None => { return false; },
        };
        let (x, d0) = bounded_int_div_rem(x, q);
        let (x, d1) = bounded_int_div_rem(x, q);
        let (x, d2) = bounded_int_div_rem(x, q);
        let (x, d3) = bounded_int_div_rem(x, q);
        let (x, d4) = bounded_int_div_rem(x, q);
        let (x, d5) = bounded_int_div_rem(x, q);
        let (x, d6) = bounded_int_div_rem(x, q);
        let (x, d7) = bounded_int_div_rem(x, q);
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a63, d0, c63)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a64, d1, c64)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a65, d2, c65)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a66, d3, c66)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a67, d4, c67)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a68, d5, c68)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a69, d6, c69)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a70, d7, c70)) {
            return false;
        }
        if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a71, x, c71)) {
            return false;
        }
        if s1n.is_empty() {
            break;
        }
    }
    let last = match slots.pop_front() {
        Some(v) => *v,
        None => { return false; },
    };
    // Q52: the pk's last slot must split Narrow (high half 0); no u256 merge, no zero test (Q51 H2's shape).
    let low = match u128s_from_felt252(last) {
        U128sFromFelt252Result::Narrow(x) => x,
        U128sFromFelt252Result::Wide(_) => { return false; },
    };
    let x: Acc7 = match downcast(low) {
        Some(v) => v,
        None => { return false; },
    };
    let (x, d0) = bounded_int_div_rem(x, q);
    let (x, d1) = bounded_int_div_rem(x, q);
    let (x, d2) = bounded_int_div_rem(x, q);
    let (x, d3) = bounded_int_div_rem(x, q);
    let (x, d4) = bounded_int_div_rem(x, q);
    let (x, d5) = bounded_int_div_rem(x, q);
    let (x, d6) = bounded_int_div_rem(x, q);
    let [a0, a1, a2, a3, a4, a5, a6, a7] = s1n_tail.unbox();
    let [c0, c1, c2, c3, c4, c5, c6, c7] = hn_tail.unbox();
    if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a0, d0, c0)) {
        return false;
    }
    if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a1, d1, c1)) {
        return false;
    }
    if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a2, d2, c2)) {
        return false;
    }
    if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a3, d3, c3)) {
        return false;
    }
    if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a4, d4, c4)) {
        return false;
    }
    if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a5, d5, c5)) {
        return false;
    }
    if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a6, d6, c6)) {
        return false;
    }
    if let U128sFromFelt252Result::Wide(_) = u128s_from_felt252(hint_quotient_inv(a7, x, c7)) {
        return false;
    }
    true
}
