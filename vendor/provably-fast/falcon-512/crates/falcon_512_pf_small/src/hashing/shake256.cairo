//! SHAKE-256 extendable-output function (FIPS 202), implemented in pure Cairo.
//!
//! Written from the FIPS 202 specification (Keccak-f[1600] sponge, rate 1088 bits =
//! 136 bytes, capacity 512, domain-separation `0x1F`, pad10*1). Starknet exposes no
//! SHAKE primitive and its `keccak` syscall bakes in keccak256's `0x01` padding and a
//! fixed 256-bit output, so neither is reusable here; the permutation is implemented
//! directly. A future `keccak_f1600` syscall (SNIP-32) would replace [`keccak_f1600`]
//! and collapse the cost.
//!
//! State: 25 lanes of 64 bits, `lane[x + 5y]`, bytes mapped little-endian per lane.
//!
//! The permutation dominates on-chain cost, so it is written flat:
//! - each round is a straight-line expression over 25 lane locals — no round-local
//!   arrays, no index arithmetic, no table lookups; θ is fused into the ρ+π terms and
//!   ι into the first χ lane;
//! - lanes are carried as `u128` — the bitwise builtin's native operand width — so
//!   XOR/AND need no per-operation downcast. The `< 2^64` lane invariant is
//!   maintained structurally: XOR/AND of 64-bit values is 64-bit, complements are
//!   taken over 128 bits as a bounded `2^128 - 1 - b` (exact for every `u128`, so no
//!   runtime check and no builtin) and only ever ANDed with a 64-bit lane, which clears
//!   the high bits, and rotations reassemble disjoint bit ranges below bit 64;
//! - rotations are division-free: every rotation amount is baked in as its power of
//!   two, so a left-rotate is one bounded-integer multiply and one bounded `div_rem` by
//!   2^64 — the wrapped high bits and the shifted low bits occupy disjoint positions, so
//!   their sum is the rotation. Being bounded integers, the multiply, the sum and the
//!   conversion back to `u128` need no runtime check.
//!
//! [`keccak_f1600`] is shared with the hash-to-point squeezer
//! (`hash_to_point::hash_to_point_shake_512`), which drives the sponge lazily and
//! reads candidates straight from the rate lanes; the byte-oriented [`shake256`] here
//! is the generic XOF, pinned to the FIPS 202 known-answer vectors below.

const RATE_LANES: u32 = 17; // 136 bytes / 8
const RATE_BYTES: u32 = 136;

/// Keccak-f[1600] round constants (FIPS 202, Table 1).
const ROUND_CONSTANTS: [u128; 24] = [
    0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
    0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
    0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
];

use corelib_imports::bounded_int::{
    AddHelper, BoundedInt, DivRemHelper, MulHelper, UnitInt, bounded_int, upcast,
};
#[feature("bounded-int-utils")]
use core::internal::bounded_int::{ConstrainHelper, SubHelper, constrain};

/// A rotation's power of two, 2^1 to 2^63.
type Pow = BoundedInt<2, 0x8000000000000000>;
/// A lane (< 2^128 as typed) times a power: below (2^128 - 1) * 2^63.
type Wide = BoundedInt<0, 0x7fffffffffffffffffffffffffffffff8000000000000000>;
type Two64 = UnitInt<0x10000000000000000>;
type High = BoundedInt<0, 0x7fffffffffffffffffffffffffffffff>;
pub(crate) type Low = BoundedInt<0, 0xffffffffffffffff>;
type Rotated = BoundedInt<0, 0x8000000000000000fffffffffffffffe>;
const TWO64_NZ: NonZero<Two64> = 0x10000000000000000;

impl MulLanePow of MulHelper<u128, Pow> {
    type Result = Wide;
}
impl DivRemWideTwo64 of DivRemHelper<Wide, Two64> {
    type DivT = High;
    type RemT = Low;
}
impl AddHighLow of AddHelper<High, Low> {
    type Result = Rotated;
}

type Mask128 = UnitInt<0xffffffffffffffffffffffffffffffff>;
const MASK128: Mask128 = 0xffffffffffffffffffffffffffffffff;

impl SubMaskLane of SubHelper<Mask128, u128> {
    type Result = BoundedInt<0, 0xffffffffffffffffffffffffffffffff>;
}

/// `2^128 - 1 - x`: the 128-bit complement, exact for every `u128` and so with no runtime
/// check. Only ever ANDed with a 64-bit lane, which clears the high bits it sets.
#[inline(always)]
fn not128(x: u128) -> u128 {
    upcast(bounded_int::sub(MASK128, x))
}

/// Rotate a 64-bit lane left, given `pow = 2^r` with 0 < r < 64. The product `x * 2^r`
/// splits at bit 64 into the bits that stay (`low`) and the bits that wrap to the bottom
/// (`high`); they occupy disjoint positions, so `high + low` is the rotation. The product,
/// the sum and the final upcast are bounded-integer operations whose ranges are checked by
/// type, so the split at bit 64 is the only checked operation.
#[inline(always)]
fn rotl(x: u128, pow: Pow) -> u128 {
    let wide = bounded_int::mul(x, pow);
    let (high, low) = bounded_int::div_rem(wide, TWO64_NZ);
    upcast(bounded_int::add(high, low))
}

/// `w` as its high and low 64-bit halves (both exactly 64-bit by type).
#[inline(always)]
fn split(w: u128) -> (u128, u128) {
    let (high, low) = bounded_int::div_rem(w, TWO64_NZ);
    (upcast(high), upcast(low))
}

/// `lo + hi * 2^64` for two lanes below 2^64.
#[inline(always)]
pub(crate) fn pack(lo: u128, hi: u128) -> u128 {
    let packed: felt252 = lo.into() + hi.into() * 0x10000000000000000;
    packed.try_into().unwrap()
}

impl DivRemU128Two64 of DivRemHelper<u128, Two64> {
    type DivT = Low;
    type RemT = Low;
}

/// Keccak-f[1600]: 24 rounds of θ, ρ, π, χ, ι, fully unrolled over lane locals, on a
/// packed state: per column `x`, `p0[x]` holds rows 0 and 1 (low and high 64 bits), `p1[x]`
/// rows 2 and 3, and `q[x]` row 4. One bitwise call then handles two lanes in θ's column
/// sums, in applying θ's mixing term, and in χ (which works along rows, so the two halves of a
/// packed word never interact). Lanes are split only for the ρ rotations and repacked for χ.

/// `w` as its high and low 64-bit halves, kept as exact 64-bit bounded integers.
#[inline(always)]
fn split_exact(w: u128) -> (Low, Low) {
    bounded_int::div_rem(w, TWO64_NZ)
}

type Two64Unit = UnitInt<0x10000000000000000>;
type HiTimes2_64 = BoundedInt<0, 0xffffffffffffffff0000000000000000>;
impl MulLowTwo64 of MulHelper<Low, Two64Unit> {
    type Result = HiTimes2_64;
}
impl AddLowHiTimes of AddHelper<Low, HiTimes2_64> {
    type Result = BoundedInt<0, 0xffffffffffffffffffffffffffffffff>;
}

/// `lo + hi * 2^64` for two exact 64-bit lanes: the sum is below 2^128 by type, so no
/// runtime check.
#[inline(always)]
pub(crate) fn pack_exact(lo: Low, hi: Low) -> u128 {
    let two64: Two64Unit = 0x10000000000000000;
    upcast(bounded_int::add(lo, bounded_int::mul(hi, two64)))
}

/// `hi * 2^64`, computed once for a lane that is the high half of two packs.
#[inline(always)]
fn scale_hi(hi: Low) -> HiTimes2_64 {
    let two64: Two64Unit = 0x10000000000000000;
    bounded_int::mul(hi, two64)
}

type Two64Plus1 = UnitInt<0x10000000000000001>;
impl MulLowTwo64Plus1 of MulHelper<Low, Two64Plus1> {
    type Result = BoundedInt<0, 0xffffffffffffffffffffffffffffffff>;
}

/// `x + x * 2^64` (the lane in both halves) as one product.
#[inline(always)]
fn dup_lane(x: Low) -> u128 {
    let m: Two64Plus1 = 0x10000000000000001;
    upcast(bounded_int::mul(x, m))
}

/// [`pack_exact`] with the high half already scaled by [`scale_hi`].
#[inline(always)]
fn pack_scaled(lo: Low, hi: HiTimes2_64) -> u128 {
    upcast(bounded_int::add(lo, hi))
}

type RotQ1 = BoundedInt<0, 1>;
type RotR1 = BoundedInt<0, 9223372036854775807>;
type RotM1 = BoundedInt<0, 18446744073709551614>;
impl DivRemRot1 of DivRemHelper<Low, UnitInt<9223372036854775808>> {
    type DivT = RotQ1;
    type RemT = RotR1;
}
impl MulRot1 of MulHelper<RotR1, UnitInt<2>> {
    type Result = RotM1;
}
impl AddRot1 of AddHelper<RotM1, RotQ1> {
    type Result = Low;
}
#[inline(always)]
fn rotl_exact_1(x: Low) -> Low {
    let d: NonZero<UnitInt<9223372036854775808>> = 9223372036854775808;
    let m: UnitInt<2> = 2;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

type RotQ3 = BoundedInt<0, 7>;
type RotR3 = BoundedInt<0, 2305843009213693951>;
type RotM3 = BoundedInt<0, 18446744073709551608>;
impl DivRemRot3 of DivRemHelper<Low, UnitInt<2305843009213693952>> {
    type DivT = RotQ3;
    type RemT = RotR3;
}
impl MulRot3 of MulHelper<RotR3, UnitInt<8>> {
    type Result = RotM3;
}
impl AddRot3 of AddHelper<RotM3, RotQ3> {
    type Result = Low;
}
#[inline(always)]
fn rotl_exact_3(x: Low) -> Low {
    let d: NonZero<UnitInt<2305843009213693952>> = 2305843009213693952;
    let m: UnitInt<8> = 8;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

type RotQ6 = BoundedInt<0, 63>;
type RotR6 = BoundedInt<0, 288230376151711743>;
type RotM6 = BoundedInt<0, 18446744073709551552>;
impl DivRemRot6 of DivRemHelper<Low, UnitInt<288230376151711744>> {
    type DivT = RotQ6;
    type RemT = RotR6;
}
impl MulRot6 of MulHelper<RotR6, UnitInt<64>> {
    type Result = RotM6;
}
impl AddRot6 of AddHelper<RotM6, RotQ6> {
    type Result = Low;
}
#[inline(always)]
fn rotl_exact_6(x: Low) -> Low {
    let d: NonZero<UnitInt<288230376151711744>> = 288230376151711744;
    let m: UnitInt<64> = 64;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

type RotQ8 = BoundedInt<0, 255>;
type RotR8 = BoundedInt<0, 72057594037927935>;
type RotM8 = BoundedInt<0, 18446744073709551360>;
impl DivRemRot8 of DivRemHelper<Low, UnitInt<72057594037927936>> {
    type DivT = RotQ8;
    type RemT = RotR8;
}
impl MulRot8 of MulHelper<RotR8, UnitInt<256>> {
    type Result = RotM8;
}
impl AddRot8 of AddHelper<RotM8, RotQ8> {
    type Result = Low;
}
#[inline(always)]
fn rotl_exact_8(x: Low) -> Low {
    let d: NonZero<UnitInt<72057594037927936>> = 72057594037927936;
    let m: UnitInt<256> = 256;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

type RotQ10 = BoundedInt<0, 1023>;
type RotR10 = BoundedInt<0, 18014398509481983>;
type RotM10 = BoundedInt<0, 18446744073709550592>;
impl DivRemRot10 of DivRemHelper<Low, UnitInt<18014398509481984>> {
    type DivT = RotQ10;
    type RemT = RotR10;
}
impl MulRot10 of MulHelper<RotR10, UnitInt<1024>> {
    type Result = RotM10;
}
impl AddRot10 of AddHelper<RotM10, RotQ10> {
    type Result = Low;
}
#[inline(always)]
fn rotl_exact_10(x: Low) -> Low {
    let d: NonZero<UnitInt<18014398509481984>> = 18014398509481984;
    let m: UnitInt<1024> = 1024;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

type RotQ15 = BoundedInt<0, 32767>;
type RotR15 = BoundedInt<0, 562949953421311>;
type RotM15 = BoundedInt<0, 18446744073709518848>;
impl DivRemRot15 of DivRemHelper<Low, UnitInt<562949953421312>> {
    type DivT = RotQ15;
    type RemT = RotR15;
}
impl MulRot15 of MulHelper<RotR15, UnitInt<32768>> {
    type Result = RotM15;
}
impl AddRot15 of AddHelper<RotM15, RotQ15> {
    type Result = Low;
}
#[inline(always)]
fn rotl_exact_15(x: Low) -> Low {
    let d: NonZero<UnitInt<562949953421312>> = 562949953421312;
    let m: UnitInt<32768> = 32768;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

type RotQ20 = BoundedInt<0, 1048575>;
type RotR20 = BoundedInt<0, 17592186044415>;
type RotM20 = BoundedInt<0, 18446744073708503040>;
impl DivRemRot20 of DivRemHelper<Low, UnitInt<17592186044416>> {
    type DivT = RotQ20;
    type RemT = RotR20;
}
impl MulRot20 of MulHelper<RotR20, UnitInt<1048576>> {
    type Result = RotM20;
}
impl AddRot20 of AddHelper<RotM20, RotQ20> {
    type Result = Low;
}
#[inline(always)]
fn rotl_exact_20(x: Low) -> Low {
    let d: NonZero<UnitInt<17592186044416>> = 17592186044416;
    let m: UnitInt<1048576> = 1048576;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

type RotQ21 = BoundedInt<0, 2097151>;
type RotR21 = BoundedInt<0, 8796093022207>;
type RotM21 = BoundedInt<0, 18446744073707454464>;
impl DivRemRot21 of DivRemHelper<Low, UnitInt<8796093022208>> {
    type DivT = RotQ21;
    type RemT = RotR21;
}
impl MulRot21 of MulHelper<RotR21, UnitInt<2097152>> {
    type Result = RotM21;
}
impl AddRot21 of AddHelper<RotM21, RotQ21> {
    type Result = Low;
}
#[inline(always)]
fn rotl_exact_21(x: Low) -> Low {
    let d: NonZero<UnitInt<8796093022208>> = 8796093022208;
    let m: UnitInt<2097152> = 2097152;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

type RotQ25 = BoundedInt<0, 33554431>;
type RotR25 = BoundedInt<0, 549755813887>;
type RotM25 = BoundedInt<0, 18446744073675997184>;
impl DivRemRot25 of DivRemHelper<Low, UnitInt<549755813888>> {
    type DivT = RotQ25;
    type RemT = RotR25;
}
impl MulRot25 of MulHelper<RotR25, UnitInt<33554432>> {
    type Result = RotM25;
}
impl AddRot25 of AddHelper<RotM25, RotQ25> {
    type Result = Low;
}
#[inline(always)]
fn rotl_exact_25(x: Low) -> Low {
    let d: NonZero<UnitInt<549755813888>> = 549755813888;
    let m: UnitInt<33554432> = 33554432;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

type RotQ27 = BoundedInt<0, 134217727>;
type RotR27 = BoundedInt<0, 137438953471>;
type RotM27 = BoundedInt<0, 18446744073575333888>;
impl DivRemRot27 of DivRemHelper<Low, UnitInt<137438953472>> {
    type DivT = RotQ27;
    type RemT = RotR27;
}
impl MulRot27 of MulHelper<RotR27, UnitInt<134217728>> {
    type Result = RotM27;
}
impl AddRot27 of AddHelper<RotM27, RotQ27> {
    type Result = Low;
}
#[inline(always)]
fn rotl_exact_27(x: Low) -> Low {
    let d: NonZero<UnitInt<137438953472>> = 137438953472;
    let m: UnitInt<134217728> = 134217728;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

type RotQ28 = BoundedInt<0, 268435455>;
type RotR28 = BoundedInt<0, 68719476735>;
type RotM28 = BoundedInt<0, 18446744073441116160>;
impl DivRemRot28 of DivRemHelper<Low, UnitInt<68719476736>> {
    type DivT = RotQ28;
    type RemT = RotR28;
}
impl MulRot28 of MulHelper<RotR28, UnitInt<268435456>> {
    type Result = RotM28;
}
impl AddRot28 of AddHelper<RotM28, RotQ28> {
    type Result = Low;
}
#[inline(always)]
fn rotl_exact_28(x: Low) -> Low {
    let d: NonZero<UnitInt<68719476736>> = 68719476736;
    let m: UnitInt<268435456> = 268435456;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

type RotQ36 = BoundedInt<0, 68719476735>;
type RotR36 = BoundedInt<0, 268435455>;
type RotM36 = BoundedInt<0, 18446744004990074880>;
impl DivRemRot36 of DivRemHelper<Low, UnitInt<268435456>> {
    type DivT = RotQ36;
    type RemT = RotR36;
}
impl MulRot36 of MulHelper<RotR36, UnitInt<68719476736>> {
    type Result = RotM36;
}
impl AddRot36 of AddHelper<RotM36, RotQ36> {
    type Result = Low;
}
#[inline(always)]
fn rotl_exact_36(x: Low) -> Low {
    let d: NonZero<UnitInt<268435456>> = 268435456;
    let m: UnitInt<68719476736> = 68719476736;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

type RotQ39 = BoundedInt<0, 549755813887>;
type RotR39 = BoundedInt<0, 33554431>;
type RotM39 = BoundedInt<0, 18446743523953737728>;
impl DivRemRot39 of DivRemHelper<Low, UnitInt<33554432>> {
    type DivT = RotQ39;
    type RemT = RotR39;
}
impl MulRot39 of MulHelper<RotR39, UnitInt<549755813888>> {
    type Result = RotM39;
}
impl AddRot39 of AddHelper<RotM39, RotQ39> {
    type Result = Low;
}
#[inline(always)]
fn rotl_exact_39(x: Low) -> Low {
    let d: NonZero<UnitInt<33554432>> = 33554432;
    let m: UnitInt<549755813888> = 549755813888;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

type RotQ41 = BoundedInt<0, 2199023255551>;
type RotR41 = BoundedInt<0, 8388607>;
type RotM41 = BoundedInt<0, 18446741874686296064>;
impl DivRemRot41 of DivRemHelper<Low, UnitInt<8388608>> {
    type DivT = RotQ41;
    type RemT = RotR41;
}
impl MulRot41 of MulHelper<RotR41, UnitInt<2199023255552>> {
    type Result = RotM41;
}
impl AddRot41 of AddHelper<RotM41, RotQ41> {
    type Result = Low;
}
#[inline(always)]
fn rotl_exact_41(x: Low) -> Low {
    let d: NonZero<UnitInt<8388608>> = 8388608;
    let m: UnitInt<2199023255552> = 2199023255552;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

type RotQ43 = BoundedInt<0, 8796093022207>;
type RotR43 = BoundedInt<0, 2097151>;
type RotM43 = BoundedInt<0, 18446735277616529408>;
impl DivRemRot43 of DivRemHelper<Low, UnitInt<2097152>> {
    type DivT = RotQ43;
    type RemT = RotR43;
}
impl MulRot43 of MulHelper<RotR43, UnitInt<8796093022208>> {
    type Result = RotM43;
}
impl AddRot43 of AddHelper<RotM43, RotQ43> {
    type Result = Low;
}
#[inline(always)]
fn rotl_exact_43(x: Low) -> Low {
    let d: NonZero<UnitInt<2097152>> = 2097152;
    let m: UnitInt<8796093022208> = 8796093022208;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

type RotQ44 = BoundedInt<0, 17592186044415>;
type RotR44 = BoundedInt<0, 1048575>;
type RotM44 = BoundedInt<0, 18446726481523507200>;
impl DivRemRot44 of DivRemHelper<Low, UnitInt<1048576>> {
    type DivT = RotQ44;
    type RemT = RotR44;
}
impl MulRot44 of MulHelper<RotR44, UnitInt<17592186044416>> {
    type Result = RotM44;
}
impl AddRot44 of AddHelper<RotM44, RotQ44> {
    type Result = Low;
}
#[inline(always)]
fn rotl_exact_44(x: Low) -> Low {
    let d: NonZero<UnitInt<1048576>> = 1048576;
    let m: UnitInt<17592186044416> = 17592186044416;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

type RotQ45 = BoundedInt<0, 35184372088831>;
type RotR45 = BoundedInt<0, 524287>;
type RotM45 = BoundedInt<0, 18446708889337462784>;
impl DivRemRot45 of DivRemHelper<Low, UnitInt<524288>> {
    type DivT = RotQ45;
    type RemT = RotR45;
}
impl MulRot45 of MulHelper<RotR45, UnitInt<35184372088832>> {
    type Result = RotM45;
}
impl AddRot45 of AddHelper<RotM45, RotQ45> {
    type Result = Low;
}
#[inline(always)]
fn rotl_exact_45(x: Low) -> Low {
    let d: NonZero<UnitInt<524288>> = 524288;
    let m: UnitInt<35184372088832> = 35184372088832;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

type RotQ55 = BoundedInt<0, 36028797018963967>;
type RotR55 = BoundedInt<0, 511>;
type RotM55 = BoundedInt<0, 18410715276690587648>;
impl DivRemRot55 of DivRemHelper<Low, UnitInt<512>> {
    type DivT = RotQ55;
    type RemT = RotR55;
}
impl MulRot55 of MulHelper<RotR55, UnitInt<36028797018963968>> {
    type Result = RotM55;
}
impl AddRot55 of AddHelper<RotM55, RotQ55> {
    type Result = Low;
}
#[inline(always)]
fn rotl_exact_55(x: Low) -> Low {
    let d: NonZero<UnitInt<512>> = 512;
    let m: UnitInt<36028797018963968> = 36028797018963968;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

type RotQ62 = BoundedInt<0, 4611686018427387903>;
type RotR62 = BoundedInt<0, 3>;
type RotM62 = BoundedInt<0, 13835058055282163712>;
impl DivRemRot62 of DivRemHelper<Low, UnitInt<4>> {
    type DivT = RotQ62;
    type RemT = RotR62;
}
impl MulRot62 of MulHelper<RotR62, UnitInt<4611686018427387904>> {
    type Result = RotM62;
}
impl AddRot62 of AddHelper<RotM62, RotQ62> {
    type Result = Low;
}
#[inline(always)]
fn rotl_exact_62(x: Low) -> Low {
    let d: NonZero<UnitInt<4>> = 4;
    let m: UnitInt<4611686018427387904> = 4611686018427387904;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

type RotQ2 = BoundedInt<0, 3>;
type RotR2 = BoundedInt<0, 4611686018427387903>;
type RotM2 = BoundedInt<0, 18446744073709551612>;
impl DivRemRot2 of DivRemHelper<Low, UnitInt<4611686018427387904>> {
    type DivT = RotQ2;
    type RemT = RotR2;
}
impl MulRot2 of MulHelper<RotR2, UnitInt<4>> {
    type Result = RotM2;
}
impl AddRot2 of AddHelper<RotM2, RotQ2> {
    type Result = Low;
}

#[inline(always)]
fn rotl_exact_k_2(x: Low, d: NonZero<UnitInt<4611686018427387904>>) -> Low {
    let m: UnitInt<4> = 4;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

type RotQ18 = BoundedInt<0, 262143>;
type RotR18 = BoundedInt<0, 70368744177663>;
type RotM18 = BoundedInt<0, 18446744073709289472>;
impl DivRemRot18 of DivRemHelper<Low, UnitInt<70368744177664>> {
    type DivT = RotQ18;
    type RemT = RotR18;
}
impl MulRot18 of MulHelper<RotR18, UnitInt<262144>> {
    type Result = RotM18;
}
impl AddRot18 of AddHelper<RotM18, RotQ18> {
    type Result = Low;
}

#[inline(always)]
fn rotl_exact_k_18(x: Low, d: NonZero<UnitInt<70368744177664>>) -> Low {
    let m: UnitInt<262144> = 262144;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

type RotQ56 = BoundedInt<0, 72057594037927935>;
type RotR56 = BoundedInt<0, 255>;
type RotM56 = BoundedInt<0, 18374686479671623680>;
impl DivRemRot56 of DivRemHelper<Low, UnitInt<256>> {
    type DivT = RotQ56;
    type RemT = RotR56;
}
impl MulRot56 of MulHelper<RotR56, UnitInt<72057594037927936>> {
    type Result = RotM56;
}
impl AddRot56 of AddHelper<RotM56, RotQ56> {
    type Result = Low;
}

#[inline(always)]
fn rotl_exact_k_56(x: Low, d: NonZero<UnitInt<256>>) -> Low {
    let m: UnitInt<72057594037927936> = 72057594037927936;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

type RotQ61 = BoundedInt<0, 2305843009213693951>;
type RotR61 = BoundedInt<0, 7>;
type RotM61 = BoundedInt<0, 16140901064495857664>;
impl DivRemRot61 of DivRemHelper<Low, UnitInt<8>> {
    type DivT = RotQ61;
    type RemT = RotR61;
}
impl MulRot61 of MulHelper<RotR61, UnitInt<2305843009213693952>> {
    type Result = RotM61;
}
impl AddRot61 of AddHelper<RotM61, RotQ61> {
    type Result = Low;
}

#[inline(always)]
fn rotl_exact_k_61(x: Low, d: NonZero<UnitInt<8>>) -> Low {
    let m: UnitInt<2305843009213693952> = 2305843009213693952;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

type RotQ14 = BoundedInt<0, 16383>;
type RotR14 = BoundedInt<0, 1125899906842623>;
type RotM14 = BoundedInt<0, 18446744073709535232>;
impl DivRemRot14 of DivRemHelper<Low, UnitInt<1125899906842624>> {
    type DivT = RotQ14;
    type RemT = RotR14;
}
impl MulRot14 of MulHelper<RotR14, UnitInt<16384>> {
    type Result = RotM14;
}
impl AddRot14 of AddHelper<RotM14, RotQ14> {
    type Result = Low;
}

#[inline(always)]
fn rotl_exact_k_14(x: Low, d: NonZero<UnitInt<1125899906842624>>) -> Low {
    let m: UnitInt<16384> = 16384;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

type Mask64 = UnitInt<0xffffffffffffffff>;
impl SubMask64Low of SubHelper<Mask64, Low> {
    type Result = Low;
}

/// XOR of two exact 64-bit lanes through the `u64` bitwise libfunc, so the result stays
/// typed below 2^64 and can be packed with no runtime check.
#[inline(always)]
fn xor64(a: Low, b: Low) -> Low {
    let a: u64 = upcast(a);
    let b: u64 = upcast(b);
    upcast(a ^ b)
}

/// `~b & c` on exact 64-bit lanes (the complement is a bounded `2^64 - 1 - b`).
#[inline(always)]
fn andn64(b: Low, c: Low, mask: Mask64) -> Low {
    let nb: u64 = upcast(bounded_int::sub(mask, b));
    let c: u64 = upcast(c);
    upcast(nb & c)
}

/// `2^-63 - 2` in the field: `2w + t * (2^-63 - 2)` is `2(w - t) + t / 2^63`.
const INV63_MINUS_2: felt252 = 0x800000000000010efffffffffffffddffffffffffffffffffffffffffffffff;

/// Both 64-bit halves of `w` rotated left by one. `t` holds the two top bits (63 and 127),
/// taken by one AND: `2(w - t)` shifts the rest up within each half and `t / 2^63` (exact in
/// the field) brings bit 63 to 0 and bit 127 to 64. The result is below 2^128, so the checked
/// conversion never fails.
#[inline(always)]
fn rot1x2(w: u128, top: u128) -> u128 {
    let t = w & top;
    let wf: felt252 = w.into();
    let tf: felt252 = t.into();
    let r = wf * 2 + tf * INV63_MINUS_2;
    r.try_into().unwrap()
}

/// The constants of a round, built by a non-inlined call so that inside the round loop
/// they are cells (loop parameters) rather than immediates: a division or subtraction
/// can then use them directly instead of first copying the constant with `store_temp`.
#[derive(Copy, Drop)]
struct RoundConsts {
    two64: NonZero<Two64>,
    mask: Mask128,
    top: u128,
    d2: NonZero<UnitInt<4611686018427387904>>,
    d18: NonZero<UnitInt<70368744177664>>,
    d56: NonZero<UnitInt<256>>,
    d61: NonZero<UnitInt<8>>,
    d3: NonZero<UnitInt<2305843009213693952>>,
    d6: NonZero<UnitInt<288230376151711744>>,
    d8: NonZero<UnitInt<72057594037927936>>,
    d10: NonZero<UnitInt<18014398509481984>>,
    d15: NonZero<UnitInt<562949953421312>>,
    d20: NonZero<UnitInt<17592186044416>>,
    d21: NonZero<UnitInt<8796093022208>>,
    d25: NonZero<UnitInt<549755813888>>,
    d27: NonZero<UnitInt<137438953472>>,
    d28: NonZero<UnitInt<68719476736>>,
    d36: NonZero<UnitInt<268435456>>,
    d39: NonZero<UnitInt<33554432>>,
    d41: NonZero<UnitInt<8388608>>,
    d43: NonZero<UnitInt<2097152>>,
    d44: NonZero<UnitInt<1048576>>,
    d45: NonZero<UnitInt<524288>>,
    d55: NonZero<UnitInt<512>>,
    d62: NonZero<UnitInt<4>>,
    d14: NonZero<UnitInt<1125899906842624>>,
    mask64: Mask64,
}

#[inline(never)]
fn round_consts() -> RoundConsts {
    RoundConsts {
        two64: TWO64_NZ,
        mask: MASK128,
        top: 0x80000000000000008000000000000000,
        d2: 4611686018427387904,
        d18: 70368744177664,
        d56: 256,
        d61: 8,
        d3: 2305843009213693952,
        d6: 288230376151711744,
        d8: 72057594037927936,
        d10: 18014398509481984,
        d15: 562949953421312,
        d20: 17592186044416,
        d21: 8796093022208,
        d25: 549755813888,
        d27: 137438953472,
        d28: 68719476736,
        d36: 268435456,
        d39: 33554432,
        d41: 8388608,
        d43: 2097152,
        d44: 1048576,
        d45: 524288,
        d55: 512,
        d62: 4,
        d14: 1125899906842624,
        mask64: 0xffffffffffffffff,
    }
}

#[inline(always)]
fn not128_k(x: u128, mask: Mask128) -> u128 {
    upcast(bounded_int::sub(mask, x))
}

#[inline(always)]
fn rotl_k(x: u128, pow: Pow, two64: NonZero<Two64>) -> u128 {
    let wide = bounded_int::mul(x, pow);
    let (high, low) = bounded_int::div_rem(wide, two64);
    upcast(bounded_int::add(high, low))
}

#[inline(always)]
fn split_k(w: u128, two64: NonZero<Two64>) -> (u128, u128) {
    let (high, low) = bounded_int::div_rem(w, two64);
    (upcast(high), upcast(low))
}

#[inline(always)]
fn split_exact_k(w: u128, two64: NonZero<Two64>) -> (Low, Low) {
    bounded_int::div_rem(w, two64)
}

impl ConstrainLowTop of ConstrainHelper<Low, 0x8000000000000000> {
    type LowT = BoundedInt<0, 0x7fffffffffffffff>;
    type HighT = BoundedInt<0x8000000000000000, 0xffffffffffffffff>;
}
impl MulRot1High of MulHelper<BoundedInt<0x8000000000000000, 0xffffffffffffffff>, UnitInt<2>> {
    type Result = BoundedInt<0x10000000000000000, 0x1fffffffffffffffe>;
}
impl SubRot1High of SubHelper<BoundedInt<0x10000000000000000, 0x1fffffffffffffffe>, UnitInt<0xffffffffffffffff>> {
    type Result = BoundedInt<1, 0xffffffffffffffff>;
}

/// Rotate left by one with a single range check: below 2^63 the lane just doubles; at or
/// above it, doubling carries bit 63 out to bit 64, and subtracting 2^64 - 1 moves it to bit 0.
#[inline(always)]
fn rotl1_c(x: Low) -> Low {
    let two: UnitInt<2> = 2;
    match constrain::<Low, 0x8000000000000000>(x) {
        Ok(lo) => upcast(bounded_int::mul(lo, two)),
        Err(hi) => {
            let m: UnitInt<0xffffffffffffffff> = 0xffffffffffffffff;
            upcast(bounded_int::sub(bounded_int::mul(hi, two), m))
        },
    }
}

#[inline(always)]
fn rotl_exact_k_1(x: Low, d: NonZero<UnitInt<9223372036854775808>>) -> Low {
    let m: UnitInt<2> = 2;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

#[inline(always)]
fn rotl_exact_k_3(x: Low, d: NonZero<UnitInt<2305843009213693952>>) -> Low {
    let m: UnitInt<8> = 8;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

#[inline(always)]
fn rotl_exact_k_6(x: Low, d: NonZero<UnitInt<288230376151711744>>) -> Low {
    let m: UnitInt<64> = 64;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

#[inline(always)]
fn rotl_exact_k_8(x: Low, d: NonZero<UnitInt<72057594037927936>>) -> Low {
    let m: UnitInt<256> = 256;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

#[inline(always)]
fn rotl_exact_k_10(x: Low, d: NonZero<UnitInt<18014398509481984>>) -> Low {
    let m: UnitInt<1024> = 1024;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

#[inline(always)]
fn rotl_exact_k_15(x: Low, d: NonZero<UnitInt<562949953421312>>) -> Low {
    let m: UnitInt<32768> = 32768;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

#[inline(always)]
fn rotl_exact_k_20(x: Low, d: NonZero<UnitInt<17592186044416>>) -> Low {
    let m: UnitInt<1048576> = 1048576;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

#[inline(always)]
fn rotl_exact_k_21(x: Low, d: NonZero<UnitInt<8796093022208>>) -> Low {
    let m: UnitInt<2097152> = 2097152;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

#[inline(always)]
fn rotl_exact_k_25(x: Low, d: NonZero<UnitInt<549755813888>>) -> Low {
    let m: UnitInt<33554432> = 33554432;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

#[inline(always)]
fn rotl_exact_k_27(x: Low, d: NonZero<UnitInt<137438953472>>) -> Low {
    let m: UnitInt<134217728> = 134217728;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

#[inline(always)]
fn rotl_exact_k_28(x: Low, d: NonZero<UnitInt<68719476736>>) -> Low {
    let m: UnitInt<268435456> = 268435456;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

#[inline(always)]
fn rotl_exact_k_36(x: Low, d: NonZero<UnitInt<268435456>>) -> Low {
    let m: UnitInt<68719476736> = 68719476736;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

#[inline(always)]
fn rotl_exact_k_39(x: Low, d: NonZero<UnitInt<33554432>>) -> Low {
    let m: UnitInt<549755813888> = 549755813888;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

#[inline(always)]
fn rotl_exact_k_41(x: Low, d: NonZero<UnitInt<8388608>>) -> Low {
    let m: UnitInt<2199023255552> = 2199023255552;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

#[inline(always)]
fn rotl_exact_k_43(x: Low, d: NonZero<UnitInt<2097152>>) -> Low {
    let m: UnitInt<8796093022208> = 8796093022208;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

#[inline(always)]
fn rotl_exact_k_44(x: Low, d: NonZero<UnitInt<1048576>>) -> Low {
    let m: UnitInt<17592186044416> = 17592186044416;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

#[inline(always)]
fn rotl_exact_k_45(x: Low, d: NonZero<UnitInt<524288>>) -> Low {
    let m: UnitInt<35184372088832> = 35184372088832;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

#[inline(always)]
fn rotl_exact_k_55(x: Low, d: NonZero<UnitInt<512>>) -> Low {
    let m: UnitInt<36028797018963968> = 36028797018963968;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

#[inline(always)]
fn rotl_exact_k_62(x: Low, d: NonZero<UnitInt<4>>) -> Low {
    let m: UnitInt<4611686018427387904> = 4611686018427387904;
    let (top, rest) = bounded_int::div_rem(x, d);
    bounded_int::add(bounded_int::mul(rest, m), top)
}

/// Lane complementing. The rounds keep some lanes stored complemented, chosen so that chi
/// needs almost no NOTs: for a stored-complemented operand, `~b & c` becomes `b & c` or
/// `b | c` (De Morgan), which the bitwise builtin gives at the same cost. Complements pass
/// through theta, rho and pi unchanged (all XOR-linear, and rotation commutes with NOT); where
/// a lane must change status, theta XORs its word with `~D` instead of `D` (one NOT per mixing
/// word, shared by every row that uses it) or complements the split lane (`2^64 - 1 - x`).
/// Status pattern after rounds 1 to 23 (bit `x + 5y` set = lane (x, y) stored complemented):
/// 0x1108421, i.e. column 0 and lane (4, 4) complemented. Round 24 returns the true state.
/// Each round's choices were found by a search over status patterns and checked lane by lane
/// against a reference Keccak-f in simulation; the known-answer tests check the result.

/// `2^64 - 1 - x` on an exact 64-bit lane.
#[inline(always)]
fn not64(x: Low, mask: Mask64) -> Low {
    bounded_int::sub(mask, x)
}

/// theta for round 1 (layout A input, true state): per row `y`, `u[y]` holds lanes (0, y) and
/// (1, y) and `v[y]` lanes (2, y) and (3, y); column 4 is carried as the pairs ((4, 0), (4, 1))
/// and ((4, 2), (4, 3)) plus lane (4, 4). Rows 2 and 4 take `~D`, and lanes (4, 2) and (4, 4)
/// are complemented, giving the status chi of round 1 expects.
#[inline(always)]
fn theta_a(st: [u128; 12], g4: Low, k: RoundConsts) -> (Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low) {
    let [u0, u1, u2, u3, u4, v0, v1, v2, v3, v4, g01, g23] = st;
    let cc01 = u0 ^ u1 ^ u2 ^ u3 ^ u4;
    let cc23 = v0 ^ v1 ^ v2 ^ v3 ^ v4;
    let (gh, gl) = split_exact_k(g01 ^ g23, k.two64);
    let c4 = xor64(xor64(gh, gl), g4);
    let (c1, c0) = split_exact_k(cc01, k.two64);
    let (c3, c2) = split_exact_k(cc23, k.two64);
    let r0 = rotl1_c(c0);
    // (r1, r2) and (r3, r4) by rotating packed pairs of parities in place.
    let p12 = pack_exact(c1, c2);
    let d01 = pack_exact(c4, c0) ^ rot1x2(p12, k.top);
    let d23 = p12 ^ rot1x2(pack_exact(c3, c4), k.top);
    let nd01 = not128_k(d01, k.mask);
    let nd23 = not128_k(d23, k.mask);
    let d4 = xor64(c3, r0);
    let dd4 = dup_lane(d4);
    let (a01, a00) = split_exact_k(u0 ^ d01, k.two64);
    let (a03, a02) = split_exact_k(v0 ^ d23, k.two64);
    let (a06, a05) = split_exact_k(u1 ^ d01, k.two64);
    let (a08, a07) = split_exact_k(v1 ^ d23, k.two64);
    let (a11, a10) = split_exact_k(u2 ^ nd01, k.two64);
    let (a13, a12) = split_exact_k(v2 ^ nd23, k.two64);
    let (a16, a15) = split_exact_k(u3 ^ d01, k.two64);
    let (a18, a17) = split_exact_k(v3 ^ d23, k.two64);
    let (a21, a20) = split_exact_k(u4 ^ nd01, k.two64);
    let (a23, a22) = split_exact_k(v4 ^ nd23, k.two64);
    let (a09, a04) = split_exact_k(g01 ^ dd4, k.two64);
    let (a19, a14) = split_exact_k(g23 ^ dd4, k.two64);
    let a14 = not64(a14, k.mask64);
    let a24 = not64(xor64(g4, d4), k.mask64);
    (a00, a01, a02, a03, a04, a05, a06, a07, a08, a09, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24)
}

/// theta on layout B: per row `y`, `e[y]` holds lanes (0, y) and (2, y) and `o[y]` lanes
/// (1, y) and (3, y); column 4 as in layout A. The parities come out as (C0, C2) and (C1, C3),
/// so the mixing words (D0, D2) = (C4, C1) ^ rot(C1, C3) and (D1, D3) = (C0, C2) ^ rot(C2, C4)
/// rotate one parity word as it is and use the other unchanged. Rounds 2 to 23: rows 0, 1
/// and 3 of columns (0, 2) and rows 2 and 4 of columns (1, 3) take `~D`, and lane (4, 2) is
/// complemented.
#[inline(always)]
fn theta_b(st: ([u128; 12], Low), k: RoundConsts) -> (Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low) {
    let (st, g4) = st;
    let [e0, e1, e2, e3, e4, o0, o1, o2, o3, o4, g01, g23] = st;
    let cc02 = e0 ^ e1 ^ e2 ^ e3 ^ e4;
    let cc13 = o0 ^ o1 ^ o2 ^ o3 ^ o4;
    let (gh, gl) = split_exact_k(g01 ^ g23, k.two64);
    let c4 = xor64(xor64(gh, gl), g4);
    let (c2, c0) = split_exact_k(cc02, k.two64);
    let (c3, c1) = split_exact_k(cc13, k.two64);
    let r0 = rotl1_c(c0);
    let d02 = pack_exact(c4, c1) ^ rot1x2(cc13, k.top);
    let d13 = cc02 ^ rot1x2(pack_exact(c2, c4), k.top);
    let nd02 = not128_k(d02, k.mask);
    let nd13 = not128_k(d13, k.mask);
    let d4 = xor64(c3, r0);
    let dd4 = dup_lane(d4);
    let (a02, a00) = split_exact_k(e0 ^ nd02, k.two64);
    let (a03, a01) = split_exact_k(o0 ^ d13, k.two64);
    let (a07, a05) = split_exact_k(e1 ^ nd02, k.two64);
    let (a08, a06) = split_exact_k(o1 ^ d13, k.two64);
    let (a12, a10) = split_exact_k(e2 ^ d02, k.two64);
    let (a13, a11) = split_exact_k(o2 ^ nd13, k.two64);
    let (a17, a15) = split_exact_k(e3 ^ nd02, k.two64);
    let (a18, a16) = split_exact_k(o3 ^ d13, k.two64);
    let (a22, a20) = split_exact_k(e4 ^ d02, k.two64);
    let (a23, a21) = split_exact_k(o4 ^ nd13, k.two64);
    let (a09, a04) = split_exact_k(g01 ^ dd4, k.two64);
    let (a19, a14) = split_exact_k(g23 ^ dd4, k.two64);
    let a14 = not64(a14, k.mask64);
    let a24 = xor64(g4, d4);
    (a00, a01, a02, a03, a04, a05, a06, a07, a08, a09, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24)
}

/// theta for round 24 (layout B, status as after round 23): columns (1, 3) and the column-4
/// pairs take `~D`, which gives every row a uniform status for [`chi_a`] to undo.
#[inline(always)]
fn theta_b_last(st: ([u128; 12], Low), k: RoundConsts) -> (Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low) {
    let (st, g4) = st;
    let [e0, e1, e2, e3, e4, o0, o1, o2, o3, o4, g01, g23] = st;
    let cc02 = e0 ^ e1 ^ e2 ^ e3 ^ e4;
    let cc13 = o0 ^ o1 ^ o2 ^ o3 ^ o4;
    let (gh, gl) = split_exact_k(g01 ^ g23, k.two64);
    let c4 = xor64(xor64(gh, gl), g4);
    let (c2, c0) = split_exact_k(cc02, k.two64);
    let (c3, c1) = split_exact_k(cc13, k.two64);
    let r0 = rotl1_c(c0);
    let d02 = pack_exact(c4, c1) ^ rot1x2(cc13, k.top);
    let nd13 = not128_k(cc02 ^ rot1x2(pack_exact(c2, c4), k.top), k.mask);
    let d4 = xor64(c3, r0);
    let ndd4 = not128_k(dup_lane(d4), k.mask);
    let (a02, a00) = split_exact_k(e0 ^ d02, k.two64);
    let (a03, a01) = split_exact_k(o0 ^ nd13, k.two64);
    let (a07, a05) = split_exact_k(e1 ^ d02, k.two64);
    let (a08, a06) = split_exact_k(o1 ^ nd13, k.two64);
    let (a12, a10) = split_exact_k(e2 ^ d02, k.two64);
    let (a13, a11) = split_exact_k(o2 ^ nd13, k.two64);
    let (a17, a15) = split_exact_k(e3 ^ d02, k.two64);
    let (a18, a16) = split_exact_k(o3 ^ nd13, k.two64);
    let (a22, a20) = split_exact_k(e4 ^ d02, k.two64);
    let (a23, a21) = split_exact_k(o4 ^ nd13, k.two64);
    let (a09, a04) = split_exact_k(g01 ^ ndd4, k.two64);
    let (a19, a14) = split_exact_k(g23 ^ ndd4, k.two64);
    let a24 = xor64(g4, d4);
    (a00, a01, a02, a03, a04, a05, a06, a07, a08, a09, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24)
}

/// rho + pi, straight into destination order.
#[inline(always)]
fn rho_pi(a: (Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low), k: RoundConsts) -> (Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low) {
    let (a00, a01, a02, a03, a04, a05, a06, a07, a08, a09, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24) = a;
    let b00 = a00;
    let b01 = rotl_exact_k_44(a06, k.d44);
    let b02 = rotl_exact_k_43(a12, k.d43);
    let b03 = rotl_exact_k_21(a18, k.d21);
    let b04 = rotl_exact_k_14(a24, k.d14);
    let b05 = rotl_exact_k_28(a03, k.d28);
    let b06 = rotl_exact_k_20(a09, k.d20);
    let b07 = rotl_exact_k_3(a10, k.d3);
    let b08 = rotl_exact_k_45(a16, k.d45);
    let b09 = rotl_exact_k_61(a22, k.d61);
    let b10 = rotl1_c(a01);
    let b11 = rotl_exact_k_6(a07, k.d6);
    let b12 = rotl_exact_k_25(a13, k.d25);
    let b13 = rotl_exact_k_8(a19, k.d8);
    let b14 = rotl_exact_k_18(a20, k.d18);
    let b15 = rotl_exact_k_27(a04, k.d27);
    let b16 = rotl_exact_k_36(a05, k.d36);
    let b17 = rotl_exact_k_10(a11, k.d10);
    let b18 = rotl_exact_k_15(a17, k.d15);
    let b19 = rotl_exact_k_56(a23, k.d56);
    let b20 = rotl_exact_k_62(a02, k.d62);
    let b21 = rotl_exact_k_55(a08, k.d55);
    let b22 = rotl_exact_k_39(a14, k.d39);
    let b23 = rotl_exact_k_41(a15, k.d41);
    let b24 = rotl_exact_k_2(a21, k.d2);
    (b00, b01, b02, b03, b04, b05, b06, b07, b08, b09, b10, b11, b12, b13, b14, b15, b16, b17, b18, b19, b20, b21, b22, b23, b24)
}

/// chi + iota into layout A: along each row on column pairs (0, 1) and (2, 3); column 4 on
/// row pairs (0, 1) and (2, 3), then lane (4, 4).
#[inline(always)]
fn chi_a(b: (Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low), rc: u128, k: RoundConsts) -> ([u128; 12], Low) {
    let (b00, b01, b02, b03, b04, b05, b06, b07, b08, b09, b10, b11, b12, b13, b14, b15, b16, b17, b18, b19, b20, b21, b22, b23, b24) = b;
    let s05 = scale_hi(b05);
    let s06 = scale_hi(b06);
    let s15 = scale_hi(b15);
    let s16 = scale_hi(b16);
    let s19 = scale_hi(b19);
    let s09 = scale_hi(b09);
    let p001 = pack_exact(b00, b01);
    let p012 = pack_exact(b01, b02);
    let p023 = pack_exact(b02, b03);
    let p034 = pack_exact(b03, b04);
    let p040 = pack_exact(b04, b00);
    let p101 = pack_scaled(b05, s06);
    let p112 = pack_exact(b06, b07);
    let p123 = pack_exact(b07, b08);
    let p134 = pack_scaled(b08, s09);
    let p140 = pack_scaled(b09, s05);
    let p201 = pack_exact(b10, b11);
    let p212 = pack_exact(b11, b12);
    let p223 = pack_exact(b12, b13);
    let p234 = pack_exact(b13, b14);
    let p240 = pack_exact(b14, b10);
    let p301 = pack_scaled(b15, s16);
    let p312 = pack_exact(b16, b17);
    let p323 = pack_exact(b17, b18);
    let p334 = pack_scaled(b18, s19);
    let p340 = pack_scaled(b19, s15);
    let p401 = pack_exact(b20, b21);
    let p412 = pack_exact(b21, b22);
    let p423 = pack_exact(b22, b23);
    let p434 = pack_exact(b23, b24);
    let p440 = pack_exact(b24, b20);
    let h01 = pack_scaled(b04, s09);
    let n01 = pack_scaled(b00, s05);
    let m01 = pack_scaled(b01, s06);
    let h23 = pack_scaled(b14, s19);
    let n23 = pack_scaled(b10, s15);
    let m23 = pack_scaled(b11, s16);
    ([
        p001 ^ (not128_k(p012, k.mask) & p023) ^ rc,
        p101 ^ (not128_k(p112, k.mask) & p123),
        p201 ^ (not128_k(p212, k.mask) & p223),
        p301 ^ (not128_k(p312, k.mask) & p323),
        p401 ^ (not128_k(p412, k.mask) & p423),
        p023 ^ (not128_k(p034, k.mask) & p040),
        p123 ^ (not128_k(p134, k.mask) & p140),
        p223 ^ (not128_k(p234, k.mask) & p240),
        p323 ^ (not128_k(p334, k.mask) & p340),
        p423 ^ (not128_k(p434, k.mask) & p440),
        h01 ^ (not128_k(n01, k.mask) & m01),
        h23 ^ (not128_k(n23, k.mask) & m23),
    ], xor64(b24, andn64(b20, b21, k.mask64)))
}

/// `b | c` on exact 64-bit lanes.
#[inline(always)]
fn or64(b: Low, c: Low) -> Low {
    let b: u64 = upcast(b);
    let c: u64 = upcast(c);
    upcast(b | c)
}

/// chi + iota of round 1 into layout B (true state in, status 0x1108421 out): along each
/// row on column pairs (0, 2) and (1, 3) with packs (0, 2), (1, 3), (2, 4), (3, 0). Every row of
/// the input has status (0, 0, 1, 0, 1), so `~b & c` is `b | c` for lanes 0 and 2 and `b & c`
/// for lanes 1 and 3 (no NOT); column 4 needs one NOT per word.
#[inline(always)]
fn chi_b_first(b: (Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low), rc: u128, k: RoundConsts) -> ([u128; 12], Low) {
    let (b00, b01, b02, b03, b04, b05, b06, b07, b08, b09, b10, b11, b12, b13, b14, b15, b16, b17, b18, b19, b20, b21, b22, b23, b24) = b;
    let s05 = scale_hi(b05);
    let s15 = scale_hi(b15);
    let s19 = scale_hi(b19);
    let s09 = scale_hi(b09);
    let q002 = pack_exact(b00, b02);
    let q013 = pack_exact(b01, b03);
    let q024 = pack_exact(b02, b04);
    let q030 = pack_exact(b03, b00);
    let q102 = pack_exact(b05, b07);
    let q113 = pack_exact(b06, b08);
    let q124 = pack_scaled(b07, s09);
    let q130 = pack_scaled(b08, s05);
    let q202 = pack_exact(b10, b12);
    let q213 = pack_exact(b11, b13);
    let q224 = pack_exact(b12, b14);
    let q230 = pack_exact(b13, b10);
    let q302 = pack_exact(b15, b17);
    let q313 = pack_exact(b16, b18);
    let q324 = pack_scaled(b17, s19);
    let q330 = pack_scaled(b18, s15);
    let q402 = pack_exact(b20, b22);
    let q413 = pack_exact(b21, b23);
    let q424 = pack_exact(b22, b24);
    let q430 = pack_exact(b23, b20);
    let h01 = pack_scaled(b04, s09);
    let n01 = pack_scaled(b00, s05);
    let m01 = pack_exact(b01, b06);
    let h23 = pack_scaled(b14, s19);
    let n23 = pack_scaled(b10, s15);
    let m23 = pack_exact(b11, b16);
    ([
        q002 ^ (q013 | q024) ^ rc,
        q102 ^ (q113 | q124),
        q202 ^ (q213 | q224),
        q302 ^ (q313 | q324),
        q402 ^ (q413 | q424),
        q013 ^ (q024 & q030),
        q113 ^ (q124 & q130),
        q213 ^ (q224 & q230),
        q313 ^ (q324 & q330),
        q413 ^ (q424 & q430),
        h01 ^ (n01 | not128_k(m01, k.mask)),
        h23 ^ (n23 | not128_k(m23, k.mask)),
    ], xor64(b24, andn64(b20, b21, k.mask64)))
}

/// chi + iota of rounds 2 to 23 into layout B (status 0x1108421 in and out). Every row of the
/// input has status (1, 1, 0, 1, 0), so `~b & c` is `b & c` for lanes 0 and 2 and `b | c` for
/// lanes 1 and 3 (no NOT); column 4 needs one NOT per word.
#[inline(always)]
fn chi_b(b: (Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low, Low), rc: u128, k: RoundConsts) -> ([u128; 12], Low) {
    let (b00, b01, b02, b03, b04, b05, b06, b07, b08, b09, b10, b11, b12, b13, b14, b15, b16, b17, b18, b19, b20, b21, b22, b23, b24) = b;
    let s05 = scale_hi(b05);
    let s15 = scale_hi(b15);
    let s19 = scale_hi(b19);
    let s09 = scale_hi(b09);
    let q002 = pack_exact(b00, b02);
    let q013 = pack_exact(b01, b03);
    let q024 = pack_exact(b02, b04);
    let q030 = pack_exact(b03, b00);
    let q102 = pack_exact(b05, b07);
    let q113 = pack_exact(b06, b08);
    let q124 = pack_scaled(b07, s09);
    let q130 = pack_scaled(b08, s05);
    let q202 = pack_exact(b10, b12);
    let q213 = pack_exact(b11, b13);
    let q224 = pack_exact(b12, b14);
    let q230 = pack_exact(b13, b10);
    let q302 = pack_exact(b15, b17);
    let q313 = pack_exact(b16, b18);
    let q324 = pack_scaled(b17, s19);
    let q330 = pack_scaled(b18, s15);
    let q402 = pack_exact(b20, b22);
    let q413 = pack_exact(b21, b23);
    let q424 = pack_exact(b22, b24);
    let q430 = pack_exact(b23, b20);
    let h01 = pack_scaled(b04, s09);
    let n01 = pack_scaled(b00, s05);
    let m01 = pack_exact(b01, b06);
    let h23 = pack_scaled(b14, s19);
    let n23 = pack_scaled(b10, s15);
    let m23 = pack_exact(b11, b16);
    ([
        q002 ^ (q013 & q024) ^ rc,
        q102 ^ (q113 & q124),
        q202 ^ (q213 & q224),
        q302 ^ (q313 & q324),
        q402 ^ (q413 & q424),
        q013 ^ (q024 | q030),
        q113 ^ (q124 | q130),
        q213 ^ (q224 | q230),
        q313 ^ (q324 | q330),
        q413 ^ (q424 | q430),
        h01 ^ (n01 & not128_k(m01, k.mask)),
        h23 ^ (n23 & not128_k(m23, k.mask)),
    ], xor64(b24, or64(not64(b20, k.mask64), b21)))
}

/// Keccak-f[1600] on the packed 13-word state, in layout A at both ends (see [`theta_a`]); the
/// squeezer keeps its state packed between permutations. Rounds 2 to 24 take layout B
/// (see [`theta_b`]), whose chi needs fewer packs: rho/pi splits every lane anyway, so chi can
/// pack into either layout.
#[inline(always)]
pub(crate) fn keccak_f1600_packed(st: [u128; 13]) -> [u128; 13] {
    let [u0, u1, u2, u3, u4, v0, v1, v2, v3, v4, g01, g23, g4] = st;
    // Lane (4, 4) is below 2^64 (lane invariant); typing it so keeps column 4 exact.
    let g4: u64 = g4.try_into().unwrap();
    let ([u0, u1, u2, u3, u4, v0, v1, v2, v3, v4, g01, g23], g4) = keccak_f1600_lanes(
        [u0, u1, u2, u3, u4, v0, v1, v2, v3, v4, g01, g23], upcast(g4),
    );
    [u0, u1, u2, u3, u4, v0, v1, v2, v3, v4, g01, g23, upcast(g4)]
}

/// [`keccak_f1600_packed`] with lane (4, 4) carried apart and typed below 2^64, so a caller
/// that keeps the state between permutations (the squeezer) pays no check on it.
pub(crate) fn keccak_f1600_lanes(st: [u128; 12], g4: Low) -> ([u128; 12], Low) {
    let k = round_consts();
    // All 24 rounds straight-line; the round constants come from memory in one read.
    let [rc0, rc1, rc2, rc3, rc4, rc5, rc6, rc7, rc8, rc9, rc10, rc11, rc12, rc13, rc14, rc15, rc16, rc17, rc18, rc19, rc20, rc21, rc22, rc23] = core::box::BoxTrait::new(ROUND_CONSTANTS).unbox();
    let mut st = chi_b_first(rho_pi(theta_a(st, g4, k), k), rc0, k);
    st = chi_b(rho_pi(theta_b(st, k), k), rc1, k);
    st = chi_b(rho_pi(theta_b(st, k), k), rc2, k);
    st = chi_b(rho_pi(theta_b(st, k), k), rc3, k);
    st = chi_b(rho_pi(theta_b(st, k), k), rc4, k);
    st = chi_b(rho_pi(theta_b(st, k), k), rc5, k);
    st = chi_b(rho_pi(theta_b(st, k), k), rc6, k);
    st = chi_b(rho_pi(theta_b(st, k), k), rc7, k);
    st = chi_b(rho_pi(theta_b(st, k), k), rc8, k);
    st = chi_b(rho_pi(theta_b(st, k), k), rc9, k);
    st = chi_b(rho_pi(theta_b(st, k), k), rc10, k);
    st = chi_b(rho_pi(theta_b(st, k), k), rc11, k);
    st = chi_b(rho_pi(theta_b(st, k), k), rc12, k);
    st = chi_b(rho_pi(theta_b(st, k), k), rc13, k);
    st = chi_b(rho_pi(theta_b(st, k), k), rc14, k);
    st = chi_b(rho_pi(theta_b(st, k), k), rc15, k);
    st = chi_b(rho_pi(theta_b(st, k), k), rc16, k);
    st = chi_b(rho_pi(theta_b(st, k), k), rc17, k);
    st = chi_b(rho_pi(theta_b(st, k), k), rc18, k);
    st = chi_b(rho_pi(theta_b(st, k), k), rc19, k);
    st = chi_b(rho_pi(theta_b(st, k), k), rc20, k);
    st = chi_b(rho_pi(theta_b(st, k), k), rc21, k);
    st = chi_b(rho_pi(theta_b(st, k), k), rc22, k);
    chi_a(rho_pi(theta_b_last(st, k), k), rc23, k)
}

pub(crate) fn keccak_f1600(state: [u128; 25]) -> [u128; 25] {
    let [s00, s01, s02, s03, s04, s05, s06, s07, s08, s09, s10, s11, s12, s13, s14, s15, s16, s17, s18, s19, s20, s21, s22, s23, s24] = state;
    let st: [u128; 13] = [
        pack(s00, s01), pack(s05, s06), pack(s10, s11), pack(s15, s16), pack(s20, s21),
        pack(s02, s03), pack(s07, s08), pack(s12, s13), pack(s17, s18), pack(s22, s23),
        pack(s04, s09), pack(s14, s19), s24,
    ];
    let st = keccak_f1600_packed(st);
    let [u0, u1, u2, u3, u4, v0, v1, v2, v3, v4, g01, g23, g4] = st;
    let (o01, o00) = split(u0);
    let (o06, o05) = split(u1);
    let (o11, o10) = split(u2);
    let (o16, o15) = split(u3);
    let (o21, o20) = split(u4);
    let (o03, o02) = split(v0);
    let (o08, o07) = split(v1);
    let (o13, o12) = split(v2);
    let (o18, o17) = split(v3);
    let (o23, o22) = split(v4);
    let (o09, o04) = split(g01);
    let (o19, o14) = split(g23);
    [o00, o01, o02, o03, o04, o05, o06, o07, o08, o09, o10, o11, o12, o13, o14, o15, o16, o17, o18, o19, o20, o21, o22, o23, g4]
}
/// SHAKE-256: absorb `input`, squeeze `out_bytes` bytes.
pub(crate) fn shake256(input: Array<u8>, out_bytes: u32) -> Array<u8> {
    // Pad (pad10*1 with SHAKE domain 0x1F) to a multiple of the rate.
    let mut padded = input;
    let l = padded.len();
    let pad_len = RATE_BYTES - (l % RATE_BYTES); // in [1, RATE_BYTES]
    padded.append(0x1f);
    let mut z = 1;
    while z != pad_len {
        padded.append(0);
        z += 1;
    }
    let last_idx = l + pad_len - 1;
    let bytes = pad_ored_msb(padded, last_idx);

    // Absorb rate-sized blocks: XOR each block's 17 lanes into the state, permute.
    let mut state = [0_u128; 25];
    let n_blocks = (l + pad_len) / RATE_BYTES;
    let mut blk = 0;
    while blk != n_blocks {
        let base = blk * RATE_BYTES;
        let [
            s00,
            s01,
            s02,
            s03,
            s04,
            s05,
            s06,
            s07,
            s08,
            s09,
            s10,
            s11,
            s12,
            s13,
            s14,
            s15,
            s16,
            s17,
            s18,
            s19,
            s20,
            s21,
            s22,
            s23,
            s24,
        ] =
            state;
        state =
            keccak_f1600(
                [
                    s00 ^ load_lane_le(@bytes, base), s01 ^ load_lane_le(@bytes, base + 8),
                    s02 ^ load_lane_le(@bytes, base + 16), s03 ^ load_lane_le(@bytes, base + 24),
                    s04 ^ load_lane_le(@bytes, base + 32), s05 ^ load_lane_le(@bytes, base + 40),
                    s06 ^ load_lane_le(@bytes, base + 48), s07 ^ load_lane_le(@bytes, base + 56),
                    s08 ^ load_lane_le(@bytes, base + 64), s09 ^ load_lane_le(@bytes, base + 72),
                    s10 ^ load_lane_le(@bytes, base + 80), s11 ^ load_lane_le(@bytes, base + 88),
                    s12 ^ load_lane_le(@bytes, base + 96), s13 ^ load_lane_le(@bytes, base + 104),
                    s14 ^ load_lane_le(@bytes, base + 112), s15 ^ load_lane_le(@bytes, base + 120),
                    s16 ^ load_lane_le(@bytes, base + 128), s17, s18, s19, s20, s21, s22, s23, s24,
                ],
            );
        blk += 1;
    }

    // Squeeze rate-sized blocks, permuting only when more output is needed.
    let mut out: Array<u8> = array![];
    loop {
        let mut lanes = state.span().slice(0, RATE_LANES);
        while let Some(lane) = lanes.pop_front() {
            emit_lane_le(*lane, ref out, out_bytes);
        }
        if out.len() == out_bytes {
            break;
        }
        state = keccak_f1600(state);
    }
    out
}

/// Append up to 8 little-endian bytes of the lane `v` (< 2^64), stopping at `out_bytes`.
fn emit_lane_le(v: u128, ref out: Array<u8>, out_bytes: u32) {
    let mut rem: u64 = v.try_into().unwrap();
    let mut k = 0;
    while k != 8 && out.len() < out_bytes {
        out.append((rem % 256).try_into().unwrap());
        rem = rem / 256;
        k += 1;
    }
}

/// Rebuild `bytes` with `bytes[idx] |= 0x80` (that byte is < 0x80 here, so `+ 0x80`).
fn pad_ored_msb(bytes: Array<u8>, idx: u32) -> Array<u8> {
    let mut out: Array<u8> = array![];
    let span = bytes.span();
    let mut i = 0;
    while i != span.len() {
        if i == idx {
            out.append(*span[i] + 0x80);
        } else {
            out.append(*span[i]);
        }
        i += 1;
    }
    out
}

/// Little-endian 64-bit lane from 8 bytes at `off`.
fn load_lane_le(bytes: @Array<u8>, off: u32) -> u128 {
    let span = bytes.span();
    let mut acc: u128 = 0;
    let mut k = 8;
    while k != 0 {
        k -= 1;
        acc = acc * 256 + (*span[off + k]).into();
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::shake256;

    fn to_hex(bytes: Array<u8>) -> ByteArray {
        let hexchars: ByteArray = "0123456789abcdef";
        let mut s: ByteArray = "";
        let mut span = bytes.span();
        while let Some(b) = span.pop_front() {
            s.append_byte(hexchars.at((*b / 16).into()).unwrap());
            s.append_byte(hexchars.at((*b % 16).into()).unwrap());
        }
        s
    }

    // KAT vectors from Python `hashlib.shake_256` (FIPS 202).
    #[test]
    fn test_shake256_empty() {
        let got = to_hex(shake256(array![], 32));
        assert!(got == "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f");
    }

    #[test]
    fn test_shake256_abc() {
        let got = to_hex(shake256(array![0x61, 0x62, 0x63], 32));
        assert!(got == "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739");
    }

    // 200 bytes of 0xA3: a 2-block absorb (input > 136-byte rate). NIST SHAKE-256 vector.
    #[test]
    fn test_shake256_multiblock() {
        let mut input: Array<u8> = array![];
        let mut i = 0;
        while i != 200_u32 {
            input.append(0xa3);
            i += 1;
        }
        let got = to_hex(shake256(input, 32));
        assert!(got == "cd8a920ed141aa0407a22d59288652e9d9f1a7ee0c1e7c1ca699424da84a904d");
    }

    // Squeeze past one rate block (137 bytes > 136): exercises the squeeze-side
    // permutation. Tail bytes from Python `hashlib.shake_256(b"abc").hexdigest(137)`.
    #[test]
    fn test_shake256_multiblock_squeeze() {
        let out = shake256(array![0x61, 0x62, 0x63], 137);
        assert_eq!(out.len(), 137);
        // First bytes match the 32-byte KAT above.
        assert_eq!(*out.at(0), 0x48);
        assert_eq!(*out.at(1), 0x33);
        // Bytes 128.. of the stream: e8 a2 d7 ec 71 a7 cc 29 cf (last is out[136]).
        let tail: [u8; 9] = [0xe8, 0xa2, 0xd7, 0xec, 0x71, 0xa7, 0xcc, 0x29, 0xcf];
        let mut i: u32 = 128;
        for expected in tail.span() {
            assert_eq!(*out.at(i), *expected);
            i += 1;
        }
    }
}


#[cfg(test)]
mod keccak_f_vectors {
    use super::keccak_f1600;
    #[test]
    fn test_keccak_f_vector_0_falcon_512_shake() {
        let out = keccak_f1600([0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0]);
        assert!(out.span() == [0xf1258f7940e1dde7, 0x84d5ccf933c0478a, 0xd598261ea65aa9ee, 0xbd1547306f80494d, 0x8b284e056253d057, 0xff97a42d7f8e6fd4, 0x90fee5a0a44647c4, 0x8c5bda0cd6192e76, 0xad30a6f71b19059c, 0x30935ab7d08ffc64, 0xeb5aa93f2317d635, 0xa9a6e6260d712103, 0x81a57c16dbcf555f, 0x43b831cd0347c826, 0x1f22f1a11a5569f, 0x5e5635a21d9ae61, 0x64befef28cc970f2, 0x613670957bc46611, 0xb87c5a554fd00ecb, 0x8c3ee88a1ccf32c8, 0x940c7922ae3a2614, 0x1841f924a2c509e4, 0x16f53526e70465c2, 0x75f644e97f30a13b, 0xeaf1ff7b5ceca249].span());
    }
    #[test]
    fn test_keccak_f_vector_1_falcon_512_shake() {
        let out = keccak_f1600([0xf1258f7940e1dde7, 0x84d5ccf933c0478a, 0xd598261ea65aa9ee, 0xbd1547306f80494d, 0x8b284e056253d057, 0xff97a42d7f8e6fd4, 0x90fee5a0a44647c4, 0x8c5bda0cd6192e76, 0xad30a6f71b19059c, 0x30935ab7d08ffc64, 0xeb5aa93f2317d635, 0xa9a6e6260d712103, 0x81a57c16dbcf555f, 0x43b831cd0347c826, 0x1f22f1a11a5569f, 0x5e5635a21d9ae61, 0x64befef28cc970f2, 0x613670957bc46611, 0xb87c5a554fd00ecb, 0x8c3ee88a1ccf32c8, 0x940c7922ae3a2614, 0x1841f924a2c509e4, 0x16f53526e70465c2, 0x75f644e97f30a13b, 0xeaf1ff7b5ceca249]);
        assert!(out.span() == [0x2d5c954df96ecb3c, 0x6a332cd07057b56d, 0x93d8d1270d76b6c, 0x8a20d9b25569d094, 0x4f9c4f99e5e7f156, 0xf957b9a2da65fb38, 0x85773dae1275af0d, 0xfaf4f247c3d810f7, 0x1f1b9ee6f79a8759, 0xe4fecc0fee98b425, 0x68ce61b6b9ce68a1, 0xdeea66c4ba8f974f, 0x33c43d836eafb1f5, 0xe00654042719dbd9, 0x7cf8a9f009831265, 0xfd5449a6bf174743, 0x97ddad33d8994b40, 0x48ead5fc5d0be774, 0xe3b8c8ee55b7b03c, 0x91a0226e649e42e9, 0x900e3129e7badd7b, 0x202a9ec5faa3cce8, 0x5b3402464e1c3db6, 0x609f4e62a44c1059, 0x20d06cd26a8fbf5c].span());
    }
    #[test]
    fn test_keccak_f_vector_2_falcon_512_shake() {
        let out = keccak_f1600([0xc93a7b79aeda89b, 0x19274f6f35db5136, 0x25baf726d0c8f9d1, 0x324e9ede6bb6a26c, 0x3ee2469606a44b07, 0x4b75ee4da191f3a2, 0x580996053c7f9c3d, 0x649d3dbcd76d44d8, 0x7130e574725aed73, 0x7dc48d2c0d48960e, 0x8a5834e3a8363ea9, 0x96ebdc9b4323e744, 0xa37f8452de118fdf, 0xb0132c0a78ff387a, 0xbca6d3c213ece115, 0xc93a7b79aeda89b0, 0xd5ce233149c8324b, 0xe261cae8e4b5dae6, 0xeef572a07fa38381, 0xfb891a581a912c1c, 0x81cc20fb57ed4b7, 0x14b069c7506c7d52, 0x2144117eeb5a25ed, 0x2dd7b9368647ce88, 0x3a6b60ee21357723]);
        assert!(out.span() == [0x9a55f58818107b8b, 0x9c237535940baf72, 0xbd0c324152d6220d, 0x9da8569ccdb5dd3a, 0xf0d46ce0f516f6ef, 0x53e71ddc3d52f807, 0xf4607b43da76737, 0x335f9806c8093c30, 0xb7fe91f3443df64, 0xa8daf764a67c5b2d, 0xc4d14662ca484e1d, 0xce05173999243243, 0xce0794b41ae88376, 0x58bc49864db0750d, 0x95e1762981b2c986, 0xe589329e740f147, 0x43a283a94c4c4392, 0x48b1b58973e61ee2, 0x32d7ccb6f0dd477b, 0x7d5ca23bf2b6a73, 0x69dd5a92ff95434d, 0x8d7da9e66673bf7a, 0x28df10e4105aab86, 0xae75fe0245d5b0de, 0xf6e32cdf7679c422].span());
    }
    #[test]
    fn test_keccak_f_vector_3_falcon_512_shake() {
        let out = keccak_f1600([0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff, 0xffffffffffffffff]);
        assert!(out.span() == [0x9f00f21bba6817c4, 0xcdf5aa0d21af5e78, 0xd6539abf24095b97, 0x8bb6f30a010f8228, 0xf0f711ba0547331d, 0x4f44330558eb182f, 0x2213b79d9055207c, 0xeb5e5b55ca4fb490, 0xbfaeb81a299b5d4, 0x9e5d924f1a65ed48, 0x4650c533b7bfb3, 0xddad454b84d7ab05, 0xf03ce56503e82921, 0xce442e92c6728660, 0x1a9ce5e4b37ddcd3, 0xf63b60e27cea6f0e, 0xcc4cc7fca665bfad, 0x40cf4eba54a2285d, 0x2725f1f142304213, 0x554d327de6fbad9b, 0x19866a26cbc8bdc2, 0xe8c3c28faf02c7f5, 0xc6bc1f3512a665ae, 0xcaa831f1a5dc86ce, 0x3f82afe91ca4b9b0].span());
    }
    #[test]
    fn test_keccak_f_iterated_falcon_512_shake() {
        let mut s: [u128; 25] = [0; 25];
        let mut i: u32 = 0;
        while i < 5 {
            s = keccak_f1600(s);
            i += 1;
        }
        assert!(s.span() == [0xc9f309ff271c6631, 0x9281c8b3825841b4, 0x2219cb1928ca14c4, 0xf50d1d2ae140281a, 0xf0a33a68985b6934, 0xd8a79767500429f6, 0xbe55a8fff0767faf, 0xbc2a9530cca9d7a8, 0x7e7947debc81b851, 0x772429b40aa052a8, 0x58f891e79ce86365, 0x3110152cadf8860f, 0x7f6f0628bda22d08, 0xa89fb4db4293cc0a, 0x390bca6688ab09be, 0xfadcbb8bbbedce4b, 0x2d78a388460c4a73, 0xe692f192c06ea9ae, 0x909de0d99f0083f0, 0x76773fcdc7e9d261, 0x344d00ae9d02c853, 0x9d85cb92ef2a6155, 0xa1a8ecf6537e0b3, 0xa6da3fb1f1688e95, 0xcfe9307b7db8bed0].span());
    }
}
