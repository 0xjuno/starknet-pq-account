//! Hash-to-point for Falcon-512, three backends sharing one rejection rule
//! ([`push_candidate`]): the non-standard BLAKE2s counter-mode construction
//! ([`hash_to_point_512`]), the standard SHAKE-256 construction of the Falcon spec
//! ([`hash_to_point_shake_512`], interoperable with stock signers like falcon.py), and a
//! Poseidon squeeze over the native `hades_permutation` builtin
//! ([`hash_to_point_poseidon_512`], non-standard but native and inexpensive).
//!
//! ## BLAKE2s backend
//!
//! Maps `(message_hash, salt)` to 512 coefficients in `[0, Q)`:
//!
//! ```text
//! prefix   = salt_a[20 bytes LE] || salt_b[20 bytes LE] || message_hash[32 bytes LE]
//! digest_i = blake2s-256(prefix || u32_le(i))          for i = 0, 1, 2, ...
//! ```
//!
//! Each digest yields 16 little-endian u16 candidates, consumed in order; candidates
//! < 61445 (= 5Q, the largest multiple of Q below 2^16) are accepted as `candidate % Q`
//! (uniform in `[0, Q)`), until 512 coefficients are collected — the same rejection rule
//! as the SHAKE-256 construction in the Falcon spec.
//!
//! The salt is 40 bytes (the FIPS-206 salt length), carried as two felts of 20 bytes each.
//!
//! The XOF is BLAKE2s in counter mode (the Cairo-native `core::blake` builtin), not the
//! SHAKE-256 of FIPS 206: signatures are NOT FIPS-206-interoperable, and the off-chain
//! signer must hash with this exact construction (see `scripts/gen_falcon_fixture.py`).

use core::blake::{blake2s_compress, blake2s_finalize};
use core::poseidon::hades_permutation;
use corelib_imports::bounded_int::{
    BoundedInt, DivRemHelper, UnitInt, bounded_int_div_rem, downcast, upcast,
};
#[feature("bounded-int-utils")]
use core::internal::bounded_int::{ConstrainHelper, constrain};
use super::shake256::{Low, keccak_f1600_lanes, keccak_f1600_packed, pack, pack_exact};
use corelib_imports::bounded_int::{AddHelper, MulHelper, bounded_int};
type Q32 = BoundedInt<0, 0xffffffff>;
type T32 = UnitInt<0x100000000>;
const T32_V: T32 = 0x100000000;
impl DivRemU128T32 of DivRemHelper<u128, T32> {
    type DivT = BoundedInt<0, 0xffffffffffffffffffffffff>;
    type RemT = Q32;
}
impl DivRemQ96Two64 of DivRemHelper<BoundedInt<0, 0xffffffffffffffffffffffff>, SqueezeTwo64> {
    type DivT = Q32;
    type RemT = Low;
}
type T96 = UnitInt<0x1000000000000000000000000>;
impl DivRemU128T96 of DivRemHelper<u128, T96> {
    type DivT = Q32;
    type RemT = BoundedInt<0, 0xffffffffffffffffffffffff>;
}
impl MulQ96T32 of MulHelper<BoundedInt<0, 0xffffffffffffffffffffffff>, T32> {
    type Result = BoundedInt<0, 0xffffffffffffffffffffffff00000000>;
}
impl AddQ32Q96Hi of AddHelper<Q32, BoundedInt<0, 0xffffffffffffffffffffffff00000000>> {
    type Result = BoundedInt<0, 0xffffffffffffffffffffffffffffffff>;
}
impl MulQ32T32 of MulHelper<Q32, T32> {
    type Result = BoundedInt<0, 0xffffffff00000000>;
}
impl AddQ32Hi of AddHelper<Q32, BoundedInt<0, 0xffffffff00000000>> {
    type Result = Low;
}

/// blake2s-256 initial state: the BLAKE2s IV with the standard parameter word
/// (digest_length = 32, key = 0, fanout = 1, depth = 1) XORed into h[0].
const BLAKE2S_256_INIT: [u32; 8] = [
    0x6B08E647, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

/// Rejection bound: the largest multiple of Q below 2^16 (5 * 12289).
const REJECT_BOUND: u32 = 61445;

/// Each salt felt must fit in 20 bytes.
const TWO_POW_160: u256 = 0x10000000000000000000000000000000000000000_u256;

/// Total bytes hashed per counter block: 40 (salt) + 32 (message hash) + 4 (counter).
const HASH_INPUT_BYTES: u32 = 76;

// Exact bounds for reading a felt's low 240 bits as little-endian 16-bit words.
// Each division peels one word; the final quotient after seven divisions is itself
// one 16-bit word for the low half and is discarded for the high half.
type Word16 = BoundedInt<0, 65535>;
type AcceptedWord = BoundedInt<0, 61444>;
type Base16 = UnitInt<65536>;
type Quot112 = BoundedInt<0, 5192296858534827628530496329220095>;
type Quot96 = BoundedInt<0, 79228162514264337593543950335>;
type Quot80 = BoundedInt<0, 1208925819614629174706175>;
type Quot64 = BoundedInt<0, 18446744073709551615>;
type Quot48 = BoundedInt<0, 281474976710655>;
type Quot32 = BoundedInt<0, 4294967295>;
type PoseidonQ = UnitInt<12289>;
type PoseidonZq = BoundedInt<0, 12288>;

const BASE16_NZ: NonZero<Base16> = 65536;
const POSEIDON_Q_NZ: NonZero<PoseidonQ> = 12289;

impl DivRemU128ByBase16 of DivRemHelper<u128, Base16> {
    type DivT = Quot112;
    type RemT = Word16;
}

impl DivRemQuot112ByBase16 of DivRemHelper<Quot112, Base16> {
    type DivT = Quot96;
    type RemT = Word16;
}

impl DivRemQuot96ByBase16 of DivRemHelper<Quot96, Base16> {
    type DivT = Quot80;
    type RemT = Word16;
}

impl DivRemQuot80ByBase16 of DivRemHelper<Quot80, Base16> {
    type DivT = Quot64;
    type RemT = Word16;
}

impl DivRemQuot64ByBase16 of DivRemHelper<Quot64, Base16> {
    type DivT = Quot48;
    type RemT = Word16;
}

impl DivRemQuot48ByBase16 of DivRemHelper<Quot48, Base16> {
    type DivT = Quot32;
    type RemT = Word16;
}

impl DivRemQuot32ByBase16 of DivRemHelper<Quot32, Base16> {
    type DivT = Word16;
    type RemT = Word16;
}

impl DivRemAcceptedWordByPoseidonQ of DivRemHelper<AcceptedWord, PoseidonQ> {
    type DivT = BoundedInt<0, 4>;
    type RemT = PoseidonZq;
}

/// Hash `(message_hash, salt)` to 512 coefficients in `[0, Q)`.
/// Returns `None` if either salt felt exceeds 20 bytes.
pub fn hash_to_point_512(
    message_hash: felt252, salt_a: felt252, salt_b: felt252,
) -> Option<Array<u16>> {
    let sa: u256 = salt_a.into();
    let sb: u256 = salt_b.into();
    if sa >= TWO_POW_160 || sb >= TWO_POW_160 {
        return None;
    }
    let (a0, a1, a2, a3, a4) = limbs_160(sa);
    let (b0, b1, b2, b3, b4) = limbs_160(sb);
    let mh: u256 = message_hash.into();
    let (m0, m1, m2, m3) = limbs_128(mh.low);
    let (m4, m5, m6, m7) = limbs_128(mh.high);

    // Bytes 0..63 (identical for every counter, so compressed once): the 40-byte salt
    // followed by the first 24 bytes of the message hash.
    let prefix_state = blake2s_compress(
        BoxTrait::new(BLAKE2S_256_INIT),
        64,
        BoxTrait::new([a0, a1, a2, a3, a4, b0, b1, b2, b3, b4, m0, m1, m2, m3, m4, m5]),
    )
        .unbox();

    let sixteen_bits: NonZero<u32> = 0x10000_u32.try_into().unwrap();
    let q32: NonZero<u32> = 12289_u32.try_into().unwrap();
    let mut coeffs: Array<u16> = array![];
    let mut ctr: u32 = 0;
    while coeffs.len() != 512 {
        // Bytes 64..75: the last 8 bytes of the message hash and the LE counter.
        let digest = blake2s_finalize(
            BoxTrait::new(prefix_state),
            HASH_INPUT_BYTES,
            BoxTrait::new([m6, m7, ctr, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
        )
            .unbox();
        let mut words = digest.span();
        while let Some(w) = words.pop_front() {
            // Two LE u16 candidates per digest word, low half first.
            let (hi, lo) = DivRem::div_rem(*w, sixteen_bits);
            push_candidate(lo, q32, ref coeffs);
            push_candidate(hi, q32, ref coeffs);
        }
        ctr += 1;
    }
    Some(coeffs)
}

/// Rejection-sample one 16-bit candidate: accept `candidate % Q` while below the
/// bound and 512 coefficients have not been collected yet.
#[inline(always)]
fn push_candidate(candidate: u32, q32: NonZero<u32>, ref coeffs: Array<u16>) {
    if coeffs.len() != 512 && candidate < REJECT_BOUND {
        let (_, r) = DivRem::div_rem(candidate, q32);
        coeffs.append(r.try_into().unwrap());
    }
}

/// ## SHAKE-256 backend
///
/// The standard Falcon (FIPS 206) construction: absorb `salt || message_hash` with
/// SHAKE-256, then consume the squeezed stream as big-endian 16-bit words, applying the
/// shared [`push_candidate`] rule (accept `word % Q` while `word < 5Q`) until 512
/// coefficients are collected. Unlike the BLAKE2s backend this is interoperable with any
/// standards-compliant Falcon signer (e.g. falcon.py). The message hash is absorbed as
/// its 32 little-endian bytes, the salt as its two 20-byte little-endian halves.
///
/// The sponge is driven directly on the Keccak lanes: the 72-byte input fits a single
/// rate block whose padded lanes are assembled straight from the salt and message-hash
/// limbs, and squeezing reads candidate words from the 17 rate lanes in place
/// ([`push_lane_words`]), permuting again only while more candidates are needed.

/// Hash `(message_hash, salt)` to 512 coefficients in `[0, Q)` with the standard
/// SHAKE-256 construction. Returns `None` if either salt felt exceeds 20 bytes.
pub fn hash_to_point_shake_512(
    message_hash: felt252, salt_a: felt252, salt_b: felt252,
) -> Option<Array<u16>> {
    let sa: u256 = salt_a.into();
    let sb: u256 = salt_b.into();
    if sa >= TWO_POW_160 || sb >= TWO_POW_160 {
        return None;
    }
    let mh: u256 = message_hash.into();

    // The absorbed block, assembled directly as little-endian lanes: bytes 0..40 hold
    // the salt, 40..72 the message hash, byte 72 the 0x1F SHAKE domain byte, and byte
    // 135 the pad10*1 terminator. The sponge state starts at zero, so this first
    // (and only) absorbed block IS the pre-permutation state.
    let two64: NonZero<u128> = 0x10000000000000000_u128.try_into().unwrap();
    let two32: NonZero<u128> = 0x100000000_u128.try_into().unwrap();
    let (a1, a0) = DivRem::div_rem(sa.low, two64); // salt_a bytes 0..8 and 8..16
    let (sbq, sb0) = DivRem::div_rem(sb.low, two32); // salt_b bytes 0..4 and 4..16
    let (sb12, l3) = DivRem::div_rem(sbq, two64); // salt_b bytes 4..12 -> lane 3
    let (m1, m0) = DivRem::div_rem(mh.low, two64);
    let (m3, m2) = DivRem::div_rem(mh.high, two64);
    // Lane 2: salt_a bytes 16..20 in the low half, salt_b bytes 0..4 in the high half.
    let l2: u128 = (sa.high.into() + sb0.into() * 0x100000000).try_into().unwrap();
    // Lane 4: salt_b bytes 12..16 in the low half, salt_b bytes 16..20 in the high half.
    let l4: u128 = (sb12.into() + sb.high.into() * 0x100000000).try_into().unwrap();

    // The same block in the packed layout of `keccak_f1600_packed`: per row `y`, lanes
    // 5y, 5y + 1 in one word and 5y + 2, 5y + 3 in another, then column 4 as the pairs
    // (4, 9), (14, 19) and lane 24. Only lane 16 (the pad terminator) is set beyond lane 9.
    let mut state = keccak_f1600_packed(
        [
            pack(a0, a1), pack(m0, m1), 0, 0x80000000000000000000000000000000, 0, pack(l2, l3),
            pack(m2, m3), 0, 0, 0, pack(l4, 0x1f), 0, 0,
        ],
    );

    let mut coeffs: Array<u16> = array![];
    let k = squeeze_consts();
    loop {
        push_block(@state, ref coeffs, k);
        if coeffs.len() == 512 {
            break;
        }
        state = keccak_f1600_packed(state);
    }
    Some(coeffs)
}

/// The squeeze's divisors and byte mask as cells rather than immediates: built by a
/// non-inlined call, they are used in place by every division and AND of the block
/// instead of first being copied.
#[derive(Copy, Drop)]
struct SqueezeConsts {
    two64: NonZero<SqueezeTwo64>,
    base16: NonZero<Base16>,
    q: NonZero<PoseidonQ>,
    even_bytes: u128,
}

#[inline(never)]
fn squeeze_init() -> (Array<u16>, felt252) {
    (array![], 1)
}

#[inline(never)]
fn squeeze_consts() -> SqueezeConsts {
    SqueezeConsts {
        two64: 0x10000000000000000, base16: BASE16_NZ, q: POSEIDON_Q_NZ, even_bytes: EVEN_BYTES_128,
    }
}

type SqueezeTwo64 = UnitInt<0x10000000000000000>;
type SqueezeLane = BoundedInt<0, 0xffffffffffffffff>;
impl DivRemSqueezeWord of DivRemHelper<u128, SqueezeTwo64> {
    type DivT = SqueezeLane;
    type RemT = SqueezeLane;
}

/// A packed state word as its (high, low) 64-bit lanes.
#[inline(always)]
fn split_lanes(w: u128, k: SqueezeConsts) -> (u128, u128) {
    let (high, low) = bounded_int_div_rem(w, k.two64);
    (upcast(high), upcast(low))
}

/// A squeezed state word with the bytes of every 16-bit chunk swapped, and its quotients
/// as its 16-bit chunks are peeled off.
type Swapped128 = BoundedInt<0, 0xffffffffffffffffffffffffffffffff>;
type Swapped112 = BoundedInt<0, 0xffffffffffffffffffffffffffff>;
type Swapped96 = BoundedInt<0, 0xffffffffffffffffffffffff>;
type Swapped80 = BoundedInt<0, 0xffffffffffffffffffff>;
type Swapped48 = BoundedInt<0, 0xffffffffffff>;
type Swapped32 = BoundedInt<0, 0xffffffff>;
impl DivRemSwapped128 of DivRemHelper<Swapped128, Base16> {
    type DivT = Swapped112;
    type RemT = Word16;
}

/// The even bytes of a 128-bit word.
const EVEN_BYTES_128: u128 = 0x00ff00ff00ff00ff00ff00ff00ff00ff;

/// Swap the two bytes of every 16-bit chunk of a packed word (two rate lanes) at once,
/// as [`push_lane_words`] does for one lane: one AND and one conversion per two lanes.
#[inline(always)]
fn swap_word(w: u128, k: SqueezeConsts) -> Swapped128 {
    let even: u128 = w & k.even_bytes;
    let even_f: felt252 = even.into();
    let w_f: felt252 = w.into();
    let swapped: u128 = (even_f * 256 + (w_f - even_f) * INV_256).try_into().unwrap();
    upcast(swapped)
}

/// The eight 16-bit stream words of a swapped word, low lane first, in seven divisions.
#[inline(always)]
fn word_chunks(
    w: Swapped128, k: SqueezeConsts,
) -> (Word16, Word16, Word16, Word16, Word16, Word16, Word16, Word16) {
    let (q, c0) = bounded_int_div_rem(w, k.base16);
    let (q, c1) = bounded_int_div_rem(q, k.base16);
    let (q, c2) = bounded_int_div_rem(q, k.base16);
    let (q, c3) = bounded_int_div_rem(q, k.base16);
    let (q, c4) = bounded_int_div_rem(q, k.base16);
    let (q, c5) = bounded_int_div_rem(q, k.base16);
    let (c7, c6) = bounded_int_div_rem(q, k.base16);
    (c0, c1, c2, c3, c4, c5, c6, c7)
}

/// The four 16-bit stream words of a swapped word's low lane, in four divisions.
#[inline(always)]
fn low_lane_chunks(w: Swapped128, k: SqueezeConsts) -> (Word16, Word16, Word16, Word16) {
    let (q, c0) = bounded_int_div_rem(w, k.base16);
    let (q, c1) = bounded_int_div_rem(q, k.base16);
    let (q, c2) = bounded_int_div_rem(q, k.base16);
    let (_, c3) = bounded_int_div_rem(q, k.base16);
    (c0, c1, c2, c3)
}

/// The eight candidates of a swapped word, low lane first.
#[inline(always)]
fn push_word8_uncapped(w: u128, ref coeffs: Array<u16>, k: SqueezeConsts) {
    let (c0, c1, c2, c3, c4, c5, c6, c7) = word_chunks(swap_word(w, k), k);
    push_shake_candidate_uncapped(c0, ref coeffs, k);
    push_shake_candidate_uncapped(c1, ref coeffs, k);
    push_shake_candidate_uncapped(c2, ref coeffs, k);
    push_shake_candidate_uncapped(c3, ref coeffs, k);
    push_shake_candidate_uncapped(c4, ref coeffs, k);
    push_shake_candidate_uncapped(c5, ref coeffs, k);
    push_shake_candidate_uncapped(c6, ref coeffs, k);
    push_shake_candidate_uncapped(c7, ref coeffs, k);
}

#[inline(always)]
fn push_word8_capped(w: u128, ref coeffs: Array<u16>, k: SqueezeConsts) {
    let (c0, c1, c2, c3, c4, c5, c6, c7) = word_chunks(swap_word(w, k), k);
    push_shake_candidate(c0, ref coeffs, k);
    push_shake_candidate(c1, ref coeffs, k);
    push_shake_candidate(c2, ref coeffs, k);
    push_shake_candidate(c3, ref coeffs, k);
    push_shake_candidate(c4, ref coeffs, k);
    push_shake_candidate(c5, ref coeffs, k);
    push_shake_candidate(c6, ref coeffs, k);
    push_shake_candidate(c7, ref coeffs, k);
}

#[inline(always)]
fn push_word8(w: u128, ref coeffs: Array<u16>, k: SqueezeConsts) {
    if coeffs.len() <= 512 - 8 {
        push_word8_uncapped(w, ref coeffs, k);
    } else {
        push_word8_capped(w, ref coeffs, k);
    }
}

#[inline(always)]
fn push4_uncapped(c0: Word16, c1: Word16, c2: Word16, c3: Word16, ref coeffs: Array<u16>, k: SqueezeConsts) {
    push_shake_candidate_uncapped(c0, ref coeffs, k);
    push_shake_candidate_uncapped(c1, ref coeffs, k);
    push_shake_candidate_uncapped(c2, ref coeffs, k);
    push_shake_candidate_uncapped(c3, ref coeffs, k);
}

#[inline(always)]
fn push4(c0: Word16, c1: Word16, c2: Word16, c3: Word16, ref coeffs: Array<u16>, k: SqueezeConsts) {
    if coeffs.len() <= 512 - 4 {
        push4_uncapped(c0, c1, c2, c3, ref coeffs, k);
    } else {
        push_shake_candidate(c0, ref coeffs, k);
        push_shake_candidate(c1, ref coeffs, k);
        push_shake_candidate(c2, ref coeffs, k);
        push_shake_candidate(c3, ref coeffs, k);
    }
}

/// Read the 17 rate lanes of a squeezed block, in order, from the packed state: words
/// (0, 1), (2, 3), (5, 6), (7, 8), (10, 11), (12, 13), (15, 16) are swapped and peeled
/// whole, each just before its candidates; lanes 4 and 9 come from the column-4 pair
/// (4, 9), and lane 14 from (14, 19).
#[inline(always)]
fn push_block(state: @[u128; 13], ref coeffs: Array<u16>, k: SqueezeConsts) {
    let [u0, u1, u2, u3, _, v0, v1, v2, _, _, g01, g23, _] = *state;
    let (g0, g1, g2, g3, g4, g5, g6, g7) = word_chunks(swap_word(g01, k), k);
    if coeffs.len() <= 512 - 68 {
        // A block yields at most 68 candidates, so it cannot reach 512 from here: no
        // per-candidate cap check.
        push_word8_uncapped(u0, ref coeffs, k);
        push_word8_uncapped(v0, ref coeffs, k);
        push4_uncapped(g0, g1, g2, g3, ref coeffs, k);
        push_word8_uncapped(u1, ref coeffs, k);
        push_word8_uncapped(v1, ref coeffs, k);
        push4_uncapped(g4, g5, g6, g7, ref coeffs, k);
        push_word8_uncapped(u2, ref coeffs, k);
        push_word8_uncapped(v2, ref coeffs, k);
        let (h0, h1, h2, h3) = low_lane_chunks(swap_word(g23, k), k);
        push4_uncapped(h0, h1, h2, h3, ref coeffs, k);
        push_word8_uncapped(u3, ref coeffs, k);
    } else {
        // The last block: a group needs the per-candidate cap check only when it could
        // reach 512.
        push_word8(u0, ref coeffs, k);
        push_word8(v0, ref coeffs, k);
        push4(g0, g1, g2, g3, ref coeffs, k);
        push_word8(u1, ref coeffs, k);
        push_word8(v1, ref coeffs, k);
        push4(g4, g5, g6, g7, ref coeffs, k);
        push_word8(u2, ref coeffs, k);
        push_word8(v2, ref coeffs, k);
        let (h0, h1, h2, h3) = low_lane_chunks(swap_word(g23, k), k);
        push4(h0, h1, h2, h3, ref coeffs, k);
        push_word8(u3, ref coeffs, k);
    }
}

impl DivRemWord16ByPoseidonQ of DivRemHelper<Word16, PoseidonQ> {
    type DivT = BoundedInt<0, 5>;
    type RemT = PoseidonZq;
}

/// [`push_poseidon_candidate`] with a single division: `candidate = k q + r` with `k` in
/// [0, 5], and `candidate < 5q` exactly when `k != 5`, so the rejection test needs no
/// separate checked downcast.
#[inline(always)]
fn push_shake_candidate(candidate: Word16, ref coeffs: Array<u16>, k: SqueezeConsts) {
    if coeffs.len() == 512 {
        return;
    }
    let (k, r) = bounded_int_div_rem(candidate, k.q);
    let k: felt252 = k.into();
    if k != 5 {
        coeffs.append(upcast(r));
    }
}

/// 256^-1 in the Stark field: dividing an exact multiple of 256 by 256 as a field product.
const INV_256: felt252 = 0x7f8000000000010ef0000000000000000000000000000000000000000000001;

/// The even bytes of a 64-bit lane (bytes 0, 2, 4 and 6).
const EVEN_BYTES: u128 = 0x00ff00ff00ff00ff;

/// Read one squeezed rate lane (< 2^64) as four big-endian 16-bit candidate words. The
/// lane's bytes are little-endian, so each 16-bit chunk holds its stream word
/// byte-swapped: chunk = b0 + 256*b1 for the stream word 256*b0 + b1.
///
/// All four chunks are swapped at once: with `even` the lane's even bytes and `odd` the
/// rest, `256 * even + odd / 256` moves every even byte up and every odd byte down by
/// eight bits (the division is exact, done as a field product), so its 16-bit chunks are
/// the stream words. They are then peeled with three bounded divisions.
#[inline(always)]
fn push_lane_words(lane: u128, ref coeffs: Array<u16>, k: SqueezeConsts) {
    let even: u128 = lane & k.even_bytes;
    let even_f: felt252 = even.into();
    let lane_f: felt252 = lane.into();
    let swapped_f: felt252 = even_f * 256 + (lane_f - even_f) * INV_256;
    let swapped: u64 = swapped_f.try_into().unwrap();
    let swapped: Quot64 = upcast(swapped);
    let (q1, w0) = bounded_int_div_rem(swapped, k.base16);
    let (q2, w1) = bounded_int_div_rem(q1, k.base16);
    let (w3, w2) = bounded_int_div_rem(q2, k.base16);
    push_shake_candidate(w0, ref coeffs, k);
    push_shake_candidate(w1, ref coeffs, k);
    push_shake_candidate(w2, ref coeffs, k);
    push_shake_candidate(w3, ref coeffs, k);
}

/// [`push_shake_candidate`] for a block that cannot fill the 512 coefficients.
#[inline(always)]
fn push_shake_candidate_uncapped(candidate: Word16, ref coeffs: Array<u16>, k: SqueezeConsts) {
    let (k, r) = bounded_int_div_rem(candidate, k.q);
    let k: felt252 = k.into();
    if k != 5 {
        coeffs.append(upcast(r));
    }
}

/// [`push_lane_words`] for a block that cannot fill the 512 coefficients.
#[inline(always)]
fn push_lane_words_uncapped(lane: u128, ref coeffs: Array<u16>, k: SqueezeConsts) {
    let even: u128 = lane & k.even_bytes;
    let even_f: felt252 = even.into();
    let lane_f: felt252 = lane.into();
    let swapped_f: felt252 = even_f * 256 + (lane_f - even_f) * INV_256;
    let swapped: u64 = swapped_f.try_into().unwrap();
    let swapped: Quot64 = upcast(swapped);
    let (q1, w0) = bounded_int_div_rem(swapped, k.base16);
    let (q2, w1) = bounded_int_div_rem(q1, k.base16);
    let (w3, w2) = bounded_int_div_rem(q2, k.base16);
    push_shake_candidate_uncapped(w0, ref coeffs, k);
    push_shake_candidate_uncapped(w1, ref coeffs, k);
    push_shake_candidate_uncapped(w2, ref coeffs, k);
    push_shake_candidate_uncapped(w3, ref coeffs, k);
}

/// ## Poseidon backend
///
/// Absorb `(salt_a, salt_b, message_hash)` as three field elements with the native Poseidon
/// permutation (`hades_permutation`, a Starknet builtin), then squeeze — take the two rate
/// elements `(s0, s1)` of the state, read 15 little-endian 16-bit words from the low 240
/// bits of each (uniform, since the field prime exceeds `2^251`), apply the shared
/// [`push_candidate`] rule, and permute the state again for the next block until 512
/// coefficients are collected.
///
/// Non-standard (Poseidon is not in the Falcon spec), so the off-chain signer must match
/// this construction (see `scripts/gen_falcon_fixture.py --variant poseidon`). Every step
/// is a native field operation, so the hash-to-point is inexpensive: on-chain verify cost
/// is close to the BLAKE2s backend and far below the pure-Cairo SHAKE-256 (the shared
/// NTT/hint core dominates either way).

/// Hash `(message_hash, salt)` to 512 coefficients in `[0, Q)` with a Poseidon squeeze.
/// Returns `None` if either salt felt exceeds 20 bytes.
pub fn hash_to_point_poseidon_512(
    message_hash: felt252, salt_a: felt252, salt_b: felt252,
) -> Option<Array<u16>> {
    let sa: u256 = salt_a.into();
    let sb: u256 = salt_b.into();
    if sa >= TWO_POW_160 || sb >= TWO_POW_160 {
        return None;
    }
    // Absorb the three inputs, then squeeze the rate elements two felts at a time.
    let (mut s0, mut s1, mut s2) = hades_permutation(salt_a, salt_b, message_hash);
    let mut coeffs: Array<u16> = array![];
    while coeffs.len() != 512 {
        push_felt_words(s0, ref coeffs);
        push_felt_words(s1, ref coeffs);
        if coeffs.len() == 512 {
            break;
        }
        let (n0, n1, n2) = hades_permutation(s0, s1, s2);
        s0 = n0;
        s1 = n1;
        s2 = n2;
    }
    Some(coeffs)
}

/// Read the low 240 bits of `felt` as 15 little-endian 16-bit candidate words — 8 from
/// the low 128-bit half and 7 from the high half.
fn push_felt_words(felt: felt252, ref coeffs: Array<u16>) {
    let v: u256 = felt.into();
    push_u128_words8(v.low, ref coeffs);
    push_u128_words7(v.high, ref coeffs);
}

/// Feed all eight 16-bit words of a u128, low first, as rejection-sampled candidates.
#[inline(always)]
fn push_u128_words8(value: u128, ref coeffs: Array<u16>) {
    let (q1, w0) = bounded_int_div_rem(value, BASE16_NZ);
    let (q2, w1) = bounded_int_div_rem(q1, BASE16_NZ);
    let (q3, w2) = bounded_int_div_rem(q2, BASE16_NZ);
    let (q4, w3) = bounded_int_div_rem(q3, BASE16_NZ);
    let (q5, w4) = bounded_int_div_rem(q4, BASE16_NZ);
    let (q6, w5) = bounded_int_div_rem(q5, BASE16_NZ);
    let (w7, w6) = bounded_int_div_rem(q6, BASE16_NZ);
    push_poseidon_candidate(w0, ref coeffs);
    push_poseidon_candidate(w1, ref coeffs);
    push_poseidon_candidate(w2, ref coeffs);
    push_poseidon_candidate(w3, ref coeffs);
    push_poseidon_candidate(w4, ref coeffs);
    push_poseidon_candidate(w5, ref coeffs);
    push_poseidon_candidate(w6, ref coeffs);
    push_poseidon_candidate(w7, ref coeffs);
}

/// Feed the low seven 16-bit words of a u128 and discard its remaining high 16 bits.
#[inline(always)]
fn push_u128_words7(value: u128, ref coeffs: Array<u16>) {
    let (q1, w0) = bounded_int_div_rem(value, BASE16_NZ);
    let (q2, w1) = bounded_int_div_rem(q1, BASE16_NZ);
    let (q3, w2) = bounded_int_div_rem(q2, BASE16_NZ);
    let (q4, w3) = bounded_int_div_rem(q3, BASE16_NZ);
    let (q5, w4) = bounded_int_div_rem(q4, BASE16_NZ);
    let (q6, w5) = bounded_int_div_rem(q5, BASE16_NZ);
    let (_, w6) = bounded_int_div_rem(q6, BASE16_NZ);
    push_poseidon_candidate(w0, ref coeffs);
    push_poseidon_candidate(w1, ref coeffs);
    push_poseidon_candidate(w2, ref coeffs);
    push_poseidon_candidate(w3, ref coeffs);
    push_poseidon_candidate(w4, ref coeffs);
    push_poseidon_candidate(w5, ref coeffs);
    push_poseidon_candidate(w6, ref coeffs);
}

/// Apply the unchanged Falcon rejection rule to one exact 16-bit Poseidon word.
#[inline(always)]
fn push_poseidon_candidate(candidate: Word16, ref coeffs: Array<u16>) {
    if coeffs.len() == 512 {
        return;
    }
    match downcast::<Word16, AcceptedWord>(candidate) {
        Some(accepted) => {
            let (_, r) = bounded_int_div_rem(accepted, POSEIDON_Q_NZ);
            coeffs.append(upcast(r));
        },
        None => {},
    }
}

/// Little-endian u32 limbs of a u128.
fn limbs_128(x: u128) -> (u32, u32, u32, u32) {
    let two_pow_32: NonZero<u128> = 0x100000000_u128.try_into().unwrap();
    let (rest, l0) = DivRem::div_rem(x, two_pow_32);
    let (rest, l1) = DivRem::div_rem(rest, two_pow_32);
    let (l3, l2) = DivRem::div_rem(rest, two_pow_32);
    (l0.try_into().unwrap(), l1.try_into().unwrap(), l2.try_into().unwrap(), l3.try_into().unwrap())
}

/// Little-endian u32 limbs of a 160-bit value (caller checks the range).
fn limbs_160(x: u256) -> (u32, u32, u32, u32, u32) {
    let (l0, l1, l2, l3) = limbs_128(x.low);
    (l0, l1, l2, l3, x.high.try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::{TWO_POW_160, hash_to_point_512};

    const MSG: felt252 = 'BENCH_MSG';

    // Known-answer vectors generated with the reference Python construction
    // (hashlib.blake2s counter mode; see scripts/gen_falcon_fixture.py).
    #[test]
    fn test_hash_to_point_kat() {
        let coeffs = hash_to_point_512(MSG, 1, 2).unwrap();
        assert_eq!(coeffs.len(), 512);
        let first8: [u16; 8] = [9961, 3944, 2517, 2545, 1832, 3277, 10883, 3861];
        let last8: [u16; 8] = [5236, 2206, 424, 1825, 8022, 8816, 4999, 9640];
        let mid4: [u16; 4] = [9941, 5062, 7268, 7838];
        let mut i: u32 = 0;
        for expected in first8.span() {
            assert_eq!(*coeffs.at(i), *expected);
            i += 1;
        }
        let mut j: u32 = 504;
        for expected in last8.span() {
            assert_eq!(*coeffs.at(j), *expected);
            j += 1;
        }
        let mut k: u32 = 255;
        for expected in mid4.span() {
            assert_eq!(*coeffs.at(k), *expected);
            k += 1;
        }
    }

    #[test]
    fn test_hash_to_point_domain_separation() {
        // Different message, salt halves, or salt order all change the point.
        let base = hash_to_point_512(MSG, 1, 2).unwrap();
        let other_msg = hash_to_point_512('OTHER_MSG', 1, 2).unwrap();
        let other_salt = hash_to_point_512(MSG, 2, 1).unwrap();
        assert_ne!(base.span(), other_msg.span());
        assert_ne!(base.span(), other_salt.span());
    }

    #[test]
    fn test_hash_to_point_rejects_oversized_salt() {
        let too_big: felt252 = TWO_POW_160.try_into().unwrap();
        assert!(hash_to_point_512(MSG, too_big, 0).is_none());
        assert!(hash_to_point_512(MSG, 0, too_big).is_none());
        // 2^160 - 1 is the largest valid salt half.
        assert!(hash_to_point_512(MSG, too_big - 1, too_big - 1).is_some());
    }
}

impl ConstrainWord16FiveQ of ConstrainHelper<Word16, 61445> {
    type LowT = BoundedInt<0, 61444>;
    type HighT = BoundedInt<61445, 65535>;
}


/// Candidates accepted in a straight line: while each is below 5q it is appended with no
/// branch merge (no per-candidate store of the array and range-check pointer); the first
/// rejected one hands the rest to the out-of-line [`raw_tail1`]..[`raw_tail7`] (rare: a
/// candidate is rejected with probability 4091/65536). Same accepted values, same order.
#[inline(never)]
fn raw_tail1(c0: Word16, ref coeffs: Array<u16>) {
    // A loop (it iterates at most once and changes nothing) gives this function, and every
    // tail that calls it, an unknown ap change and a gas counter of its own: callers then
    // merge after a tail without an `ap += n` on each accepted candidate, and a tail is
    // charged for the branches it takes rather than for its most expensive path.
    let mut i: u32 = coeffs.len();
    while i == 0 {
        i += 1;
    }
    let l0 = match constrain::<Word16, 61445>(c0) {
        Ok(l) => l,
        Err(_) => { return; },
    };
    coeffs.append(upcast(l0));
}


/// Q48: the rest of a swapped word, lane or pair of them, from its remaining quotient: one
/// division, check and append per candidate. A reject hands the quotient (not the peeled
/// chunks) to the out-of-line [`rt`]. Same divisions, same accepted values, same order.
trait Rest<T> {
    fn run(q: T, b: NonZero<Base16>, ref c: Array<u16>);
    fn tail(q: T, b: NonZero<Base16>, ref c: Array<u16>);
}
/// [`Rest::run`] stopping at 512, for the last block's words.
trait Cap<T> {
    fn cap(q: T, b: NonZero<Base16>, ref c: Array<u16>);
}
#[inline(never)]
fn capo<T, +Cap<T>, +Drop<T>>(q: T, b: NonZero<Base16>, ref c: Array<u16>) {
    // A gas counter of its own (see raw_tail1): charged for the candidates it reads.
    let mut i = c.len();
    while i == 0 {
        i += 1;
    }
    Cap::cap(q, b, ref c);
}
#[inline(never)]
fn rt<T, +Rest<T>, +Drop<T>>(q: T, b: NonZero<Base16>, ref c: Array<u16>) {
    Rest::run(q, b, ref c);
}
impl RestW of Rest<Word16> {
    #[inline(always)]
    fn run(q: Word16, b: NonZero<Base16>, ref c: Array<u16>) {
        if let Ok(l) = constrain::<Word16, 61445>(q) {
            c.append(upcast(l));
        }
    }
    #[inline(always)]
    fn tail(q: Word16, b: NonZero<Base16>, ref c: Array<u16>) {
        raw_tail1(q, ref c);
    }
}
impl CapW of Cap<Word16> {
    #[inline(always)]
    fn cap(q: Word16, b: NonZero<Base16>, ref c: Array<u16>) {
        RestW::run(q, b, ref c);
    }
}
impl RestQ<
    T, impl H: DivRemHelper<T, Base16>, +Rest<H::DivT>, +Drop<H::DivT>, +Drop<T>,
> of Rest<T> {
    #[inline(always)]
    fn run(q: T, b: NonZero<Base16>, ref c: Array<u16>) {
        let (q, w) = bounded_int_div_rem(q, b);
        match constrain::<Word16, 61445>(upcast(w)) {
            Ok(l) => {
                c.append(upcast(l));
                Rest::run(q, b, ref c);
            },
            Err(_) => Rest::tail(q, b, ref c),
        }
    }
    #[inline(always)]
    fn tail(q: T, b: NonZero<Base16>, ref c: Array<u16>) {
        rt(q, b, ref c);
    }
}
impl CapQ<
    T, impl H: DivRemHelper<T, Base16>, +Cap<H::DivT>, +Drop<H::DivT>, +Drop<T>,
> of Cap<T> {
    #[inline(always)]
    fn cap(q: T, b: NonZero<Base16>, ref c: Array<u16>) {
        let (q, w) = bounded_int_div_rem(q, b);
        RestW::run(upcast(w), b, ref c);
        if c.len() != 512 {
            Cap::cap(q, b, ref c);
        }
    }
}
impl RestPW<N, +Rest<N>, +Drop<N>> of Rest<(Word16, N)> {
    #[inline(always)]
    fn run(q: (Word16, N), b: NonZero<Base16>, ref c: Array<u16>) {
        let (w, n) = q;
        match constrain::<Word16, 61445>(upcast(w)) {
            Ok(l) => {
                c.append(upcast(l));
                Rest::run(n, b, ref c);
            },
            Err(_) => Rest::tail(n, b, ref c),
        }
    }
    #[inline(always)]
    fn tail(q: (Word16, N), b: NonZero<Base16>, ref c: Array<u16>) {
        rt(q, b, ref c);
    }
}
impl RestP<
    T, N, impl H: DivRemHelper<T, Base16>, +Rest<(H::DivT, N)>, +Drop<H::DivT>,
    +Drop<T>, +Drop<N>,
> of Rest<(T, N)> {
    #[inline(always)]
    fn run(q: (T, N), b: NonZero<Base16>, ref c: Array<u16>) {
        let (q, n) = q;
        let (q, w) = bounded_int_div_rem(q, b);
        match constrain::<Word16, 61445>(upcast(w)) {
            Ok(l) => {
                c.append(upcast(l));
                Rest::run((q, n), b, ref c);
            },
            Err(_) => Rest::tail((q, n), b, ref c),
        }
    }
    #[inline(always)]
    fn tail(q: (T, N), b: NonZero<Base16>, ref c: Array<u16>) {
        rt(q, b, ref c);
    }
}

impl DivRemSwappedTwo64 of DivRemHelper<Swapped128, SqueezeTwo64> {
    type DivT = Quot64;
    type RemT = Quot64;
}

/// A swapped word's (high, low) lanes.
#[inline(always)]
fn lanes_raw(w: u128, k: SqueezeConsts) -> (Quot64, Quot64) {
    bounded_int_div_rem(swap_word(w, k), k.two64)
}

#[inline(always)]
fn push_word8_raw(w: u128, ref coeffs: Array<u16>, k: SqueezeConsts) {
    let len = coeffs.len();
    if len <= 512 - 8 {
        Rest::run(swap_word(w, k), k.base16, ref coeffs);
    } else if len != 512 {
        Cap::cap(swap_word(w, k), k.base16, ref coeffs);
    }
    // Full: the word's candidates are past the 512th and are never read, so it is not peeled.
}

#[inline(always)]
fn push_word8_rawo(w: u128, ref coeffs: Array<u16>, k: SqueezeConsts) {
    let len = coeffs.len();
    if len <= 512 - 8 {
        Rest::run(swap_word(w, k), k.base16, ref coeffs);
    } else if len != 512 {
        capo(swap_word(w, k), k.base16, ref coeffs);
    }
}

#[inline(always)]
fn push_lane_raw(q: Quot64, ref coeffs: Array<u16>, k: SqueezeConsts) {
    let len = coeffs.len();
    if len <= 512 - 4 {
        Rest::run(q, k.base16, ref coeffs);
    } else if len != 512 {
        capo(q, k.base16, ref coeffs);
    }
}

/// Read the 17 rate lanes of a squeezed block, in order, from the packed state: words
/// (0, 1), (2, 3), (5, 6), (7, 8), (10, 11), (12, 13), (15, 16) are swapped and peeled
/// whole; lanes 4 and 9 come from the column-4 pair (4, 9), and lane 14 from (14, 19).
#[inline(always)]
fn push_block_raw(state: @[u128; 12], ref coeffs: Array<u16>, k: SqueezeConsts) {
    let [u0, u1, u2, u3, _, v0, v1, v2, _, _, g01, g23] = *state;
    let (g1, g0) = lanes_raw(g01, k);
    if coeffs.len() <= 512 - 68 {
        // A block yields at most 68 candidates, so it cannot reach 512 from here: no
        // per-candidate cap check. Groups of 16, 20, 20 and 12: one branch merge per group.
        let b = k.base16;
        let (s0, s1, s2, s3, s4, s5) = (swap_word(u0, k), swap_word(v0, k), swap_word(u1, k), swap_word(v1, k), swap_word(u2, k), swap_word(v2, k));
        let (s6, (_, h)) = (swap_word(u3, k), lanes_raw(g23, k));
        Rest::run((s0, s1), b, ref coeffs);
        Rest::run((g0, (s2, s3)), b, ref coeffs);
        Rest::run((g1, (s4, s5)), b, ref coeffs);
        Rest::run((h, s6), b, ref coeffs);
    } else if coeffs.len() <= 512 - 36 {
        // The last block (block 8 always enters here: 7 blocks give at most 476): the first
        // 36 candidates cannot reach 512, so the first two groups run uncapped; a word needs
        // the per-candidate cap check only when it could reach 512.
        let b = k.base16;
        let (s0, s1, s2, s3) = (swap_word(u0, k), swap_word(v0, k), swap_word(u1, k), swap_word(v1, k));
        Rest::run((s0, s1), b, ref coeffs);
        Rest::run((g0, (s2, s3)), b, ref coeffs);
        if coeffs.len() <= 512 - 20 {
            Rest::run((g1, (swap_word(u2, k), swap_word(v2, k))), b, ref coeffs);
        } else {
            push_lane_raw(g1, ref coeffs, k);
            push_word8_rawo(u2, ref coeffs, k);
            push_word8_rawo(v2, ref coeffs, k);
        }
        if coeffs.len() != 512 {
            let (_, h) = lanes_raw(g23, k);
            push_lane_raw(h, ref coeffs, k);
            push_word8_rawo(u3, ref coeffs, k);
        }
    } else {
        // Past 476 (block 9 on, < 2% of signatures): every lane through the compact reader.
        push_block_lanes_raw(state, ref coeffs, k, true);
    }
}

/// Q62: [`push_block_raw`]'s fast branch for every block. The verifier reads the message point
/// with `multi_pop_front::<512>()`, so candidates appended past the 512th are never read: the
/// last block needs no cap, no selector and no compact reader. The first 512 are unchanged.
#[inline(always)]
fn push_block_fast(state: @[u128; 12], ref coeffs: Array<u16>, k: SqueezeConsts) {
    let [u0, u1, u2, u3, _, v0, v1, v2, _, _, g01, g23] = *state;
    let (g1, g0) = lanes_raw(g01, k);
    let b = k.base16;
    let (s0, s1, s2, s3, s4, s5) = (swap_word(u0, k), swap_word(v0, k), swap_word(u1, k), swap_word(v1, k), swap_word(u2, k), swap_word(v2, k));
    let (s6, (_, h)) = (swap_word(u3, k), lanes_raw(g23, k));
    Rest::run((s0, s1), b, ref coeffs);
    Rest::run((g0, (s2, s3)), b, ref coeffs);
    Rest::run((g1, (s4, s5)), b, ref coeffs);
    Rest::run((h, s6), b, ref coeffs);
}

/// [`hash_to_point_shake_512`] for the verifier: the same accepted candidates, in the same
/// order, but not reduced mod q (each is below 5q). The verifier uses the message point only
/// in the norm, as `msg - t` mod q, where any representative mod q gives the same value.
#[inline(always)]
pub(crate) fn hash_to_point_shake_512_raw(
    message_hash: felt252, salt_a: felt252, salt_b: felt252,
) -> Option<Array<u16>> {
    hash_to_point_shake_512_raw_tail(message_hash, salt_a, salt_b, SYSCALL_TAIL_MISSING)
}

/// [`hash_to_point_shake_512_raw`] with the syscall threshold as a parameter.
#[inline(always)]
fn hash_to_point_shake_512_raw_tail(
    message_hash: felt252, salt_a: felt252, salt_b: felt252, tail: u32,
) -> Option<Array<u16>> {
    let sa: u256 = salt_a.into();
    let sb: u256 = salt_b.into();
    // Below 2^160 iff the high half is below 2^32, which also types it.
    let sah: Q32 = match downcast(sa.high) { Some(v) => v, None => { return None; } };
    let sbh: Q32 = match downcast(sb.high) { Some(v) => v, None => { return None; } };
    let mh: u256 = message_hash.into();
    // The absorbed block as exact little-endian lanes (see `hash_to_point_shake_512`).
    let t64: NonZero<SqueezeTwo64> = 0x10000000000000000;
    // Lanes (0, 0)/(1, 0) and (1, 1)..(3, 1)'s words are salt_a.low, mh.low and mh.high as they are
    // (packed little-endian); only the syscall head needs them split, so they stay packed here.
    // Lanes (2, 0), (3, 0) as one word: salt_a's top 32 bits, then salt_b's low 96 bits; lane (4, 0)
    // is salt_b's top 64 bits. One split of salt_b.low at bit 96 gives both.
    let t96: NonZero<T96> = 0x1000000000000000000000000;
    let (sb12, sb96) = bounded_int_div_rem(sb.low, t96);
    let wl23: u128 = upcast(bounded_int::add(sah, bounded_int::mul(sb96, T32_V)));
    let l4: Low = bounded_int::add(sb12, bounded_int::mul(sbh, T32_V));
    let (state, g4) = keccak_f1600_lanes(
        [
            sa.low, mh.low, 0, 0x80000000000000000000000000000000, 0,
            wl23, mh.high, 0, 0, 0, pack_exact(l4, 0x1f), 0,
        ],
        0,
    );

    // The absorbed words and lane that are not constant, for the keccak_syscall tail below.
    let block: AbsorbedBlock = ([sa.low, mh.low, mh.high, wl23], l4);
    Some(squeeze_raw(state, g4, block, tail))
}

/// At most this many coefficients missing after a block: read the next block's first 16
/// candidates (lanes 0..3) from keccak_syscall instead of permuting in Cairo.
const SYSCALL_TAIL_MISSING: u32 = 15;

/// The absorbed block's non-constant content: the words salt_a.low, mh.low, mh.high and lanes
/// (2, 0)/(3, 0) (two lanes each, low lane first), and lane (4, 0).
type AbsorbedBlock = ([u128; 4], Low);

/// The 9 lanes of [`shake_head_lanes`] from an [`AbsorbedBlock`]; runs once, on the head path only.
#[inline(always)]
fn absorbed_lanes(block: AbsorbedBlock) -> [Low; 9] {
    let ([wa, wm0, wm1, wl23], l4) = block;
    let t64: NonZero<SqueezeTwo64> = 0x10000000000000000;
    let (a1, a0) = bounded_int_div_rem(wa, t64);
    let (m1, m0) = bounded_int_div_rem(wm0, t64);
    let (m3, m2) = bounded_int_div_rem(wm1, t64);
    let (l3, l2) = bounded_int_div_rem(wl23, t64);
    [a0, a1, l2, l3, l4, m0, m1, m2, m3]
}

/// keccak_syscall absorbs whole 17-lane blocks with no padding and returns lanes 0..3 of
/// the final state, low = lanes 0, 1 and high = lanes 2, 3 (the packed words u0, v0).
/// Absorbing a zero block leaves the state unchanged before its permutation, so the SHAKE
/// block followed by `zero_blocks` (<= 8) zero blocks gives lanes 0..3 of squeeze block
/// `zero_blocks + 1`.
#[inline(never)]
fn shake_head_lanes(block: [Low; 9], zero_blocks: u32) -> u256 {
    let [a0, a1, l2, l3, l4, m0, m1, m2, m3] = block;
    let input: [u64; 153] = [
        upcast(a0), upcast(a1), upcast(l2), upcast(l3), upcast(l4), upcast(m0), upcast(m1), upcast(m2), upcast(m3), 0x1f,
        0, 0, 0, 0, 0, 0, 0x8000000000000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    starknet::SyscallResultTrait::unwrap_syscall(
        starknet::syscalls::keccak_syscall(input.span().slice(0, (zero_blocks + 1) * 17)),
    )
}

/// Q62: [`shake_head_lanes`] with `zero_blocks = 8`, the only value production reaches (the head
/// needs >= 497 accepted and 7 blocks give at most 476): the whole 153-lane input, no slice.
#[inline(never)]
fn shake_head_lanes8(block: [Low; 9]) -> u256 {
    let [a0, a1, l2, l3, l4, m0, m1, m2, m3] = block;
    let input: [u64; 153] = [
        upcast(a0), upcast(a1), upcast(l2), upcast(l3), upcast(l4), upcast(m0), upcast(m1), upcast(m2), upcast(m3), 0x1f,
        0, 0, 0, 0, 0, 0, 0x8000000000000000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ];
    starknet::SyscallResultTrait::unwrap_syscall(starknet::syscalls::keccak_syscall(input.span()))
}

/// The squeeze of [`hash_to_point_shake_512_raw`] from the first squeezed state; `tail` is
/// [`SYSCALL_TAIL_MISSING`] in production and a parameter so a test can force the fallback.
#[inline(always)]
pub(crate) fn squeeze_raw(
    mut state: [u128; 12], mut g4: Low, block: AbsorbedBlock, tail: u32,
) -> Array<u16> {
    // From a non-inlined call, so the loop below is not cloned for its first iteration.
    let (mut coeffs, mut blocks) = squeeze_init();
    let k = squeeze_consts();
    let limit = 512 - tail;
    let SqueezeConsts { base16, even_bytes, .. } = k;
    // Plain blocks until the syscall tail could qualify; carries only the 2 used constants.
    loop {
        push_block_fast(@state, ref coeffs, SqueezeConsts { two64: 0x10000000000000000, base16, q: POSEIDON_Q_NZ, even_bytes });
        if coeffs.len() >= limit {
            break;
        }
        blocks += 1;
        let (s, g) = keccak_f1600_lanes(state, g4);
        state = s;
        g4 = g;
    }
    if coeffs.len() >= 512 {
        return coeffs;
    }
    squeeze_raw_last(state, g4, block, blocks, coeffs, k)
}

/// The rest of [`squeeze_raw`] once at most `tail` coefficients are missing after block
/// `blocks` (already read from `state`).
#[inline(always)]
fn squeeze_raw_last(
    state: [u128; 12], g4: Low, block: AbsorbedBlock, blocks: felt252, mut coeffs: Array<u16>, k: SqueezeConsts,
) -> Array<u16> {
    // Q50: the head runs once, outside a loop (no gas check). A 2nd head would only give lanes the
    // loop computes anyway. Identity upcasts: the state is stored on this path, not at the loop exit.
    let [a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11] = state;
    let mut state: [u128; 12] = [
        upcast(a0), upcast(a1), upcast(a2), upcast(a3), upcast(a4), upcast(a5), upcast(a6), upcast(a7),
        upcast(a8), upcast(a9), upcast(a10), upcast(a11),
    ];
    let mut g4: Low = upcast(g4);
    // Q53: one permutation and one reader call site for both paths.
    let mut all = true;
    // Q51: `coeffs.len() + tail >= 512` holds on entry (the loop above exits only there); the felt
    // counter is range-checked straight into [0, 8] (no u32 conversion, no unwrap, no compare).
    // Q62: production reaches the head only after block 8; other counts (tests forcing `tail`) take
    // the Cairo loop below, which reads the same lanes.
    if blocks == 8 {
        let head = shake_head_lanes8(absorbed_lanes(block));
        push_word8_raw(head.low, ref coeffs, k);
        push_word8_raw(head.high, ref coeffs, k);
        if coeffs.len() == 512 {
            return coeffs;
        }
        // Not enough: permute in Cairo and read the block from lane 4 on.
        all = false;
    }
    // Otherwise only past 9 blocks (P < 2^-59): every lane, through the compact reader.
    while coeffs.len() != 512 {
        let (s, g) = keccak_f1600_lanes(state, g4);
        state = s;
        g4 = g;
        push_block_lanes_raw(@state, ref coeffs, k, all);
        all = true;
    }
    coeffs
}

/// [`push_block_raw`]'s last-block branch from lane 4 (or, with `head`, from lane 0), one lane per loop pass: only
/// the fallback after a short syscall head and blocks past 9 come here, so it is kept small.
#[inline(never)]
fn push_block_lanes_raw(state: @[u128; 12], ref coeffs: Array<u16>, k: SqueezeConsts, head: bool) {
    let [u0, u1, u2, u3, _, v0, v1, v2, _, _, g01, g23] = *state;
    let mut lanes: Array<u128> = array![];
    if head {
        let (l1, l0) = split_lanes(u0, k);
        let (l3, l2) = split_lanes(v0, k);
        lanes.append(l0);
        lanes.append(l1);
        lanes.append(l2);
        lanes.append(l3);
    }
    let (l9, l4) = split_lanes(g01, k);
    let (l6, l5) = split_lanes(u1, k);
    let (l8, l7) = split_lanes(v1, k);
    let (l11, l10) = split_lanes(u2, k);
    let (l13, l12) = split_lanes(v2, k);
    let (_, l14) = split_lanes(g23, k);
    let (l16, l15) = split_lanes(u3, k);
    lanes.append_span(array![l4, l5, l6, l7, l8, l9, l10, l11, l12, l13, l14, l15, l16].span());
    let mut lanes = lanes.span();
    while let Some(lane) = lanes.pop_front() {
        if coeffs.len() == 512 {
            break;
        }
        let (_, h) = lanes_raw(*lane, k);
        push_lane_raw(h, ref coeffs, k);
    }
}

#[cfg(test)]
mod lane_reader_tests {
    use super::{push_block_lanes_raw, push_block_raw, squeeze_consts};
    use super::super::shake256::keccak_f1600_packed;

    // The compact reader (every lane) against push_block_raw, from several fill levels, on
    // states that reject candidates (permutations of a seed).
    #[test]
    fn test_lane_reader_matches_block_reader_falcon_512_shake() {
        let k = squeeze_consts();
        let mut st: [u128; 13] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0xffffffffffffffffffffffffffffffff, 12, 13];
        let mut round = 0_u32;
        while round != 6 {
            st = keccak_f1600_packed(st);
            for start in array![0_u32, 400, 444, 445, 480, 500, 508, 511] {
                let mut a: Array<u16> = array![];
                let mut b: Array<u16> = array![];
                let mut i = 0;
                while i != start {
                    a.append(0);
                    b.append(0);
                    i += 1;
                }
                let [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11, _] = st;
                let lanes = [s0, s1, s2, s3, s4, s5, s6, s7, s8, s9, s10, s11];
                push_block_raw(@lanes, ref a, k);
                push_block_lanes_raw(@lanes, ref b, k, true);
                assert(a == b, 'lane reader');
            }
            round += 1;
        }
    }
}

#[cfg(test)]
mod syscall_tail_tests {
    use super::{hash_to_point_shake_512, hash_to_point_shake_512_raw_tail};

    fn check(mh: felt252, sa: felt252, sb: felt252) {
        let reduced = hash_to_point_shake_512(mh, sa, sb).unwrap();
        // 0: never the syscall; 15: production; 68 and 512: the syscall (and the Cairo
        // fallback) on late blocks and on every block.
        for tail in array![0_u32, 15, 68, 512] {
            let raw = hash_to_point_shake_512_raw_tail(mh, sa, sb, tail).unwrap();
            // Q62: past the 512th the raw squeeze may append more; only the first 512 are read.
            assert(raw.len() >= 512, 'len');
            let mut i = 0;
            while i != 512 {
                let r: u32 = (*raw[i]).into();
                let c: u32 = (*reduced[i]).into();
                assert(r % 12289 == c, 'coeff');
                i += 1;
            }
        }
    }

    #[test]
    fn test_syscall_tail_falcon_512_shake() {
        check(0x1234, 0x5678, 0x9abc);
        check(
            0x7ff0123456789abcdef0123456789abcdef0123456789abcdef0123456789ab,
            0xffffffffffffffffffffffffffffffffffffffff,
            0xfedcba9876543210fedcba9876543210fedcba98,
        );
        check(1, 2, 3);
        check(0xdeadbeef, 0, 0xffffffffffffffffffffffffffffffffffffffff);
        check(42, 0x0123456789abcdef0123456789abcdef01234567, 7);
    }
}
