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
use core::internal::bounded_int::{ConstrainHelper as jr,constrain as iF};use corelib_imports::bounded_int::{bounded_int_div_rem as eF,BoundedInt as eX,upcast as gO,DivRemHelper as gU,UnitInt as iL};use super::shake256::{keccak_f1600_packed as jG};use super::shake256::{u,bD,co,bb,bJ,QF,keccak_next_k,eo,bH,pack as kD,aa};use corelib_imports::bounded_int::{AddHelper as jX,MulHelper as jA,bounded_int as hF};type Q32=eX<0,0xffffffff>;type ji=iL<4294967296>;const hD:ji=4294967296;type nM=iL<0x1000000000000000000000000>;impl hh of gU<u128,nM>{type DivT=Q32;type RemT=eX<0,0xffffffffffffffffffffffff>;}impl j5 of jA<eX<0,0xffffffffffffffffffffffff>,ji>{type Result=eX<0,0xffffffffffffffffffffffff00000000>;}impl iN of jX<Q32,eX<0,0xffffffffffffffffffffffff00000000>>{type Result=eX<0,0xffffffffffffffffffffffffffffffff>;}impl j4 of jA<Q32,ji>{type Result=eX<0,0xffffffff00000000>;}impl mz of jX<Q32,eX<0,0xffffffff00000000>>{type Result=u;}

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

let mut state=jG(
        [
kD(a0,a1),kD(m0,m1),0,0x80000000000000000000000000000000,0,kD(l2,l3),kD(m2,m3),0,0,0,kD(l4,31),0,0,
        ],
    );

    let mut coeffs: Array<u16> = array![];
let k=bd();
    loop {
eH(@state,ref coeffs,k);
        if coeffs.len() == 512 {
            break;
        }
state=jG(state);
    }
    Some(coeffs)
}

#[derive(Copy,Drop)]struct aj{two64:NonZero<aY>,aB:NonZero<Base16>,q:NonZero<PoseidonQ>,aR:u128,cX:NonZero<el>,cY:NonZero<hE>,}#[inline(always)]fn eg()->(Array<ae>,felt252){(array![],1)}#[inline(always)]fn bd()->aj{aj{two64:0x10000000000000000,aB:BASE16_NZ,q:POSEIDON_Q_NZ,aR:dO,cX:16777216,cY:0x1000000000000000000,}}type aY=iL<0x10000000000000000>;type dh=eX<0,0xffffffffffffffff>;impl eT of gU<u128,aY>{type DivT=dh;type RemT=dh;}#[inline(always)]fn aE(w:u128,k:aj)->(u128,u128){let(high,low)=eF(w,k.two64);(gO(high),gO(low))}type bE=eX<0,0xffffffffffffffffffffffffffffffff>;type eB=eX<0,0xffffffffffffffffffffffffffff>;impl ft of gU<bE,Base16>{type DivT=eB;type RemT=Word16;}const dO:u128=0xff00ff00ff00ff00ff00ff00ff00ff;#[inline(always)]fn by(w:u128,k:aj)->bE{let even:u128=w&k.aR;let en:felt252=even.into();let uE:felt252=w.into();let ct:u128=((uE+en*65535)*ez).try_into().unwrap();gO(ct)}#[inline(always)]fn cd(w:bE,k:aj)->(Word16,Word16,Word16,Word16,Word16,Word16,Word16,Word16){let(q,c0)=eF(w,k.aB);let(q,c1)=eF(q,k.aB);let(q,c2)=eF(q,k.aB);let(q,c3)=eF(q,k.aB);let(q,c4)=eF(q,k.aB);let(q,c5)=eF(q,k.aB);let(c7,c6)=eF(q,k.aB);(c0,c1,c2,c3,c4,c5,c6,c7)}#[inline(always)]fn bP(w:bE,k:aj)->(Word16,Word16,Word16,Word16){let(q,c0)=eF(w,k.aB);let(q,c1)=eF(q,k.aB);let(q,c2)=eF(q,k.aB);let(_,c3)=eF(q,k.aB);(c0,c1,c2,c3)}#[inline(always)]fn au(w:u128,ref coeffs:Array<u16>,k:aj){let(c0,c1,c2,c3,c4,c5,c6,c7)=cd(by(w,k),k);ac(c0,ref coeffs,k);ac(c1,ref coeffs,k);ac(c2,ref coeffs,k);ac(c3,ref coeffs,k);ac(c4,ref coeffs,k);ac(c5,ref coeffs,k);ac(c6,ref coeffs,k);ac(c7,ref coeffs,k);}#[inline(always)]fn cV(w:u128,ref coeffs:Array<u16>,k:aj){let(c0,c1,c2,c3,c4,c5,c6,c7)=cd(by(w,k),k);af(c0,ref coeffs,k);af(c1,ref coeffs,k);af(c2,ref coeffs,k);af(c3,ref coeffs,k);af(c4,ref coeffs,k);af(c5,ref coeffs,k);af(c6,ref coeffs,k);af(c7,ref coeffs,k);}#[inline(always)]fn aS(w:u128,ref coeffs:Array<u16>,k:aj){if coeffs.len()<=512-8{au(w,ref coeffs,k);}else{cV(w,ref coeffs,k);}}#[inline(always)]fn bc(c0:Word16,c1:Word16,c2:Word16,c3:Word16,ref coeffs:Array<u16>,k:aj){ac(c0,ref coeffs,k);ac(c1,ref coeffs,k);ac(c2,ref coeffs,k);ac(c3,ref coeffs,k);}#[inline(always)]fn fg(c0:Word16,c1:Word16,c2:Word16,c3:Word16,ref coeffs:Array<u16>,k:aj){if coeffs.len()<=512-4{bc(c0,c1,c2,c3,ref coeffs,k);}else{af(c0,ref coeffs,k);af(c1,ref coeffs,k);af(c2,ref coeffs,k);af(c3,ref coeffs,k);}}#[inline(always)]fn eH(state:@[u128;13],ref coeffs:Array<u16>,k:aj){let[u0,u1,u2,u3,_,v0,v1,v2,_,_,bk,bL,_]= *state;let(g0,g1,g2,g3,g4,g5,g6,g7)=cd(by(bk,k),k);if coeffs.len()<=512-68{au(u0,ref coeffs,k);au(v0,ref coeffs,k);bc(g0,g1,g2,g3,ref coeffs,k);au(u1,ref coeffs,k);au(v1,ref coeffs,k);bc(g4,g5,g6,g7,ref coeffs,k);au(u2,ref coeffs,k);au(v2,ref coeffs,k);let(h0,h1,h2,h3)=bP(by(bL,k),k);bc(h0,h1,h2,h3,ref coeffs,k);au(u3,ref coeffs,k);}else{aS(u0,ref coeffs,k);aS(v0,ref coeffs,k);fg(g0,g1,g2,g3,ref coeffs,k);aS(u1,ref coeffs,k);aS(v1,ref coeffs,k);fg(g4,g5,g6,g7,ref coeffs,k);aS(u2,ref coeffs,k);aS(v2,ref coeffs,k);let(h0,h1,h2,h3)=bP(by(bL,k),k);fg(h0,h1,h2,h3,ref coeffs,k);aS(u3,ref coeffs,k);}}impl ed of gU<Word16,PoseidonQ>{type DivT=eX<0,5>;type RemT=PoseidonZq;}#[inline(always)]fn af(candidate:Word16,ref coeffs:Array<u16>,k:aj){if coeffs.len()==512{return;}let(k,r)=eF(candidate,k.q);let k:felt252=k.into();if k!=5{coeffs.append(gO(r));}}const ez:felt252=0x7f8000000000010ef0000000000000000000000000000000000000000000001;
/// Read one squeezed rate lane (< 2^64) as four big-endian 16-bit candidate words. The
/// lane's bytes are little-endian, so each 16-bit chunk holds its stream word
/// byte-swapped: chunk = b0 + 256*b1 for the stream word 256*b0 + b1.


#[inline(always)]fn ac(candidate:Word16,ref coeffs:Array<u16>,k:aj){let(k,r)=eF(candidate,k.q);let k:felt252=k.into();if k!=5{coeffs.append(gO(r));}}
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
impl ew of jr<Word16,61445>{type LowT=eX<0,61444>;type HighT=eX<61445,65535>;}#[inline(always)]fn aU(state:@[u128;10],ref coeffs:Array<ae>,k:aj){let[u0,u1,u2,u3,v0,v1,v2,_,bk,bL]= *state;let kd=Kd{b16:k.aB,b24:k.cX};let(s0,s1,s2,s3,s4,s5,s6)=(bf(u0,k),bf(v0,k),bf(u1,k),bf(v1,k),bf(u2,k),bf(v2,k),bf(u3,k));let uB=bf(bk,k);let uD=bf(bL,k);Rd::run((s0,s1),kd,ref coeffs);let(qW,rb)=eF(uB,k.cY);Rd::run((Lo{v:gO(rb)},(s2,s3)),kd,ref coeffs);Rd::run((Lo2{v:qW},(s4,s5)),kd,ref coeffs);let(_,oi)=eF(uD,k.cY);Rd::run((Lo{v:gO(oi)},s6),kd,ref coeffs);}type br=eX<0,0xffffffffffffffffffffffffffffffff0000>;type el=iL<16777216>;type hE=iL<0x1000000000000000000>;type bz=eX<0,0xffffff>;type jD=eX<0,0xffffffffffffffffffffffffffffff>;type jC=eX<0,0xffffffffffffffffffffffffff>;type nL=eX<0,0xffffffffffffffffffffff>;type hn=eX<0,0xffffffffffffffffff>;type j8=eX<0,0xffffffffffffff>;type nK=eX<0,0xffffffffff>;pub(crate)type ae=eX<0,192549938479>;type fu=eX<0,15729919>;const iO:iL<65535> =65535;const da:iL<12241> =12241;impl iG of jA<u128,iL<65535>>{type Result=eX<0,0xfffeffffffffffffffffffffffffffff0001>;}impl my of jX<eX<0,0xfffeffffffffffffffffffffffffffff0001>,u128>{type Result=br;}impl fq of gU<br,el>{type DivT=jD;type RemT=bz;}impl fr of gU<br,hE>{type DivT=hn;type RemT=hn;}type j3=eX<0,0xffffffffffffffffff00>;impl hf of gU<j3,el>{type DivT=j8;type RemT=bz;}impl jt of gU<jD,Base16>{type DivT=jC;type RemT=Word16;}impl js of gU<jC,Base16>{type DivT=nL;type RemT=Word16;}impl j2 of gU<nL,Base16>{type DivT=hn;type RemT=Word16;}impl j1 of gU<hn,Base16>{type DivT=j8;type RemT=Word16;}impl j0 of gU<j8,Base16>{type DivT=nK;type RemT=Word16;}impl jZ of gU<nK,Base16>{type DivT=bz;type RemT=Word16;}impl eQ of jr<bz,61445>{type LowT=eX<0,61444>;type HighT=eX<61445,0xffffff>;}impl fm of jr<bz,15729920>{type LowT=fu;type HighT=eX<15729920,0xffffff>;}impl jB of jA<fu,iL<12241>>{type Result=ae;}#[derive(Copy,Drop)]struct Lo{v:j3,}#[derive(Copy,Drop)]struct Lo2{v:hn,}impl vV2<N,+Rd<N>,+Rd<(eX<0,0xffffffffffffff>,N)>>of Rd<(Lo2,N)>{#[inline(always)]fn run(q:(Lo2,N),k:Kd,ref c:Array<ae>){let(lo,n)=q;let(q,h)=eF(lo.v,k.b16);match iF::<Word16,61445>(h){Ok(l)=>{c.append(gO(l));Rd::run((q,n),k,ref c);},Err(_)=>Rd::tail((q,n),k,ref c),}}#[inline(always)]fn tail(q:(Lo2,N),k:Kd,ref c:Array<ae>){eJ(q,k,ref c);}}#[derive(Copy,Drop)]struct Kd{b16:NonZero<Base16>,b24:NonZero<el>,}#[inline(always)]fn bf(w:u128,k:aj)->br{let even:u128=w&k.aR;hF::add(hF::mul(even,iO),w)}#[inline(never)]fn eI(c0:bz,ref coeffs:Array<ae>){core::internal::revoke_ap_tracking();core::gas::redeposit_gas();let l0=match iF::<bz,61445>(c0){Ok(l)=>l,Err(_)=>{return;},};coeffs.append(gO(l0));}trait Rd<T>{fn run(q:T,k:Kd,ref c:Array<ae>);fn tail(q:T,k:Kd,ref c:Array<ae>);}#[inline(never)]fn eJ<T,+Rd<T>>(q:T,k:Kd,ref c:Array<ae>){Rd::run(q,k,ref c);}trait Ru<T>{fn rt(q:T,k:B6,ref c:Array<ae>);}type B6=NonZero<Base16>;#[inline(always)]fn kz(k:B6)->Kd{Kd{b16:k,b24:16777216}}trait Rt<T>{fn rt(q:T,k:Kd,ref c:Array<ae>);}impl Tz0 of Ru<eX<0,0xffffffffff>>{#[inline(never)]fn rt(q:eX<0,0xffffffffff>,k:B6,ref c:Array<ae>){Rd::run(q,kz(k),ref c);}}impl Tz1 of Ru<eX<0,0xffffffffffffff>>{#[inline(never)]fn rt(q:eX<0,0xffffffffffffff>,k:B6,ref c:Array<ae>){Rd::run(q,kz(k),ref c);}}impl Tz2 of Ru<eX<0,0xffffffffffffffffff>>{#[inline(never)]fn rt(q:eX<0,0xffffffffffffffffff>,k:B6,ref c:Array<ae>){Rd::run(q,kz(k),ref c);}}impl Tz3 of Ru<eX<0,0xffffffffffffffffffffff>>{#[inline(never)]fn rt(q:eX<0,0xffffffffffffffffffffff>,k:B6,ref c:Array<ae>){Rd::run(q,kz(k),ref c);}}impl Tz4 of Ru<eX<0,0xffffffffffffffffffffffffff>>{#[inline(never)]fn rt(q:eX<0,0xffffffffffffffffffffffffff>,k:B6,ref c:Array<ae>){Rd::run(q,kz(k),ref c);}}impl Tz5 of Ru<eX<0,0xffffffffffffffffffffffffffffff>>{#[inline(never)]fn rt(q:eX<0,0xffffffffffffffffffffffffffffff>,k:B6,ref c:Array<ae>){Rd::run(q,kz(k),ref c);}}impl Tz6 of Rt<br>{#[inline(never)]fn rt(q:br,k:Kd,ref c:Array<ae>){Rd::run(q,k,ref c);}}impl Tz7 of Rt<(bz,br)>{#[inline(never)]fn rt(q:(bz,br),k:Kd,ref c:Array<ae>){Rd::run(q,k,ref c);}}impl Tz8 of Rt<(eX<0,0xffffffffff>,br)>{#[inline(never)]fn rt(q:(eX<0,0xffffffffff>,br),k:Kd,ref c:Array<ae>){Rd::run(q,k,ref c);}}impl Tz9 of Rt<(eX<0,0xffffffffffffff>,br)>{#[inline(never)]fn rt(q:(eX<0,0xffffffffffffff>,br),k:Kd,ref c:Array<ae>){Rd::run(q,k,ref c);}}impl Tz10 of Rt<(eX<0,0xffffffffffffffffff>,br)>{#[inline(never)]fn rt(q:(eX<0,0xffffffffffffffffff>,br),k:Kd,ref c:Array<ae>){Rd::run(q,k,ref c);}}impl Tz11 of Rt<(eX<0,0xffffffffffffffffffffff>,br)>{#[inline(never)]fn rt(q:(eX<0,0xffffffffffffffffffffff>,br),k:Kd,ref c:Array<ae>){Rd::run(q,k,ref c);}}impl Tz12 of Rt<(eX<0,0xffffffffffffffffffffffffff>,br)>{#[inline(never)]fn rt(q:(eX<0,0xffffffffffffffffffffffffff>,br),k:Kd,ref c:Array<ae>){Rd::run(q,k,ref c);}}impl Tz13 of Rt<(eX<0,0xffffffffffffffffffffffffffffff>,br)>{#[inline(never)]fn rt(q:(eX<0,0xffffffffffffffffffffffffffffff>,br),k:Kd,ref c:Array<ae>){Rd::run(q,k,ref c);}}impl Tz14 of Rt<(br,br)>{#[inline(never)]fn rt(q:(br,br),k:Kd,ref c:Array<ae>){Rd::run(q,k,ref c);}}impl Tz15 of Rt<(bz,(br,br))>{#[inline(never)]fn rt(q:(bz,(br,br)),k:Kd,ref c:Array<ae>){Rd::run(q,k,ref c);}}impl Tz16 of Rt<(eX<0,0xffffffffff>,(br,br))>{#[inline(never)]fn rt(q:(eX<0,0xffffffffff>,(br,br)),k:Kd,ref c:Array<ae>){Rd::run(q,k,ref c);}}impl Tz17 of Rt<(eX<0,0xffffffffffffff>,(br,br))>{#[inline(never)]fn rt(q:(eX<0,0xffffffffffffff>,(br,br)),k:Kd,ref c:Array<ae>){Rd::run(q,k,ref c);}}impl qs of Rd<Word16>{#[inline(always)]fn run(q:Word16,k:Kd,ref c:Array<ae>){if let Ok(l)=iF::<Word16,61445>(q){c.append(gO(l));}}#[inline(always)]fn tail(q:Word16,k:Kd,ref c:Array<ae>){eI(gO(q),ref c);}}impl j9 of Rd<bz>{#[inline(always)]fn run(q:bz,k:Kd,ref c:Array<ae>){if let Ok(l)=iF::<bz,61445>(q){c.append(gO(l));}}#[inline(always)]fn tail(q:bz,k:Kd,ref c:Array<ae>){eI(q,ref c);}}impl wv<T,impl H:gU<T,Base16>,+Rd<H::DivT>,+Ru<T>,>of Rd<T>{#[inline(always)]fn run(q:T,k:Kd,ref c:Array<ae>){let(q,w)=eF(q,k.b16);match iF::<Word16,61445>(gO(w)){Ok(l)=>{c.append(gO(l));Rd::run(q,k,ref c);},Err(_)=>Rd::tail(q,k,ref c),}}#[inline(always)]fn tail(q:T,k:Kd,ref c:Array<ae>){Ru::rt(q,k.b16,ref c);}}impl pY<N,+Rd<N>,+Rt<(bz,N)>>of Rd<(bz,N)>{#[inline(always)]fn run(q:(bz,N),k:Kd,ref c:Array<ae>){let(w,n)=q;match iF::<bz,61445>(w){Ok(l)=>{c.append(gO(l));Rd::run(n,k,ref c);},Err(_)=>Rd::tail(n,k,ref c),}}#[inline(always)]fn tail(q:(bz,N),k:Kd,ref c:Array<ae>){Rt::rt(q,k,ref c);}}impl wu<T,N,impl H:gU<T,Base16>,+Rd<(H::DivT,N)>,+Rt<(T,N)>,>of Rd<(T,N)>{#[inline(always)]
fn run(q:(T,N),k:Kd,ref c:Array<ae>){let(q,n)=q;let(q,w)=eF(q,k.b16);match iF::<Word16,61445>(gO(w)){Ok(l)=>{c.append(gO(l));Rd::run((q,n),k,ref c);},Err(_)=>Rd::tail((q,n),k,ref c),}}#[inline(always)]fn tail(q:(T,N),k:Kd,ref c:Array<ae>){Rt::rt(q,k,ref c);}}impl ww of Rd<br>{#[inline(always)]fn run(q:br,k:Kd,ref c:Array<ae>){let(q,h)=eF(q,k.b24);match iF::<bz,15729920>(h){Ok(l)=>{c.append(hF::mul(l,da));Rd::run(q,k,ref c);},Err(_)=>Rd::tail(q,k,ref c),}}#[inline(always)]fn tail(q:br,k:Kd,ref c:Array<ae>){Rt::rt(q,k,ref c);}}impl vX<N,+Rd<N>,+Rt<(br,N)>,+Rd<(eX<0,0xffffffffffffffffffffffffffffff>,N)>>of Rd<(br,N)>{#[inline(always)]fn run(q:(br,N),k:Kd,ref c:Array<ae>){let(q,n)=q;let(q,h)=eF(q,k.b24);match iF::<bz,15729920>(h){Ok(l)=>{c.append(hF::mul(l,da));Rd::run((q,n),k,ref c);},Err(_)=>Rd::tail((q,n),k,ref c),}}#[inline(always)]fn tail(q:(br,N),k:Kd,ref c:Array<ae>){Rt::rt(q,k,ref c);}}trait Cp<T>{fn eY(q:T,k:Kd,ref c:Array<ae>);}impl qa of Cp<bz>{#[inline(always)]fn eY(q:bz,k:Kd,ref c:Array<ae>){j9::run(q,k,ref c);}}impl wl<T,impl H:gU<T,Base16>,+Cp<H::DivT>,+Drop<H::DivT>,>of Cp<T>{#[inline(always)]fn eY(q:T,k:Kd,ref c:Array<ae>){let(q,w)=eF(q,k.b16);qs::run(gO(w),k,ref c);if c.len()!=512{Cp::eY(q,k,ref c);}}}impl wm of Cp<br>{#[inline(always)]fn eY(q:br,k:Kd,ref c:Array<ae>){let(q,h)=eF(q,k.b24);if let Ok(l)=iF::<bz,15729920>(h){c.append(hF::mul(l,da));}if c.len()!=512{Cp::eY(q,k,ref c);}}}impl wt of Rd<Lo>{#[inline(always)]fn run(q:Lo,k:Kd,ref c:Array<ae>){let(q,h)=eF(q.v,k.b24);match iF::<bz,15729920>(h){Ok(l)=>{c.append(hF::mul(l,da));Rd::run(q,k,ref c);},Err(_)=>Rd::tail(q,k,ref c),}}#[inline(always)]fn tail(q:Lo,k:Kd,ref c:Array<ae>){eJ(q,k,ref c);}}impl vV<N,+Rd<N>,+Rd<(eX<0,0xffffffffffffff>,N)>>of Rd<(Lo,N)>{#[inline(always)]fn run(q:(Lo,N),k:Kd,ref c:Array<ae>){let(lo,n)=q;let(q,h)=eF(lo.v,k.b24);match iF::<bz,15729920>(h){Ok(l)=>{c.append(hF::mul(l,da));Rd::run((q,n),k,ref c);},Err(_)=>Rd::tail((q,n),k,ref c),}}#[inline(always)]fn tail(q:(Lo,N),k:Kd,ref c:Array<ae>){eJ(q,k,ref c);}}#[inline(always)]pub(crate)fn hash_to_point_shake_512_raw(message_hash:felt252,salt_a:felt252,salt_b:felt252)->Option<Array<ae>>{hash_to_point_shake_512_raw_tail(message_hash,salt_a,salt_b,cj)}#[inline(always)]fn hash_to_point_shake_512_raw_tail(message_hash:felt252,salt_a:felt252,salt_b:felt252,tail:u32)->Option<Array<ae>>{let sa:u256=salt_a.into();let sb:u256=salt_b.into();let tY:Q32=match downcast(sa.high){Some(v)=>v,None=>{return None;}};let tZ:Q32=match downcast(sb.high){Some(v)=>v,None=>{return None;}};let mh:u256=message_hash.into();let uq:NonZero<nM> =0x1000000000000000000000000;let(sb12,pM)=eF(sb.low,uq);let eM:u128=gO(hF::add(tY,hF::mul(pM,hD)));let l4:u=hF::add(sb12,hF::mul(tZ,hD));let nk=eo();let(state,r4)=bb(bJ(sa.low,mh.low,0x80000000000000000000000000000000,eM,mh.high,aa(l4,31),(QF(sa.low^mh.low),eM^mh.high,gO(gO::<u,u64>(l4)^31)),nk),);let block:bh=([sa.low,mh.low,mh.high,eM],l4);Some(es(state,r4,block,tail,nk))}const cj:u32=15;type bh=([u128;4],u);#[inline(always)]fn dP(block:bh,hW:NonZero<aY>)->[u;9]{let([wa,uF,uG,eM],l4)=block;let(a1,a0)=eF(wa,hW);let(m1,m0)=eF(uF,hW);let(m3,m2)=eF(uG,hW);let(l3,l2)=eF(eM,hW);[a0,a1,l2,l3,l4,m0,m1,m2,m3]}#[inline(never)]fn zz()->u64{0}#[inline(always)]fn cW(block:[u;9])->u256{let[a0,a1,l2,l3,l4,m0,m1,m2,m3]=block;let z=zz();let mut input:Array<u64> =array![];input.append(gO(a0));input.append(gO(a1));input.append(gO(l2));input.append(gO(l3));input.append(gO(l4));input.append(gO(m0));input.append(gO(m1));input.append(gO(m2));input.append(gO(m3));input.append(31);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(0x8000000000000000);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);input.append(z);starknet::SyscallResultTrait::unwrap_syscall(starknet::syscalls::keccak_syscall(input.span()))}type B9=(br,br,br,br,br,br,br,br,br);#[inline(always)]fn pU(state:@[u128;10],k:aj)->B9{let[u0,u1,u2,u3,v0,v1,v2,_,bk,bL]= *state;(bf(u0,k),bf(v0,k),bf(u1,k),bf(v1,k),bf(u2,k),bf(v2,k),bf(u3,k),bf(bk,k),bf(bL,k))}#[inline(always)]fn rU(b:B9,ref coeffs:Array<ae>,kd:Kd,cY:NonZero<hE>){let(s0,s1,s2,s3,s4,s5,s6,uB,uD)=b;Rd::run((s0,s1),kd,ref coeffs);let(qW,rb)=eF(uB,cY);Rd::run((Lo{v:gO(rb)},(s2,s3)),kd,ref coeffs);Rd::run((Lo2{v:qW},(s4,s5)),kd,ref coeffs);let(_,oi)=eF(uD,cY);Rd::run((Lo{v:gO(oi)},s6),kd,ref coeffs);}#[inline(never)]fn q8x(ref coeffs:Array<ae>,st:([u128;10],bD),kd:Kd,aR:u128,cY:NonZero<hE>,nk:co,last:bool)->([u128;10],bD){let aB=kd.b16;let cX=kd.b24;let(mut state,mut r4)=st;let b0=pU(@state,aj{two64:0x10000000000000000,aB,q:POSEIDON_Q_NZ,aR,cX,cY});let(s,r)=keccak_next_k((state,r4),nk);state=s;r4=r;let b1=pU(@state,aj{two64:0x10000000000000000,aB,q:POSEIDON_Q_NZ,aR,cX,cY});let(s,r)=keccak_next_k((state,r4),nk);state=s;r4=r;let b2=pU(@state,aj{two64:0x10000000000000000,aB,q:POSEIDON_Q_NZ,aR,cX,cY});let(s,r)=keccak_next_k((state,r4),nk);state=s;r4=r;let b3=pU(@state,aj{two64:0x10000000000000000,aB,q:POSEIDON_Q_NZ,aR,cX,cY});rU(b0,ref coeffs,kd,cY);rU(b1,ref coeffs,kd,cY);rU(b2,ref coeffs,kd,cY);rU(b3,ref coeffs,kd,cY);if last{return (state,r4);}keccak_next_k((state,r4),nk)}#[inline(always)]pub(crate)fn es(mut state:[u128;10],mut r4:bD,block:bh,tail:u32,nk:co,)->Array<ae>{let(mut coeffs,_)=eg();let k=bd();let ff=512-tail;let aj{aB,aR,cX,cY,..}=k;let kd=Kd{b16:aB,b24:cX};let st=q8x(ref coeffs,(state,r4),kd,aR,cY,nk,false);let(state,r4)=q8x(ref coeffs,st,kd,aR,cY,nk,true);if coeffs.len()>=512{return coeffs;}dm(state,r4,block,ff,coeffs,k)}#[inline(always)]fn dm(state:[u128;10],r4:bD,block:bh,ff:u32,mut coeffs:Array<ae>,k:aj,)->Array<ae>{let[a0,a1,a2,a3,a4,a5,a6,a7,a8,a9]=state;let mut state:[u128;10]=[gO(a0),gO(a1),gO(a2),gO(a3),gO(a4),gO(a5),gO(a6),gO(a7),gO(a8),gO(a9),];let mut r4=r4;let mut all=true;if coeffs.len()>=ff{let head=cW(dP(block,k.two64));let kd=Kd{b16:k.aB,b24:k.cX};Cp::eY(bf(head.low,k),kd,ref coeffs);if coeffs.len()==512{return coeffs;}Cp::eY(bf(head.high,k),kd,ref coeffs);if coeffs.len()==512{return coeffs;}all=false;}while coeffs.len()<512{let(s,r)=bH((state,r4));state=s;r4=r;aO(@state,ref coeffs,k,all);all=true;}coeffs}#[inline(never)]fn aO(state:@[u128;10],ref coeffs:Array<ae>,k:aj,head:bool){let[u0,u1,u2,u3,v0,v1,v2,_,bk,bL]= *state;let mut lanes:Array<u128> =array![];if head{let(l1,l0)=aE(u0,k);let(l3,l2)=aE(v0,k);lanes.append(l0);lanes.append(l1);lanes.append(l2);lanes.append(l3);}let(l9,l4)=aE(bk,k);let(l6,l5)=aE(u1,k);let(l8,l7)=aE(v1,k);let(qY,qX)=aE(u2,k);let(q0,qZ)=aE(v2,k);let(_,q7)=aE(bL,k);let(q9,q8)=aE(u3,k);lanes.append(l4);lanes.append(l5);lanes.append(l6);lanes.append(l7);lanes.append(l8);lanes.append(l9);lanes.append(qX);lanes.append(qY);lanes.append(qZ);lanes.append(q0);lanes.append(q7);lanes.append(q8);lanes.append(q9);let mut lanes=lanes.span();let kd=Kd{b16:k.aB,b24:k.cX};while let Some(lane)=lanes.pop_front(){if coeffs.len()>=512{break;}let(_,lo)=eF(bf(*lane,k),k.cY);Rd::run(Lo{v:gO(lo)},kd,ref coeffs);}}#[cfg(test)]mod lane_reader_tests{use corelib_imports::bounded_int::upcast;use super::{ae,aU,aO,bd};use super::super::shake256::keccak_f1600_packed;#[test]fn test_lane_reader_matches_block_reader_falcon_512_shake(){let k=bd();let mut st:[u128;13]=[1,2,3,4,5,6,7,8,9,10,0xffffffffffffffffffffffffffffffff,12,13];let mut round=0_u32;while round!=6{st=keccak_f1600_packed(st);for start in array![0_u32,400,444,445,480,500,508,511]{let mut a:Array<ae> =array![];let mut b:Array<ae> =array![];let mut i=0;while i!=start{a.append(0);b.append(0);i+=1;}let[s0,s1,s2,s3,_,s5,s6,s7,s8,_,s10,s11,_]=st;let lanes=[s0,s1,s2,s3,s5,s6,s7,s8,s10,s11];aU(@lanes,ref a,k);aO(@lanes,ref b,k,true);let n=if a.len()<b.len(){a.len()}else{b.len()};
assert(n>=512||a.len()==b.len(),'lane reader len');
let mut j=0;while j!=n{let x:u64=upcast(*a[j]);let y:u64=upcast(*b[j]);
assert(x%12289==y%12289,'lane reader');
j+=1;}}round+=1;}}}
