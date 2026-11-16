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

use pqbench_ntt_pf_record::engine::intt;
use pqbench_ntt_pf_record::falcon512::{PRODUCT_BITS, PRODUCT_BOUND_FELT, config};
use pqbench_ntt_pf_record::{ad,aw,ntt_falcon512_fast_u16_unchecked};use corelib_imports::integer::{U128sFromFelt252Result as aV,u128s_from_felt252 as cu};
use crate::zq::{Q32, center_sq, centered_difference_sq};

/// Maximum allowed `||s0||^2 + ||s1||^2` for Falcon-512 (FIPS 206 / falcon.py sig_bound).
pub const SIG_BOUND_512: u64 = 34034726;

/// The Falcon modulus as a u32 divisor.
const Q32_NZ: NonZero<u32> = 12289;

use corelib_imports::bounded_int::{AddHelper as bv,BoundedInt as ax,DivRemHelper as aX,MulHelper as cv,UnitInt as aW,bounded_int as aQ,upcast as cw,};
#[feature("bounded-int-utils")]
use core::internal::bounded_int::SubHelper as b9;type bw=aW<12289>;const fx:NonZero<bw> =12289;#[inline(never)]fn jo()->NonZero<bw>{fx}type dJ=ax<0,4294836225>;type cD=ax<0,12288>;type dW=ax<0,0xffffffffffffffffffffffffffffffff>;const bj:felt252=0x4000000000000000000000000000a19;type cF=ax<2054,133124>;type dn=ax<-6144,6144>;type ex=ax<-37748736,37748736>;impl j7 of cv<u16,u16>{type Result=dJ;}impl ja of aX<dW,bw>{type DivT=ax<0,0x55538e425e9e075fd8ab7c6d68632>;type RemT=cD;}impl eb of bv<u16,aW<67589>>{type Result=ax<67589,133124>;}impl gT of b9<ax<67589,133124>,u16>{type Result=cF;}impl fo of aX<cF,bw>{type DivT=ax<0,10>;type RemT=cD;}impl jE of b9<cD,aW<6144>>{type Result=dn;}impl jb of cv<dn,dn>{type Result=ex;}#[inline(always)]fn Z(a:u16,b:u16,c:ad,q:NonZero<bw>)->felt252{let product:felt252=aQ::mul(a,b).into();let x=product+(bj-c.value);let x:dW=match cu(x){aV::Narrow(low)=>cw(low),
aV::Wide(_)=>panic!("lazy hint check out of range"),
};let(_,r)=aQ::div_rem(x,q);r.into()}type db=ax<6144,71679>;impl jq of bv<u16,aW<6144>>{type Result=db;}impl eO of aX<db,bw>{type DivT=ax<0,5>;type RemT=cD;}#[inline(always)]fn ar(v:u16,q:NonZero<bw>)->felt252{let half:aW<6144> =6144;let(_,r)=aQ::div_rem(aQ::add(v,half),q);let c=aQ::sub(r,half);aQ::mul(c,c).into()}#[inline(always)]fn ab(a:u16,b:u16,q:NonZero<bw>)->felt252{let offset:aW<67589> =67589;let half:aW<6144> =6144;let(_,r)=aQ::div_rem(aQ::sub(aQ::add(a,offset),b),q);let c=aQ::sub(r,half);aQ::mul(c,c).into()}
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
let hint_ntt=aw(mul_hint);

    let mut s1_ntt_iter = s1_ntt.span();
let mut hint_ntt_iter=hint_ntt;
    let mut h_iter = h_ntt;
    let mut msg_iter = msg_point;
    let mut hint_iter = mul_hint;
    let mut s1_iter = s1;

    // Fused pass, 16-way unrolled (512 = 16 * 32, no remainder): hint check and
    // centered-norm accumulation per coefficient.
    // Max acc = 512 * 2 * 6144^2 < 2^36, so the felt252 accumulator cannot wrap
    // and always fits u64.
let qb=jo();
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
let r0=Z(s1n0,h0,hn0,qb);let r1=Z(s1n1,h1,hn1,qb);let r2=Z(s1n2,h2,hn2,qb);let r3=Z(s1n3,h3,hn3,qb);let r4=Z(s1n4,h4,hn4,qb);let r5=Z(s1n5,h5,hn5,qb);let r6=Z(s1n6,h6,hn6,qb);let r7=Z(s1n7,h7,hn7,qb);let r8=Z(s1n8,h8,hn8,qb);let r9=Z(s1n9,h9,hn9,qb);let r10=Z(s1n10,h10,hn10,qb);let r11=Z(s1n11,h11,hn11,qb);let r12=Z(s1n12,h12,hn12,qb);let r13=Z(s1n13,h13,hn13,qb);let r14=Z(s1n14,h14,hn14,qb);let r15=Z(s1n15,h15,hn15,qb);
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
acc+=ab(m0,t0,qb)+ar(v0,qb);acc+=ab(m1,t1,qb)+ar(v1,qb);acc+=ab(m2,t2,qb)+ar(v2,qb);acc+=ab(m3,t3,qb)+ar(v3,qb);acc+=ab(m4,t4,qb)+ar(v4,qb);acc+=ab(m5,t5,qb)+ar(v5,qb);acc+=ab(m6,t6,qb)+ar(v6,qb);acc+=ab(m7,t7,qb)+ar(v7,qb);acc+=ab(m8,t8,qb)+ar(v8,qb);acc+=ab(m9,t9,qb)+ar(v9,qb);acc+=ab(m10,t10,qb)+ar(v10,qb);acc+=ab(m11,t11,qb)+ar(v11,qb);acc+=ab(m12,t12,qb)+ar(v12,qb);acc+=ab(m13,t13,qb)+ar(v13,qb);acc+=ab(m14,t14,qb)+ar(v14,qb);acc+=ab(m15,t15,qb)+ar(v15,qb);
    }
    if !ok {
        return false;
    }
    let norm: u64 = acc.try_into().unwrap();
    norm <= SIG_BOUND_512
}

pub(crate)const do:felt252=bj;
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
    use pqbench_ntt_pf_record::engine::{intt, ntt};
    use pqbench_ntt_pf_record::falcon512::{PRODUCT_BITS, PRODUCT_BOUND_FELT, config};
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
