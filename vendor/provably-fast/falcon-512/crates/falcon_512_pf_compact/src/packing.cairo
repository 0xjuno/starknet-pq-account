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
AddHelper as uI,BoundedInt,DivRemHelper,MulHelper as uL,UnitInt,bounded_int as ur,bounded_int_div_rem as qR,downcast,upcast,
};
#[feature("bounded-int-utils")]
use core::internal::bounded_int::{ConstrainHelper as uK,SubHelper as uJ,constrain as tW};use corelib_imports::bounded_int::{downcast as ra,BoundedInt as tX,UnitInt as us,DivRemHelper as uH};use corelib_imports::integer::{U128sFromFelt252Result as qS,u128s_from_felt252 as qT};use pqbench_ntt_pf_compact::typed_ntt::{Input,Word,pack,typed_ntt};use crate::hashing::hash_to_point::ae;
use crate::zq::Q;

/// Coefficients per full felt252 slot (two u128 halves of 9).
pub const VALS_PER_FELT: u32 = 18;
/// felt252 slots for 512 coefficients: 28 full slots + 1 slot with 8.
pub const PACKED_SLOTS: u32 = 29;
/// Coefficients in the last slot: 512 - 28*18.
const LAST_SLOT_VALS: u32 = 8;

const TWO_POW_128: felt252 = 0x100000000000000000000000000000000;

pub(crate)type PackingZq=tX<0,12288>;
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

#[inline(never)]fn cf()->NonZero<PackingQ>{PACKING_Q_NZ}
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
let q=cf();
    let mut full_slots = packed.slice(0, PACKED_SLOTS - 1);
    while let Some(chunk) = full_slots.multi_pop_front::<7>() {
        let [f0, f1, f2, f3, f4, f5, f6] = (*chunk).unbox();
if!unpack_full_slot_u16(f0,ref coeffs,q)|| !unpack_full_slot_u16(f1,ref coeffs,q)|| !unpack_full_slot_u16(f2,ref coeffs,q)|| !unpack_full_slot_u16(f3,ref coeffs,q)|| !unpack_full_slot_u16(f4,ref coeffs,q)|| !unpack_full_slot_u16(f5,ref coeffs,q)|| !unpack_full_slot_u16(f6,ref coeffs,q){
            return None;
        }
    }
    let last: u256 = (*packed.at(PACKED_SLOTS - 1)).into();
if last.high!=0|| !unpack_half8_u16(last.low,ref coeffs,q){
        return None;
    }
    Some(coeffs)
}

#[inline(always)]
fn unpack_full_slot_u16(felt:felt252,ref coeffs:Array<u16>,q:NonZero<PackingQ>)->bool{
    let value: u256 = felt.into();
unpack_half9_u16(value.low,ref coeffs,q)&&unpack_half9_u16(value.high,ref coeffs,q)
}

/// Extract nine base-Q digits from a u128 half. Values below Q^9 are canonical;
/// after eight divisions the remaining quotient is the ninth digit.
#[inline(always)]
fn unpack_half9_u16(value:u128,ref coeffs:Array<u16>,q:NonZero<PackingQ>)->bool{
    let value: Acc8 = match downcast(value) {
        Some(v) => v,
        None => { return false; },
    };
let(rest,d0)=qR(value,q);let(rest,d1)=qR(rest,q);let(rest,d2)=qR(rest,q);let(rest,d3)=qR(rest,q);let(rest,d4)=qR(rest,q);let(rest,d5)=qR(rest,q);let(rest,d6)=qR(rest,q);let(rest,d7)=qR(rest,q);
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
fn unpack_half8_u16(value:u128,ref coeffs:Array<u16>,q:NonZero<PackingQ>)->bool{
    let value: Acc7 = match downcast(value) {
        Some(v) => v,
        None => { return false; },
    };
let(rest,d0)=qR(value,q);let(rest,d1)=qR(rest,q);let(rest,d2)=qR(rest,q);let(rest,d3)=qR(rest,q);let(rest,d4)=qR(rest,q);let(rest,d5)=qR(rest,q);let(rest,d6)=qR(rest,q);
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
type cl=tX<6144,18432>;type cm=tX<-6144,6144>;impl jY of uI<PackingZq,us<6144>>{type Result=cl;}impl ey of uH<cl,PackingQ>{type DivT=tX<0,1>;type RemT=PackingZq;}impl kb of uJ<PackingZq,us<6144>>{type Result=cm;}impl hk of uL<cm,cm>{type Result=tX<-37748736,37748736>;}impl gQ of uK<PackingZq,6145>{type LowT=tX<0,6144>;type HighT=tX<6145,12288>;}type dc=tX<6145,192549956912>;impl fl of uI<ae,us<18433>>{type Result=tX<18433,192549956912>;}impl ka of uJ<tX<18433,192549956912>,PackingZq>{type Result=dc;}impl eR of uH<dc,PackingQ>{type DivT=tX<0,15668480>;type RemT=PackingZq;}
#[inline(always)]fn bg2(d0:PackingZq,d1:PackingZq)->felt252{let p=ur::add(d0,ur::mul(d1,N4B));let t:u128=upcast(ur::add(p,N4BIAS2));let flags=t & N4MASK2;let v:felt252=p.into()-flags.into()*N4QINV;v*v}#[inline(always)]fn sg3(d0:PackingZq,d1:PackingZq,d2:PackingZq,nm:u128)->felt252{let p=ur::add(ur::add(d0,ur::mul(d1,N4B)),ur::mul(d2,N4B3));let t:u128=upcast(ur::add(p,N4BIAS3));let flags=t & nm;let v:felt252=p.into()-flags.into()*N4QINV;v*v}#[inline(always)]fn ay(value:Acc8,ref norm:felt252,q:NonZero<PackingQ>,nm:u128)->(PackingZq,PackingZq,PackingZq,PackingZq,PackingZq,PackingZq,PackingZq,PackingZq,PackingZq){let(rest,d0)=qR(value,q);let(rest,d1)=qR(rest,q);let(rest,d2)=qR(rest,q);let(rest,d3)=qR(rest,q);let(rest,d4)=qR(rest,q);let(rest,d5)=qR(rest,q);let(rest,d6)=qR(rest,q);let(rest,d7)=qR(rest,q);norm+=sg3(d0,d1,d2,nm);norm+=sg3(d3,d4,d5,nm);norm+=sg3(d6,d7,rest,nm);(d0,d1,d2,d3,d4,d5,d6,d7,rest)}#[inline(always)]fn aA(value:Acc8,q:NonZero<PackingQ>)->(PackingZq,PackingZq,PackingZq,PackingZq,PackingZq,PackingZq,PackingZq,PackingZq,PackingZq){let(rest,d0)=qR(value,q);let(rest,d1)=qR(rest,q);let(rest,d2)=qR(rest,q);let(rest,d3)=qR(rest,q);let(rest,d4)=qR(rest,q);let(rest,d5)=qR(rest,q);let(rest,d6)=qR(rest,q);let(rest,d7)=qR(rest,q);(d0,d1,d2,d3,d4,d5,d6,d7,rest)}#[inline(always)]fn ah2(ma:ae,ta:PackingZq,mb:ae,tb:PackingZq,q:NonZero<PackingQ>)->felt252{let offset:us<18433> =18433;let(_,ra_)=qR(ur::sub(ur::add(ma,offset),ta),q);let(_,rb_)=qR(ur::sub(ur::add(mb,offset),tb),q);let u:felt252=ra_.into()+rb_.into()*KJ+KD2;u*u}#[inline(always)]fn ah3(ma:ae,ta:PackingZq,mb:ae,tb:PackingZq,mc:ae,tc:PackingZq,q:NonZero<PackingQ>)->felt252{let o:us<18433> =18433;let(_,x)=qR(ur::sub(ur::add(ma,o),ta),q);let(_,y)=qR(ur::sub(ur::add(mb,o),tb),q);let(_,z)=qR(ur::sub(ur::add(mc,o),tc),q);let u:felt252=x.into()+y.into()*KJ+z.into()*KJ3+KD3;u*u}#[inline(always)]fn eE(value:Acc7,ref norm:felt252,q:NonZero<PackingQ>)->(PackingZq,PackingZq,PackingZq,PackingZq,PackingZq,PackingZq,PackingZq,PackingZq){let(rest,d0)=qR(value,q);let(rest,d1)=qR(rest,q);let(rest,d2)=qR(rest,q);let(rest,d3)=qR(rest,q);let(rest,d4)=qR(rest,q);let(rest,d5)=qR(rest,q);let(rest,d6)=qR(rest,q);norm+=sg3(d0,d1,d2,N4MASK3);norm+=sg3(d3,d4,d5,N4MASK3);norm+=bg2(d6,rest);(d0,d1,d2,d3,d4,d5,d6,rest)}#[inline(always)]fn eZ(value:Acc7,m:[ae;8],ref norm:felt252,q:NonZero<PackingQ>)->(PackingZq,PackingZq,PackingZq,PackingZq,PackingZq,PackingZq,PackingZq,PackingZq){let(rest,d0)=qR(value,q);let(rest,d1)=qR(rest,q);let(rest,d2)=qR(rest,q);let(rest,d3)=qR(rest,q);let(rest,d4)=qR(rest,q);let(rest,d5)=qR(rest,q);let(rest,d6)=qR(rest,q);let[m0,m1,m2,m3,m4,m5,m6,m7]=m;norm+=ah3(m0,d0,m1,d1,m2,d2,q);norm+=ah3(m3,d3,m4,d4,m5,d5,q);norm+=ah2(m6,d6,m7,rest,q);(d0,d1,d2,d3,d4,d5,d6,rest)}#[inline(never)]fn wFL(ref z:felt252)->([felt252;126],[felt252;126]){z+=ag;([z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z],[z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z,z])}#[inline(never)]fn aKJ(f:[felt252;7],g:[felt252;7],ref msg:Span<ae>,ref ny:felt252,q:NonZero<PackingQ>,nm:u128)->Option<[Input;126]>{let[f0,f1,f2,f3,f4,f5,f6]=f;let(high,low)=match qT(f0){qS::Wide(x)=>x,qS::Narrow(x)=>(0,x),};let h0:Acc8=match ra(low){Some(v)=>v,None=>{return None;},};let h1:Acc8=match ra(high){Some(v)=>v,None=>{return None;},};let(high,low)=match qT(f1){qS::Wide(x)=>x,qS::Narrow(x)=>(0,x),};let h2:Acc8=match ra(low){Some(v)=>v,None=>{return None;},};let h3:Acc8=match ra(high){Some(v)=>v,None=>{return None;},};let(high,low)=match qT(f2){qS::Wide(x)=>x,qS::Narrow(x)=>(0,x),};let h4:Acc8=match ra(low){Some(v)=>v,None=>{return None;},};let h5:Acc8=match ra(high){Some(v)=>v,None=>{return None;},};let(high,low)=match qT(f3){qS::Wide(x)=>x,qS::Narrow(x)=>(0,x),};let h6:Acc8=match ra(low){Some(v)=>v,None=>{return None;},};let h7:Acc8=match ra(high){Some(v)=>v,None=>{return None;},};
let(high,low)=match qT(f4){qS::Wide(x)=>x,qS::Narrow(x)=>(0,x),};let h8:Acc8=match ra(low){Some(v)=>v,None=>{return None;},};let h9:Acc8=match ra(high){Some(v)=>v,None=>{return None;},};let(high,low)=match qT(f5){qS::Wide(x)=>x,qS::Narrow(x)=>(0,x),};let h10:Acc8=match ra(low){Some(v)=>v,None=>{return None;},};let h11:Acc8=match ra(high){Some(v)=>v,None=>{return None;},};let(high,low)=match qT(f6){qS::Wide(x)=>x,qS::Narrow(x)=>(0,x),};let h12:Acc8=match ra(low){Some(v)=>v,None=>{return None;},};let h13:Acc8=match ra(high){Some(v)=>v,None=>{return None;},};let(x0,x1,x2,x3,x4,x5,x6,x7,jW)=ay(h0,ref ny,q,nm);let(x9,x10,x11,kN,kO,kP,kQ,kR,hL)=ay(h1,ref ny,q,nm);let x8:PackingZq=jW;let kS:PackingZq=hL;let(kT,kU,x20,x21,kV,kW,kX,kY,hM)=ay(h2,ref ny,q,nm);let(k8,k9,lc,x30,x31,ld,lf,lg,hN)=ay(h3,ref ny,q,nm);let kZ:PackingZq=hM;let lh:PackingZq=hN;let(lj,lk,ll,lm,ln,lp,lq,lr,hO)=ay(h4,ref ny,q,nm);let(lu,lv,lw,lx,ly,lz,lA,lB,hP)=ay(h5,ref ny,q,nm);let ls:PackingZq=hO;let lC:PackingZq=hP;let(lD,lE,lF,lG,lH,lI,lJ,lK,hQ)=ay(h6,ref ny,q,nm);let(lM,lN,lO,lP,lQ,lR,lS,lT,hR)=ay(h7,ref ny,q,nm);let lL:PackingZq=hQ;let lU:PackingZq=hR;let(lV,lW,lX,lY,lZ,ma,mb,mc,hS)=ay(h8,ref ny,q,nm);let(me,mf,mg,mi,mj,mk,ml,mm,hT)=ay(h9,ref ny,q,nm);let md:PackingZq=hS;let mn:PackingZq=hT;let(mo,mp,mq,mr,ms,mt,mu,mv,hU)=ay(h10,ref ny,q,nm);let(mx,hY,hZ,ia,ib,ic,ie,ig,gK)=ay(h11,ref ny,q,nm);let mw:PackingZq=hU;let ih:PackingZq=gK;let(ii,ij,ik,il,im,io,ip,iq,gL)=ay(h12,ref ny,q,nm);let(iu,iv,iw,ix,iy,iz,iA,iB,gM)=ay(h13,ref ny,q,nm);let ir:PackingZq=gL;let iC:PackingZq=gM;let[f0_t,f1_t,f2_t,f3_t,f4_t,f5_t,f6_t]=g;let(high_t,low_t)=match qT(f0_t){qS::Wide(x_t)=>x_t,qS::Narrow(x_t)=>(0,x_t),};let h0_t:Acc8=match ra(low_t){Some(v_t)=>v_t,None=>{return None;},};let h1_t:Acc8=match ra(high_t){Some(v_t)=>v_t,None=>{return None;},};let(high_t,low_t)=match qT(f1_t){qS::Wide(x_t)=>x_t,qS::Narrow(x_t)=>(0,x_t),};let h2_t:Acc8=match ra(low_t){Some(v_t)=>v_t,None=>{return None;},};let h3_t:Acc8=match ra(high_t){Some(v_t)=>v_t,None=>{return None;},};let(high_t,low_t)=match qT(f2_t){qS::Wide(x_t)=>x_t,qS::Narrow(x_t)=>(0,x_t),};let h4_t:Acc8=match ra(low_t){Some(v_t)=>v_t,None=>{return None;},};let h5_t:Acc8=match ra(high_t){Some(v_t)=>v_t,None=>{return None;},};let(high_t,low_t)=match qT(f3_t){qS::Wide(x_t)=>x_t,qS::Narrow(x_t)=>(0,x_t),};let h6_t:Acc8=match ra(low_t){Some(v_t)=>v_t,None=>{return None;},};let h7_t:Acc8=match ra(high_t){Some(v_t)=>v_t,None=>{return None;},};let(high_t,low_t)=match qT(f4_t){qS::Wide(x_t)=>x_t,qS::Narrow(x_t)=>(0,x_t),};let h8_t:Acc8=match ra(low_t){Some(v_t)=>v_t,None=>{return None;},
};let h9_t:Acc8=match ra(high_t){Some(v_t)=>v_t,None=>{return None;},};let(high_t,low_t)=match qT(f5_t){qS::Wide(x_t)=>x_t,qS::Narrow(x_t)=>(0,x_t),};let h10_t:Acc8=match ra(low_t){Some(v_t)=>v_t,None=>{return None;},};let h11_t:Acc8=match ra(high_t){Some(v_t)=>v_t,None=>{return None;},};let(high_t,low_t)=match qT(f6_t){qS::Wide(x_t)=>x_t,qS::Narrow(x_t)=>(0,x_t),};let h12_t:Acc8=match ra(low_t){Some(v_t)=>v_t,None=>{return None;},};let h13_t:Acc8=match ra(high_t){Some(v_t)=>v_t,None=>{return None;},};let[n0,n1,n2,n3,n4,n5,n6,n7,n8,n9,n10,n11,n12,n13,n14,n15,n16,n17,n18,n19,n20,n21,n22,n23,n24,n25,n26,n27,n28,n29,n30,n31,n32,n33,n34,n35,n36,n37,n38,n39,n40,n41,n42,n43,n44,n45,n46,n47,n48,n49,n50,n51,n52,n53,n54,n55,n56,n57,n58,n59,n60,n61,n62,n63,n64,n65,n66,n67,n68,n69,n70,n71,n72,n73,n74,n75,n76,n77,n78,n79,n80,n81,n82,n83,n84,n85,n86,n87,n88,n89,n90,n91,n92,n93,n94,n95,n96,n97,n98,n99,n100,n101,n102,n103,n104,n105,n106,n107,n108,n109,n110,n111,n112,n113,n114,n115,n116,n117,n118,n119,n120,n121,n122,n123,n124,n125]=match msg.multi_pop_front::<126>(){Some(b_t)=>(*b_t).unbox(),None=>{return None;},};let(t0,t1,t2,t3,t4,t5,t6,t7,t8)=aA(h0_t,q);let(t9,t10,t11,t12,t13,t14,t15,t16,t17)=aA(h1_t,q);let(t18,t19,t20,t21,t22,t23,t24,t25,t26)=aA(h2_t,q);let(t27,t28,t29,t30,t31,t32,t33,t34,t35)=aA(h3_t,q);let(t36,t37,t38,t39,t40,t41,t42,t43,t44)=aA(h4_t,q);let(t45,t46,t47,t48,t49,t50,t51,t52,t53)=aA(h5_t,q);let(t54,t55,t56,t57,t58,t59,t60,t61,t62)=aA(h6_t,q);let(t63,t64,t65,t66,t67,t68,t69,t70,t71)=aA(h7_t,q);let(t72,t73,t74,t75,t76,t77,t78,t79,t80)=aA(h8_t,q);let(t81,t82,t83,t84,t85,t86,t87,t88,t89)=aA(h9_t,q);let(t90,t91,t92,t93,t94,t95,t96,t97,t98)=aA(h10_t,q);let(t99,t100,t101,t102,t103,t104,t105,t106,t107)=aA(h11_t,q);let(t108,t109,t110,t111,t112,t113,t114,t115,t116)=aA(h12_t,q);let(t117,t118,t119,t120,t121,t122,t123,t124,t125)=aA(h13_t,q);ny+=ah3(n0,t0,n1,t1,n2,t2,q);ny+=ah3(n3,t3,n4,t4,n5,t5,q);ny+=ah3(n6,t6,n7,t7,n8,t8,q);ny+=ah3(n9,t9,n10,t10,n11,t11,q);ny+=ah3(n12,t12,n13,t13,n14,t14,q);ny+=ah3(n15,t15,n16,t16,n17,t17,q);ny+=ah3(n18,t18,n19,t19,n20,t20,q);ny+=ah3(n21,t21,n22,t22,n23,t23,q);ny+=ah3(n24,t24,n25,t25,n26,t26,q);ny+=ah3(n27,t27,n28,t28,n29,t29,q);ny+=ah3(n30,t30,n31,t31,n32,t32,q);ny+=ah3(n33,t33,n34,t34,n35,t35,q);ny+=ah3(n36,t36,n37,t37,n38,t38,q);ny+=ah3(n39,t39,n40,t40,n41,t41,q);ny+=ah3(n42,t42,n43,t43,n44,t44,q);ny+=ah3(n45,t45,n46,t46,n47,t47,q);ny+=ah3(n48,t48,n49,t49,n50,t50,q);ny+=ah3(n51,t51,n52,t52,n53,t53,q);ny+=ah3(n54,t54,n55,t55,n56,t56,q);ny+=ah3(n57,t57,n58,t58,n59,t59,q);ny+=ah3(n60,t60,n61,t61,n62,t62,q);ny+=ah3(n63,t63,n64,t64,n65,t65,q);ny+=ah3(n66,t66,n67,t67,n68,t68,q);ny+=ah3(n69,t69,n70,t70,n71,t71,q);ny+=ah3(n72,t72,n73,t73,n74,t74,q);ny+=ah3(n75,t75,n76,t76,n77,t77,q);ny+=ah3(n78,t78,n79,t79,n80,t80,q);ny+=ah3(n81,t81,n82,t82,n83,t83,q);ny+=ah3(n84,t84,n85,t85,n86,t86,q);ny+=ah3(n87,t87,n88,t88,n89,t89,q);ny+=ah3(n90,t90,n91,t91,n92,t92,q);ny+=ah3(n93,t93,n94,t94,n95,t95,q);ny+=ah3(n96,t96,n97,t97,n98,t98,q);ny+=ah3(n99,t99,n100,t100,n101,t101,q);ny+=ah3(n102,t102,n103,t103,n104,t104,q);ny+=ah3(n105,t105,n106,t106,n107,t107,q);ny+=ah3(n108,t108,n109,t109,n110,t110,q);ny+=ah3(n111,t111,n112,t112,n113,t113,q);ny+=ah3(n114,t114,n115,t115,n116,t116,q);ny+=ah3(n117,t117,n118,t118,n119,t119,q);ny+=ah3(n120,t120,n121,t121,n122,t122,q);ny+=ah3(n123,t123,n124,t124,n125,t125,q);Some([pack(x0,t0),pack(x1,t1),pack(x2,t2),pack(x3,t3),pack(x4,t4),pack(x5,t5),pack(x6,t6),pack(x7,t7),pack(x8,t8),pack(x9,t9),pack(x10,t10),pack(x11,t11),pack(kN,t12),pack(kO,t13),pack(kP,t14),pack(kQ,t15),pack(kR,t16),pack(kS,t17),pack(kT,t18),pack(kU,t19),pack(x20,t20),pack(x21,t21),pack(kV,t22),pack(kW,t23),pack(kX,t24),pack(kY,t25),pack(kZ,t26),pack(k8,t27),pack(k9,t28),pack(lc,t29),pack(x30,t30),pack(x31,t31),pack(ld,t32),pack(lf,t33),pack(lg,t34),pack(lh,t35),pack(lj,t36),pack(lk,t37),pack(ll,t38),pack(lm,t39),pack(ln,t40),pack(lp,t41),pack(lq,t42),pack(lr,t43),pack(ls,t44),pack(lu,t45),pack(lv,t46),pack(lw,t47),pack(lx,t48),pack(ly,t49),pack(lz,t50),pack(lA,t51),pack(lB,t52),pack(lC,t53),pack(lD,t54),pack(lE,t55),pack(lF,t56),pack(lG,t57),pack(lH,t58),pack(lI,t59),pack(lJ,t60),pack(lK,t61),pack(lL,t62),pack(lM,t63),pack(lN,t64),pack(lO,t65),pack(lP,t66),pack(lQ,t67),pack(lR,t68),pack(lS,t69),pack(lT,t70),pack(lU,t71),pack(lV,t72),pack(lW,t73),pack(lX,t74),pack(lY,t75),pack(lZ,t76),pack(ma,t77),pack(mb,t78),pack(mc,t79),pack(md,t80),pack(me,t81),pack(mf,t82),pack(mg,t83),pack(mi,t84),pack(mj,t85),pack(mk,t86),pack(ml,t87),pack(mm,t88),pack(mn,t89),pack(mo,t90),pack(mp,t91),pack(mq,t92),pack(mr,t93),pack(ms,t94),pack(mt,t95),pack(mu,t96),pack(mv,t97),pack(mw,t98),pack(mx,t99),pack(hY,t100),pack(hZ,t101),pack(ia,t102),pack(ib,t103),pack(ic,t104),pack(ie,t105),pack(ig,t106),pack(ih,t107),pack(ii,t108),pack(ij,t109),pack(ik,t110),pack(il,t111),pack(im,t112),pack(io,t113),pack(ip,t114),pack(iq,t115),pack(ir,t116),pack(iu,t117),pack(iv,t118),pack(iw,t119),pack(ix,t120),pack(iy,t121),pack(iz,t122),pack(iA,t123),pack(iB,t124),pack(iC,t125)])}const aq:[felt252;126]=[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0];const S00:felt252=0x590625348ee7b13ed5063a897278482929cf2104a53c8ebd06ba86c7dbd6164;const S01:felt252=0x590625348ee7b13ed5063a897278482929cf2104a53c8ebd06ba86c7dbd6164;const S02:felt252=0x658337eed5b0e27dae0c5fbe015ff8aad1c64bde6b5dc361434e99077a82c80;const S03:felt252=0x31b1a1a1f74ad985138f97acd710da50c8fbd01654de3b5ec35bee15b4e190b;const S04:felt252=0x41d3f64033feeb3c541394ece5bb36c4313ef95ace1bb4c1914cf91025023b;const S10:felt252=0x740d950ce510909e495e78b2d19ba2174a2e745d9362434943ce965cde10b51;const S11:felt252=0x740d950ce510909e495e78b2d19ba2174a2e745d9362434943ce965cde10b51;const S12:felt252=0x2f5458e8d07ba87bbd6c0dbfb6ac31bef6b031a9a1cca111fa4ac91bcf6bcfa;const S13:felt252=0x5053a8ec7b12c59becc066a88727d9d620df50ae51b3a1974cd910cfa657a98;const S14:felt252=0x79e8207f52ae480c3d140f95023a9ec75bd8c0d150f8fad01baa171f87a3948;const S20:felt252=0x79e8207f52ae480c3d140f95023a9ec75bd8c0d150f8fad01baa171f87a3948;const S21:felt252=0x5280f2a59c8cbdc0b6fc301454e8e5d08ba7c1d6a0dca611dfa0aca711da4b8;const S22:felt252=0x791824d490e7a6d8897d22b9f175a2e1f0a051fe4ab3c6ebdb161a34c9912ec;const S23:felt252=0x193ccebbb16c4df40295478e825d48b926cf31044fe9007aa81c7f68032ac4f;const S24:felt252=0x44f93acec65bdea89bd2164a33c99677882d29b9cc2114a4e73b2ec45cfe2ae;const S30:felt252=0x44f93acec65bdea89bd2164a33c99677882d29b9cc2114a4e73b2ec45cfe2ae;const S31:felt252=0x7a781d7f62adf2b9e0cb5118fa25748d9262489e7cb2bc46be86b286f285bbb;const S32:felt252=0x704da90c7a681ec35b436e985cd3664333eeeb05c5368edd060fdfab57dc634;const S33:felt252=0x1354ee3b096fcdd4cb9117a4d73b8417ea2b1f1a04ca911cfa101faa0474088;const S34:felt252=0x4c13bf96acdc66b4dee605dfe0ab51c3a141f94ace71084fd3ab9728a20e978;const ZS5:felt252=0x4c13bf96acdc66b4dee605dfe0ab51c3a141f94ace71084fd3ab9728a20e978;
const ek:felt252=0x590625348ee7b13ed5063a897278482929cf2104a53c8ebd06ba86c7dbd6164;const eC:felt252=0x740d950ce510909e495e78b2d19ba2174a2e745d9362434943ce965cde10b51;const ej:felt252=0x7a781d7f62adf2b9e0cb5118fa25748d9262489e7cb2bc46be86b286f285bbb;const ag:felt252=0x20000000000000000000000000000000000000000000000000000000000000;const eA:felt252=0x31b1a1a1f74ad985138f97acd710da50c8fbd01654de3b5ec35bee15b4e190b;const dX:felt252=0x5053a8ec7b12c59becc066a88727d9d620df50ae51b3a1974cd910cfa657a98;const bF:felt252=0x1354ee3b096fcdd4cb9117a4d73b8417ea2b1f1a04ca911cfa101faa0474088;const cE:felt252=0x193ccebbb16c4df40295478e825d48b926cf31044fe9007aa81c7f68032ac4f;const dK:felt252=0x5280f2a59c8cbdc0b6fc301454e8e5d08ba7c1d6a0dca611dfa0aca711da4b8;type TypedLane=tX<0,10633823966279326983230456482242756607>;type TypedBase=us<10633823966279326983230456482242756608>;const TYPED_BASE:NonZero<TypedBase>=10633823966279326983230456482242756608;#[inline(never)]fn ctb()->NonZero<TypedBase>{TYPED_BASE}impl TypedSplit of uH<Word,TypedBase>{type DivT=TypedLane;type RemT=TypedLane;}#[inline(always)]fn ak(w:Word,b:PackingZq,dv:NonZero<TypedBase>)->felt252{let(c,a)=qR(w,dv);let a:felt252=a.into();let c:felt252=c.into();let b:felt252=b.into();(a*b+c)*ek}#[inline(always)]fn ce(value:u128,a:[[Word;3];3],q:NonZero<PackingQ>,dv:NonZero<TypedBase>)->bool{let[ta,tb,tc]=a;let[a0,a1,a2]=ta;let x:Acc8=match ra(value){Some(x)=>x,None=>{return false;},};let(x,d0)=qR(x,q);if let qS::Wide(_)=qT(ak(a0,d0,dv)){return false;}let(x,d1)=qR(x,q);if let qS::Wide(_)=qT(ak(a1,d1,dv)){return false;}let(x,d2)=qR(x,q);if let qS::Wide(_)=qT(ak(a2,d2,dv)){return false;}
let(x,d3)=qR(x,q);let[a3,a4,a5]=tb;if let qS::Wide(_)=qT(ak(a3,d3,dv)){return false;}let(x,d4)=qR(x,q);if let qS::Wide(_)=qT(ak(a4,d4,dv)){return false;}let(x,d5)=qR(x,q);if let qS::Wide(_)=qT(ak(a5,d5,dv)){return false;}let(x,d6)=qR(x,q);let[a6,a7,a8]=tc;if let qS::Wide(_)=qT(ak(a6,d6,dv)){return false;}let(x,d7)=qR(x,q);if let qS::Wide(_)=qT(ak(a7,d7,dv)){return false;}if let qS::Wide(_)=qT(ak(a8,x,dv)){return false;}true}#[inline(never)]fn bN(f:[felt252;7],a:[[[Word;3];6];7],q:NonZero<PackingQ>,dv:NonZero<TypedBase>)->(felt252,felt252,felt252){let[f0,f1,f2,f3,f4,f5,f6]=f;let[a0,a1,a2,a3,a4,a5,a6]=a;if!(aC(f0,a0,q,dv)&&aC(f1,a1,q,dv)&&aC(f2,a2,q,dv)&&aC(f3,a3,q,dv)&&aC(f4,a4,q,dv)&&aC(f5,a5,q,dv)){return(-1,-1,-1);}let[a0,a1,a2,a3,a4,a5]=a6;let(high,low)=match qT(f6){qS::Wide(x)=>x,qS::Narrow(x)=>(0,x),};if!ce(low,[a0,a1,a2],q,dv){return(-1,-1,-1);}zL(high,[a3,a4,a5],q,dv)}#[inline(always)]fn zL(value:u128,a:[[Word;3];3],q:NonZero<PackingQ>,dv:NonZero<TypedBase>)->(felt252,felt252,felt252){let[ta,tb,tc]=a;let[a0,a1,a2]=ta;let x:Acc8=match ra(value){Some(x)=>x,None=>{return(-1,-1,-1);},};let(x,d0)=qR(x,q);if let qS::Wide(_)=qT(ak(a0,d0,dv)){return(-1,-1,-1);}let(x,d1)=qR(x,q);if let qS::Wide(_)=qT(ak(a1,d1,dv)){return(-1,-1,-1);}let(x,d2)=qR(x,q);if let qS::Wide(_)=qT(ak(a2,d2,dv)){return(-1,-1,-1);}
let(x,d3)=qR(x,q);let[a3,a4,a5]=tb;if let qS::Wide(_)=qT(ak(a3,d3,dv)){return(-1,-1,-1);}let(x,d4)=qR(x,q);if let qS::Wide(_)=qT(ak(a4,d4,dv)){return(-1,-1,-1);}let(x,d5)=qR(x,q);if let qS::Wide(_)=qT(ak(a5,d5,dv)){return(-1,-1,-1);}let(x,d6)=qR(x,q);let[a6,a7,a8]=tc;let(x,d7)=qR(x,q);(ak(a6,d6,dv),ak(a7,d7,dv),ak(a8,x,dv))}#[inline(always)]fn aC(felt:felt252,a:[[Word;3];6],q:NonZero<PackingQ>,dv:NonZero<TypedBase>)->bool{let[a0,a1,a2,a3,a4,a5]=a;let(high,low)=match qT(felt){qS::Wide(x)=>x,qS::Narrow(x)=>(0,x),};ce(low,[a0,a1,a2],q,dv)&&ce(high,[a3,a4,a5],q,dv)}#[inline(always)]fn cA(felt:felt252,a:[Word;8],q:NonZero<PackingQ>,n:felt252,dv:NonZero<TypedBase>)->(felt252,felt252){if let qS::Wide(_)=qT(n){return(-1,-1);}let[a0,a1,a2,a3,a4,a5,a6,a7]=a;let x:Acc7=match ra(felt){Some(x)=>x,None=>{return(-1,-1);},};let(x,d0)=qR(x,q);if let qS::Wide(_)=qT(ak(a0,d0,dv)){return(-1,-1);}let(x,d1)=qR(x,q);if let qS::Wide(_)=qT(ak(a1,d1,dv)){return(-1,-1);}let(x,d2)=qR(x,q);if let qS::Wide(_)=qT(ak(a2,d2,dv)){return(-1,-1);}let(x,d3)=qR(x,q);if let qS::Wide(_)=qT(ak(a3,d3,dv)){return(-1,-1);}let(x,d4)=qR(x,q);if let qS::Wide(_)=qT(ak(a4,d4,dv)){return(-1,-1);}let(x,d5)=qR(x,q);if let qS::Wide(_)=qT(ak(a5,d5,dv)){return(-1,-1);}let(x,d6)=qR(x,q);(ak(a6,d6,dv),ak(a7,x,dv))}#[inline(never)]pub(crate)fn et(dE:@Box<[felt252;29]>,dY:@Box<[felt252;29]>,mut msg:Span<ae>,tF:@Box<[felt252;29]>)->(felt252,felt252){let q=cf();let[s0,s1,s2,s3,s4,s5,s6,s7,s8,s9,s10,s11,s12,s13,s14,s15,s16,s17,s18,s19,s20,s21,s22,s23,s24,tS,tT,tU,tV]=(*dE).unbox();let mut cy:felt252=0;let[t0,t1,t2,t3,t4,t5,t6,t7,t8,t9,t10,t11,t12,t13,t14,t15,ud,ue,uf,ug,uh,ui,uj,uk,ul,um,un,uo,up]=(*dY).unbox();let tv:Acc7=match ra(up){Some(v)=>v,None=>{return(-1,-1);},};let x0=match aKJ([s0,s1,s2,s3,s4,s5,s6],[t0,t1,t2,t3,t4,t5,t6],ref msg,ref cy,q,N4MASK3){Some(v)=>v,None=>{return(-1,-1);},};let x1=match aKJ([s7,s8,s9,s10,s11,s12,s13],[t7,t8,t9,t10,t11,t12,t13],ref msg,ref cy,q,N4MASK3){Some(v)=>v,None=>{return(-1,-1);},};let x2=match aKJ([s14,s15,s16,s17,s18,s19,s20],[t14,t15,ud,ue,uf,ug,uh],ref msg,ref cy,q,N4MASK3){Some(v)=>v,None=>{return(-1,-1);},};let x3=match aKJ([s21,s22,s23,s24,tS,tT,tU],[ui,uj,uk,ul,um,un,uo],ref msg,ref cy,q,N4MASK3){Some(v)=>v,None=>{return(-1,-1);},};let value:Acc7=match ra(tV){Some(v)=>v,None=>{return(-1,-1);},};let(e0,e1,e2,e3,e4,e5,e6,e7)=eE(value,ref cy,q);let[m0,m1,m2,m3,m4,m5,m6,m7]=match msg.multi_pop_front::<8>(){Some(b)=>(*b).unbox(),_=>{return(-1,-1);}};let(ut,uu,uv,uw,ux,uy,uz,uA)=eZ(tv,[m0,m1,m2,m3,m4,m5,m6,m7],ref cy,q);let(sa,sb)=typed_ntt([x0,x1,x2,x3],[pack(e0,ut),pack(e1,uu),pack(e2,uv),pack(e3,uw),pack(e4,ux),pack(e5,uy),pack(e6,uz),pack(e7,uA)]);let[a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,cJ,cK,cL,cM,cc,cp,cq,cN,cO,cP,cQ,cr,cR,cS,cT,qt,qu,qv]=sa;let[p0,p1,p2,p3,p4,p5,p6,p7,p8,p9,p10,p11,p12,p13,p14,p15,tp,tq,tr,tt,tu,tw,tx,tz,tA,tB,tC,tD,tE]=(*tF).unbox();let dv=ctb();let(u0,v0,w0)=bN([p0,p1,p2,p3,p4,p5,p6],[a0,a1,a2,a3,a4,a5,a6],q,dv);let(u1,v1,w1)=bN([p7,p8,p9,p10,p11,p12,p13],[a7,a8,a9,cJ,cK,cL,cM],q,dv);let(u2,v2,w2)=bN([p14,p15,tp,tq,tr,tt,tu],[cc,cp,cq,cN,cO,cP,cQ],q,dv);let(u3,v3,w3)=bN([tw,tx,tz,tA,tB,tC,tD],[cr,cR,cS,cT,qt,qu,qv],q,dv);if let qS::Wide(_)=qT(u0){return(-1,-1);}if let qS::Wide(_)=qT(v0){return(-1,-1);}if let qS::Wide(_)=qT(u1){return(-1,-1);}if let qS::Wide(_)=qT(v1){return(-1,-1);}if let qS::Wide(_)=qT(u2){return(-1,-1);}if let qS::Wide(_)=qT(v2){return(-1,-1);}if let qS::Wide(_)=qT(u3){return(-1,-1);}if let qS::Wide(_)=qT(v3){return(-1,-1);}if let qS::Wide(_)=qT(w0){return(-1,-1);}if let qS::Wide(_)=qT(w1){return(-1,-1);}if let qS::Wide(_)=qT(w2){return(-1,-1);}if let qS::Wide(_)=qT(w3){return(-1,-1);}let(jh,jl)=match qT(cy+OFJ){qS::Wide(x)=>x,qS::Narrow(_)=>{return(-1,-1);},};let(_,s02)=qR(jl&0xfffffffff000000000fffffffff,N72);let(s6,_)=qR(jh,N88);let nn:felt252=s02.into()+s6.into();cA(tE,sb,q,34034726-nn,dv)}
#[inline(always)]fn zf(x:PackingZq)->felt252{x.into()}const KJ:felt252=0x1000000000;const KJ3:felt252=0x1000000000000000000000000000;const KD2:felt252=0x800000000000010fffffffffffffffffffffffffffffffffffe7fffffffe801;const KD3:felt252=0x800000000000010fffffffffffffffffe7ffffffffffffffffe7fffffffe801;const OFJ:felt252=0x800000000800000000000000000800000000000000000;const N72:NonZero<us<0xffffffffffffffffff>> =0xffffffffffffffffff;const N88:NonZero<us<0x10000000000000000000000>> =0x10000000000000000000000;impl jU1 of uH<u128,us<0xffffffffffffffffff>>{type DivT=tX<0,0x100000000000000>;type RemT=tX<0,0xfffffffffffffffffe>;}impl jU4 of uH<u128,us<0x10000000000000000000000>>{type DivT=tX<0,0xffffffffff>;type RemT=tX<0,0xffffffffffffffffffffff>;}

// Extract independent centered-digit flags from separated norm lanes.
type N4D1=tX<0,844424930131968>;type N4D2=tX<0,3987683987354747618711421180841033728>;type N4P2=tX<0,844424930144256>;type N4P3=tX<0,3987683987354747618712265605771177984>;
const N4B:us<68719476736>=68719476736;const N4B3:us<324518553658426726783156020576256>=324518553658426726783156020576256;
impl N4Mul1 of uL<PackingZq,us<68719476736>>{type Result=N4D1;}impl N4Mul2 of uL<PackingZq,us<324518553658426726783156020576256>>{type Result=N4D2;}
impl N4Add1 of uI<PackingZq,N4D1>{type Result=N4P2;}impl N4Add2 of uI<N4P2,N4D2>{type Result=N4P3;}
const N4BIAS2:us<140668768880639>=140668768880639;const N4MASK2:u128=562949953429504;impl N4Bias2 of uI<N4P2,us<140668768880639>>{type Result=tX<140668768880639,985093699024895>;}
const N4BIAS3:us<664289479338799509725261042888476671>=664289479338799509725261042888476671;const N4MASK3:u128=2658455991569831745808177070514118656;impl N4Bias3 of uI<N4P3,us<664289479338799509725261042888476671>>{type Result=tX<664289479338799509725261042888476671,4651973466693547128437526648659654655>;}
const N4QINV:felt252=1808809682566871010753239355074989267886550786960801817186256343979052236802;
