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
//! - rotations are division-free: every rotation amount is baked in as its power of
//!
//! [`keccak_f1600`] is shared with the hash-to-point squeezer
//! (`hash_to_point::hash_to_point_shake_512`), which drives the sponge lazily and
//! reads candidates straight from the rate lanes; the byte-oriented [`shake256`] here
//! is the generic XOF, pinned to the FIPS 202 known-answer vectors below.

const RATE_LANES: u32 = 17; // 136 bytes / 8
const RATE_BYTES: u32 = 136;

/// Keccak-f[1600] round constants (FIPS 202, Table 1).
const ROUND_CONSTANTS:[u128;24]=[0x40000000000000000000000000000000,0x20000000000008080000000000000000,0x2a000000000002020000000000000000,0x800000008000800000000000000000,0x22c00000000000200000000000000000,0x100000000800000000000000000000,0x2060000000200020000000000000000,0x80098000000000000000000000000000,0x228000000000000000000000000000,0x88000000000000000000000000000,0x2002400000002000000000000000000,0xa00000000800000000000000000,0x2022c0000000200000000000000000,0x8b8000000000000000000000000,0x20226000000000000000000000000,0x800380000000,0x28000000000008,0x8080,0x800a0000000,0xa800000008000,0x800080818,0x8080800000,0x100000000800,0x8000000080008008];

use corelib_imports::bounded_int::{AddHelper as oS,BoundedInt as oh,DivRemHelper as oR,MulHelper as oT,UnitInt as oP,bounded_int as oQ,upcast as pK,};
#[feature("bounded-int-utils")]
use core::internal::bounded_int::{ConstrainHelper as pZ,SubHelper as pN,constrain as pL};type dp=oP<0x10000000000000000>;pub(crate)type u=oh<0,0xffffffffffffffff>;const bM:NonZero<dp> =0x10000000000000000;type cn=oP<0xffffffffffffffffffffffffffffffff>;const bq:cn=0xffffffffffffffffffffffffffffffff;impl jg of pN<cn,u128>{type Result=oh<0,0xffffffffffffffffffffffffffffffff>;}
#[inline(always)]
fn split(w:u128)->(u128,u128){let(high,low)=oQ::div_rem(w,bM);(pK(high),pK(low))
}

#[inline(always)]pub(crate)fn pack(lo:u128,hi:u128)->u128{let packed:felt252=lo.into()+hi.into()*0x10000000000000000;packed.try_into().unwrap()}impl gR of oR<u128,dp>{type DivT=u;type RemT=u;}type cG=oP<0x10000000000000000>;type bs=oh<0,0xffffffffffffffff0000000000000000>;impl jc of oT<u,cG>{type Result=bs;}impl he of oS<u,bs>{type Result=oh<0,0xffffffffffffffffffffffffffffffff>;}#[inline(always)]pub(crate)fn aa(lo:u,hi:u)->u128{let two64:cG=0x10000000000000000;pK(oQ::add(lo,oQ::mul(hi,two64)))}#[inline(always)]fn aN(hi:u)->bs{let two64:cG=0x10000000000000000;oQ::mul(hi,two64)}type dI=oP<0x10000000000000001>;impl fv of oT<u,dI>{type Result=oh<0,0xffffffffffffffffffffffffffffffff>;}#[inline(always)]fn bO(x:u)->u128{let m:dI=0x10000000000000001;pK(oQ::mul(x,m))}#[inline(always)]fn al(lo:u,hi:bs)->u128{pK(oQ::add(lo,hi))}type hy=oh<0,0x7fffffffffffffff>;type ho=oh<0,0xfffffffffffffffe>;type hw=oh<0,63>;type hB=oh<0,0x3ffffffffffffff>;type hr=oh<0,0xffffffffffffffc0>;impl jx of oR<u,oP<0x400000000000000>>{type DivT=hw;type RemT=hB;}impl nF of oT<hB,oP<64>>{type Result=hr;}impl ns of oS<hr,hw>{type Result=u;}type hx=oh<0,255>;type hC=oh<0,0xffffffffffffff>;type hs=oh<0,0xffffffffffffff00>;impl jy of oR<u,oP<72057594037927936>>{type DivT=hx;type RemT=hC;}impl nG of oT<hC,oP<256>>{type Result=hs;}impl nt of oS<hs,hx>{type Result=u;}type fV=oh<0,1048575>;type gv=oh<0,0xfffffffffff>;type fC=oh<0,0xfffffffffff00000>;impl iT of oR<u,oP<17592186044416>>{type DivT=fV;type RemT=gv;}impl mY of oT<gv,oP<1048576>>{type Result=fC;}impl mE of oS<fC,fV>{type Result=u;}type fW=oh<0,2097151>;type gw=oh<0,8796093022207>;type fD=oh<0,0xffffffffffe00000>;impl iU of oR<u,oP<8796093022208>>{type DivT=fW;type RemT=gw;}impl mZ of oT<gw,oP<2097152>>{type Result=fD;}impl mF of oS<fD,fW>{type Result=u;}type fX=oh<0,33554431>;type gx=oh<0,549755813887>;type fE=oh<0,0xfffffffffe000000>;impl iV of oR<u,oP<549755813888>>{type DivT=fX;type RemT=gx;}impl na of oT<gx,oP<33554432>>{type Result=fE;}impl mG of oS<fE,fX>{type Result=u;}type fZ=oh<0,268435455>;type gz=oh<0,68719476735>;type fG=oh<0,0xfffffffff0000000>;impl iX of oR<u,oP<68719476736>>{type DivT=fZ;type RemT=gz;}impl nd of oT<gz,oP<268435456>>{type Result=fG;}impl mI of oS<fG,fZ>{type Result=u;}type gd=oh<0,549755813887>;type gB=oh<0,33554431>;type fI=oh<0,0xffffff8000000000>;impl iZ of oR<u,oP<33554432>>{type DivT=gd;type RemT=gB;}impl ng of oT<gB,oP<549755813888>>{type Result=fI;}impl mK of oS<fI,gd>{type Result=u;}type gf=oh<0,2199023255551>;type gC=oh<0,8388607>;type fJ=oh<0,0xfffffe0000000000>;impl i0 of oR<u,oP<8388608>>{type DivT=gf;type RemT=gC;}impl nh of oT<gC,oP<2199023255552>>{type Result=fJ;}impl mL of oS<fJ,gf>{
type Result=u;}type gg=oh<0,8796093022207>;type gD=oh<0,2097151>;type fK=oh<0,0xfffff80000000000>;impl i1 of oR<u,oP<2097152>>{type DivT=gg;type RemT=gD;}impl ni of oT<gD,oP<8796093022208>>{type Result=fK;}impl mM of oS<fK,gg>{type Result=u;}type gk=oh<0,35184372088831>;type gF=oh<0,524287>;type fM=oh<0,0xffffe00000000000>;impl i4 of oR<u,oP<524288>>{type DivT=gk;type RemT=gF;}impl nk of oT<gF,oP<35184372088832>>{type Result=fM;}impl mO of oS<fM,gk>{type Result=u;}type gp=oh<0,0x3fffffffffffffff>;type gJ=oh<0,3>;type fQ=oh<0,0xc000000000000000>;impl i9 of oR<u,oP<4>>{type DivT=gp;type RemT=gJ;}impl no of oT<gJ,oP<0x4000000000000000>>{type Result=fQ;}impl mS of oS<fQ,gp>{type Result=u;}type fU=oh<0,262143>;type gu=oh<0,70368744177663>;type fB=oh<0,0xfffffffffffc0000>;impl iS of oR<u,oP<70368744177664>>{type DivT=fU;type RemT=gu;}impl mX of oT<gu,oP<262144>>{type Result=fB;}impl mD of oS<fB,fU>{type Result=u;}#[inline(always)]fn bm(x:u,d:NonZero<oP<70368744177664>>)->u{let m:oP<262144> =262144;let(aH,rest)=oQ::div_rem(x,d);oQ::add(oQ::mul(rest,m),aH)}type gn=oh<0,0xffffffffffffff>;type gH=oh<0,255>;type fO=oh<0,0xff00000000000000>;impl i6 of oR<u,oP<256>>{type DivT=gn;type RemT=gH;}impl nm of oT<gH,oP<72057594037927936>>{type Result=fO;}impl mQ of oS<fO,gn>{type Result=u;}#[inline(always)]fn bY(x:u,d:NonZero<oP<256>>)->u{let m:oP<72057594037927936> =72057594037927936;let(aH,rest)=oQ::div_rem(x,d);oQ::add(oQ::mul(rest,m),aH)}type go=oh<0,0x1fffffffffffffff>;type gI=oh<0,7>;type fP=oh<0,0xe000000000000000>;impl i7 of oR<u,oP<8>>{type DivT=go;type RemT=gI;}impl nn of oT<gI,oP<0x2000000000000000>>{type Result=fP;}impl mR of oS<fP,go>{type Result=u;}#[inline(always)]fn bZ(x:u,d:NonZero<oP<8>>)->u{let m:oP<0x2000000000000000> =0x2000000000000000;let(aH,rest)=oQ::div_rem(x,d);oQ::add(oQ::mul(rest,m),aH)}fn aI<D,M,impl H:oR<u,D>,impl X:oT<H::RemT,M>,impl A:oS<X::Result,H::DivT>>(x:u,d:NonZero<D>,m:M)->A::Result{let(t,r)=oQ::div_rem(x,d);oQ::add(oQ::mul(r,m),t)}impl ve of oR<u,oP<9007199254740992>>{type DivT=oh<0,2047>;type RemT=oh<0,9007199254740991>;}impl vA of oT<oh<0,9007199254740991>,oP<2048>>{type Result=oh<0,0xfffffffffffff800>;}impl uN of oS<oh<0,0xfffffffffffff800>,oh<0,2047>>{type Result=u;}const nv:oP<2048>=2048;impl vf of oR<u,oP<4503599627370496>>{type DivT=oh<0,4095>;type RemT=oh<0,0xfffffffffffff>;}impl vB of oT<oh<0,0xfffffffffffff>,oP<4096>>{type Result=oh<0,0xfffffffffffff000>;}impl uO of oS<oh<0,0xfffffffffffff000>,oh<0,4095>>{type Result=u;}const qd:oP<4096>=4096;impl vh of oR<u,oP<0x800000000000>>{type DivT=oh<0,131071>;type RemT=oh<0,0x7fffffffffff>;}impl vD of oT<oh<0,0x7fffffffffff>,oP<131072>>{type Result=oh<0,0xfffffffffffe0000>;}impl uQ of oS<oh<0,0xfffffffffffe0000>,oh<0,131071>>{type Result=u;}const qf:oP<131072>=131072;
impl vi of oR<u,oP<4398046511104>>{type DivT=oh<0,4194303>;type RemT=oh<0,4398046511103>;}impl vE of oT<oh<0,4398046511103>,oP<4194304>>{type Result=oh<0,0xffffffffffc00000>;}impl uR of oS<oh<0,0xffffffffffc00000>,oh<0,4194303>>{type Result=u;}const nw:oP<4194304>=4194304;impl vj of oR<u,oP<2199023255552>>{type DivT=oh<0,8388607>;type RemT=oh<0,2199023255551>;}impl vF of oT<oh<0,2199023255551>,oP<8388608>>{type Result=oh<0,0xffffffffff800000>;}impl uS of oS<oh<0,0xffffffffff800000>,oh<0,8388607>>{type Result=u;}const nx:oP<8388608>=8388608;impl vk of oR<u,oP<274877906944>>{type DivT=oh<0,67108863>;type RemT=oh<0,274877906943>;}impl vG of oT<oh<0,274877906943>,oP<67108864>>{type Result=oh<0,0xfffffffffc000000>;}impl uT of oS<oh<0,0xfffffffffc000000>,oh<0,67108863>>{type Result=u;}const ny:oP<67108864>=67108864;impl vm of oR<u,oP<17179869184>>{type DivT=oh<0,1073741823>;type RemT=oh<0,17179869183>;}impl vI of oT<oh<0,17179869183>,oP<1073741824>>{type Result=oh<0,0xffffffffc0000000>;}impl uV of oS<oh<0,0xffffffffc0000000>,oh<0,1073741823>>{type Result=u;}const qh:oP<1073741824>=1073741824;impl vo of oR<u,oP<1073741824>>{type DivT=oh<0,17179869183>;type RemT=oh<0,1073741823>;}impl vK of oT<oh<0,1073741823>,oP<17179869184>>{type Result=oh<0,0xfffffffc00000000>;}impl uX of oS<oh<0,0xfffffffc00000000>,oh<0,17179869183>>{type Result=u;}const qj:oP<17179869184>=17179869184;impl vp of oR<u,oP<536870912>>{type DivT=oh<0,34359738367>;type RemT=oh<0,536870911>;}impl vL of oT<oh<0,536870911>,oP<34359738368>>{type Result=oh<0,0xfffffff800000000>;}impl uY of oS<oh<0,0xfffffff800000000>,oh<0,34359738367>>{type Result=u;}const nA:oP<34359738368>=34359738368;impl vq of oR<u,oP<67108864>>{type DivT=oh<0,274877906943>;type RemT=oh<0,67108863>;}impl vM of oT<oh<0,67108863>,oP<274877906944>>{type Result=oh<0,0xffffffc000000000>;}impl uZ of oS<oh<0,0xffffffc000000000>,oh<0,274877906943>>{type Result=u;}const qk:oP<274877906944>=274877906944;impl vr of oR<u,oP<16777216>>{type DivT=oh<0,0xffffffffff>;type RemT=oh<0,16777215>;}impl vN of oT<oh<0,16777215>,oP<1099511627776>>{type Result=oh<0,0xffffff0000000000>;}impl u5 of oS<oh<0,0xffffff0000000000>,oh<0,0xffffffffff>>{type Result=u;}const ql:oP<1099511627776>=1099511627776;impl vs of oR<u,oP<131072>>{type DivT=oh<0,0x7fffffffffff>;type RemT=oh<0,131071>;}impl vO of oT<oh<0,131071>,oP<0x800000000000>>{type Result=oh<0,0xffff800000000000>;}impl u6 of oS<oh<0,0xffff800000000000>,oh<0,0x7fffffffffff>>{type Result=u;}const nB:oP<0x800000000000>=0x800000000000;impl vt of oR<u,oP<65536>>{type DivT=oh<0,0xffffffffffff>;type RemT=oh<0,65535>;}impl vP of oT<oh<0,65535>,oP<281474976710656>>{type Result=oh<0,0xffff000000000000>;}impl u7 of oS<oh<0,0xffff000000000000>,oh<0,0xffffffffffff>>{type Result=u;}const qm:oP<281474976710656>=281474976710656;impl vz of oR<u,oP<32>>{type DivT=oh<0,0x7ffffffffffffff>;type RemT=oh<0,31>;}impl vU of oT<oh<0,31>,oP<0x800000000000000>>{type Result=oh<0,0xf800000000000000>;}impl vd of oS<oh<0,0xf800000000000000>,oh<0,0x7ffffffffffffff>>{type Result=u;}const qr:oP<0x800000000000000>=0x800000000000000;impl vg of oR<u,oP<281474976710656>>{type DivT=oh<0,65535>;type RemT=oh<0,0xffffffffffff>;}impl vC of oT<oh<0,0xffffffffffff>,oP<65536>>{type Result=oh<0,0xffffffffffff0000>;}impl uP of oS<oh<0,0xffffffffffff0000>,oh<0,65535>>{type Result=u;}const qe:oP<65536>=65536;
impl vy of oR<u,oP<2048>>{type DivT=oh<0,9007199254740991>;type RemT=oh<0,2047>;}impl vT of oT<oh<0,2047>,oP<9007199254740992>>{type Result=oh<0,0xffe0000000000000>;}impl vc of oS<oh<0,0xffe0000000000000>,oh<0,9007199254740991>>{type Result=u;}const qq:oP<9007199254740992>=9007199254740992;type eW=oP<0x20000000000000000>;type eV=oh<0,0x1ffffffffffffffff>;impl gS of oR<u128,eW>{type DivT=oh<0,0x7fffffffffffffff>;type RemT=eV;}impl g8 of pZ<eV,0x10000000000000000>{type LowT=u;type HighT=oh<0x10000000000000000,0x1ffffffffffffffff>;}impl iJ of pN<oh<0x10000000000000000,0x1ffffffffffffffff>,oP<0x10000000000000000>>{type Result=u;}impl iD of oS<oh<0,0x7fffffffffffffff>,oP<0x8000000000000000>>{type Result=oh<0x8000000000000000,0xffffffffffffffff>;}#[inline(always)]fn ci(w:u128,hH:NonZero<eW>)->(u,u){let(q,rem)=oQ::div_rem(w,hH);match pL::<eV,0x10000000000000000>(rem){Ok(lo)=>(lo,pK(q)),Err(hi)=>{let t:oP<0x10000000000000000>=0x10000000000000000;let p:oP<0x8000000000000000>=0x8000000000000000;(oQ::sub(hi,t),pK(oQ::add(q,p)))},}}type df=oP<0xffffffffffffffff>;impl iI of pN<df,u>{type Result=u;}#[inline(always)]fn aP(a:u,b:u)->u{let a:u64=pK(a);let b:u64=pK(b);pK(a^b)}#[inline(always)]fn em(b:u,c:u,aG:df)->u{let nb:u64=pK(oQ::sub(aG,b));let c:u64=pK(c);pK(nb&c)}#[derive(Copy,Drop)]struct az{two64:NonZero<dp>,q4:NonZero<oP<0x1000000000000000>>,q13:NonZero<oP<0x8000000000000>>,q19:NonZero<oP<0x200000000000>>,q37:NonZero<oP<0x8000000>>,q42:NonZero<oP<0x400000>>,q54:NonZero<oP<0x400>>,q60:NonZero<oP<0x10>>,aG:cn,jj:NonZero<oP<70368744177664>>,kB:NonZero<oP<256>>,kC:NonZero<oP<8>>,d6:NonZero<oP<0x400000000000000>>,d8:NonZero<oP<72057594037927936>>,kr:NonZero<oP<17592186044416>>,ks:NonZero<oP<8796093022208>>,nV:NonZero<oP<549755813888>>,jk:NonZero<oP<68719476736>>,n5:NonZero<oP<33554432>>,kx:NonZero<oP<8388608>>,n7:NonZero<oP<2097152>>,kz:NonZero<oP<524288>>,og:NonZero<oP<4>>,hH:NonZero<eW>,ko:NonZero<oP<9007199254740992>>,nR:NonZero<oP<4503599627370496>>,nU:NonZero<oP<0x800000000000>>,kt:NonZero<oP<4398046511104>>,ck:NonZero<oP<2199023255552>>,ku:NonZero<oP<274877906944>>,nY:NonZero<oP<17179869184>>,n3:NonZero<oP<1073741824>>,kv:NonZero<oP<536870912>>,n4:NonZero<oP<67108864>>,n6:NonZero<oP<16777216>>,kA:NonZero<oP<131072>>,n8:NonZero<oP<65536>>,oe:NonZero<oP<32>>,nT:NonZero<oP<281474976710656>>,oc:NonZero<oP<2048>>,bI:df,}#[inline(never)]fn ef()->az{az{q4:0x1000000000000000,q13:0x8000000000000,q19:0x200000000000,q37:0x8000000,q42:0x400000,q54:0x400,q60:0x10,two64:bM,aG:bq,
jj:70368744177664,kB:256,kC:8,d6:0x400000000000000,d8:72057594037927936,kr:17592186044416,ks:8796093022208,nV:549755813888,jk:68719476736,n5:33554432,kx:8388608,n7:2097152,kz:524288,og:4,hH:0x20000000000000000,ko:9007199254740992,nR:4503599627370496,nU:0x800000000000,kt:4398046511104,ck:2199023255552,ku:274877906944,nY:17179869184,n3:1073741824,kv:536870912,n4:67108864,n6:16777216,kA:131072,n8:65536,oe:32,nT:281474976710656,oc:2048,bI:0xffffffffffffffff,}}

#[inline(always)]fn am(x:u128,aG:cn)->u128{pK(oQ::sub(aG,x))}#[inline(always)]fn W(w:u128,two64:NonZero<dp>)->(u,u){oQ::div_rem(w,two64)}impl gP of pZ<u,0x8000000000000000>{type LowT=oh<0,0x7fffffffffffffff>;type HighT=oh<0x8000000000000000,0xffffffffffffffff>;}impl jh of pN<oh<0x10000000000000000,0x1fffffffffffffffe>,oP<0xffffffffffffffff>>{type Result=oh<1,0xffffffffffffffff>;}#[inline(always)]fn cg(x:u,d:NonZero<oP<0x400000000000000>>)->u{let m:oP<64> =64;let(aH,rest)=oQ::div_rem(x,d);oQ::add(oQ::mul(rest,m),aH)}#[inline(always)]fn ch(x:u,d:NonZero<oP<72057594037927936>>)->u{let m:oP<256> =256;let(aH,rest)=oQ::div_rem(x,d);oQ::add(oQ::mul(rest,m),aH)}#[inline(always)]fn bS(x:u,d:NonZero<oP<17592186044416>>)->u{let m:oP<1048576> =1048576;let(aH,rest)=oQ::div_rem(x,d);oQ::add(oQ::mul(rest,m),aH)}#[inline(always)]fn bT(x:u,d:NonZero<oP<8796093022208>>)->u{let m:oP<2097152> =2097152;let(aH,rest)=oQ::div_rem(x,d);oQ::add(oQ::mul(rest,m),aH)}#[inline(always)]fn dy(x:u,d:NonZero<oP<549755813888>>)->u{let m:oP<33554432> =33554432;let(aH,rest)=oQ::div_rem(x,d);oQ::add(oQ::mul(rest,m),aH)}#[inline(always)]fn bn(x:u,d:NonZero<oP<68719476736>>)->u{let m:oP<268435456> =268435456;let(aH,rest)=oQ::div_rem(x,d);oQ::add(oQ::mul(rest,m),aH)}#[inline(always)]fn dA(x:u,d:NonZero<oP<33554432>>)->u{let m:oP<549755813888> =549755813888;let(aH,rest)=oQ::div_rem(x,d);oQ::add(oQ::mul(rest,m),aH)}#[inline(always)]fn bV(x:u,d:NonZero<oP<8388608>>)->u{let m:oP<2199023255552> =2199023255552;let(aH,rest)=oQ::div_rem(x,d);oQ::add(oQ::mul(rest,m),aH)}#[inline(always)]fn dB(x:u,d:NonZero<oP<2097152>>)->u{let m:oP<8796093022208> =8796093022208;let(aH,rest)=oQ::div_rem(x,d);oQ::add(oQ::mul(rest,m),aH)}#[inline(always)]fn bX(x:u,d:NonZero<oP<524288>>)->u{let m:oP<35184372088832> =35184372088832;let(aH,rest)=oQ::div_rem(x,d);oQ::add(oQ::mul(rest,m),aH)}#[inline(always)]fn dD(x:u,d:NonZero<oP<4>>)->u{let m:oP<0x4000000000000000> =0x4000000000000000;let(aH,rest)=oQ::div_rem(x,d);oQ::add(oQ::mul(rest,m),aH)}#[inline(always)]fn ep(x:u,aG:df)->u{oQ::sub(aG,x)}impl pO of oT<oh<0,0x7fffffffffffffff>,oP<0x20000000000000000>>{type Result=oh<0,0xfffffffffffffffe0000000000000000>;}impl pP of oS<oh<0,0xfffffffffffffffe0000000000000000>,oh<0,0x7fffffffffffffff>>{type Result=oh<0,0xfffffffffffffffe7fffffffffffffff>;}impl nH of oS<oh<0x100000000000000000000000000000000,0x1fffffffffffffffe0000000000000000>,oh<0x8000000000000000,0xffffffffffffffff>>{type Result=oh<0x100000000000000008000000000000000,0x1fffffffffffffffeffffffffffffffff>;}impl nI of pN<oh<0x100000000000000008000000000000000,0x1fffffffffffffffeffffffffffffffff>,oP<0xffffffffffffffffffffffffffffffff>>{type Result=oh<0x8000000000000001,0xffffffffffffffff0000000000000000>;}
impl nJ of oS<oh<0x8000000000000001,0xffffffffffffffff0000000000000000>,oh<0x8000000000000000,0xffffffffffffffff>>{type Result=oh<0x10000000000000001,0xffffffffffffffffffffffffffffffff>;}impl pQ of oS<oh<0,0xfffffffffffffffe7fffffffffffffff>,oh<0,0x7fffffffffffffff>>{type Result=oh<0,0xfffffffffffffffefffffffffffffffe>;}impl pR of oT<oh<0x8000000000000000,0xffffffffffffffff>,oP<0x20000000000000000>>{type Result=oh<0x100000000000000000000000000000000,0x1fffffffffffffffe0000000000000000>;}impl pS of oS<oh<0x100000000000000000000000000000000,0x1fffffffffffffffe0000000000000000>,oh<0,0x7fffffffffffffff>>{type Result=oh<0x100000000000000000000000000000000,0x1fffffffffffffffe7fffffffffffffff>;}impl pT of pN<oh<0x100000000000000000000000000000000,0x1fffffffffffffffe7fffffffffffffff>,oP<0xffffffffffffffff0000000000000000>>{type Result=oh<0x10000000000000000,0xffffffffffffffff7fffffffffffffff>;}impl pU of oS<oh<0x10000000000000000,0xffffffffffffffff7fffffffffffffff>,oh<0,0x7fffffffffffffff>>{type Result=oh<0x10000000000000000,0xfffffffffffffffffffffffffffffffe>;}impl pV of oS<oh<0,0xfffffffffffffffe0000000000000000>,oh<0x8000000000000000,0xffffffffffffffff>>{type Result=oh<0x8000000000000000,0xfffffffffffffffeffffffffffffffff>;}impl pW of pN<oh<0x8000000000000000,0xfffffffffffffffeffffffffffffffff>,oP<0xffffffffffffffff>>{type Result=oh<-0x7fffffffffffffff,0xfffffffffffffffe0000000000000000>;}impl pX of oS<oh<-0x7fffffffffffffff,0xfffffffffffffffe0000000000000000>,oh<0x8000000000000000,0xffffffffffffffff>>{type Result=oh<1,0xfffffffffffffffeffffffffffffffff>;}#[inline(always)]fn aT(c0:u,ca:u,cb:u,bo:eW,gV:df,g8:cn)->(u,u128){match zc(ca){Ok(xa)=>match zc(cb){Ok(xb)=>match zc(c0){Ok(x0)=>(zr0(x0),z0(xa,xb,bo)),Err(x0)=>(zr1(x0,gV),z0(xa,xb,bo)),},Err(xb)=>match zc(c0){Ok(x0)=>(zr0(x0),z1(xa,xb,bo)),Err(x0)=>(zr1(x0,gV),z1(xa,xb,bo)),},},Err(xa)=>match zc(cb){Ok(xb)=>match zc(c0){Ok(x0)=>(zr0(x0),z2(xa,xb,bo,gV)),Err(x0)=>(zr1(x0,gV),z2(xa,xb,bo,gV)),},Err(xb)=>match zc(c0){Ok(x0)=>(zr0(x0),z3(xa,xb,bo,g8)),Err(x0)=>(zr1(x0,gV),z3(xa,xb,bo,g8)),},},}}pub(crate)type jf=([u128;10],u128,u,u,u);

#[inline(always)]fn eK(u0:u128,cU:eU)->(u128,u,u,u,u128){dZ(u0,cU,bM,zV,bq)}

#[inline(always)]fn dZ(u0:u128,cU:eU,two64:NonZero<dp>,gV:df,g8:cn)->(u128,u,u,u,u128){let(nP,nQ,c4)=cU;let(c1,c0)=W(nP,two64);let(c3,c2)=W(nQ,two64);let(r0,tG)=aT(c0,c1,c2,zM,gV,g8);let p12=aa(c1,c2);let di=aa(c4,c0)^tG;(di,c3,c4,r0,p12)}#[inline(always)]pub(crate)fn fk(st:[u128;12],g4:u,cU:eU)->jf{let[u0,u1,u2,u3,u4,v0,v1,v2,v3,v4,bk,bL]=st;let(di,c3,c4,r0,p12)=eK(u0,cU);let dM=am(di,bq);let(cK,cJ)=W(u2^dM,bM);let(cJ,tH)=aT(cJ,c3,c4,zM,zV,bq);let ck=p12^tH;let d4=aP(c3,r0);let dN=am(ck,bq);let dj=bO(d4);([v0^ck,u1^di,v1^ck,v2^dN,u3^di,v3^ck,u4^dM,v4^dN,bk^dj,bL^dj],u0^di,cJ,cK,ep(aP(g4,d4),0xffffffffffffffff))}#[inline(always)]pub(crate)fn bJ(u0:u128,u1:u128,_u3:u128,v0:u128,v1:u128,bk:u128,cU:eU,k:co)->jf{let(di,c3,c4,r0,p12)=dZ(u0,cU,k.two64,k.bI,k.aG);let dM=am(di,k.aG);let(cK,cJ)=W(dM,k.two64);let(cJ,tH)=aT(cJ,c3,c4,zM,k.bI,k.aG);let ck=p12^tH;let d4=aP(c3,r0);let dN=am(ck,k.aG);let dj=bO(d4);([v0^ck,u1^di,v1^ck,dN,QF(di),ck,dM,dN,bk^dj,dj],u0^di,cJ,cK,ep(d4,k.bI))}#[inline(always)]fn hX(p:jf,k:az)->(u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u){let([w0,w1,w2,w4,w5,w6,w7,w8,w9,uC],wu,cJ,cK,cT)=p;let(bK,bx)=ci(wu,k.hH);let(dq,cH)=W(w0,k.two64);let(dt,ds)=W(w1,k.two64);let(cI,du)=W(w2,k.two64);let(cM,cL)=W(w4,k.two64);let(cq,cp)=W(w5,k.two64);let(cO,cN)=W(w6,k.two64);let(cr,cQ)=W(w7,k.two64);let(cS,cR)=W(w8,k.two64);let(dv,dr)=W(w9,k.two64);let(cP,cc)=W(uC,k.two64);let cc=ep(cc,k.bI);(bK,bx,cH,dq,dr,ds,dt,du,cI,dv,cJ,cK,cL,cM,cc,cp,cq,cN,cO,cP,cQ,cr,cR,cS,cT)}#[inline(always)]fn ao(st:([u128;12],u),k:az)->(u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u){let(st,g3)=st;let[e0,e1,e2,e3,e4,o0,o1,o2,o3,o4,bk,hI]=st;let eD=e0^e1^e2^e3^e4;let hG=o0^o1^o2^o3^o4;let(gh,gl)=W(bk^hI,k.two64);let c4=aP(aP(gh,gl),g3);let(c2,c0)=W(eD,k.two64);let(c3,c1)=W(hG,k.two64);let(kL,kM)=zA(c1,c3,c2,c4,k.hH.into(),k.bI,k.aG);let kp=eD^kM;let dk=am(kp,k.aG);let(cO,cq)=W(o3^dk,k.two64);let ee=aa(c4,c1)^kL;let jH=am(ee,k.aG);let(zq,zm)=oQ::div_rem(e2^jH,k.hH);let(r0,cq,cJ,cL)=zB(c0,cq,zq,zm,k.bI);let(dq,bx)=W(o0^dk,k.two64);let d4=aP(c3,r0);let dj=bO(d4);let(cH,bK)=W(e0^ee,k.two64);let(du,ds)=W(e1^ee,k.two64);let(cI,dt)=W(o1^dk,k.two64);let(cM,cK)=W(o2^kp,k.two64);let(cN,cp)=W(e3^ee,k.two64);let(cR,cQ)=W(e4^jH,k.two64);let(cS,cr)=W(o4^kp,k.two64);let(dv,dr)=W(bk^dj,k.two64);let(cT,cc)=W(hI^dj,k.two64);let cP=aP(g3,d4);(bK,bx,cH,dq,dr,ds,dt,du,cI,dv,cJ,cK,cL,cM,cc,cp,cq,cN,cO,cP,cQ,cr,cR,cS,cT)}#[inline(always)]fn av(a:(u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u),k:az)->(u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u){let(bK,bx,cH,dq,dr,ds,dt,du,cI,dv,cJ,cK,cL,cM,cc,cp,cq,cN,cO,cP,cQ,cr,cR,cS,cT)=a;(bS(bK,k.kr),dt,cL,bV(cO,k.kx),aI(cT,k.n3,qj),aI(dq,k.n8,qm),aI(dv,k.n6,ql),aI(cJ,k.ck,nx),cq,aI(cR,k.nU,qf),bT(bx,k.ks),aI(du,k.ku,ny),bX(cM,k.kz),bn(cP,k.jk),aI(cQ,k.n4,qk),aI(dr,k.kA,nB),bY(ds,k.kB),aI(cK,k.nY,qh),aI(cN,k.kv,nA),aI(cS,k.nR,qd),bm(cH,k.jj),aI(cI,k.ko,nv),aI(cc,k.oe,qr),bZ(cp,k.kC),aI(cr,k.kt,nw))}pub(crate)type bD=(u,u,u,u,u);#[inline(always)]pub(crate)fn pJ(r:bD)->(u128,u128,u){let(b20,b21,b22,b23,b24)=r;let eG=aa(b22,b23);(aa(b20,b21)^(am(aa(b21,b22),bq)&eG),eG^(am(aa(b23,b24),bq)&aa(b24,b20)),aP(b24,em(b20,b21,0xffffffffffffffff)))}#[inline(always)]pub(crate)fn jp(s:([u128;10],bD))->([u128;12],u){let([u0,u1,u2,u3,v0,v1,v2,v3,bk,bL],r)=s;let(u4,v4,g4)=pJ(r);([u0,u1,u2,u3,u4,v0,v1,v2,v3,v4,bk,bL],g4)}pub(crate)type eU=(u128,u128,u);#[inline(always)]pub(crate)fn jn(st:@[u128;12],g4:u)->eU{let[u0,u1,u2,u3,u4,v0,v1,v2,v3,v4,bk,bL]= *st;let(gh,gl)=W(bk^bL,bM);(u0^u1^u2^u3^u4,v0^v1^v2^v3^v4,aP(aP(gh,gl),g4))}#[inline(never)]fn dw(st:[u128;12],g4:u,cU:eU)->([u128;10],bD){dQ(st,g4,cU)
}

#[inline(always)]pub(crate)fn bH(s:([u128;10],bD))->([u128;10],bD){bu(s)}#[inline(always)]pub(crate)fn bu(s:([u128;10],bD))->([u128;10],bD){keccak_next_k(s,eo())}#[inline(always)]pub(crate)fn keccak_next_k(s:([u128;10],bD),c:co)->([u128;10],bD){let co{two64,aG,bI}=c;let([u0,u1,u2,u3,v0,v1,v2,v3,bk,bL],(b20,b21,b22,b23,b24))=s;let eG=aa(b22,b23);let u4=aa(b20,b21)^(am(aa(b21,b22),aG)&eG);let v4=eG^(am(aa(b23,b24),aG)&aa(b24,b20));let g4=aP(b24,em(b20,b21,bI));let(gh,gl)=W(bk^bL,two64);let cU=(u0^u1^u2^u3^u4,v0^v1^v2^v3^v4,aP(aP(gh,gl),g4));let(di,c3,c4,r0,p12)=dZ(u0,cU,two64,bI,aG);let dM=am(di,aG);let(cK,cJ)=W(u2^dM,two64);let(cJ,tH)=aT(cJ,c3,c4,zM,bI,aG);let ck=p12^tH;let d4=aP(c3,r0);let dN=am(ck,aG);let dj=bO(d4);bb(([v0^ck,u1^di,v1^ck,v2^dN,u3^di,v3^ck,u4^dM,v4^dN,bk^dj,bL^dj],u0^di,cJ,cK,ep(aP(g4,d4),bI)))}#[derive(Copy,Drop)]pub(crate)struct co{two64:NonZero<dp>,aG:cn,bI:df,}#[inline(never)]pub(crate)fn eo()->co{co{two64:bM,aG:bq,bI:0xffffffffffffffff}}#[inline(always)]fn km(b:(u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u),rc:u128,k:az)->[u128;10]{let(b00,b01,b02,b03,b04,b05,b06,b07,b08,b09,b10,b11,b12,b13,b14,b15,b16,b17,b18,b19)=b;let s05=aN(b05);let s06=aN(b06);let s15=aN(b15);let s16=aN(b16);let s19=aN(b19);let s09=aN(b09);let oU=aa(b00,b01);let oV=aa(b01,b02);let jI=aa(b02,b03);let oW=aa(b03,b04);let oX=aa(b04,b00);let oY=al(b05,s06);let oZ=aa(b06,b07);let jJ=aa(b07,b08);let o5=al(b08,s09);let o6=al(b09,s05);let o7=aa(b10,b11);let o8=aa(b11,b12);let jK=aa(b12,b13);let o9=aa(b13,b14);let pa=aa(b14,b10);let pb=al(b15,s16);let pd=aa(b16,b17);let jL=aa(b17,b18);let pe=al(b18,s19);let pf=al(b19,s15);let kF=al(b04,s09);let kJ=al(b00,s05);let kG=al(b01,s06);let qU=al(b14,s19);let sL=al(b10,s15);let kH=al(b11,s16);[oU^(am(oV,k.aG)&jI)^rc,oY^(am(oZ,k.aG)&jJ),o7^(am(o8,k.aG)&jK),pb^(am(pd,k.aG)&jL),jI^(am(oW,k.aG)&oX),jJ^(am(o5,k.aG)&o6),jK^(am(o9,k.aG)&pa),jL^(am(pe,k.aG)&pf),kF^(am(kJ,k.aG)&kG),qU^(am(sL,k.aG)&kH)]}#[inline(always)]fn aF(b:(u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u),rc:u128,k:az)->([u128;12],u){let(b00,b01,b02,b03,b04,b05,b06,b07,b08,b09,b10,b11,b12,b13,b14,b15,b16,b17,b18,b19,b20,b21,b22,b23,b24)=b;let s05=aN(b05);let s09=aN(b09);let s20=aN(b20);let s24=aN(b24);let pg=aa(b00,b02);let jM=aa(b01,b03);let jN=aa(b02,b04);let ph=aa(b03,b00);let pi=aa(b05,b07);let jO=aa(b06,b08);let jP=al(b07,s09);let pj=al(b08,s05);let pl=aa(b10,b12);let jQ=aa(b11,b13);let jR=aa(b12,b14);let pm=aa(b13,b10);let pn=aa(b15,b17);let jS=aa(b16,b18);let jT=aa(b17,b19);let po=aa(b18,b15);let pp=aa(b20,b22);let jU=aa(b21,b23);let jV=al(b22,s24);let pq=al(b23,s20);let kF=al(b04,s09);let kJ=al(b00,s05);let kG=aa(b01,b06);let qV=al(b14,s24);let sM=al(b10,s20);let kI=aa(b11,b21);([pg^(jM|jN)^rc,pi^(jO|jP),pl^(jQ|jR),pn^(jS|jT),pp^(jU|jV),jM^(jN&ph),jO^(jP&pj),jQ^(jR&pm),jS^(jT&po),jU^(jV&pq),kF^(am(kJ,k.aG)&kG),qV^(sM|am(kI,k.aG))],aP(b19,em(b15,b16,k.bI)))}#[inline(always)]pub(crate)fn keccak_f1600_packed(st:[u128;13])->[u128;13]{let[u0,u1,u2,u3,u4,v0,v1,v2,v3,v4,bk,bL,g4]=st;let g4:u64=g4.try_into().unwrap();let([u0,u1,u2,u3,u4,v0,v1,v2,v3,v4,bk,bL],g4)=cB([u0,u1,u2,u3,u4,v0,v1,v2,v3,v4,bk,bL],pK(g4));[u0,u1,u2,u3,u4,v0,v1,v2,v3,v4,bk,bL,pK(g4)]}#[inline(always)]pub(crate)fn cB(st:[u128;12],g4:u)->([u128;12],u){let cU=jn(@st,g4);jp(dw(st,g4,cU))}#[inline(always)]pub(crate)fn dQ(st:[u128;12],g4:u,cU:eU)->([u128;10],bD){bb(fk(st,g4,cU))}pub(crate)fn bb(p:jf)->([u128;10],bD){let k=ef();let[r0,r1,r2,r3,r4,r5,r6,r7,r8,r9,r10,r11,r12,r13,r14,r15,r16,r17,r18,r19,r20,r21,r22,r23]=core::box::BoxTrait::new(ROUND_CONSTANTS).unbox();let mut st=QC(QR(hX(p,k),k),r0,k);st=QC(QR(QT(st,k),k),r1,k);st=QC(QR(QT(st,k),k),r2,k);st=QC(QR(QT(st,k),k),r3,k);st=QC(QR(QT(st,k),k),r4,k);st=QC(QR(QT(st,k),k),r5,k);st=QC(QR(QT(st,k),k),r6,k);st=QC(QR(QT(st,k),k),r7,k);st=QC(QR(QT(st,k),k),r8,k);st=QC(QR(QT(st,k),k),r9,k);st=QC(QR(QT(st,k),k),r10,k);st=QC(QR(QT(st,k),k),r11,k);st=QC(QR(QT(st,k),k),r12,k);st=QC(QR(QT(st,k),k),r13,k);st=QC(QR(QT(st,k),k),r14,k);st=aF(QR(QT(st,k),k),r15,k);st=aF(av(ao(st,k),k),r16,k);st=aF(av(ao(st,k),k),r17,k);st=aF(av(ao(st,k),k),r18,k);st=aF(av(ao(st,k),k),r19,k);st=aF(av(ao(st,k),k),r20,k);st=aF(av(ao(st,k),k),r21,k);st=aF(av(ao(st,k),k),r22,k);let(b00,b01,b02,b03,b04,b05,b06,b07,b08,b09,b10,b11,b12,b13,b14,b15,b16,b17,b18,b19,b20,b21,b22,b23,b24)=av(QL(st,k),k);(km((b00,b01,b02,b03,b04,b05,b06,b07,b08,b09,b10,b11,b12,b13,b14,b15,b16,b17,b18,b19),r23,k),(b20,b21,b22,b23,b24))}pub(crate)fn keccak_f1600(state:[u128;25])->[u128;25]{let[s00,s01,s02,s03,s04,s05,s06,s07,s08,s09,s10,s11,s12,s13,s14,s15,s16,s17,s18,s19,s20,s21,s22,s23,s24]=state;let st:[u128;13]=[pack(s00,s01),pack(s05,s06),pack(s10,s11),pack(s15,s16),pack(s20,s21),pack(s02,s03),pack(s07,s08),pack(s12,s13),pack(s17,s18),pack(s22,s23),pack(s04,s09),pack(s14,s19),s24];let st=keccak_f1600_packed(st);let[u0,u1,u2,u3,u4,v0,v1,v2,v3,v4,bk,bL,g4]=st;let(sO,sN)=split(u0);let(sT,sS)=split(u1);let(sY,sX)=split(u2);let(tg,tf)=split(u3);let(tl,tk)=split(u4);let(sQ,sP)=split(v0);let(sV,sU)=split(v1);let(td,sZ)=split(v2);let(ti,th)=split(v3);let(tn,tm)=split(v4);let(sW,sR)=split(bk);let(tj,te)=split(bL);[sN,sO,sP,sQ,sR,sS,sT,sU,sV,sW,sX,sY,sZ,td,te,tf,tg,th,ti,tj,tk,tl,tm,tn,g4]}
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
#[cfg(test)]mod keccak_f_vectors{use super::keccak_f1600;#[test]fn test_keccak_f_vector_0_falcon_512_shake(){let out=keccak_f1600([0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]);assert!(out.span()==[0xf1258f7940e1dde7,0x84d5ccf933c0478a,0xd598261ea65aa9ee,0xbd1547306f80494d,0x8b284e056253d057,0xff97a42d7f8e6fd4,0x90fee5a0a44647c4,0x8c5bda0cd6192e76,0xad30a6f71b19059c,0x30935ab7d08ffc64,0xeb5aa93f2317d635,0xa9a6e6260d712103,0x81a57c16dbcf555f,0x43b831cd0347c826,0x1f22f1a11a5569f,0x5e5635a21d9ae61,0x64befef28cc970f2,0x613670957bc46611,0xb87c5a554fd00ecb,0x8c3ee88a1ccf32c8,0x940c7922ae3a2614,0x1841f924a2c509e4,0x16f53526e70465c2,0x75f644e97f30a13b,0xeaf1ff7b5ceca249].span());}#[test]fn test_keccak_f_vector_1_falcon_512_shake(){let out=keccak_f1600([0xf1258f7940e1dde7,0x84d5ccf933c0478a,0xd598261ea65aa9ee,0xbd1547306f80494d,0x8b284e056253d057,0xff97a42d7f8e6fd4,0x90fee5a0a44647c4,0x8c5bda0cd6192e76,0xad30a6f71b19059c,0x30935ab7d08ffc64,0xeb5aa93f2317d635,0xa9a6e6260d712103,0x81a57c16dbcf555f,0x43b831cd0347c826,0x1f22f1a11a5569f,0x5e5635a21d9ae61,0x64befef28cc970f2,0x613670957bc46611,0xb87c5a554fd00ecb,0x8c3ee88a1ccf32c8,0x940c7922ae3a2614,0x1841f924a2c509e4,0x16f53526e70465c2,0x75f644e97f30a13b,0xeaf1ff7b5ceca249]);assert!(out.span()==[0x2d5c954df96ecb3c,0x6a332cd07057b56d,0x93d8d1270d76b6c,0x8a20d9b25569d094,0x4f9c4f99e5e7f156,0xf957b9a2da65fb38,0x85773dae1275af0d,0xfaf4f247c3d810f7,0x1f1b9ee6f79a8759,0xe4fecc0fee98b425,0x68ce61b6b9ce68a1,0xdeea66c4ba8f974f,0x33c43d836eafb1f5,0xe00654042719dbd9,0x7cf8a9f009831265,0xfd5449a6bf174743,0x97ddad33d8994b40,0x48ead5fc5d0be774,0xe3b8c8ee55b7b03c,0x91a0226e649e42e9,0x900e3129e7badd7b,0x202a9ec5faa3cce8,0x5b3402464e1c3db6,0x609f4e62a44c1059,0x20d06cd26a8fbf5c].span());}#[test]fn test_keccak_f_vector_2_falcon_512_shake(){let out=keccak_f1600([0xc93a7b79aeda89b,0x19274f6f35db5136,0x25baf726d0c8f9d1,0x324e9ede6bb6a26c,0x3ee2469606a44b07,0x4b75ee4da191f3a2,0x580996053c7f9c3d,0x649d3dbcd76d44d8,0x7130e574725aed73,0x7dc48d2c0d48960e,0x8a5834e3a8363ea9,0x96ebdc9b4323e744,0xa37f8452de118fdf,0xb0132c0a78ff387a,0xbca6d3c213ece115,0xc93a7b79aeda89b0,0xd5ce233149c8324b,0xe261cae8e4b5dae6,0xeef572a07fa38381,0xfb891a581a912c1c,0x81cc20fb57ed4b7,0x14b069c7506c7d52,0x2144117eeb5a25ed,0x2dd7b9368647ce88,0x3a6b60ee21357723]);assert!(out.span()==[0x9a55f58818107b8b,0x9c237535940baf72,0xbd0c324152d6220d,0x9da8569ccdb5dd3a,0xf0d46ce0f516f6ef,0x53e71ddc3d52f807,0xf4607b43da76737,0x335f9806c8093c30,0xb7fe91f3443df64,0xa8daf764a67c5b2d,0xc4d14662ca484e1d,0xce05173999243243,0xce0794b41ae88376,0x58bc49864db0750d,0x95e1762981b2c986,0xe589329e740f147,0x43a283a94c4c4392,0x48b1b58973e61ee2,0x32d7ccb6f0dd477b,0x7d5ca23bf2b6a73,0x69dd5a92ff95434d,0x8d7da9e66673bf7a,0x28df10e4105aab86,0xae75fe0245d5b0de,0xf6e32cdf7679c422].span());}#[test]fn test_keccak_f_vector_3_falcon_512_shake(){let out=keccak_f1600([0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff,0xffffffffffffffff]);assert!(out.span()==[0x9f00f21bba6817c4,0xcdf5aa0d21af5e78,0xd6539abf24095b97,0x8bb6f30a010f8228,0xf0f711ba0547331d,0x4f44330558eb182f,0x2213b79d9055207c,0xeb5e5b55ca4fb490,0xbfaeb81a299b5d4,0x9e5d924f1a65ed48,0x4650c533b7bfb3,0xddad454b84d7ab05,0xf03ce56503e82921,0xce442e92c6728660,0x1a9ce5e4b37ddcd3,0xf63b60e27cea6f0e,0xcc4cc7fca665bfad,0x40cf4eba54a2285d,0x2725f1f142304213,0x554d327de6fbad9b,0x19866a26cbc8bdc2,0xe8c3c28faf02c7f5,0xc6bc1f3512a665ae,0xcaa831f1a5dc86ce,0x3f82afe91ca4b9b0].span());}#[test]fn test_keccak_f_iterated_falcon_512_shake(){let mut s:[u128;25]=[0;25];let mut i:u32=0;while i<5{s=keccak_f1600(s);i+=1;}
assert!(s.span()==[0xc9f309ff271c6631,0x9281c8b3825841b4,0x2219cb1928ca14c4,0xf50d1d2ae140281a,0xf0a33a68985b6934,0xd8a79767500429f6,0xbe55a8fff0767faf,0xbc2a9530cca9d7a8,0x7e7947debc81b851,0x772429b40aa052a8,0x58f891e79ce86365,0x3110152cadf8860f,0x7f6f0628bda22d08,0xa89fb4db4293cc0a,0x390bca6688ab09be,0xfadcbb8bbbedce4b,0x2d78a388460c4a73,0xe692f192c06ea9ae,0x909de0d99f0083f0,0x76773fcdc7e9d261,0x344d00ae9d02c853,0x9d85cb92ef2a6155,0xa1a8ecf6537e0b3,0xa6da3fb1f1688e95,0xcfe9307b7db8bed0].span());}}

type QR4=oh<0,0xfffffffffffffff>;type QT4=oh<0,0xf>;type QP4=oh<0,0xfffffffffffffff0>;impl QDR4 of oR<u,oP<0x1000000000000000>>{type DivT=QT4;type RemT=QR4;}impl QMR4 of oT<QR4,oP<16>>{type Result=QP4;}impl QAR4 of oS<QP4,QT4>{type Result=u;}const QM4:oP<16>=16;
type QR13=oh<0,0x7ffffffffffff>;type QT13=oh<0,0x1fff>;type QP13=oh<0,0xffffffffffffe000>;impl QDR13 of oR<u,oP<0x8000000000000>>{type DivT=QT13;type RemT=QR13;}impl QMR13 of oT<QR13,oP<8192>>{type Result=QP13;}impl QAR13 of oS<QP13,QT13>{type Result=u;}const QM13:oP<8192>=8192;
type QR19=oh<0,0x1fffffffffff>;type QT19=oh<0,0x7ffff>;type QP19=oh<0,0xfffffffffff80000>;impl QDR19 of oR<u,oP<0x200000000000>>{type DivT=QT19;type RemT=QR19;}impl QMR19 of oT<QR19,oP<524288>>{type Result=QP19;}impl QAR19 of oS<QP19,QT19>{type Result=u;}const QM19:oP<524288>=524288;
type QR37=oh<0,0x7ffffff>;type QT37=oh<0,0x1fffffffff>;type QP37=oh<0,0xffffffe000000000>;impl QDR37 of oR<u,oP<0x8000000>>{type DivT=QT37;type RemT=QR37;}impl QMR37 of oT<QR37,oP<137438953472>>{type Result=QP37;}impl QAR37 of oS<QP37,QT37>{type Result=u;}const QM37:oP<137438953472>=137438953472;
type QR42=oh<0,0x3fffff>;type QT42=oh<0,0x3ffffffffff>;type QP42=oh<0,0xfffffc0000000000>;impl QDR42 of oR<u,oP<0x400000>>{type DivT=QT42;type RemT=QR42;}impl QMR42 of oT<QR42,oP<4398046511104>>{type Result=QP42;}impl QAR42 of oS<QP42,QT42>{type Result=u;}const QM42:oP<4398046511104>=4398046511104;
type QR54=oh<0,0x3ff>;type QT54=oh<0,0x3fffffffffffff>;type QP54=oh<0,0xffc0000000000000>;impl QDR54 of oR<u,oP<0x400>>{type DivT=QT54;type RemT=QR54;}impl QMR54 of oT<QR54,oP<18014398509481984>>{type Result=QP54;}impl QAR54 of oS<QP54,QT54>{type Result=u;}const QM54:oP<18014398509481984>=18014398509481984;
type QR60=oh<0,0xf>;type QT60=oh<0,0xfffffffffffffff>;type QP60=oh<0,0xf000000000000000>;impl QDR60 of oR<u,oP<0x10>>{type DivT=QT60;type RemT=QR60;}impl QMR60 of oT<QR60,oP<1152921504606846976>>{type Result=QP60;}impl QAR60 of oS<QP60,QT60>{type Result=u;}const QM60:oP<1152921504606846976>=1152921504606846976;
#[inline(always)]fn QR(a:(u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u),k:az)->(u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u){let(a00,a01,a02,a03,a04,a05,a06,a07,a08,a09,a10,a11,a12,a13,a14,a15,a16,a17,a18,a19,a20,a21,a22,a23,a24)=a;(dD(a00,k.og),aI(a06,k.q42,QM42),bV(a12,k.kx),aI(a18,k.q19,QM19),aI(a24,k.nR,qd),aI(a03,k.ku,ny),bm(a09,k.jj),a10,dB(a16,k.n7),aI(a22,k.oe,qr),a01,aI(a07,k.q4,QM4),aI(a13,k.ck,nx),cg(a19,k.d6),aI(a20,k.nT,qe),dy(a04,k.nV),aI(a05,k.n3,qj),ch(a11,k.d8),aI(a17,k.q13,QM13),aI(a23,k.q54,QM54),aI(a02,k.q60,QM60),aI(a08,k.oc,qq),aI(a14,k.q37,QM37),dA(a15,k.n5),a21)}
#[inline(always)]fn QT(st:([u128;12],u),k:az)->(u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u){let(st,g3)=st;let[e0,e1,e2,e3,e4,o0,o1,o2,o3,o4,g01,g24]=st;let x20=e0^e1^e2^e3^e4;let x31=o0^o1^o2^o3^o4;let(gh,gl)=W(g01^g24,k.two64);let c4=aP(aP(gh,gl),g3);let(c0,c2)=W(x20,k.two64);let(c1,c3)=W(x31,k.two64);let(q31,q42)=zA(c3,c1,c4,c2,k.hH.into(),k.bI,k.aG);let d20=aa(c1,c4)^q31;let n20=am(d20,k.aG);let d31=x20^q42;let n31=am(d31,k.aG);let(a10,a12)=W(e2^n20,k.two64);let(cq,crem)=oQ::div_rem(o0^n31,k.hH);let(r0,a10,a03,a01)=zB(c0,a10,cq,crem,k.bI);let d4=aP(c3,r0);let dd4=bO(d4);let(a00,a02)=W(e0^d20,k.two64);let(a05,a07)=W(e1^d20,k.two64);let(a15,a17)=W(e3^d20,k.two64);let(a20,a22)=W(e4^n20,k.two64);let(a06,a08)=W(o1^n31,k.two64);let(a11,a13)=W(o2^d31,k.two64);let(a16,a18)=W(o3^n31,k.two64);let(a21,a23)=W(o4^d31,k.two64);let(a09,a04)=W(g01^dd4,k.two64);let(a24,a14)=W(g24^dd4,k.two64);let a19=aP(g3,d4);(a00,a01,a02,a03,a04,a05,a06,a07,a08,a09,a10,a11,a12,a13,a14,a15,a16,a17,a18,a19,a20,a21,a22,a23,a24)}
#[inline(always)]fn QC(b:(u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u),rc:u128,k:az)->([u128;12],u){let(b00,b01,b02,b03,b04,b05,b06,b07,b08,b09,b10,b11,b12,b13,b14,b15,b16,b17,b18,b19,b20,b21,b22,b23,b24)=b;let s05=aN(b05);let s06=aN(b06);let s20=aN(b20);let s21=aN(b21);let q020=aa(b02,b00);let q031=aa(b03,b01);let q042=aa(b04,b02);let q003=aa(b00,b03);let q120=al(b07,s05);let q131=al(b08,s06);let q142=aa(b09,b07);let q103=aa(b05,b08);let q220=aa(b12,b10);let q231=aa(b13,b11);let q242=aa(b14,b12);let q203=aa(b10,b13);let q320=aa(b17,b15);let q331=aa(b18,b16);let q342=aa(b19,b17);let q303=aa(b15,b18);let q420=al(b22,s20);let q431=al(b23,s21);let q442=aa(b24,b22);let q403=aa(b20,b23);([q020^(q031|q042)^rc,q120^(q131|q142),q220^(q231|q242),q320^(q331|q342),q420^(q431|q442),q031^(q042&q003),q131^(q142&q103),q231^(q242&q203),q331^(q342&q303),q431^(q442&q403),aa(b04,b09)^(am(al(b00,s05),k.aG)&al(b01,s06)),aa(b14,b24)^(al(b10,s20)|am(al(b11,s21),k.aG))],aP(b19,em(b15,b16,k.bI)))}
#[inline(always)]fn QL(st:([u128;12],u),k:az)->(u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u,u){let(st,g3)=st;let[e0,e1,e2,e3,e4,o0,o1,o2,o3,o4,bk,hI]=st;let eD=e0^e1^e2^e3^e4;let hG=o0^o1^o2^o3^o4;let(gh,gl)=W(bk^hI,k.two64);let c4=aP(aP(gh,gl),g3);let(c2,c0)=W(eD,k.two64);let(c3,c1)=W(hG,k.two64);let(kL,kM)=zA(c1,c3,c2,c4,k.hH.into(),k.bI,k.aG);let dk=am(eD^kM,k.aG);let(cO,cq)=W(o3^dk,k.two64);let ee=aa(c4,c1)^kL;let(zq,zm)=oQ::div_rem(e2^ee,k.hH);let(r0,cq,cJ,cL)=zB(c0,cq,zq,zm,k.bI);let d4=aP(c3,r0);let dj=bO(d4);let oO=am(dj,k.aG);let(cH,bK)=W(e0^ee,k.two64);let(du,ds)=W(e1^ee,k.two64);let(cI,dt)=W(o1^dk,k.two64);let(cM,cK)=W(o2^dk,k.two64);let(cN,cp)=W(e3^ee,k.two64);let(dq,bx)=W(o0^dk,k.two64);let(cR,cQ)=W(e4^ee,k.two64);let(cS,cr)=W(o4^dk,k.two64);let(dv,dr)=W(bk^dj,k.two64);let(cT,cc)=W(hI^oO,k.two64);let cP=aP(g3,d4);(bK,bx,cH,dq,dr,ds,dt,du,cI,dv,cJ,cK,cL,cM,cc,cp,cq,cN,cO,cP,cQ,cr,cR,cS,cT)}
type QH=oh<0,0xffffffffffffffffffffffffffffffff>;type QL0=oh<0,0x7fffffffffffffffffffffffffffffff>;type QH1=oh<0x80000000000000000000000000000000,0xffffffffffffffffffffffffffffffff>;type QB=oP<0x80000000000000000000000000000000>;impl QC0 of pZ<QH,0x80000000000000000000000000000000>{type LowT=QL0;type HighT=QH1;}impl QC1 of oS<QL0,QB>{type Result=QH1;}impl QC2 of pN<QH1,QB>{type Result=QL0;}#[inline(always)]pub(crate)fn QF(x:u128)->u128{let t:QB=0x80000000000000000000000000000000;let x:QH=pK(x);match pL::<QH,0x80000000000000000000000000000000>(x){Ok(l)=>pK(oQ::add(l,t)),Err(h)=>pK(oQ::sub(h,t)),}}
type zH=oh<0x8000000000000000,0xffffffffffffffff>;const zM:oP<0x20000000000000000> =0x20000000000000000;impl QA1 of oS<hy,hy>{type Result=ho;}impl QA2 of oS<zH,zH>{type Result=oh<0x10000000000000000,0x1fffffffffffffffe>;}const zV:oP<0xffffffffffffffff> =0xffffffffffffffff;const zt:oP<0x10000000000000000> =0x10000000000000000;const zq:oP<0x8000000000000000> =0x8000000000000000;
#[inline(always)]fn zc(x:u)->Result<hy,zH>{pL::<u,0x8000000000000000>(x)}
#[inline(always)]fn z0(a:hy,b:hy,bo:eW)->u128{pK(oQ::add(oQ::add(oQ::mul(b,bo),a),a))}
#[inline(always)]fn z1(a:hy,b:zH,bo:eW)->u128{let k:oP<0xffffffffffffffff0000000000000000> =0xffffffffffffffff0000000000000000;pK(oQ::add(oQ::sub(oQ::add(oQ::mul(b,bo),a),k),a))}
#[inline(always)]fn z2(a:zH,b:hy,bo:eW,gV:df)->u128{pK(oQ::add(oQ::sub(oQ::add(oQ::mul(b,bo),a),gV),a))}
#[inline(always)]fn z3(a:zH,b:zH,bo:eW,g8:cn)->u128{pK(oQ::add(oQ::sub(oQ::add(oQ::mul(b,bo),a),g8),a))}
#[inline(always)]fn zr0(x:hy)->u{pK(oQ::add(x,x))}
#[inline(always)]fn zr1(x:zH,gV:df)->u{pK(oQ::sub(oQ::add(x,x),gV))}
#[inline(always)]fn zA(ca:u,cb:u,cc:u,cd:u,bo:eW,gV:df,g8:cn)->(u128,u128){match zc(ca){Ok(ya)=>match zc(cb){Ok(yb)=>match zc(cc){Ok(yc)=>match zc(cd){Ok(yd)=>(z0(ya,yb,bo),z0(yc,yd,bo)),Err(yd)=>(z0(ya,yb,bo),z1(yc,yd,bo)),},Err(yc)=>match zc(cd){Ok(yd)=>(z0(ya,yb,bo),z2(yc,yd,bo,gV)),Err(yd)=>(z0(ya,yb,bo),z3(yc,yd,bo,g8)),},},Err(yb)=>match zc(cc){Ok(yc)=>match zc(cd){Ok(yd)=>(z1(ya,yb,bo),z0(yc,yd,bo)),Err(yd)=>(z1(ya,yb,bo),z1(yc,yd,bo)),},Err(yc)=>match zc(cd){Ok(yd)=>(z1(ya,yb,bo),z2(yc,yd,bo,gV)),Err(yd)=>(z1(ya,yb,bo),z3(yc,yd,bo,g8)),},},},Err(ya)=>match zc(cb){Ok(yb)=>match zc(cc){Ok(yc)=>match zc(cd){Ok(yd)=>(z2(ya,yb,bo,gV),z0(yc,yd,bo)),Err(yd)=>(z2(ya,yb,bo,gV),z1(yc,yd,bo)),},Err(yc)=>match zc(cd){Ok(yd)=>(z2(ya,yb,bo,gV),z2(yc,yd,bo,gV)),Err(yd)=>(z2(ya,yb,bo,gV),z3(yc,yd,bo,g8)),},},Err(yb)=>match zc(cc){Ok(yc)=>match zc(cd){Ok(yd)=>(z3(ya,yb,bo,g8),z0(yc,yd,bo)),Err(yd)=>(z3(ya,yb,bo,g8),z1(yc,yd,bo)),},Err(yc)=>match zc(cd){Ok(yd)=>(z3(ya,yb,bo,g8),z2(yc,yd,bo,gV)),Err(yd)=>(z3(ya,yb,bo,g8),z3(yc,yd,bo,g8)),},},},}}
#[inline(always)]fn zB(c0:u,cl:u,cq:oh<0,0x7fffffffffffffff>,crem:eV,gV:df)->(u,u,u,u){match zc(c0){Ok(ya)=>match zc(cl){Ok(yb)=>match pL::<eV,0x10000000000000000>(crem){Ok(lo)=>{let(o3,o1)=(lo,pK(cq));(zr0(ya),zr0(yb),o3,o1)},Err(lo)=>{let(o3,o1)=(oQ::sub(lo,zt),pK(oQ::add(cq,zq)));(zr0(ya),zr0(yb),o3,o1)},},Err(yb)=>match pL::<eV,0x10000000000000000>(crem){Ok(lo)=>{let(o3,o1)=(lo,pK(cq));(zr0(ya),zr1(yb,gV),o3,o1)},Err(lo)=>{let(o3,o1)=(oQ::sub(lo,zt),pK(oQ::add(cq,zq)));(zr0(ya),zr1(yb,gV),o3,o1)},},},Err(ya)=>match zc(cl){Ok(yb)=>match pL::<eV,0x10000000000000000>(crem){Ok(lo)=>{let(o3,o1)=(lo,pK(cq));(zr1(ya,gV),zr0(yb),o3,o1)},Err(lo)=>{let(o3,o1)=(oQ::sub(lo,zt),pK(oQ::add(cq,zq)));(zr1(ya,gV),zr0(yb),o3,o1)},},Err(yb)=>match pL::<eV,0x10000000000000000>(crem){Ok(lo)=>{let(o3,o1)=(lo,pK(cq));(zr1(ya,gV),zr1(yb,gV),o3,o1)},Err(lo)=>{let(o3,o1)=(oQ::sub(lo,zt),pK(oQ::add(cq,zq)));(zr1(ya,gV),zr1(yb,gV),o3,o1)},},},}}
