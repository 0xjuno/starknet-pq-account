//! PF-04 benchmarks. Every measurement is a pair of tests: `setup_*` builds the state and inputs,
//! the measured test builds the same and makes one call, and the call's cost is the difference of
//! the two reported L2 gas figures (the method of bench/pf01 and the upstream bench).

#[cfg(test)]
mod bench;
#[cfg(test)]
mod cases;
pub mod legacy;
