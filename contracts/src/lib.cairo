//! pq_hybrid: a hybrid ECDSA-STARK + Falcon-512 Starknet account.
//!
//! EXPERIMENTAL AND UNAUDITED. Built on OpenZeppelin cairo-pq-verifiers (MIT).
//! Testnet / demo use only; never hold real funds with these contracts.

pub mod hybrid;
pub mod migratable;
pub mod utils;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_browser;
#[cfg(test)]
mod tests_migration;
#[cfg(test)]
mod tests_wallets;
#[cfg(test)]
mod tests_wallets_fixture;
