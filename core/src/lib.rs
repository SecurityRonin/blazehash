//! `blazehash-core` — the lean hash-algorithm engine behind [`blazehash`].
//!
//! This crate contains only the hash algorithms: the [`Algorithm`] enum,
//! [`hash_bytes`], and the fuzzy hashers (ssdeep, tlsh). It pulls in only the
//! hashing dependencies — no GPU, cloud, database, YARA, TUI, CLI, or signing
//! machinery lives here. The full batteries-included application is the
//! `blazehash` crate, which re-exports these modules so existing
//! `blazehash::algorithm::…` paths keep resolving.
//!
//! [`Algorithm`]: algorithm::Algorithm
//! [`hash_bytes`]: algorithm::hash_bytes

pub mod algorithm;
pub mod fuzzy;
