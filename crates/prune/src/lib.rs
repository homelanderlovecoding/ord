//! # pRune — Shielded Rune Protocol
//!
//! Private transfers for Runes on Bitcoin.
//!
//! ## Architecture
//!
//! - `poseidon`: ZK-friendly hash function used for commitments, nullifiers, and Merkle tree
//! - `keys`: Key derivation (spending_key → viewing_key → nullifier_key → public_key)
//! - `note`: Private note structure and commitment computation
//! - `nullifier`: Double-spend prevention
//! - `encryption`: ECDH + ChaCha20-Poly1305 note encryption for receiver discovery
//! - `tree`: Incremental Poseidon Merkle tree (note accumulator)

pub use ark_bn254::Fr;

pub mod poseidon;
pub mod keys;
pub mod note;
pub mod nullifier;
pub mod encryption;
pub mod tree;
pub mod broadcast;
pub mod circuit;
pub mod transaction;
pub mod wallet;
pub mod indexer;
