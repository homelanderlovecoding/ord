//! # Key Derivation
//!
//! ## What it does
//! Derives all wallet keys from a single secret (spending key).
//! One seed → four keys, each with different capabilities.
//!
//! ## Key hierarchy
//! ```text
//! spending_key (sk)        — can spend funds (KEEP SECRET)
//!   ├── viewing_key (vk)   — can see balance, can't spend (share with auditor)
//!   ├── nullifier_key (nk) — used to derive nullifiers (internal)
//!   └── public_key (pk)    — receiving address (share publicly)
//! ```
//!
//! ## Why this structure
//! Same as Zcash Sapling. The viewing key lets an auditor/regulator see all
//! your transactions without being able to spend. This solves compliance for
//! institutions — share vk with auditor, keep sk secret.
//!
//! ## How it can break
//! - If viewing_key derivation is reversible → attacker recovers spending_key
//!   Prevention: use one-way hash (Poseidon) for derivation
//! - If nullifier_key collides with viewing_key → domain separation failure
//!   Prevention: use different domain tags in the hash
//! - If spending_key has low entropy → brute force
//!   Prevention: use 256-bit random seed
//!
//! ## How to verify
//! - Derive keys from a known seed, check they match expected values
//! - Verify: can't derive sk from vk (one-way)
//! - Verify: vk and nk are different for same sk

use ark_bn254::Fr;
use ark_ff::PrimeField;

use crate::poseidon;

/// Domain separation tags — prevents different key derivations from colliding.
///
/// WHY: Without domain separation, viewing_key and nullifier_key could
/// theoretically collide if the hash inputs happen to match. Domain tags
/// make each derivation unique by mixing in a distinct constant.
const DOMAIN_VIEWING_KEY: u64 = 0x7652756e655f766b; // "pRune_vk" as bytes
const DOMAIN_NULLIFIER_KEY: u64 = 0x7052756e655f6e6b; // "pRune_nk" as bytes

/// Full key set derived from a spending key.
#[derive(Clone, Debug)]
pub struct KeySet {
    /// The master secret. Can authorize any spend. Never share.
    pub spending_key: Fr,

    /// Derived from spending_key via one-way hash.
    /// Can decrypt incoming notes and compute balances.
    /// Safe to share with auditors — they can see but not spend.
    pub viewing_key: Fr,

    /// Used internally to derive nullifiers when spending notes.
    /// Different from viewing_key (domain-separated).
    pub nullifier_key: Fr,

    /// The "address" — derived from spending_key.
    /// Share publicly so others can send you private notes.
    /// Uses a different derivation than vk/nk.
    pub public_key: Fr,
}

impl KeySet {
    /// Derive all keys from a spending key.
    ///
    /// spending_key should be a random 256-bit field element.
    /// All other keys are deterministically derived.
    pub fn from_spending_key(sk: Fr) -> Self {
        // viewing_key = Poseidon(sk, DOMAIN_VIEWING_KEY)
        // One-way: can't recover sk from vk
        let vk = poseidon::hash2(sk, Fr::from(DOMAIN_VIEWING_KEY));

        // nullifier_key = Poseidon(sk, DOMAIN_NULLIFIER_KEY)
        // Different domain tag ensures nk ≠ vk
        let nk = poseidon::hash2(sk, Fr::from(DOMAIN_NULLIFIER_KEY));

        // public_key = Poseidon(sk, sk)
        // Simple derivation — in production, this would be sk * G (elliptic curve point)
        // For MVP, we keep everything in the scalar field for simplicity
        let pk = poseidon::hash2(sk, sk);

        Self {
            spending_key: sk,
            viewing_key: vk,
            nullifier_key: nk,
            public_key: pk,
        }
    }

    /// Generate a new random key set.
    pub fn generate<R: rand::Rng>(rng: &mut R) -> Self {
        let sk = Fr::from(rng.next_u64());
        // In production: use Fr::rand(rng) for full 256-bit randomness
        // For MVP, u64 is fine for testing
        Self::from_spending_key(sk)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation_deterministic() {
        let sk = Fr::from(42u64);
        let keys1 = KeySet::from_spending_key(sk);
        let keys2 = KeySet::from_spending_key(sk);

        assert_eq!(keys1.viewing_key, keys2.viewing_key);
        assert_eq!(keys1.nullifier_key, keys2.nullifier_key);
        assert_eq!(keys1.public_key, keys2.public_key);
    }

    #[test]
    fn test_all_keys_different() {
        let sk = Fr::from(12345u64);
        let keys = KeySet::from_spending_key(sk);

        // All derived keys must be different from each other
        assert_ne!(keys.viewing_key, keys.nullifier_key, "vk and nk must differ");
        assert_ne!(keys.viewing_key, keys.public_key, "vk and pk must differ");
        assert_ne!(keys.nullifier_key, keys.public_key, "nk and pk must differ");

        // All derived keys must differ from the spending key
        assert_ne!(keys.spending_key, keys.viewing_key, "sk and vk must differ");
        assert_ne!(keys.spending_key, keys.nullifier_key, "sk and nk must differ");
    }

    #[test]
    fn test_different_spending_keys_different_derived() {
        let keys1 = KeySet::from_spending_key(Fr::from(1u64));
        let keys2 = KeySet::from_spending_key(Fr::from(2u64));

        assert_ne!(keys1.viewing_key, keys2.viewing_key);
        assert_ne!(keys1.nullifier_key, keys2.nullifier_key);
        assert_ne!(keys1.public_key, keys2.public_key);
    }

    #[test]
    fn test_generate_random() {
        let mut rng = rand::thread_rng();
        let keys1 = KeySet::generate(&mut rng);
        let keys2 = KeySet::generate(&mut rng);

        // Two random key sets should be different (with overwhelming probability)
        assert_ne!(keys1.spending_key, keys2.spending_key);
    }
}
