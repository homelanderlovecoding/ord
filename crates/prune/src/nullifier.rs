//! # Nullifier
//!
//! ## What it does
//! Prevents double-spending of private notes. When you spend a note, you publish
//! its nullifier on-chain. The indexer maintains a set of all seen nullifiers.
//! If the same nullifier appears twice → reject (double-spend attempt).
//!
//! ## How it works
//! nullifier = Poseidon(nullifier_key, note_index, commitment)
//!
//! - nullifier_key: derived from spending_key (only the owner knows it)
//! - note_index: position in the Merkle tree (unique per note)
//! - commitment: the note's commitment (unique per note)
//!
//! ## Why this formula
//! - Deterministic: same note always produces the same nullifier
//! - Unlinkable: can't determine WHICH note was spent by looking at the nullifier
//!   (because nullifier_key is secret)
//! - Unique: different notes produce different nullifiers (because note_index
//!   and commitment are different)
//!
//! ## How it can break
//! - If nullifier_key is leaked → observer can link nullifiers to notes
//!   (privacy break, not a funds-at-risk issue)
//! - If two notes somehow get the same (note_index, commitment) → nullifier collision
//!   → one note becomes unspendable. Prevention: append-only tree ensures unique indices.
//! - If the hash function has collisions → two different notes could produce the same
//!   nullifier → one note gets blocked. Poseidon is collision-resistant, so this is
//!   negligible probability.
//!
//! ## How to verify
//! - Same note + same key → same nullifier (deterministic)
//! - Different notes → different nullifiers
//! - Can't reverse: given nullifier, can't find the note without nullifier_key

use ark_bn254::Fr;

use crate::poseidon;

/// Compute the nullifier for a note.
///
/// nullifier = Poseidon(nullifier_key, note_index, commitment)
///
/// This value is published on-chain when spending a note.
/// The indexer checks it against the nullifier set to prevent double-spending.
pub fn compute_nullifier(nullifier_key: Fr, note_index: u64, commitment: Fr) -> Fr {
    poseidon::hash3(nullifier_key, Fr::from(note_index), commitment)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::KeySet;
    use crate::note::Note;

    #[test]
    fn test_nullifier_deterministic() {
        let nk = Fr::from(42u64);
        let commitment = Fr::from(12345u64);
        let index = 7u64;

        let n1 = compute_nullifier(nk, index, commitment);
        let n2 = compute_nullifier(nk, index, commitment);
        assert_eq!(n1, n2, "Nullifier must be deterministic");
    }

    #[test]
    fn test_different_notes_different_nullifiers() {
        let nk = Fr::from(42u64);

        let n1 = compute_nullifier(nk, 0, Fr::from(111u64));
        let n2 = compute_nullifier(nk, 1, Fr::from(222u64));
        assert_ne!(n1, n2, "Different notes must have different nullifiers");
    }

    #[test]
    fn test_different_keys_different_nullifiers() {
        let commitment = Fr::from(999u64);
        let index = 5u64;

        let n1 = compute_nullifier(Fr::from(1u64), index, commitment);
        let n2 = compute_nullifier(Fr::from(2u64), index, commitment);
        assert_ne!(n1, n2, "Different nullifier keys must produce different nullifiers");
    }

    #[test]
    fn test_nullifier_with_real_note() {
        // Full integration: create keys, create note, compute nullifier
        let keys = KeySet::from_spending_key(Fr::from(42u64));

        let note = Note {
            rune_id: Fr::from(1u64),
            amount: 1000,
            blinding: Fr::from(999u64),
            owner_pk: keys.public_key,
            note_index: 3,
        };

        let commitment = note.commitment();
        let nullifier = compute_nullifier(keys.nullifier_key, note.note_index, commitment);

        // Verify it's a valid field element (non-zero)
        assert_ne!(nullifier, Fr::from(0u64), "Nullifier should not be zero");

        // Verify deterministic with real note
        let nullifier2 = compute_nullifier(keys.nullifier_key, note.note_index, commitment);
        assert_eq!(nullifier, nullifier2);
    }
}
