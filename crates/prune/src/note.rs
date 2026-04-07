//! # Private Note
//!
//! ## What it does
//! A note is a "private UTXO" — it represents ownership of some amount of a Rune.
//! Unlike public Rune balances (visible to everyone), notes are hidden behind
//! Pedersen/Poseidon commitments. Only the owner (with viewing_key) can see the contents.
//!
//! ## Structure
//! ```text
//! Note {
//!   rune_id:         which Rune (e.g., bUSD)
//!   amount:          how much
//!   blinding_factor: random value that hides the commitment
//!   owner_pk:        who owns this note (public key)
//!   note_index:      position in the Merkle tree
//! }
//! ```
//!
//! ## Commitment
//! commitment = Poseidon(rune_id, amount, blinding_factor, owner_pk)
//! This 32-byte value goes on-chain. It proves the note exists without
//! revealing any of its contents.
//!
//! ## How it can break
//! - Same blinding factor used twice → two notes become linkable
//!   Prevention: always use fresh random blinding
//! - Wrong field encoding of amount → amount mismatch in circuit
//!   Prevention: encode amount as u64, convert to field element consistently
//! - rune_id collision → different Runes look the same in commitments
//!   Prevention: use unique rune_id encoding per Rune
//!
//! ## How to verify
//! - Create a note, compute commitment, verify it matches expected hash
//! - Change any field → commitment must change
//! - Two notes with same contents but different blinding → different commitments

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};

use crate::poseidon;

/// A private note — the core data structure of pRune.
///
/// Think of this as a private UTXO. It exists as a leaf in the Merkle tree
/// (represented by its commitment). Only the owner can see the contents.
#[derive(Clone, Debug)]
pub struct Note {
    /// Which Rune this note represents (e.g., bUSD rune ID).
    /// Encoded as a field element from the Rune's protocol ID.
    pub rune_id: Fr,

    /// Amount of the Rune held in this note.
    /// Stored as u64 internally, converted to Fr for hashing.
    pub amount: u64,

    /// Random value that makes the commitment hiding.
    /// Without this, someone could brute-force common amounts
    /// and match commitments. The blinding makes each commitment unique.
    pub blinding: Fr,

    /// Owner's public key. Determines who can spend this note.
    pub owner_pk: Fr,

    /// Position in the Merkle tree. Set after the note is added.
    /// Used in nullifier computation to ensure each note has a unique nullifier.
    pub note_index: u64,
}

impl Note {
    /// Create a new note with a random blinding factor.
    pub fn new<R: rand::Rng>(
        rng: &mut R,
        rune_id: Fr,
        amount: u64,
        owner_pk: Fr,
    ) -> Self {
        let blinding = Fr::from(rng.next_u64());
        Self {
            rune_id,
            amount,
            blinding,
            owner_pk,
            note_index: 0, // Set later when added to tree
        }
    }

    /// Compute the commitment for this note.
    ///
    /// commitment = Poseidon(rune_id, amount, blinding, owner_pk)
    ///
    /// This value goes on-chain. It's a binding commitment:
    /// - Hiding: can't determine the contents without the blinding factor
    /// - Binding: can't find two different notes with the same commitment
    pub fn commitment(&self) -> Fr {
        poseidon::hash4(
            self.rune_id,
            Fr::from(self.amount),
            self.blinding,
            self.owner_pk,
        )
    }

    /// Set the note's index in the Merkle tree.
    pub fn set_index(&mut self, index: u64) {
        self.note_index = index;
    }

    /// Serialize the note contents to bytes (for encryption).
    /// Format: rune_id (32 bytes) || amount (8 bytes) || blinding (32 bytes)
    pub fn to_plaintext(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(80);

        // rune_id as 32 bytes (little-endian field element)
        let rune_bytes = self.rune_id.into_bigint().to_bytes_le();
        bytes.extend_from_slice(&rune_bytes);

        // amount as 8 bytes (little-endian u64)
        bytes.extend_from_slice(&self.amount.to_le_bytes());

        // blinding as 32 bytes
        let blind_bytes = self.blinding.into_bigint().to_bytes_le();
        bytes.extend_from_slice(&blind_bytes);

        bytes
    }

    /// Deserialize note contents from plaintext bytes.
    /// Requires owner_pk to be provided separately (known by the decrypter).
    pub fn from_plaintext(plaintext: &[u8], owner_pk: Fr, note_index: u64) -> anyhow::Result<Self> {
        if plaintext.len() < 72 {
            anyhow::bail!("Plaintext too short: expected >= 72 bytes, got {}", plaintext.len());
        }

        let rune_id = Fr::from_le_bytes_mod_order(&plaintext[0..32]);
        let amount = u64::from_le_bytes(plaintext[32..40].try_into()?);
        let blinding = Fr::from_le_bytes_mod_order(&plaintext[40..72]);

        Ok(Self {
            rune_id,
            amount,
            blinding,
            owner_pk,
            note_index,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_commitment_deterministic() {
        let note = Note {
            rune_id: Fr::from(1u64),
            amount: 1000,
            blinding: Fr::from(999u64),
            owner_pk: Fr::from(42u64),
            note_index: 0,
        };

        let c1 = note.commitment();
        let c2 = note.commitment();
        assert_eq!(c1, c2, "Commitment must be deterministic");
    }

    #[test]
    fn test_different_blinding_different_commitment() {
        let note1 = Note {
            rune_id: Fr::from(1u64),
            amount: 1000,
            blinding: Fr::from(111u64),
            owner_pk: Fr::from(42u64),
            note_index: 0,
        };

        let note2 = Note {
            rune_id: Fr::from(1u64),
            amount: 1000,
            blinding: Fr::from(222u64),
            owner_pk: Fr::from(42u64),
            note_index: 0,
        };

        assert_ne!(
            note1.commitment(),
            note2.commitment(),
            "Different blinding must produce different commitments"
        );
    }

    #[test]
    fn test_different_amount_different_commitment() {
        let note1 = Note {
            rune_id: Fr::from(1u64),
            amount: 1000,
            blinding: Fr::from(999u64),
            owner_pk: Fr::from(42u64),
            note_index: 0,
        };

        let note2 = Note {
            rune_id: Fr::from(1u64),
            amount: 2000,
            blinding: Fr::from(999u64),
            owner_pk: Fr::from(42u64),
            note_index: 0,
        };

        assert_ne!(
            note1.commitment(),
            note2.commitment(),
            "Different amount must produce different commitments"
        );
    }

    #[test]
    fn test_different_rune_different_commitment() {
        let note1 = Note {
            rune_id: Fr::from(1u64), // bUSD
            amount: 1000,
            blinding: Fr::from(999u64),
            owner_pk: Fr::from(42u64),
            note_index: 0,
        };

        let note2 = Note {
            rune_id: Fr::from(2u64), // different Rune
            amount: 1000,
            blinding: Fr::from(999u64),
            owner_pk: Fr::from(42u64),
            note_index: 0,
        };

        assert_ne!(
            note1.commitment(),
            note2.commitment(),
            "Different rune_id must produce different commitments"
        );
    }

    #[test]
    fn test_note_serialization_roundtrip() {
        let note = Note {
            rune_id: Fr::from(42u64),
            amount: 50000,
            blinding: Fr::from(12345u64),
            owner_pk: Fr::from(99u64),
            note_index: 7,
        };

        let plaintext = note.to_plaintext();
        let recovered = Note::from_plaintext(&plaintext, Fr::from(99u64), 7).unwrap();

        assert_eq!(note.rune_id, recovered.rune_id);
        assert_eq!(note.amount, recovered.amount);
        assert_eq!(note.blinding, recovered.blinding);
        assert_eq!(note.commitment(), recovered.commitment());
    }

    #[test]
    fn test_note_index_does_not_affect_commitment() {
        // note_index is NOT part of the commitment — it's metadata for nullifier derivation
        let mut note = Note {
            rune_id: Fr::from(1u64),
            amount: 1000,
            blinding: Fr::from(999u64),
            owner_pk: Fr::from(42u64),
            note_index: 0,
        };

        let c1 = note.commitment();
        note.note_index = 100;
        let c2 = note.commitment();

        assert_eq!(c1, c2, "note_index should not affect commitment");
    }
}
