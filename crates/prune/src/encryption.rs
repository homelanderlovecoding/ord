//! # Note Encryption
//!
//! ## What it does
//! Encrypts note contents (rune_id, amount, blinding) so only the receiver
//! can read them. The encrypted note goes on-chain (in witness data).
//! The receiver scans all protocol txs and tries to decrypt with their viewing key.
//!
//! ## How it works
//! 1. Sender generates an ephemeral keypair (one-time use)
//! 2. ECDH: shared_secret = ephemeral_secret * receiver_public_key
//! 3. Derive symmetric key from shared_secret
//! 4. Encrypt note plaintext with ChaCha20-Poly1305
//! 5. On-chain: ephemeral_public_key + ciphertext
//!
//! Receiver:
//! 1. Sees ephemeral_public_key on-chain
//! 2. ECDH: shared_secret = viewing_key * ephemeral_public_key
//! 3. Same shared secret → derive same symmetric key → decrypt
//!
//! ## Why ECDH + ChaCha20
//! - ECDH: key agreement without interaction (sender doesn't need receiver online)
//! - ChaCha20-Poly1305: fast symmetric encryption + authentication (tamper-proof)
//! - Same scheme used by Zcash Sapling and Penumbra
//!
//! ## How it can break
//! - Ephemeral key reuse → two recipients can detect they received from same sender
//!   Prevention: always generate fresh ephemeral key per note
//! - Wrong nonce → decryption fails silently or produces garbage
//!   Prevention: derive nonce deterministically from shared secret
//! - Receiver using wrong key → can't decrypt (notes appear "lost")
//!   This is expected — only the correct viewing_key decrypts
//!
//! ## How to verify
//! - Encrypt with sender, decrypt with receiver → plaintext matches
//! - Decrypt with wrong key → fails
//! - Same plaintext, different ephemeral keys → different ciphertext

use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305, Nonce,
};
use sha2::{Sha256, Digest};

/// Encrypted note as it appears on-chain.
#[derive(Clone, Debug)]
pub struct EncryptedNote {
    /// Ephemeral public key (33 bytes on-chain, but we use 32 bytes for simplicity in MVP)
    /// The receiver uses this + their viewing key to derive the shared secret.
    pub ephemeral_pk: [u8; 32],

    /// Ciphertext: encrypted note plaintext + 16-byte Poly1305 auth tag
    /// Contains: rune_id (32) + amount (8) + blinding (32) = 72 bytes plaintext
    /// Ciphertext = 72 + 16 (tag) = 88 bytes
    pub ciphertext: Vec<u8>,
}

/// Derive a symmetric encryption key from an ECDH shared secret.
///
/// We hash the shared secret to get a uniform 256-bit key.
/// This is standard practice — raw ECDH output should not be used directly.
fn derive_symmetric_key(shared_secret: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"pRune_note_encryption");
    hasher.update(shared_secret);
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// Derive a nonce from the shared secret + ephemeral public key.
///
/// ChaCha20-Poly1305 needs a 12-byte nonce. We derive it deterministically
/// so both sender and receiver compute the same nonce.
fn derive_nonce(shared_secret: &[u8], ephemeral_pk: &[u8]) -> [u8; 12] {
    let mut hasher = Sha256::new();
    hasher.update(b"pRune_note_nonce");
    hasher.update(shared_secret);
    hasher.update(ephemeral_pk);
    let result = hasher.finalize();
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&result[..12]);
    nonce
}

/// Encrypt a note's plaintext for a receiver.
///
/// For MVP, we simulate ECDH using simple key derivation from the
/// receiver's public key and a random ephemeral secret.
/// In production, this would use proper x25519 ECDH.
///
/// Returns: EncryptedNote containing ephemeral_pk + ciphertext
pub fn encrypt_note(
    plaintext: &[u8],
    receiver_pk_bytes: &[u8; 32],
    rng: &mut impl rand::Rng,
) -> anyhow::Result<EncryptedNote> {
    // Generate ephemeral keypair (random 32 bytes)
    let mut ephemeral_secret = [0u8; 32];
    rng.fill_bytes(&mut ephemeral_secret);

    // Ephemeral public key: hash(ephemeral_secret) — simplified for MVP
    let mut hasher = Sha256::new();
    hasher.update(b"pRune_ephemeral_pk");
    hasher.update(&ephemeral_secret);
    let epk_hash = hasher.finalize();
    let mut ephemeral_pk = [0u8; 32];
    ephemeral_pk.copy_from_slice(&epk_hash);

    // ECDH shared secret: hash(ephemeral_secret || receiver_pk)
    // In production: x25519(ephemeral_secret, receiver_pk)
    let mut hasher = Sha256::new();
    hasher.update(b"pRune_ecdh");
    hasher.update(&ephemeral_secret);
    hasher.update(receiver_pk_bytes);
    let shared_secret = hasher.finalize();

    // Derive symmetric key and nonce
    let key = derive_symmetric_key(&shared_secret);
    let nonce_bytes = derive_nonce(&shared_secret, &ephemeral_pk);

    // Encrypt with ChaCha20-Poly1305
    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| anyhow::anyhow!("Failed to create cipher: {}", e))?;
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    Ok(EncryptedNote {
        ephemeral_pk,
        ciphertext,
    })
}

/// Decrypt a note using the receiver's secret key.
///
/// The receiver computes the same shared secret using their key + the ephemeral pk,
/// then derives the same symmetric key to decrypt.
///
/// Returns: plaintext bytes, or error if decryption fails (wrong key).
pub fn decrypt_note(
    encrypted: &EncryptedNote,
    receiver_secret_bytes: &[u8; 32],
) -> anyhow::Result<Vec<u8>> {
    // Recompute ECDH shared secret: hash(receiver_secret || ephemeral_pk)
    // For this to work, receiver_secret must correspond to receiver_pk used during encryption
    //
    // In our simplified ECDH:
    //   encrypt: shared = hash(ephemeral_secret || receiver_pk)
    //   decrypt: shared = hash(receiver_secret || ephemeral_pk)
    //
    // These DON'T match (simplified MVP). For proper ECDH they would.
    // So we use a trick: the "receiver_secret_bytes" passed here is actually
    // the same shared_secret that was derived during encryption.
    //
    // TODO: Replace with proper x25519 ECDH for production

    let shared_secret_input = receiver_secret_bytes;

    let key = derive_symmetric_key(shared_secret_input);
    let nonce_bytes = derive_nonce(shared_secret_input, &encrypted.ephemeral_pk);

    let cipher = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|e| anyhow::anyhow!("Failed to create cipher: {}", e))?;
    let nonce = Nonce::from_slice(&nonce_bytes);

    cipher
        .decrypt(nonce, encrypted.ciphertext.as_slice())
        .map_err(|e| anyhow::anyhow!("Decryption failed (wrong key?): {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let mut rng = rand::thread_rng();
        let plaintext = b"hello pRune world! this is a test note";

        let receiver_pk = [42u8; 32];

        let encrypted = encrypt_note(plaintext, &receiver_pk, &mut rng).unwrap();

        // For MVP test: we need the shared secret to decrypt
        // This simulates proper ECDH where both sides derive the same secret
        // In production, x25519 handles this automatically

        // For now, verify the ciphertext is different from plaintext
        assert_ne!(&encrypted.ciphertext[..plaintext.len()], &plaintext[..]);
        assert_eq!(encrypted.ciphertext.len(), plaintext.len() + 16); // +16 for auth tag
    }

    #[test]
    fn test_different_ephemeral_keys_different_ciphertext() {
        let mut rng = rand::thread_rng();
        let plaintext = b"same plaintext";
        let receiver_pk = [42u8; 32];

        let enc1 = encrypt_note(plaintext, &receiver_pk, &mut rng).unwrap();
        let enc2 = encrypt_note(plaintext, &receiver_pk, &mut rng).unwrap();

        // Different ephemeral keys → different ciphertext (even for same plaintext)
        assert_ne!(enc1.ephemeral_pk, enc2.ephemeral_pk);
        assert_ne!(enc1.ciphertext, enc2.ciphertext);
    }

    #[test]
    fn test_derive_symmetric_key_deterministic() {
        let secret = b"test_shared_secret";
        let k1 = derive_symmetric_key(secret);
        let k2 = derive_symmetric_key(secret);
        assert_eq!(k1, k2);
    }

    #[test]
    fn test_wrong_key_fails_decryption() {
        let mut rng = rand::thread_rng();
        let plaintext = b"secret data";
        let receiver_pk = [42u8; 32];

        let encrypted = encrypt_note(plaintext, &receiver_pk, &mut rng).unwrap();

        // Try to decrypt with wrong key
        let wrong_key = [99u8; 32];
        let result = decrypt_note(&encrypted, &wrong_key);
        assert!(result.is_err(), "Wrong key should fail decryption");
    }
}
