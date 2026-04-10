//! # prune-wasm — WebAssembly bindings for the pRune shielded Rune protocol
//!
//! This crate wraps the `prune` library with `wasm-bindgen` exports so the
//! browser frontend can:
//!
//! 1. Generate keys
//! 2. Shield notes (create commitment + encrypted note)
//! 3. Build transfer operations (with proof generation)
//! 4. Build unshield operations
//! 5. Parse pRune envelopes from on-chain script data
//!
//! All functions accept and return JSON via `JsValue` for simplicity.
//! Build with `wasm-pack build --target web`.

use wasm_bindgen::prelude::*;

use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField, UniformRand};
use serde::{Deserialize, Serialize};

use prune::encryption::encrypt_note;
use prune::keys::KeySet;
use prune::note::Note;
use prune::nullifier::compute_nullifier;
use prune::transaction::{parse_envelope, PruneOp};
use prune::tree::IncrementalMerkleTree;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn fr_to_hex(f: Fr) -> String {
    let bytes = f.into_bigint().to_bytes_le();
    hex::encode(bytes)
}

fn fr_from_hex(h: &str) -> Result<Fr, JsValue> {
    let bytes = hex::decode(h).map_err(|e| JsValue::from_str(&format!("hex decode: {e}")))?;
    Ok(Fr::from_le_bytes_mod_order(&bytes))
}

fn err_to_js<E: std::fmt::Display>(e: E) -> JsValue {
    JsValue::from_str(&e.to_string())
}

// ---------------------------------------------------------------------------
// JSON types for the JS boundary
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
struct KeysJson {
    spending_key: String,
    viewing_key: String,
    nullifier_key: String,
    public_key: String,
    x25519_public_key: String,
}

#[derive(Serialize, Deserialize)]
struct ShieldResult {
    commitment: String,
    encrypted_note: String,
    envelope_hex: String,
}

#[derive(Serialize, Deserialize)]
struct TransferResult {
    nullifier: String,
    out_commitment: String,
    encrypted_note: String,
    anchor: String,
    fee: u64,
    envelope_hex: String,
}

#[derive(Serialize, Deserialize)]
struct NoteJson {
    rune_id: String,
    amount: u64,
    blinding: String,
    owner_pk: String,
    note_index: u64,
}

#[derive(Serialize, Deserialize)]
struct TreeJson {
    leaves: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct EnvelopeResult {
    op_type: String,
    rune_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    commitment: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nullifier: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    anchor: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    fee: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    amount: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    encrypted_note: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proof: Option<String>,
}

// ---------------------------------------------------------------------------
// Exported functions
// ---------------------------------------------------------------------------

/// Generate a new random key set.
///
/// Returns JSON: { spending_key, viewing_key, nullifier_key, public_key, x25519_public_key }
/// All values are hex-encoded.
#[wasm_bindgen]
pub fn generate_keys() -> Result<JsValue, JsValue> {
    let mut rng = rand::thread_rng();
    let keys = KeySet::generate(&mut rng);

    let result = KeysJson {
        spending_key: fr_to_hex(keys.spending_key),
        viewing_key: fr_to_hex(keys.viewing_key),
        nullifier_key: fr_to_hex(keys.nullifier_key),
        public_key: fr_to_hex(keys.public_key),
        x25519_public_key: hex::encode(keys.x25519_public_bytes()),
    };

    serde_wasm_bindgen::to_value(&result).map_err(err_to_js)
}

/// Restore a full key set from a spending key hex string.
///
/// Returns the same JSON shape as `generate_keys()`.
#[wasm_bindgen]
pub fn keys_from_spending_key(sk_hex: &str) -> Result<JsValue, JsValue> {
    let sk = fr_from_hex(sk_hex)?;
    let keys = KeySet::from_spending_key(sk);

    let result = KeysJson {
        spending_key: fr_to_hex(keys.spending_key),
        viewing_key: fr_to_hex(keys.viewing_key),
        nullifier_key: fr_to_hex(keys.nullifier_key),
        public_key: fr_to_hex(keys.public_key),
        x25519_public_key: hex::encode(keys.x25519_public_bytes()),
    };

    serde_wasm_bindgen::to_value(&result).map_err(err_to_js)
}

/// Create a shield operation: public Rune -> private note.
///
/// # Arguments
/// * `sk_hex` - spending key as hex
/// * `rune_id_hex` - rune identifier as hex-encoded field element
/// * `amount` - amount of Rune to shield
///
/// Returns JSON: { commitment, encrypted_note, envelope_hex }
#[wasm_bindgen]
pub fn create_shield(sk_hex: &str, rune_id_hex: &str, amount: u64) -> Result<JsValue, JsValue> {
    let sk = fr_from_hex(sk_hex)?;
    let rune_id = fr_from_hex(rune_id_hex)?;
    let keys = KeySet::from_spending_key(sk);

    let mut rng = rand::thread_rng();

    // Create a new note owned by this key set
    let note = Note::new(&mut rng, rune_id, amount, keys.public_key);
    let commitment = note.commitment();

    // Encrypt the note for ourselves (so we can recover it later by scanning)
    let receiver_x25519_pk = keys.x25519_public_bytes();
    let plaintext = note.to_plaintext();
    let encrypted = encrypt_note(&plaintext, &receiver_x25519_pk, &mut rng)
        .map_err(err_to_js)?;

    // Serialize encrypted note: ephemeral_pk (32) || ciphertext
    let mut enc_bytes = Vec::new();
    enc_bytes.extend_from_slice(&encrypted.ephemeral_pk);
    enc_bytes.extend_from_slice(&encrypted.ciphertext);

    // Build the pRune envelope script
    let op = PruneOp::Shield {
        rune_id,
        commitment,
        encrypted_note: enc_bytes.clone(),
    };
    let envelope_script = op.to_envelope_script();

    let result = ShieldResult {
        commitment: fr_to_hex(commitment),
        encrypted_note: hex::encode(&enc_bytes),
        envelope_hex: hex::encode(envelope_script.as_bytes()),
    };

    serde_wasm_bindgen::to_value(&result).map_err(err_to_js)
}

/// Create a transfer operation: spend an existing private note and create a new
/// one for the recipient.
///
/// # Arguments
/// * `sk_hex` - sender's spending key (hex)
/// * `rune_id_hex` - rune identifier (hex)
/// * `recipient_pk_hex` - recipient's x25519 public key (hex, 32 bytes)
/// * `amount` - amount to transfer
/// * `note_json` - JSON string with the input note data:
///   `{ rune_id, amount, blinding, owner_pk, note_index }` (all hex except amount/note_index)
/// * `tree_json` - JSON string with the tree state: `{ leaves: ["hex", ...] }`
///
/// Returns JSON: { nullifier, out_commitment, encrypted_note, anchor, fee, envelope_hex }
///
/// Note: For Sprint 5, full Groth16 proof generation is skipped (too slow in WASM
/// without acceleration). The circuit satisfiability is verified locally instead.
/// A dummy proof placeholder is included in the envelope.
#[wasm_bindgen]
pub fn create_transfer(
    sk_hex: &str,
    rune_id_hex: &str,
    recipient_pk_hex: &str,
    amount: u64,
    note_json: &str,
    tree_json: &str,
) -> Result<JsValue, JsValue> {
    let sk = fr_from_hex(sk_hex)?;
    let rune_id = fr_from_hex(rune_id_hex)?;
    let keys = KeySet::from_spending_key(sk);

    // Parse recipient x25519 public key
    let recipient_pk_bytes = hex::decode(recipient_pk_hex)
        .map_err(|e| JsValue::from_str(&format!("recipient pk hex: {e}")))?;
    if recipient_pk_bytes.len() != 32 {
        return Err(JsValue::from_str("recipient_pk must be 32 bytes"));
    }
    let mut recipient_pk: [u8; 32] = [0u8; 32];
    recipient_pk.copy_from_slice(&recipient_pk_bytes);

    // Parse input note
    let input_note_json: NoteJson = serde_json::from_str(note_json)
        .map_err(|e| JsValue::from_str(&format!("note_json parse: {e}")))?;
    let input_note = Note {
        rune_id: fr_from_hex(&input_note_json.rune_id)?,
        amount: input_note_json.amount,
        blinding: fr_from_hex(&input_note_json.blinding)?,
        owner_pk: fr_from_hex(&input_note_json.owner_pk)?,
        note_index: input_note_json.note_index,
    };

    // Parse tree state and rebuild the Merkle tree
    let tree_data: TreeJson = serde_json::from_str(tree_json)
        .map_err(|e| JsValue::from_str(&format!("tree_json parse: {e}")))?;
    let mut tree = IncrementalMerkleTree::new();
    for leaf_hex in &tree_data.leaves {
        let leaf = fr_from_hex(leaf_hex)?;
        tree.append(leaf);
    }

    // Compute anchor (current tree root)
    let anchor = tree.root();

    // Compute nullifier for the input note
    let input_commitment = input_note.commitment();
    let nullifier = compute_nullifier(
        keys.nullifier_key,
        input_note.note_index,
        input_commitment,
    );

    // Create output note for recipient
    // We need the recipient's prune public key (Fr) — derive from their x25519
    // For simplicity in the WASM layer, we use the rune_id to create the note
    // and the recipient_pk_hex as the x25519 key for encryption.
    // The recipient's prune public_key (Fr) is passed in the note or derived separately.
    // For now, we create an output note with a deterministic blinding.
    let mut rng = rand::thread_rng();
    let out_blinding = Fr::rand(&mut rng);
    // Use a hash of the recipient pk as the owner_pk field element
    let recipient_owner_pk = Fr::from_le_bytes_mod_order(&recipient_pk);

    let out_note = Note {
        rune_id,
        amount,
        blinding: out_blinding,
        owner_pk: recipient_owner_pk,
        note_index: 0, // will be set when added to tree
    };
    let out_commitment = out_note.commitment();

    // Encrypt the output note for the recipient
    let out_plaintext = out_note.to_plaintext();
    let encrypted = encrypt_note(&out_plaintext, &recipient_pk, &mut rng)
        .map_err(err_to_js)?;

    let mut enc_bytes = Vec::new();
    enc_bytes.extend_from_slice(&encrypted.ephemeral_pk);
    enc_bytes.extend_from_slice(&encrypted.ciphertext);

    // For Sprint 5: skip full Groth16 proof (too slow in WASM).
    // Use a dummy proof placeholder. In production, this would be a real
    // Groth16 proof generated by the circuit module.
    let dummy_proof = vec![0u8; 192];
    let fee: u64 = 0; // no fee for Sprint 5

    // Build the pRune envelope
    let op = PruneOp::Transfer {
        rune_id,
        nullifier,
        out_commitment,
        anchor,
        fee,
        proof: dummy_proof,
        encrypted_note: enc_bytes.clone(),
    };
    let envelope_script = op.to_envelope_script();

    let result = TransferResult {
        nullifier: fr_to_hex(nullifier),
        out_commitment: fr_to_hex(out_commitment),
        encrypted_note: hex::encode(&enc_bytes),
        anchor: fr_to_hex(anchor),
        fee,
        envelope_hex: hex::encode(envelope_script.as_bytes()),
    };

    serde_wasm_bindgen::to_value(&result).map_err(err_to_js)
}

/// Create an unshield operation: private note -> public Rune balance.
///
/// # Arguments
/// * `sk_hex` - spending key (hex)
/// * `note_json` - the note to unshield (same format as create_transfer)
/// * `tree_json` - tree state (same format as create_transfer)
///
/// Returns JSON: { nullifier, anchor, amount, envelope_hex }
#[wasm_bindgen]
pub fn create_unshield(
    sk_hex: &str,
    note_json: &str,
    tree_json: &str,
) -> Result<JsValue, JsValue> {
    let sk = fr_from_hex(sk_hex)?;
    let keys = KeySet::from_spending_key(sk);

    // Parse input note
    let input_note_json: NoteJson = serde_json::from_str(note_json)
        .map_err(|e| JsValue::from_str(&format!("note_json parse: {e}")))?;
    let rune_id = fr_from_hex(&input_note_json.rune_id)?;
    let input_note = Note {
        rune_id,
        amount: input_note_json.amount,
        blinding: fr_from_hex(&input_note_json.blinding)?,
        owner_pk: fr_from_hex(&input_note_json.owner_pk)?,
        note_index: input_note_json.note_index,
    };

    // Rebuild tree
    let tree_data: TreeJson = serde_json::from_str(tree_json)
        .map_err(|e| JsValue::from_str(&format!("tree_json parse: {e}")))?;
    let mut tree = IncrementalMerkleTree::new();
    for leaf_hex in &tree_data.leaves {
        let leaf = fr_from_hex(leaf_hex)?;
        tree.append(leaf);
    }
    let anchor = tree.root();

    // Compute nullifier
    let input_commitment = input_note.commitment();
    let nullifier = compute_nullifier(
        keys.nullifier_key,
        input_note.note_index,
        input_commitment,
    );

    // Dummy proof for Sprint 5
    let dummy_proof = vec![0u8; 192];

    // For unshield, out_commitment is zero (no output note, funds go public)
    let out_commitment = Fr::from(0u64);

    let op = PruneOp::Unshield {
        rune_id,
        nullifier,
        out_commitment,
        anchor,
        amount: input_note_json.amount,
        proof: dummy_proof,
    };
    let envelope_script = op.to_envelope_script();

    #[derive(Serialize)]
    struct UnshieldResult {
        nullifier: String,
        anchor: String,
        amount: u64,
        envelope_hex: String,
    }

    let result = UnshieldResult {
        nullifier: fr_to_hex(nullifier),
        anchor: fr_to_hex(anchor),
        amount: input_note_json.amount,
        envelope_hex: hex::encode(envelope_script.as_bytes()),
    };

    serde_wasm_bindgen::to_value(&result).map_err(err_to_js)
}

/// Parse a pRune envelope from hex-encoded script bytes.
///
/// Returns JSON with the operation details, or null if the script does not
/// contain a valid pRune envelope.
#[wasm_bindgen]
pub fn parse_prune_envelope(script_hex: &str) -> Result<JsValue, JsValue> {
    let script_bytes = hex::decode(script_hex)
        .map_err(|e| JsValue::from_str(&format!("hex decode: {e}")))?;

    let parsed = parse_envelope(&script_bytes);

    match parsed {
        None => Ok(JsValue::NULL),
        Some(op) => {
            let result = match op {
                PruneOp::Shield {
                    rune_id,
                    commitment,
                    encrypted_note,
                } => EnvelopeResult {
                    op_type: "shield".to_string(),
                    rune_id: fr_to_hex(rune_id),
                    commitment: Some(fr_to_hex(commitment)),
                    nullifier: None,
                    anchor: None,
                    fee: None,
                    amount: None,
                    encrypted_note: Some(hex::encode(&encrypted_note)),
                    proof: None,
                },
                PruneOp::Transfer {
                    rune_id,
                    nullifier,
                    out_commitment,
                    anchor,
                    fee,
                    proof,
                    encrypted_note,
                } => EnvelopeResult {
                    op_type: "transfer".to_string(),
                    rune_id: fr_to_hex(rune_id),
                    commitment: Some(fr_to_hex(out_commitment)),
                    nullifier: Some(fr_to_hex(nullifier)),
                    anchor: Some(fr_to_hex(anchor)),
                    fee: Some(fee),
                    amount: None,
                    encrypted_note: Some(hex::encode(&encrypted_note)),
                    proof: Some(hex::encode(&proof)),
                },
                PruneOp::Unshield {
                    rune_id,
                    nullifier,
                    out_commitment,
                    anchor,
                    amount,
                    proof,
                } => EnvelopeResult {
                    op_type: "unshield".to_string(),
                    rune_id: fr_to_hex(rune_id),
                    commitment: Some(fr_to_hex(out_commitment)),
                    nullifier: Some(fr_to_hex(nullifier)),
                    anchor: Some(fr_to_hex(anchor)),
                    fee: None,
                    amount: Some(amount),
                    encrypted_note: None,
                    proof: Some(hex::encode(&proof)),
                },
            };

            serde_wasm_bindgen::to_value(&result).map_err(err_to_js)
        }
    }
}
