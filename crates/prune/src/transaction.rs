//! # pRune Transaction Builder
//!
//! Encodes and decodes pRune protocol data in Bitcoin Taproot witness.
//!
//! ## On-chain format
//!
//! pRune uses the same envelope pattern as ordinal inscriptions but with
//! its own protocol tag. Data lives in a Taproot script-path witness,
//! getting the 4x witness discount:
//!
//! ```text
//! [INTERNAL_KEY] OP_CHECKSIG
//! OP_FALSE OP_IF
//!   PUSH "prune"               ← protocol ID
//!   PUSH <tag> PUSH <value>    ← tag-value pairs (repeated)
//! OP_ENDIF
//! ```
//!
//! ## Tags
//!
//! | Tag  | Meaning           | Size       |
//! |------|-------------------|------------|
//! | 0x01 | operation type    | 1 byte     |
//! | 0x02 | rune_id           | 32 bytes   |
//! | 0x03 | commitment        | 32 bytes   |
//! | 0x04 | nullifier         | 32 bytes   |
//! | 0x05 | anchor (root)     | 32 bytes   |
//! | 0x06 | fee / amount      | 8 bytes    |
//! | 0x07 | encrypted note    | ~120 bytes |
//! | 0x08 | Groth16 proof     | ~192 bytes |
//!
//! ## Operations
//!
//! - **Shield (0x01)**: Public Rune → private note.
//!   Tags: op, rune_id, commitment, encrypted_note
//!
//! - **Transfer (0x02)**: Spend a private note, create a new one.
//!   Tags: op, rune_id, nullifier, commitment, anchor, fee, encrypted_note, proof
//!
//! - **Unshield (0x03)**: Private note → public Rune.
//!   Tags: op, rune_id, nullifier, commitment, anchor, amount, proof
//!
//! ## Witness budget
//!
//! Shield: ~200 bytes. Transfer: ~470 bytes. Unshield: ~350 bytes.
//! All well under Bitcoin's 520-byte script element limit (no chunking needed).
//! At Taproot witness discount (0.25 vbytes per byte), a transfer costs ~118 vbytes.

use ark_bn254::Fr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bitcoin::{
    script::{Builder, PushBytesBuf, ScriptBuf},
    opcodes,
};

/// Protocol identifier in the envelope (matches `b"prune"`).
pub const PROTOCOL_ID: &[u8] = b"prune";

// Tag bytes
pub const TAG_OP_TYPE: u8 = 0x01;
pub const TAG_RUNE_ID: u8 = 0x02;
pub const TAG_COMMITMENT: u8 = 0x03;
pub const TAG_NULLIFIER: u8 = 0x04;
pub const TAG_ANCHOR: u8 = 0x05;
pub const TAG_FEE_OR_AMOUNT: u8 = 0x06;
pub const TAG_ENCRYPTED_NOTE: u8 = 0x07;
pub const TAG_PROOF: u8 = 0x08;

// Operation type bytes
pub const OP_SHIELD: u8 = 0x01;
pub const OP_TRANSFER: u8 = 0x02;
pub const OP_UNSHIELD: u8 = 0x03;

// ─── Parsed envelope ─────────────────────────────────────────────────────────

/// A parsed pRune operation extracted from a Bitcoin transaction witness.
#[derive(Clone, Debug)]
pub enum PruneOp {
    /// Shield: public Rune → private note.
    Shield {
        rune_id: Fr,
        commitment: Fr,
        encrypted_note: Vec<u8>,
    },

    /// Transfer: spend a private note, create a new one.
    Transfer {
        rune_id: Fr,
        nullifier: Fr,
        out_commitment: Fr,
        anchor: Fr,
        fee: u64,
        proof: Vec<u8>,
        encrypted_note: Vec<u8>,
    },

    /// Unshield: private note → public Rune balance.
    Unshield {
        rune_id: Fr,
        nullifier: Fr,
        out_commitment: Fr,
        anchor: Fr,
        amount: u64,
        proof: Vec<u8>,
    },
}

// ─── Serialization helpers ───────────────────────────────────────────────────

fn fr_to_bytes(f: Fr) -> Vec<u8> {
    let mut bytes = Vec::new();
    f.serialize_compressed(&mut bytes).expect("Fr serialization is infallible");
    bytes
}

fn fr_from_bytes(bytes: &[u8]) -> anyhow::Result<Fr> {
    Fr::deserialize_compressed(bytes)
        .map_err(|e| anyhow::anyhow!("invalid Fr: {e}"))
}

fn push_bytes(data: &[u8]) -> PushBytesBuf {
    PushBytesBuf::try_from(data.to_vec()).expect("data within push limit")
}

// ─── Script encoding ─────────────────────────────────────────────────────────

impl PruneOp {
    /// Encode this operation as a pRune envelope script fragment.
    ///
    /// The returned script is the `OP_FALSE OP_IF ... OP_ENDIF` portion.
    /// To make a full Taproot reveal script, prepend `[PUBKEY] OP_CHECKSIG`.
    pub fn to_envelope_script(&self) -> ScriptBuf {
        let mut b = Builder::new()
            .push_opcode(opcodes::OP_FALSE)
            .push_opcode(opcodes::all::OP_IF)
            .push_slice(push_bytes(PROTOCOL_ID));

        match self {
            PruneOp::Shield { rune_id, commitment, encrypted_note } => {
                b = b.push_slice(push_bytes(&[TAG_OP_TYPE]))
                    .push_slice(push_bytes(&[OP_SHIELD]))
                    .push_slice(push_bytes(&[TAG_RUNE_ID]))
                    .push_slice(push_bytes(&fr_to_bytes(*rune_id)))
                    .push_slice(push_bytes(&[TAG_COMMITMENT]))
                    .push_slice(push_bytes(&fr_to_bytes(*commitment)))
                    .push_slice(push_bytes(&[TAG_ENCRYPTED_NOTE]))
                    .push_slice(push_bytes(encrypted_note));
            }
            PruneOp::Transfer {
                rune_id, nullifier, out_commitment, anchor,
                fee, proof, encrypted_note,
            } => {
                b = b.push_slice(push_bytes(&[TAG_OP_TYPE]))
                    .push_slice(push_bytes(&[OP_TRANSFER]))
                    .push_slice(push_bytes(&[TAG_RUNE_ID]))
                    .push_slice(push_bytes(&fr_to_bytes(*rune_id)))
                    .push_slice(push_bytes(&[TAG_NULLIFIER]))
                    .push_slice(push_bytes(&fr_to_bytes(*nullifier)))
                    .push_slice(push_bytes(&[TAG_COMMITMENT]))
                    .push_slice(push_bytes(&fr_to_bytes(*out_commitment)))
                    .push_slice(push_bytes(&[TAG_ANCHOR]))
                    .push_slice(push_bytes(&fr_to_bytes(*anchor)))
                    .push_slice(push_bytes(&[TAG_FEE_OR_AMOUNT]))
                    .push_slice(push_bytes(&fee.to_le_bytes()))
                    .push_slice(push_bytes(&[TAG_PROOF]))
                    .push_slice(push_bytes(proof))
                    .push_slice(push_bytes(&[TAG_ENCRYPTED_NOTE]))
                    .push_slice(push_bytes(encrypted_note));
            }
            PruneOp::Unshield {
                rune_id, nullifier, out_commitment, anchor,
                amount, proof,
            } => {
                b = b.push_slice(push_bytes(&[TAG_OP_TYPE]))
                    .push_slice(push_bytes(&[OP_UNSHIELD]))
                    .push_slice(push_bytes(&[TAG_RUNE_ID]))
                    .push_slice(push_bytes(&fr_to_bytes(*rune_id)))
                    .push_slice(push_bytes(&[TAG_NULLIFIER]))
                    .push_slice(push_bytes(&fr_to_bytes(*nullifier)))
                    .push_slice(push_bytes(&[TAG_COMMITMENT]))
                    .push_slice(push_bytes(&fr_to_bytes(*out_commitment)))
                    .push_slice(push_bytes(&[TAG_ANCHOR]))
                    .push_slice(push_bytes(&fr_to_bytes(*anchor)))
                    .push_slice(push_bytes(&[TAG_FEE_OR_AMOUNT]))
                    .push_slice(push_bytes(&amount.to_le_bytes()))
                    .push_slice(push_bytes(&[TAG_PROOF]))
                    .push_slice(push_bytes(proof));
            }
        }

        b.push_opcode(opcodes::all::OP_ENDIF).into_script()
    }

    /// Build the full Taproot reveal script:
    /// `[pubkey] OP_CHECKSIG OP_FALSE OP_IF "prune" ... OP_ENDIF`
    ///
    /// The `internal_key` is the 32-byte X-only public key that signs the reveal.
    pub fn to_reveal_script(&self, internal_key: &[u8; 32]) -> ScriptBuf {
        let envelope = self.to_envelope_script();

        // Prepend [pubkey] OP_CHECKSIG to the envelope
        let mut b = Builder::new()
            .push_slice(push_bytes(internal_key))
            .push_opcode(opcodes::all::OP_CHECKSIG);

        // Append the envelope script instructions
        b = b.push_opcode(opcodes::OP_FALSE)
            .push_opcode(opcodes::all::OP_IF)
            .push_slice(push_bytes(PROTOCOL_ID));

        // Re-encode the tag-value pairs (we need to rebuild since we can't
        // concatenate scripts directly)
        match self {
            PruneOp::Shield { rune_id, commitment, encrypted_note } => {
                b = b.push_slice(push_bytes(&[TAG_OP_TYPE]))
                    .push_slice(push_bytes(&[OP_SHIELD]))
                    .push_slice(push_bytes(&[TAG_RUNE_ID]))
                    .push_slice(push_bytes(&fr_to_bytes(*rune_id)))
                    .push_slice(push_bytes(&[TAG_COMMITMENT]))
                    .push_slice(push_bytes(&fr_to_bytes(*commitment)))
                    .push_slice(push_bytes(&[TAG_ENCRYPTED_NOTE]))
                    .push_slice(push_bytes(encrypted_note));
            }
            PruneOp::Transfer {
                rune_id, nullifier, out_commitment, anchor,
                fee, proof, encrypted_note,
            } => {
                b = b.push_slice(push_bytes(&[TAG_OP_TYPE]))
                    .push_slice(push_bytes(&[OP_TRANSFER]))
                    .push_slice(push_bytes(&[TAG_RUNE_ID]))
                    .push_slice(push_bytes(&fr_to_bytes(*rune_id)))
                    .push_slice(push_bytes(&[TAG_NULLIFIER]))
                    .push_slice(push_bytes(&fr_to_bytes(*nullifier)))
                    .push_slice(push_bytes(&[TAG_COMMITMENT]))
                    .push_slice(push_bytes(&fr_to_bytes(*out_commitment)))
                    .push_slice(push_bytes(&[TAG_ANCHOR]))
                    .push_slice(push_bytes(&fr_to_bytes(*anchor)))
                    .push_slice(push_bytes(&[TAG_FEE_OR_AMOUNT]))
                    .push_slice(push_bytes(&fee.to_le_bytes()))
                    .push_slice(push_bytes(&[TAG_PROOF]))
                    .push_slice(push_bytes(proof))
                    .push_slice(push_bytes(&[TAG_ENCRYPTED_NOTE]))
                    .push_slice(push_bytes(encrypted_note));
            }
            PruneOp::Unshield {
                rune_id, nullifier, out_commitment, anchor,
                amount, proof,
            } => {
                b = b.push_slice(push_bytes(&[TAG_OP_TYPE]))
                    .push_slice(push_bytes(&[OP_UNSHIELD]))
                    .push_slice(push_bytes(&[TAG_RUNE_ID]))
                    .push_slice(push_bytes(&fr_to_bytes(*rune_id)))
                    .push_slice(push_bytes(&[TAG_NULLIFIER]))
                    .push_slice(push_bytes(&fr_to_bytes(*nullifier)))
                    .push_slice(push_bytes(&[TAG_COMMITMENT]))
                    .push_slice(push_bytes(&fr_to_bytes(*out_commitment)))
                    .push_slice(push_bytes(&[TAG_ANCHOR]))
                    .push_slice(push_bytes(&fr_to_bytes(*anchor)))
                    .push_slice(push_bytes(&[TAG_FEE_OR_AMOUNT]))
                    .push_slice(push_bytes(&amount.to_le_bytes()))
                    .push_slice(push_bytes(&[TAG_PROOF]))
                    .push_slice(push_bytes(proof));
            }
        }

        b.push_opcode(opcodes::all::OP_ENDIF).into_script()
    }
}

// ─── Witness parsing ─────────────────────────────────────────────────────────

/// Parse a pRune envelope from a Taproot witness script.
///
/// Looks for the `OP_FALSE OP_IF "prune" ... OP_ENDIF` pattern in the
/// script instructions and extracts tag-value pairs.
///
/// Returns `None` if the script doesn't contain a valid pRune envelope.
pub fn parse_envelope(script: &[u8]) -> Option<PruneOp> {
    let script = ScriptBuf::from_bytes(script.to_vec());
    let mut instructions = script.instructions().peekable();

    // Scan for OP_FALSE OP_IF "prune" sequence.
    // OP_FALSE is OP_PUSHBYTES_0 (0x00) which decodes as PushBytes(empty).
    let mut found_start = false;
    while let Some(Ok(inst)) = instructions.next() {
        use bitcoin::script::Instruction;
        let is_op_false = matches!(inst, Instruction::PushBytes(d) if d.is_empty())
            || matches!(inst, Instruction::Op(op) if op == opcodes::OP_FALSE);
        if is_op_false {
            if let Some(Ok(Instruction::Op(op))) = instructions.peek() {
                if *op == opcodes::all::OP_IF {
                    instructions.next(); // consume OP_IF
                    if let Some(Ok(Instruction::PushBytes(data))) = instructions.peek() {
                        if data.as_bytes() == PROTOCOL_ID {
                            instructions.next(); // consume "prune"
                            found_start = true;
                            break;
                        }
                    }
                }
            }
        }
    }

    if !found_start {
        return None;
    }

    // Parse tag-value pairs until OP_ENDIF
    let mut op_type: Option<u8> = None;
    let mut rune_id_bytes: Option<Vec<u8>> = None;
    let mut commitment_bytes: Option<Vec<u8>> = None;
    let mut nullifier_bytes: Option<Vec<u8>> = None;
    let mut anchor_bytes: Option<Vec<u8>> = None;
    let mut fee_amount_bytes: Option<Vec<u8>> = None;
    let mut encrypted_note: Option<Vec<u8>> = None;
    let mut proof: Option<Vec<u8>> = None;

    loop {
        use bitcoin::script::Instruction;
        match instructions.next() {
            Some(Ok(Instruction::Op(op))) if op == opcodes::all::OP_ENDIF => break,
            Some(Ok(Instruction::PushBytes(tag_data))) => {
                let tag_bytes = tag_data.as_bytes();
                if tag_bytes.len() != 1 {
                    continue; // skip unexpected pushes
                }
                let tag = tag_bytes[0];

                // Read the value
                let value = match instructions.next() {
                    Some(Ok(Instruction::PushBytes(v))) => v.as_bytes().to_vec(),
                    _ => continue,
                };

                match tag {
                    TAG_OP_TYPE => op_type = value.first().copied(),
                    TAG_RUNE_ID => rune_id_bytes = Some(value),
                    TAG_COMMITMENT => commitment_bytes = Some(value),
                    TAG_NULLIFIER => nullifier_bytes = Some(value),
                    TAG_ANCHOR => anchor_bytes = Some(value),
                    TAG_FEE_OR_AMOUNT => fee_amount_bytes = Some(value),
                    TAG_ENCRYPTED_NOTE => encrypted_note = Some(value),
                    TAG_PROOF => proof = Some(value),
                    _ => {} // ignore unknown tags (forward-compatible)
                }
            }
            None => break,
            _ => continue,
        }
    }

    // Assemble into PruneOp based on op_type
    let op = op_type?;
    let rune_id = fr_from_bytes(&rune_id_bytes?).ok()?;
    let commitment = fr_from_bytes(&commitment_bytes?).ok()?;

    match op {
        OP_SHIELD => Some(PruneOp::Shield {
            rune_id,
            commitment,
            encrypted_note: encrypted_note.unwrap_or_default(),
        }),
        OP_TRANSFER => {
            let nullifier = fr_from_bytes(&nullifier_bytes?).ok()?;
            let anchor = fr_from_bytes(&anchor_bytes?).ok()?;
            let fee_bytes = fee_amount_bytes?;
            let fee = u64::from_le_bytes(fee_bytes.try_into().ok()?);
            Some(PruneOp::Transfer {
                rune_id,
                nullifier,
                out_commitment: commitment,
                anchor,
                fee,
                proof: proof.unwrap_or_default(),
                encrypted_note: encrypted_note.unwrap_or_default(),
            })
        }
        OP_UNSHIELD => {
            let nullifier = fr_from_bytes(&nullifier_bytes?).ok()?;
            let anchor = fr_from_bytes(&anchor_bytes?).ok()?;
            let amount_bytes = fee_amount_bytes?;
            let amount = u64::from_le_bytes(amount_bytes.try_into().ok()?);
            Some(PruneOp::Unshield {
                rune_id,
                nullifier,
                out_commitment: commitment,
                anchor,
                amount,
                proof: proof.unwrap_or_default(),
            })
        }
        _ => None,
    }
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::Zero;

    #[test]
    fn test_shield_envelope_roundtrip() {
        let rune_id = Fr::from(42u64);
        let commitment = Fr::from(12345u64);
        let encrypted = vec![0xaa; 88];

        let op = PruneOp::Shield {
            rune_id,
            commitment,
            encrypted_note: encrypted.clone(),
        };

        let script = op.to_envelope_script();
        let parsed = parse_envelope(script.as_bytes())
            .expect("should parse valid shield envelope");

        match parsed {
            PruneOp::Shield {
                rune_id: r,
                commitment: c,
                encrypted_note: e,
            } => {
                assert_eq!(r, rune_id);
                assert_eq!(c, commitment);
                assert_eq!(e, encrypted);
            }
            _ => panic!("expected Shield"),
        }
    }

    #[test]
    fn test_transfer_envelope_roundtrip() {
        let op = PruneOp::Transfer {
            rune_id: Fr::from(1u64),
            nullifier: Fr::from(100u64),
            out_commitment: Fr::from(200u64),
            anchor: Fr::from(300u64),
            fee: 50,
            proof: vec![0xbb; 192],
            encrypted_note: vec![0xcc; 88],
        };

        let script = op.to_envelope_script();
        let parsed = parse_envelope(script.as_bytes())
            .expect("should parse valid transfer envelope");

        match parsed {
            PruneOp::Transfer {
                rune_id, nullifier, out_commitment, anchor,
                fee, proof, encrypted_note,
            } => {
                assert_eq!(rune_id, Fr::from(1u64));
                assert_eq!(nullifier, Fr::from(100u64));
                assert_eq!(out_commitment, Fr::from(200u64));
                assert_eq!(anchor, Fr::from(300u64));
                assert_eq!(fee, 50);
                assert_eq!(proof.len(), 192);
                assert_eq!(encrypted_note.len(), 88);
            }
            _ => panic!("expected Transfer"),
        }
    }

    #[test]
    fn test_unshield_envelope_roundtrip() {
        let op = PruneOp::Unshield {
            rune_id: Fr::from(7u64),
            nullifier: Fr::from(400u64),
            out_commitment: Fr::from(500u64),
            anchor: Fr::from(600u64),
            amount: 9999,
            proof: vec![0xdd; 192],
        };

        let script = op.to_envelope_script();
        let parsed = parse_envelope(script.as_bytes())
            .expect("should parse valid unshield envelope");

        match parsed {
            PruneOp::Unshield {
                rune_id, nullifier, out_commitment, anchor,
                amount, proof,
            } => {
                assert_eq!(rune_id, Fr::from(7u64));
                assert_eq!(nullifier, Fr::from(400u64));
                assert_eq!(out_commitment, Fr::from(500u64));
                assert_eq!(anchor, Fr::from(600u64));
                assert_eq!(amount, 9999);
                assert_eq!(proof.len(), 192);
            }
            _ => panic!("expected Unshield"),
        }
    }

    #[test]
    fn test_non_prune_script_returns_none() {
        // Random script without prune envelope
        let script = Builder::new()
            .push_opcode(opcodes::all::OP_DUP)
            .push_opcode(opcodes::all::OP_HASH160)
            .push_slice(push_bytes(&[0u8; 20]))
            .into_script();

        assert!(parse_envelope(script.as_bytes()).is_none());
    }

    #[test]
    fn test_reveal_script_contains_checksig_and_envelope() {
        let op = PruneOp::Shield {
            rune_id: Fr::from(1u64),
            commitment: Fr::from(2u64),
            encrypted_note: vec![0xee; 32],
        };

        let key = [0x02u8; 32]; // dummy X-only key
        let reveal = op.to_reveal_script(&key);
        let asm = reveal.to_asm_string();

        // Should contain OP_CHECKSIG and the envelope
        assert!(asm.contains("OP_CHECKSIG"), "reveal script must contain OP_CHECKSIG");
        assert!(asm.contains("OP_IF"), "reveal script must contain OP_IF");
        assert!(asm.contains("OP_ENDIF"), "reveal script must contain OP_ENDIF");
    }

    #[test]
    fn test_envelope_size_within_limits() {
        // Transfer is the largest envelope; verify it's reasonable
        let op = PruneOp::Transfer {
            rune_id: Fr::from(1u64),
            nullifier: Fr::from(2u64),
            out_commitment: Fr::from(3u64),
            anchor: Fr::from(4u64),
            fee: 100,
            proof: vec![0xff; 192],         // Groth16 proof
            encrypted_note: vec![0xaa; 120], // encrypted note
        };

        let script = op.to_envelope_script();
        let size = script.len();
        println!("Transfer envelope script size: {size} bytes");

        // Should be well under 1000 bytes
        assert!(
            size < 1000,
            "transfer envelope should be under 1KB, got {size} bytes"
        );
    }
}
