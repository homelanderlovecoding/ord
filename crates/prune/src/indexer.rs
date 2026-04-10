//! # pRune Indexer API
//!
//! Public interface for ord's block scanner to detect and process pRune
//! operations embedded in Bitcoin transactions.
//!
//! ## Usage
//!
//! ```ignore
//! use prune::indexer::scan_transaction;
//!
//! for (input_index, op) in scan_transaction(&tx) {
//!     // Process the pRune operation found at this input
//! }
//! ```

pub use crate::transaction::PruneOp;

use ark_bn254::Fr;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use bitcoin::Transaction;

/// Scan a Bitcoin transaction for pRune operations.
///
/// For each input, extracts the tapscript from the witness (if present)
/// and attempts to parse a pRune envelope from it.
///
/// Returns a vec of `(input_index, PruneOp)` for every input that
/// contains a valid pRune envelope.
pub fn scan_transaction(tx: &Transaction) -> Vec<(usize, PruneOp)> {
    let mut results = Vec::new();

    for (idx, input) in tx.input.iter().enumerate() {
        let witness = &input.witness;

        // Extract the tapscript from the witness.
        // In a Taproot script-path spend the witness stack is:
        //   [script args...] <script> <control_block> [annex]
        // `witness.tapscript()` handles annex detection for us.
        #[allow(deprecated)]
        let Some(tapscript) = witness.tapscript() else {
            continue;
        };

        if let Some(op) = crate::transaction::parse_envelope(tapscript.as_bytes()) {
            results.push((idx, op));
        }
    }

    results
}

/// Serialize an `ark_bn254::Fr` field element to a fixed 32-byte array.
///
/// Uses arkworks canonical compressed serialization. The output is
/// always exactly 32 bytes (BN254 scalar field elements are 254 bits).
pub fn fr_to_bytes32(f: Fr) -> [u8; 32] {
    let mut buf = [0u8; 32];
    f.serialize_compressed(&mut buf[..])
        .expect("Fr compressed serialization to 32 bytes is infallible");
    buf
}

/// Deserialize an `ark_bn254::Fr` field element from a 32-byte array.
///
/// Returns an error if the bytes do not represent a valid field element.
pub fn fr_from_bytes32(b: &[u8; 32]) -> anyhow::Result<Fr> {
    Fr::deserialize_compressed(&b[..])
        .map_err(|e| anyhow::anyhow!("invalid Fr from 32 bytes: {e}"))
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::{UniformRand, Zero};
    use bitcoin::{TxIn, Witness, transaction::Version, TxOut, Amount, ScriptBuf};
    use bitcoin::locktime::absolute::LockTime;

    /// Helper: build a minimal transaction with one input whose witness
    /// contains the given tapscript (simulating a script-path spend).
    fn tx_with_tapscript(script: &ScriptBuf) -> Transaction {
        let mut witness = Witness::new();
        // Stack element (dummy script arg)
        witness.push([]);
        // Tapscript (the script being executed)
        witness.push(script.as_bytes());
        // Control block: version byte + 32-byte internal key (dummy)
        let mut control = vec![0xc0u8]; // leaf version 0xc0
        control.extend_from_slice(&[0x02; 32]); // dummy internal key
        witness.push(control);

        Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                witness,
                ..Default::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(0),
                script_pubkey: ScriptBuf::new(),
            }],
        }
    }

    #[test]
    fn test_scan_finds_shield_op() {
        let op = PruneOp::Shield {
            rune_id: Fr::from(42u64),
            commitment: Fr::from(123u64),
            encrypted_note: vec![0xaa; 88],
        };

        let script = op.to_envelope_script();
        let tx = tx_with_tapscript(&script);
        let results = scan_transaction(&tx);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, 0);
        match &results[0].1 {
            PruneOp::Shield { rune_id, commitment, .. } => {
                assert_eq!(*rune_id, Fr::from(42u64));
                assert_eq!(*commitment, Fr::from(123u64));
            }
            _ => panic!("expected Shield"),
        }
    }

    #[test]
    fn test_scan_empty_witness_skipped() {
        let tx = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn::default()],
            output: vec![],
        };

        let results = scan_transaction(&tx);
        assert!(results.is_empty());
    }

    #[test]
    fn test_fr_bytes32_roundtrip() {
        let original = Fr::from(9999u64);
        let bytes = fr_to_bytes32(original);
        let recovered = fr_from_bytes32(&bytes).expect("valid Fr");
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_fr_bytes32_roundtrip_zero() {
        let original = Fr::zero();
        let bytes = fr_to_bytes32(original);
        let recovered = fr_from_bytes32(&bytes).expect("valid Fr");
        assert_eq!(original, recovered);
    }

    #[test]
    fn test_fr_bytes32_roundtrip_random() {
        let mut rng = ark_std::test_rng();
        for _ in 0..10 {
            let original = Fr::rand(&mut rng);
            let bytes = fr_to_bytes32(original);
            let recovered = fr_from_bytes32(&bytes).expect("valid Fr");
            assert_eq!(original, recovered);
        }
    }

    #[test]
    fn test_fr_from_bytes32_invalid() {
        // All 0xFF should be out of range for BN254 scalar field
        let bad = [0xFFu8; 32];
        assert!(fr_from_bytes32(&bad).is_err());
    }
}
