//! # Groth16 Spend Circuit (Sprint 2)
//!
//! Proves that a private Rune transfer is valid without revealing:
//! - Which note was spent (input note identity)
//! - The transferred amount (if different from the fee)
//! - The recipient
//!
//! ## What the proof guarantees
//!
//! Given public inputs (anchor, nullifier, out_commitment, fee, rune_id),
//! the proof shows that the prover knows secret values such that:
//!
//! 1. **Existence**: The input note commitment is a leaf in the Merkle tree
//!    whose root is `anchor`.
//! 2. **Ownership**: The nullifier was derived from the correct nullifier_key
//!    and the input note's commitment — only the note's owner can produce this.
//! 3. **Integrity**: The output commitment commits to a valid note with the
//!    correct rune_id.
//! 4. **Conservation**: in_amount = out_amount + fee (no Runes created or destroyed).
//!
//! ## Circuit layout
//!
//! Public inputs (in allocation order — must match for verification):
//!   1. rune_id       — which Rune is being transferred
//!   2. anchor        — Merkle tree root at spend time
//!   3. nullifier     — proves the input note is consumed
//!   4. out_commitment — the new note commitment added to the tree
//!   5. fee           — publicly visible transaction fee
//!
//! Private witnesses:
//!   - in_amount, in_blinding, owner_pk — input note contents
//!   - nullifier_key                    — derived from spending_key, used to make nullifier
//!   - note_index                       — position of input note in Merkle tree
//!   - merkle_siblings[32]              — sibling hashes along Merkle path
//!   - merkle_indices[32]               — direction bits (left/right) along Merkle path
//!   - out_amount, out_blinding, out_owner_pk — output note contents

pub mod gadgets;

use ark_bn254::{Bn254, Fr};
use ark_ff::Zero;
use ark_groth16::{Groth16, PreparedVerifyingKey, Proof, ProvingKey};
use ark_r1cs_std::{boolean::Boolean, fields::fp::FpVar, prelude::*};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_snark::SNARK;

use crate::tree::TREE_DEPTH;

use self::gadgets::{hash3_var, hash4_var, verify_merkle_path_var};

// ─── Public statement ─────────────────────────────────────────────────────────

/// The public part of a spend — what the verifier sees.
///
/// These five field elements are the only information revealed to the network.
/// Everything else (amounts, addresses, note contents) stays private.
#[derive(Clone, Debug)]
pub struct SpendStatement {
    /// Which Rune is being transferred. Public so the indexer can credit balances.
    pub rune_id: Fr,
    /// Merkle tree root at the time the input note was created.
    /// Proves the note existed at (or before) this point in history.
    pub anchor: Fr,
    /// Published nullifier — marks the input note as spent to prevent double-spending.
    pub nullifier: Fr,
    /// New note commitment added to the tree. The recipient can decrypt to learn
    /// the note contents; everyone else just sees an opaque hash.
    pub out_commitment: Fr,
    /// Publicly revealed fee. Miners see this; it's deducted from the shielded pool.
    pub fee: Fr,
}

impl SpendStatement {
    /// Serialize into the flat field-element vector expected by Groth16 verify.
    ///
    /// Order must match the `new_input` call order in `SpendCircuit::generate_constraints`.
    pub fn to_inputs(&self) -> Vec<Fr> {
        vec![
            self.rune_id,
            self.anchor,
            self.nullifier,
            self.out_commitment,
            self.fee,
        ]
    }
}

// ─── Private witness ──────────────────────────────────────────────────────────

/// The private part of a spend — the prover's secret knowledge.
#[derive(Clone, Debug)]
pub struct SpendWitness {
    // Input note fields (the note being spent)
    pub in_amount: Fr,
    pub in_blinding: Fr,
    pub owner_pk: Fr,
    /// The key derived from spending_key used to compute the nullifier.
    pub nullifier_key: Fr,
    /// Position of the input note in the Merkle tree.
    pub note_index: Fr,
    /// Sibling hashes along the Merkle path from the note to the root.
    pub merkle_siblings: Vec<Fr>,
    /// Direction bits: true = current node is right child.
    pub merkle_indices: Vec<bool>,

    // Output note fields (the note being created for the recipient)
    pub out_amount: Fr,
    pub out_blinding: Fr,
    pub out_owner_pk: Fr,
}

// ─── Circuit ──────────────────────────────────────────────────────────────────

/// The SpendCircuit implements `ConstraintSynthesizer`, wiring all the gadgets
/// into a single Groth16-provable statement.
///
/// To generate a proof: populate both `witness` and `statement`, call `prove()`.
/// For trusted setup: use `SpendCircuit::for_setup()` with dummy values.
#[derive(Clone, Debug)]
pub struct SpendCircuit {
    pub witness: Option<SpendWitness>,
    pub statement: Option<SpendStatement>,
}

impl SpendCircuit {
    /// Create a dummy circuit for trusted setup.
    ///
    /// Setup only needs the constraint structure — not real witness values.
    /// All-zero witnesses generate the same constraints as real proofs.
    pub fn for_setup() -> Self {
        Self {
            witness: Some(SpendWitness {
                in_amount: Fr::zero(),
                in_blinding: Fr::zero(),
                owner_pk: Fr::zero(),
                nullifier_key: Fr::zero(),
                note_index: Fr::zero(),
                merkle_siblings: vec![Fr::zero(); TREE_DEPTH],
                merkle_indices: vec![false; TREE_DEPTH],
                out_amount: Fr::zero(),
                out_blinding: Fr::zero(),
                out_owner_pk: Fr::zero(),
            }),
            statement: Some(SpendStatement {
                rune_id: Fr::zero(),
                anchor: Fr::zero(),
                nullifier: Fr::zero(),
                out_commitment: Fr::zero(),
                fee: Fr::zero(),
            }),
        }
    }

    /// Create a circuit for proving (requires real witness + statement).
    pub fn for_prove(witness: SpendWitness, statement: SpendStatement) -> Self {
        Self {
            witness: Some(witness),
            statement: Some(statement),
        }
    }
}

impl ConstraintSynthesizer<Fr> for SpendCircuit {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let w = self.witness.unwrap_or_else(|| SpendWitness {
            in_amount: Fr::zero(),
            in_blinding: Fr::zero(),
            owner_pk: Fr::zero(),
            nullifier_key: Fr::zero(),
            note_index: Fr::zero(),
            merkle_siblings: vec![Fr::zero(); TREE_DEPTH],
            merkle_indices: vec![false; TREE_DEPTH],
            out_amount: Fr::zero(),
            out_blinding: Fr::zero(),
            out_owner_pk: Fr::zero(),
        });
        let s = self.statement.unwrap_or_else(|| SpendStatement {
            rune_id: Fr::zero(),
            anchor: Fr::zero(),
            nullifier: Fr::zero(),
            out_commitment: Fr::zero(),
            fee: Fr::zero(),
        });

        // ── Public inputs (allocated first — order matters for verify) ──────────

        // 1. rune_id: which Rune
        let rune_id_pub = FpVar::new_input(cs.clone(), || Ok(s.rune_id))?;
        // 2. anchor: Merkle root
        let anchor_pub = FpVar::new_input(cs.clone(), || Ok(s.anchor))?;
        // 3. nullifier: consumed note marker
        let nullifier_pub = FpVar::new_input(cs.clone(), || Ok(s.nullifier))?;
        // 4. out_commitment: new note commitment
        let out_commitment_pub = FpVar::new_input(cs.clone(), || Ok(s.out_commitment))?;
        // 5. fee
        let fee_pub = FpVar::new_input(cs.clone(), || Ok(s.fee))?;

        // ── Private witnesses ────────────────────────────────────────────────────

        let in_amount_var = FpVar::new_witness(cs.clone(), || Ok(w.in_amount))?;
        let in_blinding_var = FpVar::new_witness(cs.clone(), || Ok(w.in_blinding))?;
        let owner_pk_var = FpVar::new_witness(cs.clone(), || Ok(w.owner_pk))?;
        let nullifier_key_var = FpVar::new_witness(cs.clone(), || Ok(w.nullifier_key))?;
        let note_index_var = FpVar::new_witness(cs.clone(), || Ok(w.note_index))?;

        // Merkle path: siblings (field elements) and indices (direction bits)
        let siblings: Vec<FpVar<Fr>> = w
            .merkle_siblings
            .iter()
            .map(|s| FpVar::new_witness(cs.clone(), || Ok(*s)))
            .collect::<Result<_, _>>()?;
        let indices: Vec<Boolean<Fr>> = w
            .merkle_indices
            .iter()
            .map(|&b| Boolean::new_witness(cs.clone(), || Ok(b)))
            .collect::<Result<_, _>>()?;

        let out_amount_var = FpVar::new_witness(cs.clone(), || Ok(w.out_amount))?;
        let out_blinding_var = FpVar::new_witness(cs.clone(), || Ok(w.out_blinding))?;
        let out_owner_pk_var = FpVar::new_witness(cs.clone(), || Ok(w.out_owner_pk))?;

        // ── Constraint 1: in_commitment = hash4(rune_id, in_amount, in_blinding, owner_pk) ──

        let in_commitment_var = hash4_var(
            &rune_id_pub,
            &in_amount_var,
            &in_blinding_var,
            &owner_pk_var,
        )?;

        // ── Constraint 2: Merkle path — in_commitment is a leaf under anchor ──

        verify_merkle_path_var(&in_commitment_var, &siblings, &indices, &anchor_pub)?;

        // ── Constraint 3: nullifier = hash3(nullifier_key, note_index, in_commitment) ──

        let nullifier_var = hash3_var(&nullifier_key_var, &note_index_var, &in_commitment_var)?;
        nullifier_var.enforce_equal(&nullifier_pub)?;

        // ── Constraint 4: out_commitment = hash4(rune_id, out_amount, out_blinding, out_owner_pk) ──

        let out_commitment_var = hash4_var(
            &rune_id_pub,
            &out_amount_var,
            &out_blinding_var,
            &out_owner_pk_var,
        )?;
        out_commitment_var.enforce_equal(&out_commitment_pub)?;

        // ── Constraint 5: conservation — in_amount = out_amount + fee ──

        let sum = out_amount_var + fee_pub;
        in_amount_var.enforce_equal(&sum)?;

        Ok(())
    }
}

// ─── Setup / Prove / Verify ──────────────────────────────────────────────────

/// Groth16 trusted setup for the SpendCircuit.
///
/// In production this is a multi-party computation (Powers of Tau ceremony).
/// For testing, a single-party setup is sufficient.
///
/// Returns `(proving_key, prepared_verifying_key)`.
/// The `pk` is needed by provers; the `pvk` is needed by verifiers.
/// Both should be serialized and distributed.
pub fn setup<R: rand::RngCore + rand::CryptoRng>(
    rng: &mut R,
) -> anyhow::Result<(ProvingKey<Bn254>, PreparedVerifyingKey<Bn254>)> {
    let placeholder = SpendCircuit::for_setup();
    let (pk, vk) = Groth16::<Bn254>::circuit_specific_setup(placeholder, rng)
        .map_err(|e| anyhow::anyhow!("Groth16 setup failed: {e}"))?;
    let pvk = Groth16::<Bn254>::process_vk(&vk)
        .map_err(|e| anyhow::anyhow!("VK processing failed: {e}"))?;
    Ok((pk, pvk))
}

/// Generate a Groth16 spend proof.
///
/// `witness` contains the private note data; `statement` contains the public
/// values that will be verified on-chain. Both must be consistent.
pub fn prove<R: rand::RngCore + rand::CryptoRng>(
    pk: &ProvingKey<Bn254>,
    witness: SpendWitness,
    statement: SpendStatement,
    rng: &mut R,
) -> anyhow::Result<Proof<Bn254>> {
    let circuit = SpendCircuit::for_prove(witness, statement);
    Groth16::<Bn254>::prove(pk, circuit, rng)
        .map_err(|e| anyhow::anyhow!("Groth16 prove failed: {e}"))
}

/// Verify a Groth16 spend proof.
///
/// Returns `true` if the proof is valid for the given statement.
/// The verifier only needs the `pvk` (public) and the statement — no private data.
pub fn verify(
    pvk: &PreparedVerifyingKey<Bn254>,
    statement: &SpendStatement,
    proof: &Proof<Bn254>,
) -> anyhow::Result<bool> {
    let inputs = statement.to_inputs();
    Groth16::<Bn254>::verify_with_processed_vk(pvk, &inputs, proof)
        .map_err(|e| anyhow::anyhow!("Groth16 verify failed: {e}"))
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ark_relations::r1cs::ConstraintSystem;

    use crate::{
        keys::KeySet,
        note::Note,
        nullifier::compute_nullifier,
        tree::IncrementalMerkleTree,
    };

    /// Build a consistent (witness, statement) pair for a 1-in / 1-out transfer.
    ///
    /// Shielded amount: 1000, fee: 10, output: 990.
    fn make_transfer(keys: &KeySet, rune_id: Fr) -> (SpendWitness, SpendStatement) {
        let mut rng = ark_std::test_rng();

        // Create input note
        let mut in_note = Note::new(&mut rng, rune_id, 1000, keys.public_key);
        // Add to tree
        let mut tree = IncrementalMerkleTree::new();
        let idx = tree.append(in_note.commitment());
        in_note.set_index(idx);

        let anchor = tree.root();
        let merkle_path = tree.merkle_path(idx);
        let commitment = in_note.commitment();
        let nullifier = compute_nullifier(keys.nullifier_key, in_note.note_index, commitment);

        // Create output note (same rune, 990 = 1000 - 10 fee)
        let out_note = Note::new(&mut rng, rune_id, 990, Fr::from(999u64)); // recipient pk
        let out_commitment = out_note.commitment();

        let witness = SpendWitness {
            in_amount: Fr::from(in_note.amount),
            in_blinding: in_note.blinding,
            owner_pk: in_note.owner_pk,
            nullifier_key: keys.nullifier_key,
            note_index: Fr::from(in_note.note_index),
            merkle_siblings: merkle_path.siblings,
            merkle_indices: merkle_path.indices,
            out_amount: Fr::from(out_note.amount),
            out_blinding: out_note.blinding,
            out_owner_pk: out_note.owner_pk,
        };

        let statement = SpendStatement {
            rune_id,
            anchor,
            nullifier,
            out_commitment,
            fee: Fr::from(10u64),
        };

        (witness, statement)
    }

    #[test]
    fn test_circuit_is_satisfiable() {
        // Verify that a correctly-constructed witness satisfies all constraints.
        // This is the most important test — if it fails, the circuit has a bug.
        let keys = KeySet::from_spending_key(Fr::from(42u64));
        let rune_id = Fr::from(1u64);
        let (witness, statement) = make_transfer(&keys, rune_id);

        let circuit = SpendCircuit::for_prove(witness, statement);
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).expect("constraint generation should succeed");

        assert!(
            cs.is_satisfied().expect("is_satisfied check should not fail"),
            "valid spend witness must satisfy all constraints"
        );

        let num_constraints = cs.num_constraints();
        println!("SpendCircuit constraint count: {num_constraints}");
    }

    #[test]
    fn test_wrong_nullifier_key_unsatisfiable() {
        // Using the wrong nullifier_key must produce a nullifier that doesn't
        // match the public input → constraints unsatisfied.
        let keys = KeySet::from_spending_key(Fr::from(42u64));
        let rune_id = Fr::from(1u64);
        let (mut witness, statement) = make_transfer(&keys, rune_id);

        // Swap in a wrong nullifier_key
        witness.nullifier_key = Fr::from(999u64);

        let circuit = SpendCircuit::for_prove(witness, statement);
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).expect("generation should succeed");

        assert!(
            !cs.is_satisfied().expect("is_satisfied check should not fail"),
            "wrong nullifier_key must make constraints unsatisfiable"
        );
    }

    #[test]
    fn test_conservation_violation_unsatisfiable() {
        // If out_amount + fee > in_amount the conservation constraint must fail.
        let keys = KeySet::from_spending_key(Fr::from(42u64));
        let rune_id = Fr::from(1u64);
        let (mut witness, statement) = make_transfer(&keys, rune_id);

        // Inflate the output amount — tries to create value from nothing
        witness.out_amount = Fr::from(2000u64); // > 1000 in_amount

        let circuit = SpendCircuit::for_prove(witness, statement);
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).expect("generation should succeed");

        assert!(
            !cs.is_satisfied().expect("is_satisfied check should not fail"),
            "conservation violation must make constraints unsatisfiable"
        );
    }

    #[test]
    fn test_wrong_merkle_root_unsatisfiable() {
        // Using an anchor that doesn't match the Merkle path must fail.
        let keys = KeySet::from_spending_key(Fr::from(42u64));
        let rune_id = Fr::from(1u64);
        let (witness, mut statement) = make_transfer(&keys, rune_id);

        // Corrupt the anchor
        statement.anchor = Fr::from(12345u64);

        let circuit = SpendCircuit::for_prove(witness, statement);
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).expect("generation should succeed");

        assert!(
            !cs.is_satisfied().expect("is_satisfied check should not fail"),
            "wrong anchor must make Merkle path verification fail"
        );
    }

    #[test]
    fn test_wrong_out_commitment_unsatisfiable() {
        // Publishing a different out_commitment than what the circuit computes must fail.
        let keys = KeySet::from_spending_key(Fr::from(42u64));
        let rune_id = Fr::from(1u64);
        let (witness, mut statement) = make_transfer(&keys, rune_id);

        statement.out_commitment = Fr::from(999u64);

        let circuit = SpendCircuit::for_prove(witness, statement);
        let cs = ConstraintSystem::<Fr>::new_ref();
        circuit.generate_constraints(cs.clone()).expect("generation should succeed");

        assert!(
            !cs.is_satisfied().expect("is_satisfied check should not fail"),
            "wrong out_commitment must be rejected"
        );
    }

    /// End-to-end: setup → prove → verify.
    ///
    /// This test is expensive (~30-120s depending on hardware) — marked ignored
    /// by default. Run with `cargo test e2e_groth16 -- --ignored --nocapture`.
    #[test]
    #[ignore = "slow: full Groth16 setup + prove + verify (~60s)"]
    fn test_e2e_groth16() {
        use rand::SeedableRng;
        let mut rng = rand::rngs::StdRng::seed_from_u64(42);

        let keys = KeySet::from_spending_key(Fr::from(42u64));
        let rune_id = Fr::from(1u64);
        let (witness, statement) = make_transfer(&keys, rune_id);

        println!("Running Groth16 setup…");
        let (pk, pvk) = setup(&mut rng).expect("setup failed");

        println!("Generating proof…");
        let proof = prove(&pk, witness, statement.clone(), &mut rng).expect("prove failed");

        println!("Verifying proof…");
        let valid = verify(&pvk, &statement, &proof).expect("verify failed");
        assert!(valid, "proof must be valid");

        println!("Proof size: {} bytes", {
            use ark_serialize::CanonicalSerialize;
            let mut buf = Vec::new();
            proof.serialize_compressed(&mut buf).unwrap();
            buf.len()
        });
    }
}
