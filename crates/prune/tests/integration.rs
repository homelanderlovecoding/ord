//! # pRune Integration Tests
//!
//! End-to-end tests that exercise the full wallet flow in-memory.
//! No Bitcoin node needed — just the crypto + wallet logic.
//!
//! These catch bugs that unit tests miss: wrong wiring between modules,
//! state management issues, and conservation/double-spend logic.

use ark_bn254::Fr;
use ark_ff::Zero;
use tempfile::TempDir;

use prune::{
    keys::KeySet,
    note::Note,
    nullifier::compute_nullifier,
    tree::IncrementalMerkleTree,
    wallet::Wallet,
};

/// Helper: create a fresh wallet in a temp directory.
fn fresh_wallet() -> (Wallet, TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet.json");
    let wallet = Wallet::create(&path).unwrap();
    (wallet, dir)
}

// ─── 1. Happy path: shield → transfer → unshield ─────────────────────────────

#[test]
fn test_full_lifecycle_shield_transfer_unshield() {
    let (mut alice, _dir_a) = fresh_wallet();
    let rune_id = Fr::from(1u64);

    // Alice shields 1000 units
    let shield = alice.shield(rune_id, 1000).unwrap();
    assert_eq!(shield.note_index, 0);
    assert_eq!(alice.notes.len(), 1);
    assert!(!alice.notes[0].spent);

    // Alice transfers 800 to herself (for simplicity)
    let result = alice
        .transfer(alice.keys.public_key, 800, 0, rune_id, false)
        .unwrap();
    assert_eq!(result.circuit_fee, 200); // 1000 - 800

    // Original note is spent, new note is unspent
    assert!(alice.notes[0].spent);
    assert_eq!(alice.notes.len(), 2);
    assert!(!alice.notes[1].spent);
    assert_eq!(alice.notes[1].note.amount, 800);

    // Alice unshields the 800 note
    let unshield = alice.unshield(alice.notes[1].note.note_index, false).unwrap();
    assert_eq!(unshield.amount, 800);

    // Note is now spent
    assert!(alice.notes[1].spent);

    // All notes are spent
    let unspent: Vec<_> = alice.notes.iter().filter(|n| !n.spent).collect();
    assert!(unspent.is_empty(), "all notes should be spent after unshield");
}

// ─── 2. Double-spend prevention ───────────────────────────────────────────────

#[test]
fn test_double_spend_rejected() {
    let (mut wallet, _dir) = fresh_wallet();
    let rune_id = Fr::from(1u64);
    let external_pk = Fr::from(12345u64); // not wallet's own key

    wallet.shield(rune_id, 500).unwrap();

    // First transfer to external recipient succeeds (note leaves wallet)
    wallet
        .transfer(external_pk, 500, 0, rune_id, false)
        .unwrap();

    // Second transfer must fail — no unspent notes remain
    let result = wallet.transfer(external_pk, 500, 0, rune_id, false);
    assert!(
        result.is_err(),
        "spending the same note twice must fail — no unspent note with enough balance"
    );
}

// ─── 3. Cross-user flow ──────────────────────────────────────────────────────

#[test]
fn test_cross_user_transfer() {
    let (mut alice, _dir_a) = fresh_wallet();
    let bob_keys = KeySet::from_spending_key(Fr::from(999u64));
    let rune_id = Fr::from(1u64);

    // Alice shields 1000
    alice.shield(rune_id, 1000).unwrap();

    // Alice transfers 700 to Bob
    let result = alice
        .transfer(bob_keys.public_key, 700, 0, rune_id, false)
        .unwrap();
    assert_eq!(result.circuit_fee, 300);

    // Alice's note is spent, and she does NOT have Bob's output note
    assert!(alice.notes[0].spent);
    assert_eq!(
        alice.notes.len(),
        1,
        "Alice should not track Bob's output note"
    );

    // The transfer produced a valid nullifier and commitment
    assert_ne!(result.nullifier, Fr::zero());
    assert_ne!(result.out_commitment, Fr::zero());
}

// ─── 4. Conservation invariant ────────────────────────────────────────────────

#[test]
fn test_conservation_across_operations() {
    let (mut wallet, _dir) = fresh_wallet();
    let rune_id = Fr::from(1u64);

    // Shield 3 notes
    wallet.shield(rune_id, 1000).unwrap();
    wallet.shield(rune_id, 2000).unwrap();
    wallet.shield(rune_id, 500).unwrap();

    let total_shielded: u64 = 1000 + 2000 + 500;

    // Transfer from note 0 (1000 → 800 + 200 fee)
    wallet
        .transfer(wallet.keys.public_key, 800, 0, rune_id, false)
        .unwrap();

    // Unshield note 1 (2000 → all public)
    wallet.unshield(1, false).unwrap();

    // Sum of remaining unspent notes + fees + unshielded should equal total
    let unspent_sum: u64 = wallet
        .notes
        .iter()
        .filter(|n| !n.spent)
        .map(|n| n.note.amount)
        .sum();
    let fees = 200u64; // from the transfer
    let unshielded = 2000u64;

    assert_eq!(
        unspent_sum + fees + unshielded,
        total_shielded,
        "conservation: unspent ({unspent_sum}) + fees ({fees}) + unshielded ({unshielded}) = total ({total_shielded})"
    );
}

// ─── 5. Merkle tree consistency ───────────────────────────────────────────────

#[test]
fn test_merkle_tree_tracks_all_commitments() {
    let (mut wallet, _dir) = fresh_wallet();
    let rune_id = Fr::from(1u64);

    // Shield 3 notes
    wallet.shield(rune_id, 100).unwrap();
    wallet.shield(rune_id, 200).unwrap();
    wallet.shield(rune_id, 300).unwrap();

    // Tree should have 3 leaves
    assert_eq!(wallet.tree.len(), 3);

    // Each note's commitment should be verifiable via Merkle path
    let root = wallet.tree.root();
    for sn in &wallet.notes {
        let path = wallet.tree.merkle_path(sn.note.note_index);
        let computed = path.compute_root(sn.commitment);
        assert_eq!(
            computed, root,
            "Merkle path for note {} must verify against current root",
            sn.note.note_index
        );
    }
}

#[test]
fn test_tree_grows_after_transfer() {
    let (mut wallet, _dir) = fresh_wallet();
    let rune_id = Fr::from(1u64);

    wallet.shield(rune_id, 1000).unwrap();
    assert_eq!(wallet.tree.len(), 1);

    // Transfer adds the output commitment as a new leaf
    wallet
        .transfer(wallet.keys.public_key, 500, 0, rune_id, false)
        .unwrap();
    assert_eq!(wallet.tree.len(), 2, "transfer should add output commitment to tree");
}

// ─── 6. Wallet persistence (save/load roundtrip) ─────────────────────────────

#[test]
fn test_wallet_save_load_roundtrip() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("wallet.json");
    let rune_id = Fr::from(1u64);

    // Create, shield, save
    let pk;
    {
        let mut wallet = Wallet::create(&path).unwrap();
        pk = wallet.keys.public_key;
        wallet.shield(rune_id, 1000).unwrap();
        wallet.shield(rune_id, 2000).unwrap();
        wallet.transfer(wallet.keys.public_key, 500, 0, rune_id, false).unwrap();
        // wallet.save() called by each operation
    }

    // Load from disk
    let loaded = Wallet::load(&path).unwrap();

    assert_eq!(loaded.keys.public_key, pk);
    assert_eq!(loaded.notes.len(), 3); // 2 shielded + 1 transfer output
    assert!(loaded.notes[0].spent); // first note spent by transfer
    assert!(!loaded.notes[1].spent); // second note unspent
    assert!(!loaded.notes[2].spent); // transfer output unspent
    assert_eq!(loaded.notes[2].note.amount, 500);
}

// ─── 7. Nullifier uniqueness ─────────────────────────────────────────────────

#[test]
fn test_nullifiers_are_unique() {
    let (mut wallet, _dir) = fresh_wallet();
    let rune_id = Fr::from(1u64);

    wallet.shield(rune_id, 100).unwrap();
    wallet.shield(rune_id, 200).unwrap();
    wallet.shield(rune_id, 300).unwrap();

    let nullifiers: Vec<Fr> = wallet.notes.iter().map(|n| n.nullifier).collect();

    for i in 0..nullifiers.len() {
        for j in (i + 1)..nullifiers.len() {
            assert_ne!(
                nullifiers[i], nullifiers[j],
                "nullifiers for notes {} and {} must be different",
                i, j
            );
        }
    }
}

// ─── 8. Shield with different rune IDs ────────────────────────────────────────

#[test]
fn test_different_runes_independent() {
    let (mut wallet, _dir) = fresh_wallet();
    let rune_a = Fr::from(1u64);
    let rune_b = Fr::from(2u64);

    wallet.shield(rune_a, 1000).unwrap();
    wallet.shield(rune_b, 500).unwrap();

    // Transfer of rune_a should not touch rune_b
    wallet
        .transfer(wallet.keys.public_key, 800, 0, rune_a, false)
        .unwrap();

    // rune_b note should still be unspent
    let rune_b_notes: Vec<_> = wallet
        .notes
        .iter()
        .filter(|n| n.note.rune_id == rune_b)
        .collect();
    assert_eq!(rune_b_notes.len(), 1);
    assert!(!rune_b_notes[0].spent);
    assert_eq!(rune_b_notes[0].note.amount, 500);

    // Transfer of rune_b with amount > balance should fail
    let result = wallet.transfer(wallet.keys.public_key, 600, 0, rune_b, false);
    assert!(result.is_err(), "can't send more than balance");
}

// ─── 9. Circuit soundness: tampered witness fails ─────────────────────────────

#[test]
fn test_tampered_amount_fails_circuit() {
    use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystem};
    use prune::circuit::{SpendCircuit, SpendStatement, SpendWitness};

    let keys = KeySet::from_spending_key(Fr::from(42u64));
    let rune_id = Fr::from(1u64);
    let mut rng = ark_std::test_rng();

    let mut note = Note::new(&mut rng, rune_id, 1000, keys.public_key);
    let mut tree = IncrementalMerkleTree::new();
    let idx = tree.append(note.commitment());
    note.set_index(idx);

    let path = tree.merkle_path(idx);
    let commitment = note.commitment();
    let nullifier = compute_nullifier(keys.nullifier_key, note.note_index, commitment);

    let out_note = Note::new(&mut rng, rune_id, 900, Fr::from(999u64));

    // Correct witness
    let witness = SpendWitness {
        in_amount: Fr::from(1000u64),
        in_blinding: note.blinding,
        owner_pk: note.owner_pk,
        nullifier_key: keys.nullifier_key,
        note_index: Fr::from(0u64),
        merkle_siblings: path.siblings.clone(),
        merkle_indices: path.indices.clone(),
        out_amount: Fr::from(900u64),
        out_blinding: out_note.blinding,
        out_owner_pk: out_note.owner_pk,
    };

    let statement = SpendStatement {
        rune_id,
        anchor: tree.root(),
        nullifier,
        out_commitment: out_note.commitment(),
        fee: Fr::from(100u64),
    };

    // Correct witness should satisfy
    let cs = ConstraintSystem::<Fr>::new_ref();
    let circuit = SpendCircuit::for_prove(witness.clone(), statement.clone());
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(cs.is_satisfied().unwrap(), "correct witness must satisfy");

    // Tampered: claim input is 2000 instead of 1000
    let bad_witness = SpendWitness {
        in_amount: Fr::from(2000u64), // TAMPERED
        ..witness.clone()
    };
    let cs = ConstraintSystem::<Fr>::new_ref();
    let circuit = SpendCircuit::for_prove(bad_witness, statement.clone());
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(
        !cs.is_satisfied().unwrap(),
        "tampered in_amount must not satisfy (commitment won't match → Merkle path fails)"
    );

    // Tampered: wrong blinding factor
    let bad_witness = SpendWitness {
        in_blinding: Fr::from(9999u64), // TAMPERED
        ..witness.clone()
    };
    let cs = ConstraintSystem::<Fr>::new_ref();
    let circuit = SpendCircuit::for_prove(bad_witness, statement.clone());
    circuit.generate_constraints(cs.clone()).unwrap();
    assert!(
        !cs.is_satisfied().unwrap(),
        "tampered blinding must not satisfy"
    );
}

// ─── 10. Full Groth16 prove+verify via wallet ────────────────────────────────

#[test]
#[ignore = "slow: full Groth16 prove (~60s)"]
fn test_wallet_full_groth16_prove() {
    let (mut wallet, _dir) = fresh_wallet();
    let rune_id = Fr::from(1u64);

    wallet.shield(rune_id, 1000).unwrap();

    // Transfer with full Groth16 proof
    let result = wallet
        .transfer(wallet.keys.public_key, 800, 0, rune_id, true)
        .unwrap();

    assert!(
        result.proof_hex.is_some(),
        "full_prove=true must produce a proof"
    );
    let proof_hex = result.proof_hex.unwrap();
    // Groth16 BN254 proof is 192 bytes compressed = 384 hex chars
    assert!(
        proof_hex.len() >= 384,
        "proof too short: {} hex chars (expected >= 384)",
        proof_hex.len()
    );
    println!("Groth16 proof: {} bytes", proof_hex.len() / 2);
}
