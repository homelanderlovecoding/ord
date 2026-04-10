//! # R1CS Gadgets for pRune
//!
//! Circuit-land versions of the native crypto primitives.
//! These generate R1CS constraints instead of computing values directly.
//!
//! ## Constraint budget (approximate, Poseidon on BN254 with alpha=5):
//! - sbox (x^5): 3 constraints (x²=1, x⁴=1, x⁵=1)
//! - hash2 (t=3): 4 full rounds × 3 sboxes + 57 partial rounds × 1 sbox = 69 sboxes → ~207 constraints
//! - hash3/hash4 (t=5): 4 full rounds × 5 sboxes + 60 partial rounds × 1 sbox = 80 sboxes → ~240 constraints
//! - Merkle path (depth 32): 32 × hash2 → ~6,624 constraints
//! - Full SpendCircuit: ~7,500 constraints total — fast for Groth16

use ark_bn254::Fr;
use ark_r1cs_std::{
    boolean::Boolean,
    fields::fp::FpVar,
    prelude::*,
};
use ark_relations::r1cs::SynthesisError;

use crate::poseidon::PoseidonParams;

/// Poseidon S-box: x^5 in R1CS.
///
/// Cost: 3 multiplication constraints (x², x⁴, x⁵).
/// MDS and round-constant additions are free (linear combinations).
pub(super) fn sbox_var(x: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    let x2 = x.square()?; // x² — 1 constraint
    let x4 = x2.square()?; // x⁴ — 1 constraint
    Ok(&x4 * x) // x⁵ — 1 constraint
}

/// MDS matrix-vector multiply: purely linear, zero new constraints.
///
/// MDS coefficients are constants so every product is just a linear
/// combination — free in R1CS.
pub(super) fn mds_multiply_var(state: &mut Vec<FpVar<Fr>>, mds: &[Vec<Fr>]) {
    let t = state.len();
    let mut new_state = Vec::with_capacity(t);
    for i in 0..t {
        let mut sum = FpVar::zero();
        for j in 0..t {
            // Constant × variable = linear combination (no constraint)
            let term = state[j].clone() * mds[i][j];
            sum += term;
        }
        new_state.push(sum);
    }
    *state = new_state;
}

/// Poseidon permutation in R1CS.
///
/// Mirrors `poseidon::poseidon_permutation` exactly but generates constraints
/// instead of computing values. Round constants are native Fr scalars; only
/// the S-box introduces multiplication gates.
pub(super) fn poseidon_permutation_var(
    state: &mut Vec<FpVar<Fr>>,
    params: &PoseidonParams,
) -> Result<(), SynthesisError> {
    let t = params.t;
    let half_rf = params.rf / 2;
    let mut rc_offset = 0;

    // First half of full rounds
    for _ in 0..half_rf {
        for j in 0..t {
            state[j] += params.round_constants[rc_offset + j]; // free
        }
        rc_offset += t;
        for j in 0..t {
            state[j] = sbox_var(&state[j])?; // 3 constraints
        }
        mds_multiply_var(state, &params.mds_matrix); // free
    }

    // Partial rounds: S-box only on state[0] for efficiency
    for _ in 0..params.rp {
        for j in 0..t {
            state[j] += params.round_constants[rc_offset + j]; // free
        }
        rc_offset += t;
        state[0] = sbox_var(&state[0])?; // 3 constraints
        mds_multiply_var(state, &params.mds_matrix); // free
    }

    // Second half of full rounds
    for _ in 0..half_rf {
        for j in 0..t {
            state[j] += params.round_constants[rc_offset + j]; // free
        }
        rc_offset += t;
        for j in 0..t {
            state[j] = sbox_var(&state[j])?; // 3 constraints
        }
        mds_multiply_var(state, &params.mds_matrix); // free
    }

    Ok(())
}

/// hash2 in R1CS: Poseidon(a, b) → output.
///
/// Used for Merkle tree internal node hashing.
/// State layout: [2, a, b] — matches native `poseidon::hash2` (arity domain tag).
pub fn hash2_var(a: &FpVar<Fr>, b: &FpVar<Fr>) -> Result<FpVar<Fr>, SynthesisError> {
    let params = PoseidonParams::new(3);
    let mut state = vec![FpVar::constant(Fr::from(2u64)), a.clone(), b.clone()];
    poseidon_permutation_var(&mut state, &params)?;
    Ok(state.remove(0))
}

/// hash3 in R1CS: Poseidon(a, b, c) → output.
///
/// Used for nullifier = Poseidon(nullifier_key, note_index, commitment).
/// Pads with a zero input to fill the t=5 state. Arity domain tag = 3.
pub fn hash3_var(
    a: &FpVar<Fr>,
    b: &FpVar<Fr>,
    c: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    let params = PoseidonParams::new(5);
    let mut state = vec![
        FpVar::constant(Fr::from(3u64)),
        a.clone(),
        b.clone(),
        c.clone(),
        FpVar::zero(),
    ];
    poseidon_permutation_var(&mut state, &params)?;
    Ok(state.remove(0))
}

/// hash4 in R1CS: Poseidon(a, b, c, d) → output.
///
/// Used for note commitment = Poseidon(rune_id, amount, blinding, owner_pk). Arity domain tag = 4.
pub fn hash4_var(
    a: &FpVar<Fr>,
    b: &FpVar<Fr>,
    c: &FpVar<Fr>,
    d: &FpVar<Fr>,
) -> Result<FpVar<Fr>, SynthesisError> {
    let params = PoseidonParams::new(5);
    let mut state = vec![
        FpVar::constant(Fr::from(4u64)),
        a.clone(),
        b.clone(),
        c.clone(),
        d.clone(),
    ];
    poseidon_permutation_var(&mut state, &params)?;
    Ok(state.remove(0))
}

/// Merkle path verification in R1CS.
///
/// Enforces that traversing `siblings` from `leaf` using directions `indices`
/// produces exactly `expected_root`. Equivalent to `MerklePath::compute_root`
/// but as R1CS constraints.
///
/// - `indices[i] = true`  → current node is the RIGHT child at level i
/// - `indices[i] = false` → current node is the LEFT child at level i
///
/// Constraint cost: TREE_DEPTH × hash2 + TREE_DEPTH × 2 select ≈ 6,700.
pub fn verify_merkle_path_var(
    leaf: &FpVar<Fr>,
    siblings: &[FpVar<Fr>],
    indices: &[Boolean<Fr>],
    expected_root: &FpVar<Fr>,
) -> Result<(), SynthesisError> {
    assert_eq!(siblings.len(), indices.len(), "siblings and indices must be the same length");

    let mut current = leaf.clone();

    for (sibling, is_right) in siblings.iter().zip(indices.iter()) {
        // If is_right: current is the right child → hash2(sibling, current)
        // If !is_right: current is the left child → hash2(current, sibling)
        let left = is_right.select(sibling, &current)?;
        let right = is_right.select(&current, sibling)?;
        current = hash2_var(&left, &right)?;
    }

    current.enforce_equal(expected_root)
}
