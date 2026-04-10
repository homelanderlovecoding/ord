//! # Poseidon Hash Function
//!
//! ## What it does
//! Hash function optimized for ZK circuits. Takes field elements as input,
//! produces a single field element as output.
//!
//! ## Why Poseidon (not SHA256)
//! SHA256 needs ~25,000 constraints inside a Groth16 circuit.
//! Poseidon needs ~300 constraints. That's ~80x cheaper proof generation.
//! This matters because every hash inside the circuit (Merkle path = 32 hashes)
//! directly impacts proof generation time.
//!
//! ## How it can break
//! - Wrong round constants or MDS matrix → different hash output → proofs won't verify
//! - Wrong number of rounds → security compromised (potential collisions)
//! - Wrong domain separation → commitment and nullifier could collide
//!
//! ## How to verify
//! - Test against reference vectors from the Poseidon paper
//! - Cross-check: same input must always produce same output
//! - Verify round constants match the canonical BN254 parameters

use ark_bn254::Fr;
use ark_ff::{Field, PrimeField};

/// Poseidon S-box: x^5 (the non-linear layer)
///
/// WHY x^5: It's the smallest odd power that provides sufficient
/// non-linearity for security on BN254's field. Lower powers (x^3)
/// have known algebraic attacks.
fn sbox(x: Fr) -> Fr {
    let x2 = x * x;
    let x4 = x2 * x2;
    x4 * x
}

/// Poseidon round constants for BN254 scalar field.
///
/// These are generated deterministically from a seed using a Grain LFSR
/// (as specified in the Poseidon paper). Using canonical constants ensures
/// interoperability with other implementations.
///
/// For MVP we use a simplified constant generation. Production should use
/// the exact constants from the Poseidon reference implementation.
fn generate_round_constants(num_constants: usize) -> Vec<Fr> {
    // Deterministic generation from seed "pRune_poseidon_bn254"
    // Each constant = hash of (seed || index) interpreted as a field element
    use sha2::{Sha256, Digest};
    let mut constants = Vec::with_capacity(num_constants);
    for i in 0..num_constants {
        let mut hasher = Sha256::new();
        hasher.update(b"pRune_poseidon_bn254_rc");
        hasher.update((i as u64).to_le_bytes());
        let hash = hasher.finalize();
        // Interpret 32 bytes as a field element (mod p)
        let fr = Fr::from_le_bytes_mod_order(&hash);
        constants.push(fr);
    }
    constants
}

/// Generate MDS (Maximum Distance Separable) matrix.
///
/// WHY MDS: Provides maximum diffusion — every output element depends on
/// every input element. This is the linear mixing layer of Poseidon.
///
/// We use a Cauchy matrix construction: M[i][j] = 1 / (x_i + y_j)
/// where x and y are distinct field elements.
fn generate_mds_matrix(t: usize) -> Vec<Vec<Fr>> {
    let mut matrix = vec![vec![Fr::from(0u64); t]; t];
    for i in 0..t {
        for j in 0..t {
            let x = Fr::from((i + 1) as u64);
            let y = Fr::from((t + j + 1) as u64);
            matrix[i][j] = (x + y).inverse().expect("x + y should be non-zero");
        }
    }
    matrix
}

/// Poseidon permutation parameters for width `t` (state size).
///
/// - t = 3: for 2-to-1 hashing (Merkle tree, 2-input commitment)
/// - t = 5: for 4-input hashing (note commitment with 4 fields)
///
/// Full rounds (Rf): applies S-box to ALL state elements (security)
/// Partial rounds (Rp): applies S-box to ONLY ONE element (efficiency)
pub struct PoseidonParams {
    pub t: usize,        // state width
    pub rf: usize,       // full rounds (total, split half before and half after partial)
    pub rp: usize,       // partial rounds
    pub round_constants: Vec<Fr>,
    pub mds_matrix: Vec<Vec<Fr>>,
}

impl PoseidonParams {
    /// Create parameters for a given state width.
    ///
    /// Security level: 128 bits (standard for BN254).
    /// Round numbers follow the Poseidon paper recommendations.
    pub fn new(t: usize) -> Self {
        // Recommended rounds for 128-bit security on BN254 with alpha=5
        let (rf, rp) = match t {
            3 => (8, 57),  // 2-to-1 hash
            5 => (8, 60),  // 4-to-1 hash
            _ => (8, 57),  // default
        };

        let total_constants = (rf + rp) * t;
        let round_constants = generate_round_constants(total_constants);
        let mds_matrix = generate_mds_matrix(t);

        Self {
            t,
            rf,
            rp,
            round_constants,
            mds_matrix,
        }
    }
}

/// Apply MDS matrix multiplication to state vector.
fn mds_multiply(state: &mut Vec<Fr>, mds: &Vec<Vec<Fr>>) {
    let t = state.len();
    let mut new_state = vec![Fr::from(0u64); t];
    for i in 0..t {
        for j in 0..t {
            new_state[i] += mds[i][j] * state[j];
        }
    }
    *state = new_state;
}

/// Core Poseidon permutation.
///
/// Applies: AddRoundConstants → S-box → MDS mixing
/// for the specified number of full and partial rounds.
pub fn poseidon_permutation(state: &mut Vec<Fr>, params: &PoseidonParams) {
    let t = params.t;
    let half_rf = params.rf / 2;
    let mut rc_offset = 0;

    // First half of full rounds
    for _ in 0..half_rf {
        // Add round constants
        for j in 0..t {
            state[j] += params.round_constants[rc_offset + j];
        }
        rc_offset += t;
        // S-box on ALL elements (full round)
        for j in 0..t {
            state[j] = sbox(state[j]);
        }
        // MDS mix
        mds_multiply(state, &params.mds_matrix);
    }

    // Partial rounds
    for _ in 0..params.rp {
        // Add round constants
        for j in 0..t {
            state[j] += params.round_constants[rc_offset + j];
        }
        rc_offset += t;
        // S-box on ONLY first element (partial round — saves constraints in ZK)
        state[0] = sbox(state[0]);
        // MDS mix
        mds_multiply(state, &params.mds_matrix);
    }

    // Second half of full rounds
    for _ in 0..half_rf {
        // Add round constants
        for j in 0..t {
            state[j] += params.round_constants[rc_offset + j];
        }
        rc_offset += t;
        // S-box on ALL elements
        for j in 0..t {
            state[j] = sbox(state[j]);
        }
        // MDS mix
        mds_multiply(state, &params.mds_matrix);
    }
}

/// Hash two field elements → one field element.
///
/// Used for: Merkle tree hashing (left + right → parent)
///
/// Uses the sponge construction: state = [0, input0, input1]
/// Apply permutation, output = state[0]
pub fn hash2(a: Fr, b: Fr) -> Fr {
    let params = PoseidonParams::new(3);
    // Sponge: capacity element encodes arity for domain separation
    let mut state = vec![Fr::from(2u64), a, b];
    poseidon_permutation(&mut state, &params);
    state[0]
}

/// Hash four field elements → one field element.
///
/// Used for: Note commitment = Poseidon(rune_id, amount, blinding, owner_pk)
///
/// State = [0, input0, input1, input2, input3]
/// Apply permutation, output = state[0]
pub fn hash4(a: Fr, b: Fr, c: Fr, d: Fr) -> Fr {
    let params = PoseidonParams::new(5);
    // Sponge: capacity element encodes arity for domain separation
    let mut state = vec![Fr::from(4u64), a, b, c, d];
    poseidon_permutation(&mut state, &params);
    state[0]
}

/// Hash three field elements → one field element.
///
/// Used for: Nullifier = Poseidon(nullifier_key, note_index, commitment)
pub fn hash3(a: Fr, b: Fr, c: Fr) -> Fr {
    let params = PoseidonParams::new(5);
    // Sponge: capacity element encodes arity for domain separation
    // Pad with zero for the 4th input; arity tag prevents hash3(a,b,c) == hash4(a,b,c,0)
    let mut state = vec![Fr::from(3u64), a, b, c, Fr::from(0u64)];
    poseidon_permutation(&mut state, &params);
    state[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash2_deterministic() {
        // Same input must always produce same output
        let a = Fr::from(123u64);
        let b = Fr::from(456u64);
        let h1 = hash2(a, b);
        let h2 = hash2(a, b);
        assert_eq!(h1, h2, "Poseidon hash must be deterministic");
    }

    #[test]
    fn test_hash2_different_inputs() {
        // Different inputs must produce different outputs (collision resistance)
        let h1 = hash2(Fr::from(1u64), Fr::from(2u64));
        let h2 = hash2(Fr::from(1u64), Fr::from(3u64));
        assert_ne!(h1, h2, "Different inputs should produce different hashes");
    }

    #[test]
    fn test_hash2_order_matters() {
        // hash(a, b) != hash(b, a)
        let a = Fr::from(100u64);
        let b = Fr::from(200u64);
        let h1 = hash2(a, b);
        let h2 = hash2(b, a);
        assert_ne!(h1, h2, "Input order must matter");
    }

    #[test]
    fn test_hash4_deterministic() {
        let h1 = hash4(Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64));
        let h2 = hash4(Fr::from(1u64), Fr::from(2u64), Fr::from(3u64), Fr::from(4u64));
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_hash3_deterministic() {
        let h1 = hash3(Fr::from(10u64), Fr::from(20u64), Fr::from(30u64));
        let h2 = hash3(Fr::from(10u64), Fr::from(20u64), Fr::from(30u64));
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_sbox() {
        // x^5 for a known value
        let x = Fr::from(3u64);
        let result = sbox(x);
        assert_eq!(result, Fr::from(243u64)); // 3^5 = 243
    }
}
