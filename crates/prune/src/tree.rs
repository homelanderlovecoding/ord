//! # Merkle Tree (Note Accumulator)
//!
//! ## What it does
//! An append-only binary Merkle tree that stores all shielded note commitments.
//! When you shield or receive a private transfer, your note commitment is added
//! as a next leaf. The tree root is published on-chain with each spend tx.
//!
//! ## Why append-only
//! Notes are never removed from the tree (even when spent). Spending is tracked
//! by the nullifier set, not by tree removal. This keeps the tree simple and
//! allows the root to be a stable reference.
//!
//! ## How it works
//! - Leaves = note commitments
//! - Internal nodes = Poseidon(left_child, right_child)
//! - Root = single hash at the top
//! - To prove a note exists: provide the Merkle path (32 sibling hashes)
//!   The verifier re-hashes from leaf to root and checks it matches.
//!
//! ## How it can break
//! - Tree state desync between indexer and wallet → wallet's Merkle path is stale
//!   → proof generation fails (proof rejected, not a security issue)
//!   Prevention: wallet must sync tree state before generating proofs
//! - Wrong empty leaf value → tree root is different from expected
//!   Prevention: use a canonical "empty" value (Poseidon of zero)
//! - Integer overflow on next_index → tree full
//!   Prevention: depth 32 supports 2^32 = ~4 billion notes
//!
//! ## How to verify
//! - Add a leaf, compute root, verify root changes
//! - Generate a Merkle path, verify it from leaf to root
//! - Empty tree has a deterministic root

use ark_bn254::Fr;
use ark_ff::PrimeField;

use crate::poseidon;

/// Depth of the Merkle tree. 32 levels = 2^32 = ~4 billion possible notes.
pub const TREE_DEPTH: usize = 32;

/// Precomputed "empty" hashes for each level of the tree.
/// empty[0] = hash of empty leaf (zero)
/// empty[i] = Poseidon(empty[i-1], empty[i-1])
///
/// Used to fill in the "right side" of the tree when it's not full.
fn compute_empty_hashes() -> Vec<Fr> {
    let mut empty = vec![Fr::from(0u64); TREE_DEPTH + 1];
    // Level 0: empty leaf = 0
    empty[0] = Fr::from(0u64);
    // Each level up: hash of two empty children
    for i in 1..=TREE_DEPTH {
        empty[i] = poseidon::hash2(empty[i - 1], empty[i - 1]);
    }
    empty
}

/// A Merkle path (authentication path) for proving inclusion.
///
/// Contains 32 sibling hashes + direction bits (left or right).
/// Given a leaf and this path, anyone can recompute the root
/// and verify the leaf is in the tree.
#[derive(Clone, Debug)]
pub struct MerklePath {
    /// Sibling hashes from leaf level (0) to root level (31)
    pub siblings: Vec<Fr>,
    /// Direction at each level: false = leaf is on left, true = leaf is on right
    pub indices: Vec<bool>,
}

impl MerklePath {
    /// Verify that a leaf commitment produces the expected root via this path.
    pub fn compute_root(&self, leaf: Fr) -> Fr {
        let mut current = leaf;
        for i in 0..self.siblings.len() {
            if self.indices[i] {
                // Leaf is on the right
                current = poseidon::hash2(self.siblings[i], current);
            } else {
                // Leaf is on the left
                current = poseidon::hash2(current, self.siblings[i]);
            }
        }
        current
    }
}

/// Incremental Merkle tree for storing note commitments.
///
/// Append-only: leaves are added left to right, never removed.
/// Efficient: only stores the "frontier" (one node per level on the path
/// from the latest leaf to the root), not the entire tree.
pub struct IncrementalMerkleTree {
    /// Current number of leaves (also the index for the next leaf)
    pub next_index: u64,

    /// Frontier: the left-most unfilled node at each level.
    /// Used to efficiently compute the root and generate Merkle paths.
    frontier: Vec<Fr>,

    /// Precomputed empty hashes for each level
    empty_hashes: Vec<Fr>,

    /// All leaves stored (for generating Merkle paths of past notes).
    /// In production, this could be a database. For MVP, in-memory.
    leaves: Vec<Fr>,
}

impl IncrementalMerkleTree {
    /// Create a new empty tree.
    pub fn new() -> Self {
        let empty_hashes = compute_empty_hashes();
        Self {
            next_index: 0,
            frontier: vec![Fr::from(0u64); TREE_DEPTH],
            empty_hashes,
            leaves: Vec::new(),
        }
    }

    /// Append a new leaf (note commitment) to the tree.
    ///
    /// Returns the leaf's index in the tree.
    pub fn append(&mut self, leaf: Fr) -> u64 {
        let index = self.next_index;
        if index >= (1u64 << TREE_DEPTH as u64) {
            panic!("Merkle tree is full");
        }

        self.leaves.push(leaf);

        // Update the frontier
        let mut current = leaf;
        let mut idx = index;

        for level in 0..TREE_DEPTH {
            if idx % 2 == 0 {
                // This node is a left child — store it in the frontier
                self.frontier[level] = current;
                // Right sibling is empty
                // No need to hash further — we can compute root lazily
                break;
            } else {
                // This node is a right child — hash with left sibling from frontier
                current = poseidon::hash2(self.frontier[level], current);
            }
            idx /= 2;
        }

        self.next_index += 1;
        index
    }

    /// Compute the current root of the tree.
    pub fn root(&self) -> Fr {
        if self.next_index == 0 {
            return self.empty_hashes[TREE_DEPTH];
        }

        let mut current = Fr::from(0u64);
        let mut idx = self.next_index - 1;

        // Recompute from the last inserted leaf
        current = self.leaves[self.leaves.len() - 1];
        idx = self.next_index - 1;

        for level in 0..TREE_DEPTH {
            if idx % 2 == 0 {
                // Left child: right sibling is empty
                current = poseidon::hash2(current, self.empty_hashes[level]);
            } else {
                // Right child: left sibling is from frontier
                current = poseidon::hash2(self.frontier[level], current);
            }
            idx /= 2;
        }

        current
    }

    /// Generate a Merkle path for the leaf at the given index.
    ///
    /// The path allows proving that this leaf exists in the tree
    /// without revealing which leaf it is (when used inside a ZK circuit).
    pub fn merkle_path(&self, leaf_index: u64) -> MerklePath {
        assert!(
            leaf_index < self.next_index,
            "Leaf index {} out of range (tree has {} leaves)",
            leaf_index,
            self.next_index
        );

        let mut siblings = Vec::with_capacity(TREE_DEPTH);
        let mut indices = Vec::with_capacity(TREE_DEPTH);

        // Build the full tree at each level to find siblings
        // For MVP this is O(n) per query. Production would use cached layers.
        let mut current_level: Vec<Fr> = self.leaves.clone();

        // Pad to even length with empty values
        let target_len = (self.next_index as usize).next_power_of_two().max(2);
        while current_level.len() < target_len {
            current_level.push(self.empty_hashes[0]);
        }

        let mut idx = leaf_index as usize;

        for level in 0..TREE_DEPTH {
            // Direction: is our node on the left or right?
            let is_right = idx % 2 == 1;
            indices.push(is_right);

            // Sibling is the node next to us
            let sibling_idx = if is_right { idx - 1 } else { idx + 1 };
            let sibling = if sibling_idx < current_level.len() {
                current_level[sibling_idx]
            } else {
                self.empty_hashes[level]
            };
            siblings.push(sibling);

            // Compute next level
            let mut next_level = Vec::new();
            for i in (0..current_level.len()).step_by(2) {
                let left = current_level[i];
                let right = if i + 1 < current_level.len() {
                    current_level[i + 1]
                } else {
                    self.empty_hashes[level]
                };
                next_level.push(poseidon::hash2(left, right));
            }

            current_level = next_level;
            idx /= 2;

            // Pad to even for next iteration
            if current_level.len() % 2 == 1 && level + 1 < TREE_DEPTH {
                current_level.push(self.empty_hashes[level + 1]);
            }
        }

        MerklePath { siblings, indices }
    }

    /// Number of leaves in the tree.
    pub fn len(&self) -> u64 {
        self.next_index
    }

    /// Is the tree empty?
    pub fn is_empty(&self) -> bool {
        self.next_index == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_tree_has_deterministic_root() {
        let tree1 = IncrementalMerkleTree::new();
        let tree2 = IncrementalMerkleTree::new();
        assert_eq!(tree1.root(), tree2.root(), "Empty trees must have same root");
    }

    #[test]
    fn test_append_changes_root() {
        let mut tree = IncrementalMerkleTree::new();
        let root_before = tree.root();

        tree.append(Fr::from(42u64));
        let root_after = tree.root();

        assert_ne!(root_before, root_after, "Adding a leaf must change the root");
    }

    #[test]
    fn test_append_returns_sequential_indices() {
        let mut tree = IncrementalMerkleTree::new();
        assert_eq!(tree.append(Fr::from(1u64)), 0);
        assert_eq!(tree.append(Fr::from(2u64)), 1);
        assert_eq!(tree.append(Fr::from(3u64)), 2);
    }

    #[test]
    fn test_merkle_path_verifies() {
        let mut tree = IncrementalMerkleTree::new();

        let leaf = Fr::from(42u64);
        let index = tree.append(leaf);
        let root = tree.root();

        let path = tree.merkle_path(index);
        let computed_root = path.compute_root(leaf);

        assert_eq!(computed_root, root, "Merkle path must verify against tree root");
    }

    #[test]
    fn test_merkle_path_multiple_leaves() {
        let mut tree = IncrementalMerkleTree::new();

        let leaves: Vec<Fr> = (0..8).map(|i| Fr::from(i * 100u64)).collect();
        for &leaf in &leaves {
            tree.append(leaf);
        }

        let root = tree.root();

        // Verify path for each leaf
        for (i, &leaf) in leaves.iter().enumerate() {
            let path = tree.merkle_path(i as u64);
            let computed_root = path.compute_root(leaf);
            assert_eq!(
                computed_root, root,
                "Merkle path for leaf {} must verify",
                i
            );
        }
    }

    #[test]
    fn test_wrong_leaf_wrong_root() {
        let mut tree = IncrementalMerkleTree::new();
        tree.append(Fr::from(42u64));

        let root = tree.root();
        let path = tree.merkle_path(0);

        // Using wrong leaf should produce different root
        let wrong_root = path.compute_root(Fr::from(999u64));
        assert_ne!(wrong_root, root, "Wrong leaf should not verify");
    }

    #[test]
    fn test_tree_length() {
        let mut tree = IncrementalMerkleTree::new();
        assert_eq!(tree.len(), 0);
        assert!(tree.is_empty());

        tree.append(Fr::from(1u64));
        assert_eq!(tree.len(), 1);
        assert!(!tree.is_empty());

        tree.append(Fr::from(2u64));
        assert_eq!(tree.len(), 2);
    }
}
