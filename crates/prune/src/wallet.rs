//! # pRune Wallet
//!
//! Local key management and note tracking for the pRune CLI.
//!
//! ## What is stored
//! ```text
//! ~/.prune/wallet.json
//!   spending_key    — master secret (never leaves this file)
//!   notes[]         — every private note owned by this wallet
//!   tree_leaves[]   — all commitments appended locally (for tree rebuild)
//! ```
//!
//! ## What "local" means
//! Sprint 3 is offline — no Bitcoin node, no broadcasting.
//! The wallet computes commitments, nullifiers, and proofs, and prints
//! exactly what would go into a real Taproot transaction.
//! Sprint 4 hooks this into ord's block scanner and live UTXOs.

use std::path::{Path, PathBuf};

use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_relations::r1cs::ConstraintSynthesizer;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};

use crate::{
    circuit::{self, SpendCircuit, SpendStatement, SpendWitness},
    encryption::{encrypt_note, decrypt_note, EncryptedNote},
    keys::KeySet,
    note::Note,
    nullifier::compute_nullifier,
    tree::IncrementalMerkleTree,
};

// ─── Fr <-> hex helpers ───────────────────────────────────────────────────────

pub fn fr_to_hex(f: Fr) -> String {
    let mut bytes = Vec::new();
    f.serialize_compressed(&mut bytes).expect("serialization is infallible");
    hex::encode(bytes)
}

pub fn fr_from_hex(s: &str) -> anyhow::Result<Fr> {
    let bytes = hex::decode(s)?;
    Fr::deserialize_compressed(&bytes[..])
        .map_err(|e| anyhow::anyhow!("invalid field element: {e}"))
}

fn fr_to_pk_bytes(f: Fr) -> anyhow::Result<[u8; 32]> {
    let mut bytes = Vec::new();
    f.serialize_compressed(&mut bytes)?;
    bytes.try_into().map_err(|_| anyhow::anyhow!("field element is not 32 bytes"))
}

// ─── On-disk format ───────────────────────────────────────────────────────────

#[derive(Serialize, Deserialize)]
struct WalletFile {
    version: u32,
    spending_key: String,
    notes: Vec<StoredNoteJson>,
    tree_leaves: Vec<String>,
    spent_nullifiers: Vec<String>,
}

#[derive(Serialize, Deserialize, Clone)]
struct StoredNoteJson {
    rune_id: String,
    amount: u64,
    blinding: String,
    owner_pk: String,
    note_index: u64,
    commitment: String,
    nullifier: String,
    spent: bool,
}

// ─── In-memory wallet ─────────────────────────────────────────────────────────

pub struct Wallet {
    pub keys: KeySet,
    pub notes: Vec<StoredNote>,
    pub tree: IncrementalMerkleTree,
    pub spent_nullifiers: Vec<Fr>,
    /// All tree leaves (commitments) in insertion order — includes non-owned notes.
    pub tree_leaves: Vec<Fr>,
    path: PathBuf,
}

#[derive(Clone, Debug)]
pub struct StoredNote {
    pub note: Note,
    pub commitment: Fr,
    pub nullifier: Fr,
    pub spent: bool,
}

impl Wallet {
    /// Default path: `~/.prune/wallet.json`.
    pub fn default_path() -> PathBuf {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".prune")
            .join("wallet.json")
    }

    /// Create a new wallet with a freshly generated spending key.
    pub fn create(path: &Path) -> anyhow::Result<Self> {
        let mut rng = rand::thread_rng();
        let keys = KeySet::generate(&mut rng);
        let wallet = Self {
            keys,
            notes: Vec::new(),
            tree: IncrementalMerkleTree::new(),
            spent_nullifiers: Vec::new(),
            tree_leaves: Vec::new(),
            path: path.to_path_buf(),
        };
        wallet.save()?;
        Ok(wallet)
    }

    /// Load an existing wallet from disk.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let data = std::fs::read_to_string(path).map_err(|_| {
            anyhow::anyhow!(
                "Wallet not found at {}.\nRun `prune generate-keys` first.",
                path.display()
            )
        })?;
        let file: WalletFile = serde_json::from_str(&data)?;

        let sk = fr_from_hex(&file.spending_key)?;
        let keys = KeySet::from_spending_key(sk);

        // Rebuild the Merkle tree from stored leaves
        let mut tree = IncrementalMerkleTree::new();
        let mut tree_leaves = Vec::new();
        for leaf_hex in &file.tree_leaves {
            let leaf = fr_from_hex(leaf_hex)?;
            tree.append(leaf);
            tree_leaves.push(leaf);
        }

        let mut notes = Vec::new();
        for n in &file.notes {
            let note = Note {
                rune_id: fr_from_hex(&n.rune_id)?,
                amount: n.amount,
                blinding: fr_from_hex(&n.blinding)?,
                owner_pk: fr_from_hex(&n.owner_pk)?,
                note_index: n.note_index,
            };
            notes.push(StoredNote {
                commitment: fr_from_hex(&n.commitment)?,
                nullifier: fr_from_hex(&n.nullifier)?,
                spent: n.spent,
                note,
            });
        }

        let spent_nullifiers = file
            .spent_nullifiers
            .iter()
            .map(|h| fr_from_hex(h))
            .collect::<anyhow::Result<Vec<_>>>()?;

        Ok(Self { keys, notes, tree, spent_nullifiers, tree_leaves, path: path.to_path_buf() })
    }

    /// Persist current state to disk.
    pub fn save(&self) -> anyhow::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }

        let notes_json: Vec<StoredNoteJson> = self
            .notes
            .iter()
            .map(|sn| StoredNoteJson {
                rune_id: fr_to_hex(sn.note.rune_id),
                amount: sn.note.amount,
                blinding: fr_to_hex(sn.note.blinding),
                owner_pk: fr_to_hex(sn.note.owner_pk),
                note_index: sn.note.note_index,
                commitment: fr_to_hex(sn.commitment),
                nullifier: fr_to_hex(sn.nullifier),
                spent: sn.spent,
            })
            .collect();

        // tree_leaves: ALL commitments in insertion order (fixes save/load bug from Sprint 3)
        let tree_leaves: Vec<String> = self
            .tree_leaves
            .iter()
            .map(|leaf| fr_to_hex(*leaf))
            .collect();

        let file = WalletFile {
            version: 1,
            spending_key: fr_to_hex(self.keys.spending_key),
            notes: notes_json,
            tree_leaves,
            spent_nullifiers: self.spent_nullifiers.iter().map(|f| fr_to_hex(*f)).collect(),
        };

        let json = serde_json::to_string_pretty(&file)?;
        std::fs::write(&self.path, json)?;
        Ok(())
    }

    // ─── Operations ──────────────────────────────────────────────────────────

    /// Shield: create a private note for `amount` of `rune_id`.
    ///
    /// Returns the data that would go into the Taproot transaction:
    /// - `commitment`: added as a leaf to the on-chain Merkle tree
    /// - `encrypted_note_hex`: Taproot witness data (~128 bytes) so the
    ///   receiver can scan and decrypt their note
    pub fn shield(&mut self, rune_id: Fr, amount: u64) -> anyhow::Result<ShieldResult> {
        let mut rng = rand::thread_rng();

        let mut note = Note::new(&mut rng, rune_id, amount, self.keys.public_key);
        let commitment = note.commitment();
        let idx = self.tree.append(commitment);
        self.tree_leaves.push(commitment);
        note.set_index(idx);

        let nullifier = compute_nullifier(self.keys.nullifier_key, note.note_index, commitment);

        // Encrypt the note contents for on-chain receiver discovery
        let plaintext = note.to_plaintext();
        let pk_bytes = self.keys.x25519_public_bytes();
        let encrypted = encrypt_note(&plaintext, &pk_bytes, &mut rng)?;
        let enc_hex = hex::encode(
            [encrypted.ephemeral_pk.as_slice(), &encrypted.ciphertext].concat(),
        );

        self.notes.push(StoredNote { commitment, nullifier, spent: false, note });
        self.save()?;

        Ok(ShieldResult {
            note_index: idx,
            commitment,
            encrypted_note_hex: enc_hex,
            tree_root: self.tree.root(),
        })
    }

    /// Transfer: spend a private note and send `amount` to `recipient_pk`.
    ///
    /// The single-output circuit enforces: in_amount = out_amount + fee.
    /// `fee` here is the total that disappears from the shielded pool (miner fee
    /// + any change you choose to forfeit). Sprint 5 adds a change output so you
    /// can keep the remainder. For now: fee = in_note.amount - amount.
    ///
    /// Pass `full_prove = true` for a full Groth16 proof (~60s).
    pub fn transfer(
        &mut self,
        recipient_pk: Fr,
        amount: u64,
        fee: u64,
        rune_id: Fr,
        full_prove: bool,
    ) -> anyhow::Result<TransferResult> {
        let mut rng = rand::thread_rng();

        let input_idx = self
            .notes
            .iter()
            .position(|sn| !sn.spent && sn.note.rune_id == rune_id && sn.note.amount >= amount)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "No unspent note with sufficient balance for {} units of this rune",
                    amount
                )
            })?;

        let in_note = self.notes[input_idx].note.clone();
        let in_nullifier = self.notes[input_idx].nullifier;

        // Circuit requires: in_amount = out_amount + fee
        // fee here = in_amount - amount (all remainder)
        // The user-supplied fee is shown as the "miner fee" portion for display.
        let circuit_fee = in_note.amount.checked_sub(amount).ok_or_else(|| {
            anyhow::anyhow!("amount {} exceeds note balance {}", amount, in_note.amount)
        })?;
        let _ = fee; // user-provided fee is informational in Sprint 3

        let mut out_note = Note::new(&mut rng, rune_id, amount, recipient_pk);
        let out_commitment = out_note.commitment();

        let merkle_path = self.tree.merkle_path(in_note.note_index);
        let anchor = self.tree.root();

        let witness = SpendWitness {
            in_amount: Fr::from(in_note.amount),
            in_blinding: in_note.blinding,
            owner_pk: in_note.owner_pk,
            nullifier_key: self.keys.nullifier_key,
            note_index: Fr::from(in_note.note_index),
            merkle_siblings: merkle_path.siblings,
            merkle_indices: merkle_path.indices,
            out_amount: Fr::from(amount),
            out_blinding: out_note.blinding,
            out_owner_pk: recipient_pk,
        };

        let statement = SpendStatement {
            rune_id,
            anchor,
            nullifier: in_nullifier,
            out_commitment,
            fee: Fr::from(circuit_fee),
        };

        // Always verify circuit satisfiability first (fast)
        {
            use ark_relations::r1cs::ConstraintSystem;
            let cs = ConstraintSystem::<Fr>::new_ref();
            let circuit = SpendCircuit::for_prove(witness.clone(), statement.clone());
            circuit.generate_constraints(cs.clone())?;
            anyhow::ensure!(
                cs.is_satisfied()?,
                "Circuit is not satisfied — this is a bug in the witness construction"
            );
        }

        // Optional: full Groth16 proof
        let proof_hex = if full_prove {
            let (pk, _pvk) = circuit::setup(&mut rng)?;
            let proof = circuit::prove(&pk, witness, statement.clone(), &mut rng)?;
            let mut buf = Vec::new();
            proof.serialize_compressed(&mut buf)?;
            Some(hex::encode(buf))
        } else {
            None
        };

        // Update wallet state
        let out_idx = self.tree.append(out_commitment);
        self.tree_leaves.push(out_commitment);
        out_note.set_index(out_idx);

        self.notes[input_idx].spent = true;
        self.spent_nullifiers.push(in_nullifier);

        // Track the output note only if we are the recipient
        if recipient_pk == self.keys.public_key {
            let out_nullifier = compute_nullifier(
                self.keys.nullifier_key,
                out_note.note_index,
                out_commitment,
            );
            self.notes.push(StoredNote {
                commitment: out_commitment,
                nullifier: out_nullifier,
                spent: false,
                note: out_note,
            });
        }

        self.save()?;

        Ok(TransferResult {
            anchor,
            nullifier: in_nullifier,
            out_commitment,
            new_tree_root: self.tree.root(),
            circuit_fee,
            proof_hex,
        })
    }

    /// Unshield: convert a private note back to a public Rune balance.
    ///
    /// The note is spent and the full amount is credited to your public address.
    /// Uses conservation: in_amount = 0 (output) + in_amount (fee treated as the
    /// "public amount released"). Sprint 4 broadcasts the actual Bitcoin tx.
    pub fn unshield(&mut self, note_index: u64, full_prove: bool) -> anyhow::Result<UnshieldResult> {
        let mut rng = rand::thread_rng();

        let sn_idx = self
            .notes
            .iter()
            .position(|sn| sn.note.note_index == note_index && !sn.spent)
            .ok_or_else(|| {
                anyhow::anyhow!("Note index {note_index} not found or already spent")
            })?;

        let in_note = self.notes[sn_idx].note.clone();
        let in_nullifier = self.notes[sn_idx].nullifier;

        let merkle_path = self.tree.merkle_path(in_note.note_index);
        let anchor = self.tree.root();

        // Burn output: zero-value note to a well-known burn address
        // Conservation: in_amount = 0 (out_amount) + in_amount (fee)
        let burn_pk = Fr::from(0xb02bb02bu64); // "burn" sentinel
        let mut burn_note = Note::new(&mut rng, in_note.rune_id, 0, burn_pk);
        let out_commitment = burn_note.commitment();

        let witness = SpendWitness {
            in_amount: Fr::from(in_note.amount),
            in_blinding: in_note.blinding,
            owner_pk: in_note.owner_pk,
            nullifier_key: self.keys.nullifier_key,
            note_index: Fr::from(in_note.note_index),
            merkle_siblings: merkle_path.siblings,
            merkle_indices: merkle_path.indices,
            out_amount: Fr::from(0u64),
            out_blinding: burn_note.blinding,
            out_owner_pk: burn_pk,
        };

        let statement = SpendStatement {
            rune_id: in_note.rune_id,
            anchor,
            nullifier: in_nullifier,
            out_commitment,
            fee: Fr::from(in_note.amount), // full amount released publicly
        };

        {
            use ark_relations::r1cs::ConstraintSystem;
            let cs = ConstraintSystem::<Fr>::new_ref();
            let circuit = SpendCircuit::for_prove(witness.clone(), statement.clone());
            circuit.generate_constraints(cs.clone())?;
            anyhow::ensure!(cs.is_satisfied()?, "Circuit not satisfied");
        }

        let proof_hex = if full_prove {
            let (pk, _pvk) = circuit::setup(&mut rng)?;
            let proof = circuit::prove(&pk, witness, statement.clone(), &mut rng)?;
            let mut buf = Vec::new();
            proof.serialize_compressed(&mut buf)?;
            Some(hex::encode(buf))
        } else {
            None
        };

        self.notes[sn_idx].spent = true;
        self.spent_nullifiers.push(in_nullifier);
        self.save()?;

        Ok(UnshieldResult {
            rune_id: in_note.rune_id,
            amount: in_note.amount,
            anchor,
            nullifier: in_nullifier,
            proof_hex,
        })
    }

    // ─── Sync ────────────────────────────────────────────────────────────────

    /// Sync the wallet from on-chain indexed data.
    ///
    /// - Rebuilds the Merkle tree from ALL commitments (not just owned notes).
    /// - Attempts to decrypt each encrypted note with the wallet's x25519 viewing key.
    /// - Marks owned notes as spent if their nullifier appears on-chain.
    /// - Saves the wallet after sync.
    pub fn sync_from_indexed_data(
        &mut self,
        commitments: &[(u64, Fr)],           // (tree_index, commitment)
        encrypted_notes: &[(u64, Vec<u8>)],  // (tree_index, ephemeral_pk + ciphertext)
        nullifiers: &[[u8; 32]],             // all on-chain nullifiers
    ) -> anyhow::Result<SyncResult> {
        // 1. Rebuild the tree from ALL commitments
        let mut tree = IncrementalMerkleTree::new();
        let mut tree_leaves = Vec::new();
        for &(_idx, commitment) in commitments {
            tree.append(commitment);
            tree_leaves.push(commitment);
        }
        self.tree = tree;
        self.tree_leaves = tree_leaves;

        // 2. Try to decrypt each encrypted note with our x25519 secret key
        let secret_bytes = self.keys.x25519_secret_bytes();
        let mut new_notes_found = 0usize;

        for &(tree_index, ref enc_data) in encrypted_notes {
            if enc_data.len() < 33 {
                // Too short to contain ephemeral_pk (32) + any ciphertext
                continue;
            }

            let mut ephemeral_pk = [0u8; 32];
            ephemeral_pk.copy_from_slice(&enc_data[..32]);
            let ciphertext = enc_data[32..].to_vec();

            let encrypted = EncryptedNote {
                ephemeral_pk,
                ciphertext,
            };

            match decrypt_note(&encrypted, &secret_bytes) {
                Ok(plaintext) => {
                    // Decryption succeeded — this note is ours
                    match Note::from_plaintext(&plaintext, self.keys.public_key, tree_index) {
                        Ok(note) => {
                            let commitment = note.commitment();

                            // Check if we already track this note (by tree_index)
                            let already_tracked = self.notes.iter().any(|sn| {
                                sn.note.note_index == tree_index
                            });

                            if !already_tracked {
                                let nullifier = compute_nullifier(
                                    self.keys.nullifier_key,
                                    note.note_index,
                                    commitment,
                                );
                                self.notes.push(StoredNote {
                                    commitment,
                                    nullifier,
                                    spent: false,
                                    note,
                                });
                                new_notes_found += 1;
                            }
                        }
                        Err(_) => {
                            // Plaintext didn't parse — skip
                            continue;
                        }
                    }
                }
                Err(_) => {
                    // Decryption failed — not our note, skip
                    continue;
                }
            }
        }

        // 3. Mark notes as spent if their nullifier appears on-chain
        let mut notes_marked_spent = 0usize;

        // Convert on-chain nullifiers to Fr for comparison
        let on_chain_nullifiers: Vec<Fr> = nullifiers
            .iter()
            .map(|bytes| Fr::from_le_bytes_mod_order(bytes))
            .collect();

        for sn in &mut self.notes {
            if !sn.spent {
                if on_chain_nullifiers.contains(&sn.nullifier) {
                    sn.spent = true;
                    if !self.spent_nullifiers.contains(&sn.nullifier) {
                        self.spent_nullifiers.push(sn.nullifier);
                    }
                    notes_marked_spent += 1;
                }
            }
        }

        // 4. Save
        self.save()?;

        Ok(SyncResult {
            new_notes_found,
            notes_marked_spent,
        })
    }
}

// ─── Result types ─────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct ShieldResult {
    pub note_index: u64,
    pub commitment: Fr,
    pub encrypted_note_hex: String,
    pub tree_root: Fr,
}

#[derive(Debug)]
pub struct TransferResult {
    pub anchor: Fr,
    pub nullifier: Fr,
    pub out_commitment: Fr,
    pub new_tree_root: Fr,
    pub circuit_fee: u64,
    pub proof_hex: Option<String>,
}

#[derive(Debug)]
pub struct UnshieldResult {
    pub rune_id: Fr,
    pub amount: u64,
    pub anchor: Fr,
    pub nullifier: Fr,
    pub proof_hex: Option<String>,
}

#[derive(Debug)]
pub struct SyncResult {
    pub new_notes_found: usize,
    pub notes_marked_spent: usize,
}
