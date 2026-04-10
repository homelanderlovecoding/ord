use {
  super::*,
  prune::indexer::{fr_from_bytes32, fr_to_bytes32, scan_transaction, PruneOp},
  prune::tree::IncrementalMerkleTree,
};

pub(super) struct PruneUpdater<'a, 'tx> {
  event_sender: Option<&'a mpsc::Sender<Event>>,
  height: u32,
  nullifier_set: &'a mut Table<'tx, &'static [u8; 32], ()>,
  commitment_to_index: &'a mut Table<'tx, u64, &'static [u8; 32]>,
  encrypted_notes: &'a mut Table<'tx, u64, &'static [u8]>,
  tree_root_at_height: &'a mut Table<'tx, u32, &'static [u8; 32]>,
  tree_next_index: &'a mut Table<'tx, u64, u64>,
  tree: IncrementalMerkleTree,
  next_index: u64,
}

impl<'a, 'tx> PruneUpdater<'a, 'tx> {
  /// Create a new PruneUpdater, rebuilding the Merkle tree from stored state.
  pub(super) fn new(
    event_sender: Option<&'a mpsc::Sender<Event>>,
    height: u32,
    nullifier_set: &'a mut Table<'tx, &'static [u8; 32], ()>,
    commitment_to_index: &'a mut Table<'tx, u64, &'static [u8; 32]>,
    encrypted_notes: &'a mut Table<'tx, u64, &'static [u8]>,
    tree_root_at_height: &'a mut Table<'tx, u32, &'static [u8; 32]>,
    tree_next_index: &'a mut Table<'tx, u64, u64>,
  ) -> Result<Self> {
    // Load tree state: get next_index from DB
    let mut tree = IncrementalMerkleTree::new();
    let next_index = tree_next_index
      .get(&0)?
      .map(|v| v.value())
      .unwrap_or(0);

    // Rebuild tree from stored commitments
    for idx in 0..next_index {
      if let Some(commitment_guard) = commitment_to_index.get(&idx)? {
        let bytes: [u8; 32] = *commitment_guard.value();
        if let Ok(fr) = fr_from_bytes32(&bytes) {
          tree.append(fr);
        }
      }
    }

    Ok(Self {
      event_sender,
      height,
      nullifier_set,
      commitment_to_index,
      encrypted_notes,
      tree_root_at_height,
      tree_next_index,
      tree,
      next_index,
    })
  }

  /// Process a single transaction for pRune operations.
  pub(super) fn index_prune_ops(
    &mut self,
    tx: &Transaction,
    txid: Txid,
  ) -> Result<()> {
    let ops = scan_transaction(tx);

    for (_input_idx, op) in ops {
      match op {
        PruneOp::Shield {
          rune_id: _,
          commitment,
          encrypted_note,
        } => {
          self.process_shield(commitment, encrypted_note, txid)?;
        }
        PruneOp::Transfer {
          rune_id: _,
          nullifier,
          out_commitment,
          anchor: _,
          fee: _,
          proof: _,
          encrypted_note,
        } => {
          self.process_transfer(nullifier, out_commitment, encrypted_note, txid)?;
        }
        PruneOp::Unshield {
          rune_id: _,
          nullifier,
          out_commitment,
          anchor: _,
          amount,
          proof: _,
        } => {
          self.process_unshield(nullifier, out_commitment, amount, txid)?;
        }
      }
    }

    Ok(())
  }

  fn process_shield(
    &mut self,
    commitment: prune::Fr,
    encrypted_note: Vec<u8>,
    txid: Txid,
  ) -> Result<()> {
    let tree_index = self.next_index;
    let commitment_bytes = fr_to_bytes32(commitment);

    // Append to global Merkle tree
    self.tree.append(commitment);

    // Store commitment
    self.commitment_to_index
      .insert(&tree_index, &commitment_bytes)?;

    // Store encrypted note
    self.encrypted_notes
      .insert(&tree_index, encrypted_note.as_slice())?;

    self.next_index += 1;

    if let Some(sender) = self.event_sender {
      sender.blocking_send(Event::PruneShielded {
        block_height: self.height,
        txid,
        commitment: commitment_bytes,
        tree_index,
      })?;
    }

    log::info!(
      "pRune Shield: tree_index={} txid={}",
      tree_index,
      txid,
    );

    Ok(())
  }

  fn process_transfer(
    &mut self,
    nullifier: prune::Fr,
    out_commitment: prune::Fr,
    encrypted_note: Vec<u8>,
    txid: Txid,
  ) -> Result<()> {
    let nullifier_bytes = fr_to_bytes32(nullifier);

    // Double-spend check
    if self.nullifier_set.get(&nullifier_bytes)?.is_some() {
      log::warn!("pRune Transfer REJECTED: double-spend txid={}", txid);
      return Ok(());
    }

    self.nullifier_set.insert(&nullifier_bytes, &())?;

    let tree_index = self.next_index;
    let commitment_bytes = fr_to_bytes32(out_commitment);
    self.tree.append(out_commitment);
    self.commitment_to_index
      .insert(&tree_index, &commitment_bytes)?;
    self.encrypted_notes
      .insert(&tree_index, encrypted_note.as_slice())?;
    self.next_index += 1;

    if let Some(sender) = self.event_sender {
      sender.blocking_send(Event::PruneTransferred {
        block_height: self.height,
        txid,
        nullifier: nullifier_bytes,
        out_commitment: commitment_bytes,
        tree_index,
      })?;
    }

    log::info!("pRune Transfer: tree_index={} txid={}", tree_index, txid);

    Ok(())
  }

  fn process_unshield(
    &mut self,
    nullifier: prune::Fr,
    out_commitment: prune::Fr,
    amount: u64,
    txid: Txid,
  ) -> Result<()> {
    let nullifier_bytes = fr_to_bytes32(nullifier);

    // Double-spend check
    if self.nullifier_set.get(&nullifier_bytes)?.is_some() {
      log::warn!("pRune Unshield REJECTED: double-spend txid={}", txid);
      return Ok(());
    }

    self.nullifier_set.insert(&nullifier_bytes, &())?;

    let tree_index = self.next_index;
    let commitment_bytes = fr_to_bytes32(out_commitment);
    self.tree.append(out_commitment);
    self.commitment_to_index
      .insert(&tree_index, &commitment_bytes)?;
    self.next_index += 1;

    if let Some(sender) = self.event_sender {
      sender.blocking_send(Event::PruneUnshielded {
        block_height: self.height,
        txid,
        nullifier: nullifier_bytes,
        amount,
      })?;
    }

    log::info!("pRune Unshield: amount={} txid={}", amount, txid);

    Ok(())
  }

  /// Finalize: persist tree root at this height and next_index counter.
  pub(super) fn finalize(&mut self) -> Result<()> {
    let root = self.tree.root();
    let root_bytes = fr_to_bytes32(root);
    self.tree_root_at_height
      .insert(&self.height, &root_bytes)?;
    self.tree_next_index.insert(&0, &self.next_index)?;
    Ok(())
  }
}
