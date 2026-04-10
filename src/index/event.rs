use super::*;

#[derive(Debug, Clone, PartialEq)]
pub enum Event {
  InscriptionCreated {
    block_height: u32,
    charms: u16,
    inscription_id: InscriptionId,
    location: Option<SatPoint>,
    parent_inscription_ids: Vec<InscriptionId>,
    sequence_number: u32,
  },
  InscriptionTransferred {
    block_height: u32,
    inscription_id: InscriptionId,
    new_location: SatPoint,
    old_location: SatPoint,
    sequence_number: u32,
  },
  RuneBurned {
    amount: u128,
    block_height: u32,
    rune_id: RuneId,
    txid: Txid,
  },
  RuneEtched {
    block_height: u32,
    rune_id: RuneId,
    txid: Txid,
  },
  RuneMinted {
    amount: u128,
    block_height: u32,
    rune_id: RuneId,
    txid: Txid,
  },
  RuneTransferred {
    amount: u128,
    block_height: u32,
    outpoint: OutPoint,
    rune_id: RuneId,
    txid: Txid,
  },
  PruneShielded {
    block_height: u32,
    txid: Txid,
    commitment: [u8; 32],
    tree_index: u64,
  },
  PruneTransferred {
    block_height: u32,
    txid: Txid,
    nullifier: [u8; 32],
    out_commitment: [u8; 32],
    tree_index: u64,
  },
  PruneUnshielded {
    block_height: u32,
    txid: Txid,
    nullifier: [u8; 32],
    amount: u64,
  },
}
