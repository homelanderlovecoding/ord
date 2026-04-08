//! # Commit-Reveal Transaction Builder
//!
//! Builds and broadcasts pRune transactions on Bitcoin using the Taproot
//! commit-reveal pattern (same as ord inscriptions).
//!
//! ## Two-transaction flow
//!
//! 1. **Commit tx**: Funds a P2TR output whose script tree contains the
//!    pRune envelope. This is just a normal wallet-signed transaction.
//!
//! 2. **Reveal tx**: Spends the commit output via Taproot script-path,
//!    exposing the pRune envelope (nullifier, commitment, proof, etc.)
//!    in the witness data with the 4x weight discount.
//!
//! ## Why two transactions?
//!
//! The commit-reveal pattern hides the script data until spend time.
//! The commit tx is indistinguishable from any other P2TR payment.
//! Only the reveal tx exposes the pRune protocol data — and even then,
//! witness data is discounted (0.25 vbytes per byte).
//!
//! ## Regtest usage
//!
//! ```bash
//! bitcoind -regtest -txindex -rpcuser=ord -rpcpassword=ord
//! prune regtest-shield --rune-id 0x01 --amount 1000 \
//!   --rpc-url http://127.0.0.1:18443 --rpc-user ord --rpc-pass ord
//! bitcoin-cli -regtest generatetoaddress 1 <address>  # confirm
//! ```

use bitcoin::{
    absolute::LockTime,
    address::Address,
    key::{UntweakedKeypair, XOnlyPublicKey},
    opcodes,
    script::{Builder, PushBytesBuf, ScriptBuf},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{ControlBlock, LeafVersion, Signature, TapLeafHash, TaprootBuilder},
    Amount, KnownHrp, Network, OutPoint, Sequence, Transaction, TxIn, TxOut, Txid, Witness,
};
use secp256k1::Secp256k1;

use crate::transaction::PruneOp;

// ─── Plan ─────────────────────────────────────────────────────────────────────

/// Everything needed to execute a commit-reveal pair.
///
/// Created from a `PruneOp`, holds the Taproot script tree, the ephemeral
/// signing key, and the address to fund.
pub struct CommitRevealPlan {
    /// The full Taproot reveal script (OP_CHECKSIG + pRune envelope).
    pub reveal_script: ScriptBuf,
    /// Control block for script-path spend (proves the script is in the tree).
    pub control_block: ControlBlock,
    /// P2TR address to send the commit transaction to.
    pub commit_address: Address,
    /// Ephemeral key pair — signs the reveal transaction.
    /// This key is generated fresh for every operation and discarded after.
    pub key_pair: UntweakedKeypair,
    /// X-only public key (32 bytes) embedded in the reveal script.
    pub public_key: XOnlyPublicKey,
}

impl CommitRevealPlan {
    /// Create a plan for the given pRune operation.
    ///
    /// Generates a fresh ephemeral key, builds the Taproot script tree,
    /// and derives the P2TR commit address.
    pub fn new(op: &PruneOp, network: Network) -> anyhow::Result<Self> {
        let secp = Secp256k1::new();
        let key_pair = UntweakedKeypair::new(&secp, &mut rand::thread_rng());
        let (public_key, _parity) = XOnlyPublicKey::from_keypair(&key_pair);

        // Build reveal script: [pubkey] OP_CHECKSIG + pRune envelope
        let reveal_script = Self::build_reveal_script(op, &public_key);

        // Build Taproot tree with the reveal script as the only leaf
        let taproot_spend_info = TaprootBuilder::new()
            .add_leaf(0, reveal_script.clone())
            .map_err(|e| anyhow::anyhow!("failed to add leaf: {e:?}"))?
            .finalize(&secp, public_key)
            .map_err(|e| anyhow::anyhow!("failed to finalize taproot: {e:?}"))?;

        let control_block = taproot_spend_info
            .control_block(&(reveal_script.clone(), LeafVersion::TapScript))
            .ok_or_else(|| anyhow::anyhow!("failed to compute control block"))?;

        let commit_address = Address::p2tr_tweaked(
            taproot_spend_info.output_key(),
            Self::network_to_hrp(network),
        );

        Ok(Self {
            reveal_script,
            control_block,
            commit_address,
            key_pair,
            public_key,
        })
    }

    /// Build the full Taproot reveal script.
    fn build_reveal_script(op: &PruneOp, public_key: &XOnlyPublicKey) -> ScriptBuf {
        op.to_reveal_script(&public_key.serialize())
    }

    /// Convert Network to KnownHrp for address creation.
    fn network_to_hrp(network: Network) -> KnownHrp {
        match network {
            Network::Bitcoin => KnownHrp::Mainnet,
            Network::Testnet => KnownHrp::Testnets,
            Network::Signet => KnownHrp::Testnets,
            Network::Regtest => KnownHrp::Regtest,
            _ => KnownHrp::Regtest,
        }
    }

    /// Estimate the reveal transaction's virtual size (vbytes).
    ///
    /// Used to compute how much the commit output needs to hold.
    pub fn estimated_reveal_vsize(&self) -> usize {
        // Fixed overhead: version(4) + marker+flag(2) + input_count(1) +
        //                 output_count(1) + locktime(4) = 12 bytes
        // Input: prevout(36) + sequence(4) + script_sig_len(1) = 41 bytes
        // Output (change): value(8) + script_len(1) + script(34) = 43 bytes
        let base_size = 12 + 41 + 43;

        // Witness: signature(64) + script + control_block(33+)
        let witness_size = 64 + self.reveal_script.len() + self.control_block.serialize().len()
            + 3; // length prefixes

        // vsize = (base_weight + witness_weight) / 4, rounded up
        // base_weight = base_size * 4, witness_weight = witness_size * 1
        let weight = base_size * 4 + witness_size;
        (weight + 3) / 4
    }

    /// Build a signed reveal transaction that spends the commit output.
    ///
    /// `commit_outpoint`: the specific output of the commit tx to spend.
    /// `commit_value`: how many sats are in that output.
    /// `fee_rate`: sats per vbyte for the reveal transaction.
    /// `change_script`: where to send leftover sats (your wallet address).
    pub fn build_reveal_tx(
        &self,
        commit_outpoint: OutPoint,
        commit_value: Amount,
        fee_rate: u64,
        change_script: Option<ScriptBuf>,
    ) -> anyhow::Result<Transaction> {
        let secp = Secp256k1::new();

        let fee = Amount::from_sat(fee_rate * self.estimated_reveal_vsize() as u64);
        let change_value = commit_value
            .checked_sub(fee)
            .ok_or_else(|| anyhow::anyhow!("commit value {} < fee {}", commit_value, fee))?;

        // Build outputs
        let mut outputs = Vec::new();
        if change_value > Amount::from_sat(546) {
            // Send change somewhere (or to sender)
            let script = change_script.unwrap_or_else(|| {
                // Default: pay back to our own key (key-path P2TR)
                Address::p2tr(
                    &secp,
                    self.public_key,
                    None,
                    Self::network_to_hrp(Network::Regtest),
                )
                .script_pubkey()
            });
            outputs.push(TxOut {
                value: change_value,
                script_pubkey: script,
            });
        }
        // If change is dust, it all goes to fee

        let mut reveal_tx = Transaction {
            version: bitcoin::transaction::Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: commit_outpoint,
                script_sig: ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            }],
            output: outputs,
        };

        // Sign with Taproot script-path spend
        let prevouts = vec![TxOut {
            value: commit_value,
            script_pubkey: self.commit_address.script_pubkey(),
        }];

        let mut sighash_cache = SighashCache::new(&mut reveal_tx);
        let sighash = sighash_cache
            .taproot_script_spend_signature_hash(
                0, // input index
                &Prevouts::All(&prevouts),
                TapLeafHash::from_script(&self.reveal_script, LeafVersion::TapScript),
                TapSighashType::Default,
            )
            .map_err(|e| anyhow::anyhow!("sighash failed: {e}"))?;

        let msg = secp256k1::Message::from_digest_slice(sighash.as_ref())
            .map_err(|e| anyhow::anyhow!("message failed: {e}"))?;
        let signature = secp.sign_schnorr(&msg, &self.key_pair);

        // Assemble witness: [signature, script, control_block]
        let witness = sighash_cache.witness_mut(0).expect("input 0 exists");
        witness.push(
            Signature {
                signature,
                sighash_type: TapSighashType::Default,
            }
            .to_vec(),
        );
        witness.push(self.reveal_script.as_bytes());
        witness.push(self.control_block.serialize());

        Ok(sighash_cache.into_transaction().clone())
    }
}

// ─── RPC broadcaster ─────────────────────────────────────────────────────────

/// Broadcasts a pRune commit-reveal pair via Bitcoin Core RPC.
///
/// Requires a funded wallet on the connected Bitcoin Core node.
pub fn broadcast_commit_reveal(
    rpc: &bitcoincore_rpc::Client,
    plan: &CommitRevealPlan,
    fee_rate_sat_vb: u64,
    change_address: Option<Address>,
) -> anyhow::Result<BroadcastResult> {
    use bitcoincore_rpc::RpcApi;

    let commit_value = Amount::from_sat(10_000); // generous for regtest

    // Step 1: Build + fund + sign + broadcast commit tx
    let commit_address_str = plan.commit_address.to_string();
    let commit_txid = rpc
        .send_to_address(
            &plan.commit_address,
            commit_value,
            Some("pRune commit"),
            None,
            None,
            None,
            None,
            None,
        )
        .map_err(|e| anyhow::anyhow!("commit tx failed: {e}"))?;

    // Find the commit output vout
    let commit_tx = rpc
        .get_raw_transaction(&commit_txid, None)
        .map_err(|e| anyhow::anyhow!("get commit tx failed: {e}"))?;

    let commit_vout = commit_tx
        .output
        .iter()
        .position(|o| o.script_pubkey == plan.commit_address.script_pubkey())
        .ok_or_else(|| anyhow::anyhow!("commit output not found in tx"))? as u32;

    let actual_commit_value = commit_tx.output[commit_vout as usize].value;

    // Step 2: Build + sign reveal tx (we sign, not bitcoind)
    let commit_outpoint = OutPoint {
        txid: commit_txid,
        vout: commit_vout,
    };

    let change_script = change_address.map(|a| a.script_pubkey());
    let reveal_tx = plan.build_reveal_tx(
        commit_outpoint,
        actual_commit_value,
        fee_rate_sat_vb,
        change_script,
    )?;

    // Step 3: Broadcast reveal tx
    let reveal_txid = rpc
        .send_raw_transaction(&reveal_tx)
        .map_err(|e| anyhow::anyhow!("reveal tx broadcast failed: {e}"))?;

    Ok(BroadcastResult {
        commit_txid,
        reveal_txid,
        commit_address: commit_address_str,
        reveal_vsize: reveal_tx.vsize() as u64,
    })
}

/// Result of a successful commit-reveal broadcast.
pub struct BroadcastResult {
    pub commit_txid: Txid,
    pub reveal_txid: Txid,
    pub commit_address: String,
    pub reveal_vsize: u64,
}

// ─── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bn254::Fr;
    use bitcoin::hashes::Hash;

    #[test]
    fn test_plan_creation() {
        let op = PruneOp::Shield {
            rune_id: Fr::from(1u64),
            commitment: Fr::from(2u64),
            encrypted_note: vec![0xaa; 88],
        };

        let plan = CommitRevealPlan::new(&op, Network::Regtest).unwrap();

        // Verify we got a valid P2TR address
        let addr_str = plan.commit_address.to_string();
        assert!(
            addr_str.starts_with("bcrt1p"),
            "regtest P2TR should start with bcrt1p, got: {addr_str}"
        );

        // Verify control block serializes
        let cb = plan.control_block.serialize();
        assert!(!cb.is_empty(), "control block should not be empty");

        println!("Commit address: {addr_str}");
        println!("Reveal script size: {} bytes", plan.reveal_script.len());
        println!("Estimated reveal vsize: {} vbytes", plan.estimated_reveal_vsize());
    }

    #[test]
    fn test_plan_for_transfer() {
        let op = PruneOp::Transfer {
            rune_id: Fr::from(1u64),
            nullifier: Fr::from(100u64),
            out_commitment: Fr::from(200u64),
            anchor: Fr::from(300u64),
            fee: 50,
            proof: vec![0xbb; 192],
            encrypted_note: vec![0xcc; 88],
        };

        let plan = CommitRevealPlan::new(&op, Network::Regtest).unwrap();
        println!("Transfer reveal vsize: {} vbytes", plan.estimated_reveal_vsize());

        // Should be reasonable (under 500 vbytes)
        assert!(
            plan.estimated_reveal_vsize() < 500,
            "transfer reveal should be under 500 vbytes"
        );
    }

    #[test]
    fn test_reveal_tx_construction() {
        let op = PruneOp::Shield {
            rune_id: Fr::from(1u64),
            commitment: Fr::from(2u64),
            encrypted_note: vec![0xaa; 88],
        };

        let plan = CommitRevealPlan::new(&op, Network::Regtest).unwrap();

        // Build reveal tx with a fake commit outpoint
        let fake_outpoint = OutPoint {
            txid: Txid::from_byte_array([0x42; 32]),
            vout: 0,
        };

        let reveal_tx = plan
            .build_reveal_tx(fake_outpoint, Amount::from_sat(10_000), 1, None)
            .unwrap();

        // Should have 1 input and 1 output (change)
        assert_eq!(reveal_tx.input.len(), 1);
        assert!(!reveal_tx.output.is_empty());

        // Witness should have 3 elements: [signature, script, control_block]
        let witness = &reveal_tx.input[0].witness;
        assert_eq!(
            witness.len(),
            3,
            "witness must have 3 elements (sig, script, control_block)"
        );

        // First element: Schnorr signature (64 bytes for Default sighash)
        assert_eq!(witness.nth(0).unwrap().len(), 64, "signature should be 64 bytes");

        // Second element: reveal script
        assert_eq!(
            witness.nth(1).unwrap(),
            plan.reveal_script.as_bytes(),
            "second witness element should be the reveal script"
        );

        // Third element: control block
        assert_eq!(
            witness.nth(2).unwrap(),
            plan.control_block.serialize().as_slice(),
            "third witness element should be the control block"
        );

        println!(
            "Reveal tx: {} inputs, {} outputs, {} vbytes",
            reveal_tx.input.len(),
            reveal_tx.output.len(),
            reveal_tx.vsize()
        );
    }
}
