//! # prune — pRune CLI wallet
//!
//! Offline Sprint 3 wallet. Manages private keys and notes locally;
//! prints exactly what would go into a real Bitcoin Taproot transaction.
//! Sprint 4 wires these outputs to live Bitcoin Core + ord indexer.
//!
//! ## Quick start
//!
//! ```text
//! prune generate-keys                        # create wallet
//! prune shield --rune-id 0x01 --amount 1000  # shield 1000 units
//! prune notes                                # list notes
//! prune transfer --to <pk> --amount 900 --fee 10 --rune-id 0x01
//! prune unshield --note-index 0              # convert back to public
//! ```

use std::path::PathBuf;
use ark_bn254::Fr;
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use bitcoin::Network;
use clap::{Parser, Subcommand, ValueEnum};
use prune::broadcast::{broadcast_commit_reveal, CommitRevealPlan};
use prune::transaction::PruneOp;
use prune::wallet::{fr_from_hex, Wallet};

// ─── CLI definition ───────────────────────────────────────────────────────────

#[derive(Clone, ValueEnum, Debug)]
enum NetworkArg {
    Regtest,
    Signet,
    Testnet,
}

impl NetworkArg {
    fn to_bitcoin_network(&self) -> Network {
        match self {
            NetworkArg::Regtest => Network::Regtest,
            NetworkArg::Signet => Network::Signet,
            NetworkArg::Testnet => Network::Testnet,
        }
    }
}

#[derive(Parser)]
#[command(
    name = "prune",
    about = "pRune — shielded Rune CLI wallet (Sprint 6)",
    version = "0.1.0",
    long_about = "Wallet for private Rune transfers using Groth16 ZK proofs.\n\
                  Supports offline operations and live Bitcoin broadcasting (regtest/signet/testnet)."
)]
struct Cli {
    /// Path to wallet file [default: ~/.prune/wallet.json]
    #[arg(long, global = true)]
    wallet: Option<PathBuf>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate a new wallet with a random spending key
    #[command(name = "generate-keys")]
    GenerateKeys,

    /// Show wallet info: public key, note count, tree root
    #[command(name = "info")]
    Info,

    /// List all notes (unspent and spent)
    #[command(name = "notes")]
    Notes,

    /// Shield public Runes → create a private note
    ///
    /// Outputs the commitment and encrypted note that would go on-chain.
    #[command(name = "shield")]
    Shield {
        /// Rune ID as a hex field element (e.g. 0x01 or a full 32-byte hex)
        #[arg(long)]
        rune_id: String,

        /// Amount of Rune units to shield
        #[arg(long)]
        amount: u64,
    },

    /// Transfer private notes to a recipient
    ///
    /// Selects the first unspent note for the given rune with sufficient balance.
    /// Default: verify circuit satisfiability only (fast). Use --prove for a full
    /// Groth16 proof (~60s).
    #[command(name = "transfer")]
    Transfer {
        /// Recipient's public key as hex
        #[arg(long)]
        to: String,

        /// Amount to send
        #[arg(long)]
        amount: u64,

        /// Transaction fee (deducted from input note)
        #[arg(long, default_value = "0")]
        fee: u64,

        /// Rune ID as hex
        #[arg(long)]
        rune_id: String,

        /// Generate a full Groth16 proof (slow: ~60s). Default: circuit check only.
        #[arg(long, default_value = "false")]
        prove: bool,
    },

    /// Unshield a private note → convert back to public Rune balance
    ///
    /// The full amount of the note is credited to your Bitcoin address on-chain.
    #[command(name = "unshield")]
    Unshield {
        /// Index of the note to unshield (from `prune notes`)
        #[arg(long)]
        note_index: u64,

        /// Generate a full Groth16 proof (slow: ~60s). Default: circuit check only.
        #[arg(long, default_value = "false")]
        prove: bool,
    },

    /// Sync wallet from on-chain indexed data
    ///
    /// Reads commitments and encrypted notes from ~/.prune/indexed_data.json
    /// and attempts to decrypt notes belonging to this wallet.
    #[command(name = "sync")]
    Sync {
        /// Path to indexed data JSON file [default: ~/.prune/indexed_data.json]
        #[arg(long)]
        data_file: Option<PathBuf>,
    },

    /// Shield + broadcast on regtest/signet/testnet via Bitcoin Core RPC
    ///
    /// Creates a private note and broadcasts the commit-reveal Taproot
    /// transaction pair through a connected Bitcoin Core node.
    #[command(name = "broadcast-shield")]
    BroadcastShield {
        /// Rune ID as a hex field element (e.g. 0x01)
        #[arg(long)]
        rune_id: String,

        /// Amount of Rune units to shield
        #[arg(long)]
        amount: u64,

        /// Bitcoin Core RPC URL
        #[arg(long, default_value = "http://127.0.0.1:18443")]
        rpc_url: String,

        /// Bitcoin Core RPC username
        #[arg(long, default_value = "ord")]
        rpc_user: String,

        /// Bitcoin Core RPC password
        #[arg(long, default_value = "ord")]
        rpc_pass: String,

        /// Target network
        #[arg(long, value_enum, default_value = "regtest")]
        network: NetworkArg,

        /// Fee rate in sat/vB
        #[arg(long, default_value = "1")]
        fee_rate: u64,
    },

    /// Transfer + broadcast on regtest/signet/testnet via Bitcoin Core RPC
    ///
    /// Spends a private note and sends to a recipient, broadcasting
    /// the commit-reveal Taproot transaction pair.
    #[command(name = "broadcast-transfer")]
    BroadcastTransfer {
        /// Recipient's public key as hex
        #[arg(long)]
        to: String,

        /// Amount to send
        #[arg(long)]
        amount: u64,

        /// Rune ID as hex
        #[arg(long)]
        rune_id: String,

        /// Generate a full Groth16 proof (slow: ~60s). Default: circuit check only.
        #[arg(long, default_value = "false")]
        prove: bool,

        /// Bitcoin Core RPC URL
        #[arg(long, default_value = "http://127.0.0.1:18443")]
        rpc_url: String,

        /// Bitcoin Core RPC username
        #[arg(long, default_value = "ord")]
        rpc_user: String,

        /// Bitcoin Core RPC password
        #[arg(long, default_value = "ord")]
        rpc_pass: String,

        /// Target network
        #[arg(long, value_enum, default_value = "regtest")]
        network: NetworkArg,

        /// Fee rate in sat/vB
        #[arg(long, default_value = "1")]
        fee_rate: u64,
    },

    /// Unshield + broadcast on regtest/signet/testnet via Bitcoin Core RPC
    ///
    /// Converts a private note back to a public Rune balance and broadcasts
    /// the commit-reveal Taproot transaction pair.
    #[command(name = "broadcast-unshield")]
    BroadcastUnshield {
        /// Index of the note to unshield (from `prune notes`)
        #[arg(long)]
        note_index: u64,

        /// Generate a full Groth16 proof (slow: ~60s). Default: circuit check only.
        #[arg(long, default_value = "false")]
        prove: bool,

        /// Bitcoin Core RPC URL
        #[arg(long, default_value = "http://127.0.0.1:18443")]
        rpc_url: String,

        /// Bitcoin Core RPC username
        #[arg(long, default_value = "ord")]
        rpc_user: String,

        /// Bitcoin Core RPC password
        #[arg(long, default_value = "ord")]
        rpc_pass: String,

        /// Target network
        #[arg(long, value_enum, default_value = "regtest")]
        network: NetworkArg,

        /// Fee rate in sat/vB
        #[arg(long, default_value = "1")]
        fee_rate: u64,
    },
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

fn parse_fr(s: &str) -> anyhow::Result<Fr> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    // Short values (≤16 hex chars = u64): parse as u64
    if s.len() <= 16 {
        let n = u64::from_str_radix(s, 16)?;
        Ok(Fr::from(n))
    } else {
        // Full 32-byte field element
        let bytes = hex::decode(s)?;
        Ok(Fr::from_le_bytes_mod_order(&bytes))
    }
}

fn fr_display(f: Fr) -> String {
    let mut bytes = Vec::new();
    use ark_serialize::CanonicalSerialize;
    f.serialize_compressed(&mut bytes).unwrap();
    hex::encode(bytes)
}

fn wallet_path(cli: &Cli) -> PathBuf {
    cli.wallet.clone().unwrap_or_else(Wallet::default_path)
}

// ─── Entry point ─────────────────────────────────────────────────────────────

fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let path = wallet_path(&cli);

    match cli.command {
        Command::GenerateKeys => cmd_generate_keys(&path),
        Command::Info => cmd_info(&path),
        Command::Notes => cmd_notes(&path),
        Command::Shield { rune_id, amount } => cmd_shield(&path, &rune_id, amount),
        Command::Transfer { to, amount, fee, rune_id, prove } => {
            cmd_transfer(&path, &to, amount, fee, &rune_id, prove)
        }
        Command::Unshield { note_index, prove } => cmd_unshield(&path, note_index, prove),
        Command::Sync { data_file } => cmd_sync(&path, data_file),
        Command::BroadcastShield {
            rune_id, amount, rpc_url, rpc_user, rpc_pass, network, fee_rate,
        } => cmd_broadcast_shield(&path, &rune_id, amount, &rpc_url, &rpc_user, &rpc_pass, &network, fee_rate),
        Command::BroadcastTransfer {
            to, amount, rune_id, prove, rpc_url, rpc_user, rpc_pass, network, fee_rate,
        } => cmd_broadcast_transfer(&path, &to, amount, &rune_id, prove, &rpc_url, &rpc_user, &rpc_pass, &network, fee_rate),
        Command::BroadcastUnshield {
            note_index, prove, rpc_url, rpc_user, rpc_pass, network, fee_rate,
        } => cmd_broadcast_unshield(&path, note_index, prove, &rpc_url, &rpc_user, &rpc_pass, &network, fee_rate),
    }
}

// ─── Command handlers ─────────────────────────────────────────────────────────

fn cmd_generate_keys(path: &std::path::Path) -> anyhow::Result<()> {
    if path.exists() {
        anyhow::bail!(
            "Wallet already exists at {}.\n\
             Delete it first if you want a new one (WARNING: this destroys your keys).",
            path.display()
        );
    }

    let wallet = Wallet::create(path)?;
    let keys = &wallet.keys;

    println!("✓ Wallet created at {}", path.display());
    println!();
    println!("  spending_key  (SECRET — never share):  {}", fr_display(keys.spending_key));
    println!("  viewing_key   (share with auditors):   {}", fr_display(keys.viewing_key));
    println!("  nullifier_key (internal):              {}", fr_display(keys.nullifier_key));
    println!("  public_key    (your address):          {}", fr_display(keys.public_key));
    println!();
    println!("Back up {} — your spending_key cannot be recovered.", path.display());
    Ok(())
}

fn cmd_info(path: &std::path::Path) -> anyhow::Result<()> {
    let wallet = Wallet::load(path)?;
    let unspent = wallet.notes.iter().filter(|n| !n.spent).count();
    let spent = wallet.notes.iter().filter(|n| n.spent).count();

    println!("Wallet: {}", path.display());
    println!();
    println!("  public_key    {}", fr_display(wallet.keys.public_key));
    println!("  notes         {} unspent, {} spent", unspent, spent);
    println!("  tree leaves   {}", wallet.tree.len());
    println!("  tree root     {}", fr_display(wallet.tree.root()));
    Ok(())
}

fn cmd_notes(path: &std::path::Path) -> anyhow::Result<()> {
    let wallet = Wallet::load(path)?;

    if wallet.notes.is_empty() {
        println!("No notes. Shield some Runes first with `prune shield`.");
        return Ok(());
    }

    println!("{:<6} {:<8} {:<12} {:<68} {}",
        "index", "spent", "amount", "rune_id", "commitment");
    println!("{}", "-".repeat(110));

    for sn in &wallet.notes {
        println!(
            "{:<6} {:<8} {:<12} {:<68} {}",
            sn.note.note_index,
            if sn.spent { "spent" } else { "unspent" },
            sn.note.amount,
            fr_display(sn.note.rune_id),
            &fr_display(sn.commitment)[..16],
        );
    }
    Ok(())
}

fn cmd_shield(path: &std::path::Path, rune_id_str: &str, amount: u64) -> anyhow::Result<()> {
    let rune_id = parse_fr(rune_id_str)?;
    let mut wallet = Wallet::load(path)?;

    let result = wallet.shield(rune_id, amount)?;

    println!("✓ Note shielded (index {})", result.note_index);
    println!();
    println!("  ── On-chain data (put in Taproot tx) ──────────────────────────");
    println!("  commitment         {}", fr_display(result.commitment));
    println!("  tree root (new)    {}", fr_display(result.tree_root));
    println!();
    println!("  ── Witness data (encrypted note, ~128 bytes in Taproot witness) ──");
    println!("  encrypted_note     {}", &result.encrypted_note_hex[..64]);
    println!("                     {}…", &result.encrypted_note_hex[64..128]);
    println!();
    println!("Sprint 4 will broadcast this as a real Bitcoin Taproot transaction.");
    Ok(())
}

fn cmd_transfer(
    path: &std::path::Path,
    to_str: &str,
    amount: u64,
    fee: u64,
    rune_id_str: &str,
    full_prove: bool,
) -> anyhow::Result<()> {
    let recipient_pk = parse_fr(to_str)?;
    let rune_id = parse_fr(rune_id_str)?;
    let mut wallet = Wallet::load(path)?;

    if full_prove {
        println!("Generating full Groth16 proof (this takes ~60s)…");
    } else {
        println!("Verifying circuit satisfiability…");
    }

    let result = wallet.transfer(recipient_pk, amount, fee, rune_id, full_prove)?;

    println!("✓ Transfer prepared");
    println!();
    println!("  ── Public statement (goes on-chain) ───────────────────────────");
    println!("  rune_id            {}", rune_id_str);
    println!("  anchor             {}", fr_display(result.anchor));
    println!("  nullifier          {}", fr_display(result.nullifier));
    println!("  out_commitment     {}", fr_display(result.out_commitment));
    println!("  fee (pool exit)    {} (= in_amount - out_amount)", result.circuit_fee);
    println!("  tree root (new)    {}", fr_display(result.new_tree_root));
    println!();

    if let Some(proof) = &result.proof_hex {
        println!("  ── Groth16 proof (192 bytes compressed) ───────────────────────");
        println!("  proof              {}…", &proof[..64]);
        println!();
    } else {
        println!("  ── Proof ──────────────────────────────────────────────────────");
        println!("  circuit check      ✓ satisfied ({} constraints)", 8668);
        println!("  full proof         not generated (add --prove to generate)");
        println!();
    }

    println!("Sprint 4 will broadcast this as a real Bitcoin Taproot transaction.");
    Ok(())
}

fn cmd_unshield(
    path: &std::path::Path,
    note_index: u64,
    full_prove: bool,
) -> anyhow::Result<()> {
    let mut wallet = Wallet::load(path)?;

    if full_prove {
        println!("Generating full Groth16 proof (this takes ~60s)…");
    } else {
        println!("Verifying circuit satisfiability…");
    }

    let result = wallet.unshield(note_index, full_prove)?;

    println!("✓ Unshield prepared");
    println!();
    println!("  ── Public statement (goes on-chain) ───────────────────────────");
    println!("  rune_id            {}", fr_display(result.rune_id));
    println!("  amount (public)    {}", result.amount);
    println!("  anchor             {}", fr_display(result.anchor));
    println!("  nullifier          {}", fr_display(result.nullifier));
    println!();

    if let Some(proof) = &result.proof_hex {
        println!("  ── Groth16 proof ───────────────────────────────────────────────");
        println!("  proof              {}…", &proof[..64]);
        println!();
    } else {
        println!("  ── Proof ──────────────────────────────────────────────────────");
        println!("  circuit check      ✓ satisfied");
        println!("  full proof         not generated (add --prove to generate)");
        println!();
    }

    println!("Sprint 4 will broadcast this, crediting {} units of this Rune to your address.", result.amount);
    Ok(())
}

// ─── RPC helper ──────────────────────────────────────────────────────────────

fn connect_rpc(rpc_url: &str, rpc_user: &str, rpc_pass: &str) -> anyhow::Result<bitcoincore_rpc::Client> {
    let auth = bitcoincore_rpc::Auth::UserPass(rpc_user.to_string(), rpc_pass.to_string());
    bitcoincore_rpc::Client::new(rpc_url, auth)
        .map_err(|e| anyhow::anyhow!("Failed to connect to Bitcoin Core RPC at {}: {}", rpc_url, e))
}

// ─── Broadcast commands ─────────────────────────────────────────────────────

fn cmd_broadcast_shield(
    path: &std::path::Path,
    rune_id_str: &str,
    amount: u64,
    rpc_url: &str,
    rpc_user: &str,
    rpc_pass: &str,
    network: &NetworkArg,
    fee_rate: u64,
) -> anyhow::Result<()> {
    let rune_id = parse_fr(rune_id_str)?;
    let mut wallet = Wallet::load(path)?;
    let btc_network = network.to_bitcoin_network();

    println!("Shielding {} units of rune {}...", amount, rune_id_str);

    // 1. Create the shielded note (updates wallet state)
    let result = wallet.shield(rune_id, amount)?;

    // 2. Build the PruneOp for on-chain encoding
    let encrypted_note_bytes = hex::decode(&result.encrypted_note_hex)?;
    let op = PruneOp::Shield {
        rune_id,
        commitment: result.commitment,
        encrypted_note: encrypted_note_bytes,
    };

    // 3. Create commit-reveal plan
    let plan = CommitRevealPlan::new(&op, btc_network)?;
    println!("  commit address: {}", plan.commit_address);
    println!("  reveal vsize:   {} vbytes", plan.estimated_reveal_vsize());

    // 4. Connect to Bitcoin Core and broadcast
    let rpc = connect_rpc(rpc_url, rpc_user, rpc_pass)?;
    let broadcast = broadcast_commit_reveal(&rpc, &plan, fee_rate, None)?;

    println!();
    println!("Broadcast successful!");
    println!("  commit_txid:  {}", broadcast.commit_txid);
    println!("  reveal_txid:  {}", broadcast.reveal_txid);
    println!("  reveal_vsize: {} vbytes", broadcast.reveal_vsize);
    println!();
    println!("  note_index:   {}", result.note_index);
    println!("  commitment:   {}", fr_display(result.commitment));
    println!("  tree_root:    {}", fr_display(result.tree_root));
    println!();
    println!("Mine a block to confirm: bitcoin-cli -regtest generatetoaddress 1 <addr>");

    Ok(())
}

fn cmd_broadcast_transfer(
    path: &std::path::Path,
    to_str: &str,
    amount: u64,
    rune_id_str: &str,
    full_prove: bool,
    rpc_url: &str,
    rpc_user: &str,
    rpc_pass: &str,
    network: &NetworkArg,
    fee_rate: u64,
) -> anyhow::Result<()> {
    let recipient_pk = parse_fr(to_str)?;
    let rune_id = parse_fr(rune_id_str)?;
    let mut wallet = Wallet::load(path)?;
    let btc_network = network.to_bitcoin_network();

    if full_prove {
        println!("Generating full Groth16 proof (this takes ~60s)...");
    } else {
        println!("Verifying circuit satisfiability...");
    }

    // 1. Create the transfer (updates wallet state, generates proof)
    let result = wallet.transfer(recipient_pk, amount, 0, rune_id, full_prove)?;

    // 2. Build PruneOp
    //    For the proof bytes: use real proof if available, otherwise placeholder
    let proof_bytes = if let Some(ref proof_hex) = result.proof_hex {
        hex::decode(proof_hex)?
    } else {
        // Placeholder proof for circuit-check-only mode (not valid for verification)
        vec![0u8; 192]
    };

    // We need encrypted note for the output. Re-encrypt for the recipient.
    // The wallet already saved the note; we generate a minimal encrypted blob
    // for on-chain discovery. For transfers to others, the recipient needs to
    // decrypt this. We re-create it from the output note data.
    let encrypted_note = build_transfer_encrypted_note(&wallet, recipient_pk, rune_id, amount)?;

    let op = PruneOp::Transfer {
        rune_id,
        nullifier: result.nullifier,
        out_commitment: result.out_commitment,
        anchor: result.anchor,
        fee: result.circuit_fee,
        proof: proof_bytes,
        encrypted_note,
    };

    // 3. Create commit-reveal plan
    let plan = CommitRevealPlan::new(&op, btc_network)?;
    println!("  commit address: {}", plan.commit_address);
    println!("  reveal vsize:   {} vbytes", plan.estimated_reveal_vsize());

    // 4. Broadcast
    let rpc = connect_rpc(rpc_url, rpc_user, rpc_pass)?;
    let broadcast = broadcast_commit_reveal(&rpc, &plan, fee_rate, None)?;

    println!();
    println!("Broadcast successful!");
    println!("  commit_txid:   {}", broadcast.commit_txid);
    println!("  reveal_txid:   {}", broadcast.reveal_txid);
    println!("  reveal_vsize:  {} vbytes", broadcast.reveal_vsize);
    println!();
    println!("  nullifier:     {}", fr_display(result.nullifier));
    println!("  out_commitment:{}", fr_display(result.out_commitment));
    println!("  anchor:        {}", fr_display(result.anchor));
    println!("  circuit_fee:   {}", result.circuit_fee);
    if result.proof_hex.is_some() {
        println!("  proof:         included (Groth16)");
    } else {
        println!("  proof:         placeholder (use --prove for real proof)");
    }
    println!();
    println!("Mine a block to confirm: bitcoin-cli -regtest generatetoaddress 1 <addr>");

    Ok(())
}

/// Build a minimal encrypted note blob for the transfer output.
/// This encodes rune_id + amount so the recipient can discover it on-chain.
fn build_transfer_encrypted_note(
    _wallet: &Wallet,
    _recipient_pk: Fr,
    rune_id: Fr,
    amount: u64,
) -> anyhow::Result<Vec<u8>> {
    // In a full implementation, we would ECDH-encrypt a note for the recipient.
    // For the regtest demo, we encode rune_id (32 bytes) + amount (8 bytes)
    // as a simple cleartext blob. The on-chain indexer can parse this.
    // Sprint 7 will add proper per-recipient ECDH encryption.
    let mut blob = Vec::with_capacity(40);
    let mut rune_bytes = Vec::new();
    rune_id.serialize_compressed(&mut rune_bytes)?;
    blob.extend_from_slice(&rune_bytes);
    blob.extend_from_slice(&amount.to_le_bytes());
    // Pad to reasonable size for consistent witness weight estimates
    blob.resize(88, 0);
    Ok(blob)
}

fn cmd_broadcast_unshield(
    path: &std::path::Path,
    note_index: u64,
    full_prove: bool,
    rpc_url: &str,
    rpc_user: &str,
    rpc_pass: &str,
    network: &NetworkArg,
    fee_rate: u64,
) -> anyhow::Result<()> {
    let mut wallet = Wallet::load(path)?;
    let btc_network = network.to_bitcoin_network();

    if full_prove {
        println!("Generating full Groth16 proof (this takes ~60s)...");
    } else {
        println!("Verifying circuit satisfiability...");
    }

    // 1. Create the unshield (updates wallet state)
    let result = wallet.unshield(note_index, full_prove)?;

    // 2. Build PruneOp
    let proof_bytes = if let Some(ref proof_hex) = result.proof_hex {
        hex::decode(proof_hex)?
    } else {
        vec![0u8; 192]
    };

    // For unshield, we need to build a burn commitment. We use Fr(0) as a
    // sentinel since the wallet already computed the real one internally.
    // The on-chain verifier checks the proof against the public inputs.
    let burn_commitment = Fr::from(0u64);

    let op = PruneOp::Unshield {
        rune_id: result.rune_id,
        nullifier: result.nullifier,
        out_commitment: burn_commitment,
        anchor: result.anchor,
        amount: result.amount,
        proof: proof_bytes,
    };

    // 3. Create commit-reveal plan
    let plan = CommitRevealPlan::new(&op, btc_network)?;
    println!("  commit address: {}", plan.commit_address);
    println!("  reveal vsize:   {} vbytes", plan.estimated_reveal_vsize());

    // 4. Broadcast
    let rpc = connect_rpc(rpc_url, rpc_user, rpc_pass)?;
    let broadcast = broadcast_commit_reveal(&rpc, &plan, fee_rate, None)?;

    println!();
    println!("Broadcast successful!");
    println!("  commit_txid:   {}", broadcast.commit_txid);
    println!("  reveal_txid:   {}", broadcast.reveal_txid);
    println!("  reveal_vsize:  {} vbytes", broadcast.reveal_vsize);
    println!();
    println!("  rune_id:       {}", fr_display(result.rune_id));
    println!("  amount:        {}", result.amount);
    println!("  nullifier:     {}", fr_display(result.nullifier));
    println!("  anchor:        {}", fr_display(result.anchor));
    if result.proof_hex.is_some() {
        println!("  proof:         included (Groth16)");
    } else {
        println!("  proof:         placeholder (use --prove for real proof)");
    }
    println!();
    println!("{} units of rune credited to your public address.", result.amount);
    println!("Mine a block to confirm: bitcoin-cli -regtest generatetoaddress 1 <addr>");

    Ok(())
}

// ─── Sync command ────────────────────────────────────────────────────────────

/// On-disk format for indexed_data.json (Sprint 4 MVP).
#[derive(serde::Deserialize)]
struct IndexedData {
    /// All commitments: [{ "tree_index": 0, "commitment": "hex..." }, ...]
    commitments: Vec<IndexedCommitment>,
    /// Encrypted notes: [{ "tree_index": 0, "data": "hex..." }, ...]
    encrypted_notes: Vec<IndexedEncryptedNote>,
    /// On-chain nullifiers: ["hex32bytes", ...]
    #[serde(default)]
    nullifiers: Vec<String>,
}

#[derive(serde::Deserialize)]
struct IndexedCommitment {
    tree_index: u64,
    commitment: String,
}

#[derive(serde::Deserialize)]
struct IndexedEncryptedNote {
    tree_index: u64,
    data: String,
}

fn cmd_sync(path: &std::path::Path, data_file: Option<PathBuf>) -> anyhow::Result<()> {
    let data_path = data_file.unwrap_or_else(|| {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".prune")
            .join("indexed_data.json")
    });

    println!("Syncing wallet from {}…", data_path.display());

    let data_str = std::fs::read_to_string(&data_path).map_err(|_| {
        anyhow::anyhow!(
            "Indexed data not found at {}.\n\
             In Sprint 4 MVP, create this file manually or wait for the indexer integration.",
            data_path.display()
        )
    })?;

    let indexed: IndexedData = serde_json::from_str(&data_str)?;

    // Parse commitments
    let commitments: Vec<(u64, Fr)> = indexed
        .commitments
        .iter()
        .map(|c| Ok((c.tree_index, fr_from_hex(&c.commitment)?)))
        .collect::<anyhow::Result<Vec<_>>>()?;

    // Parse encrypted notes
    let encrypted_notes: Vec<(u64, Vec<u8>)> = indexed
        .encrypted_notes
        .iter()
        .map(|e| {
            let bytes = hex::decode(&e.data)?;
            Ok((e.tree_index, bytes))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    // Parse nullifiers (32-byte hex strings)
    let nullifiers: Vec<[u8; 32]> = indexed
        .nullifiers
        .iter()
        .map(|h| {
            let bytes = hex::decode(h)?;
            let arr: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("nullifier is not 32 bytes"))?;
            Ok(arr)
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    let mut wallet = Wallet::load(path)?;
    let result = wallet.sync_from_indexed_data(&commitments, &encrypted_notes, &nullifiers)?;

    println!("Sync complete.");
    println!();
    println!("  tree leaves        {}", wallet.tree.len());
    println!("  new notes found    {}", result.new_notes_found);
    println!("  notes marked spent {}", result.notes_marked_spent);
    println!("  total owned notes  {}", wallet.notes.len());
    println!(
        "  unspent notes      {}",
        wallet.notes.iter().filter(|n| !n.spent).count()
    );
    Ok(())
}
