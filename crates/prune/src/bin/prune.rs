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
use clap::{Parser, Subcommand};
use prune::wallet::Wallet;

// ─── CLI definition ───────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(
    name = "prune",
    about = "pRune — shielded Rune CLI wallet (Sprint 3)",
    version = "0.1.0",
    long_about = "Offline wallet for private Rune transfers using Groth16 ZK proofs.\n\
                  All operations run locally. Sprint 4 adds live Bitcoin broadcasting."
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
