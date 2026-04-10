# pRune -- Shielded Runes on Bitcoin

pRune brings private transfers to [Runes](https://docs.ordinals.com/runes.html) on Bitcoin using zero-knowledge proofs. Users lock public Runes into a shielded pool, receive a private note, and can then transfer value without revealing sender, recipient, or amount on-chain. When they want public Runes back, they destroy the private note and withdraw. The ZK proof (Groth16 on BN254) guarantees conservation of value and prevents double-spending -- all without exposing private data.

## How It Works

```
                       Shielded Pool (Taproot witness data)
                      +------------------------------------+
                      |                                    |
   SHIELD             |     TRANSFER                       |     UNSHIELD
   ------             |     --------                       |     --------
   Public Runes  -->  |  Private Note  -->  Private Note   |  -->  Public Runes
   (lock into pool)   |  (ZK proof)        (new owner)     |  (withdraw from pool)
                      |                                    |
                      +------------------------------------+
```

**Shield** -- Lock Runes into the shielded pool. You get a private note (a Poseidon commitment stored on-chain in encrypted form).

**Transfer** -- Spend a private note and create a new one for the recipient. A Groth16 proof attests that you own the input note, the amounts balance, and the nullifier prevents replay. No one else learns who paid whom or how much.

**Unshield** -- Destroy a private note and credit the full amount back to a public Bitcoin address as regular Runes.

## Quick Start

### Prerequisites

- Rust 1.89+
- Bitcoin Core (`bitcoind`)
- clang (for WASM compilation)
- Node.js 18+ (for frontend)

### Build

```bash
cargo build -p prune
```

### Start Bitcoin regtest

```bash
bitcoind -regtest -txindex -rpcuser=ord -rpcpassword=ord -fallbackfee=0.00001
```

### Start ord with Rune indexing

```bash
cargo run --bin ord -- --regtest --index-runes server
```

> Note: an `--index-prune` flag exists, but pRune indexing currently runs automatically on all blocks.

### Create a wallet

```bash
cargo run -p prune --bin prune -- generate-keys
```

This creates `~/.prune/wallet.json` with your spending key, viewing key, nullifier key, and public key. **Back it up** -- the spending key cannot be recovered.

### Shield Runes

```bash
cargo run -p prune --bin prune -- shield --rune-id 0x01 --amount 1000
```

### Transfer privately

```bash
cargo run -p prune --bin prune -- transfer --to <recipient_pk> --amount 500 --rune-id 0x01
```

Add `--prove` to generate a full Groth16 proof (~60 seconds). Without it, the CLI only checks circuit satisfiability (fast).

### Broadcast on regtest

```bash
cargo run -p prune --bin prune -- broadcast-shield --rune-id 0x01 --amount 1000 \
  --rpc-url http://127.0.0.1:18443 --rpc-user ord --rpc-pass ord --network regtest
```

Then mine a block:

```bash
bitcoin-cli -regtest generatetoaddress 1 $(bitcoin-cli -regtest getnewaddress)
```

### List notes

```bash
cargo run -p prune --bin prune -- notes
```

### Sync wallet from indexed data

```bash
cargo run -p prune --bin prune -- sync
```

Reads commitments and encrypted notes from `~/.prune/indexed_data.json` and decrypts any notes belonging to your wallet.

## Frontend

The web app lives in `web/` and uses React + Vite with WASM for client-side proof generation.

```bash
# Build the WASM package first
cd crates/prune-wasm && wasm-pack build --target web

# Then start the dev server
cd web && npm install && npm run dev
```

Requirements:
- [UniSat wallet](https://unisat.io/) browser extension for signing transactions
- The WASM build above (proof generation runs entirely in the browser -- no server sees your private data)

## Architecture

| Layer | Details |
|-------|---------|
| **Crypto** | Groth16 on BN254, Poseidon hash (~80x fewer constraints than SHA256), ChaCha20-Poly1305 note encryption |
| **On-chain** | Taproot commit-reveal pattern -- data goes in witness for 4x weight discount vs OP_RETURN |
| **Indexer** | Hooks into ord's block scanner; parses pRune ops from Taproot witness |
| **Frontend** | React + Vite + WASM; proof generation is client-side via wasm-pack |
| **Custody** | N-of-M federation multisig holds the shielded pool (Bitcoin lacks smart contracts for trustless pools) |

Key source files:

```
crates/prune/src/
  poseidon.rs     -- Poseidon hash (ZK-friendly)
  keys.rs         -- Key derivation (sk -> vk, nk, pk)
  note.rs         -- Private note + commitment
  nullifier.rs    -- Double-spend prevention
  encryption.rs   -- ECDH + ChaCha20-Poly1305 note encryption
  tree.rs         -- Incremental Merkle tree (depth 32)
  circuit/        -- Groth16 R1CS circuits (arkworks)
  transaction.rs  -- PruneOp encoding for Taproot witness
  broadcast.rs    -- Commit-reveal transaction construction + RPC broadcast
  wallet.rs       -- Local wallet state (keys, notes, tree)
  indexer.rs      -- Indexer integration
  bin/prune.rs    -- CLI entry point
```

## CLI Commands

| Command | Description |
|---------|-------------|
| `generate-keys` | Create a new wallet with a random spending key |
| `info` | Show wallet public key, note count, and tree root |
| `notes` | List all notes (unspent and spent) |
| `shield` | Lock public Runes into the shielded pool, creating a private note |
| `transfer` | Spend a private note and send to a recipient (ZK proof) |
| `unshield` | Destroy a private note, converting back to public Runes |
| `sync` | Sync wallet from on-chain indexed data |
| `broadcast-shield` | Shield + broadcast commit-reveal tx via Bitcoin Core RPC |
| `broadcast-transfer` | Transfer + broadcast commit-reveal tx via Bitcoin Core RPC |
| `broadcast-unshield` | Unshield + broadcast commit-reveal tx via Bitcoin Core RPC |

All broadcast commands accept `--rpc-url`, `--rpc-user`, `--rpc-pass`, `--network` (regtest/signet/testnet), and `--fee-rate`.

## Testing

```bash
cargo test -p prune
```

75 tests total: 51 unit tests, 10 integration tests, 14 regtest tests.

## E2E Demo

A full end-to-end regtest demo (start bitcoind, create wallets, shield, transfer, unshield):

```bash
bash crates/prune/scripts/regtest_e2e.sh
```

## Known Limitations

Be aware of these before using pRune:

- **Trusted setup (Groth16)** -- The proving system requires a trusted setup ceremony. A multi-party ceremony is needed before any mainnet deployment. The architecture supports swapping to PLONK (no trusted setup) since both use arkworks.
- **Federation custody** -- The shielded pool is held by an N-of-M multisig federation, not a trustless smart contract (Bitcoin does not support that). This is a trust assumption.
- **Single-input single-output circuit** -- The current circuit handles one input note and one output note. Change outputs (splitting a note) are not yet implemented.
- **Custom Poseidon parameters** -- The Poseidon hash uses custom parameters that have not been independently audited.
- **Not audited** -- This code has not undergone a security audit. **Do not use with real funds.**

## License

CC0-1.0 (same as [ord](https://github.com/ordinals/ord))
