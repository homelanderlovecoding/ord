# CLAUDE.md — pRune Development Guide

## Project Overview

This is a fork of [ordinals/ord](https://github.com/ordinals/ord) at tag 0.27.1, extended with the **pRune** (Shielded Runes) protocol — private transfers for Runes on Bitcoin.

## Repository Structure

```
ord/
├── crates/
│   ├── prune/              ← NEW: Shielded Rune protocol
│   │   ├── src/
│   │   │   ├── poseidon.rs    — Poseidon hash (ZK-friendly)
│   │   │   ├── keys.rs        — Key derivation (sk → vk, nk, pk)
│   │   │   ├── note.rs        — Private note + commitment
│   │   │   ├── nullifier.rs   — Double-spend prevention
│   │   │   ├── encryption.rs  — ECDH + ChaCha20 note encryption
│   │   │   ├── tree.rs        — Incremental Merkle tree (depth 32)
│   │   │   └── lib.rs         — Module declarations
│   │   └── Cargo.toml
│   ├── ordinals/           — Existing ord crate
│   └── ...                 — Other existing crates
├── Dockerfile.prune        — Docker build for testing prune crate
└── ...                     — Existing ord code (tag 0.27.1)
```

## Branch Strategy

- `prune-main` — main development branch (based on ord 0.27.1)

## Building & Testing

### With Docker (recommended)
```bash
docker build -f Dockerfile.prune -t prune-test .
docker run prune-test                           # run tests
docker run -it prune-test bash                  # interactive shell
```

### Without Docker
```bash
# Requires Rust 1.89+ and a C compiler (gcc/clang)
cargo test -p prune -- --nocapture
```

## Crypto Stack

| Component | Primitive | Crate |
|---|---|---|
| ZK proof system | Groth16 | ark-groth16 |
| Finite field | BN254 scalar field | ark-bn254 |
| Hash function | Poseidon | Custom (in poseidon.rs) |
| Commitments | Poseidon-based | Custom (in note.rs) |
| Nullifiers | Poseidon(nk, index, commitment) | Custom (in nullifier.rs) |
| Encryption | ECDH + ChaCha20-Poly1305 | chacha20poly1305 |
| Merkle tree | Incremental, Poseidon, depth 32 | Custom (in tree.rs) |

Architecture matches Penumbra / Zcash Sapling. Groth16 can be swapped to PLONK (~1-2 weeks) since both use arkworks.

## Sprint Plan

- Sprint 1: Crypto core (poseidon, keys, note, nullifier, encryption, tree) ✅
- Sprint 2: Groth16 circuit (arkworks) — Merkle inclusion, nullifier, conservation, range check ✅
- Sprint 3: CLI wallet (shield/transfer/unshield commands)
- Sprint 4: Indexer integration (hook into ord block scanner)
- Sprint 5: Web app — UniSat wallet connect + shield UI (replaces browser extension)
  - Stack: React + Vite, WASM for proof generation in-browser
  - UniSat API: window.unisat.requestAccounts(), getBalance(), signPsbt(), pushTx()
  - Flow: connect wallet → select Rune → enter amount → generate ZK proof (WASM) → build Taproot tx → sign via UniSat → broadcast
  - The prune crate compiles to WASM via wasm-pack; proof generation runs client-side (no server sees private data)
- Sprint 6: End-to-end on Bitcoin signet

## Git Config

```
user.name: homelander
user.email: heocon161106@gmail.com
```

## SSH Key

Deploy key path: `~/.ssh/id_ed25519` (ed25519, comment: claude@prune)

## Key Design Decisions

- **Groth16 over Halo2**: Smaller proofs (192 bytes vs 5KB). Trusted setup required but can swap to PLONK later cheaply.
- **Poseidon over SHA256**: ~80x fewer constraints in ZK circuits.
- **Federation pool for custody**: N-of-M multisig holds shielded Runes. Required because Bitcoin has no smart contracts for trustless pool. Bound can be the issuer for bUSD (no federation needed for Bound's own Rune).
- **Witness data (commit+reveal)**: Data goes in Taproot witness for 4x weight discount over OP_RETURN.
- **On-chain encrypted notes**: ~128 bytes per note, kept on-chain for full self-sovereignty (recover from Bitcoin data alone).
