#!/bin/bash
# ============================================================================
# pRune End-to-End Regtest Demo (Sprint 6)
# ============================================================================
#
# Prerequisites:
#   1. bitcoind running:
#      bitcoind -regtest -txindex -rpcuser=ord -rpcpassword=ord -fallbackfee=0.00001
#
#   2. A loaded wallet in Bitcoin Core:
#      bitcoin-cli -regtest -rpcuser=ord -rpcpassword=ord createwallet "default"
#
#   3. (Optional) ord server for indexing:
#      ord --regtest --bitcoin-rpc-username ord --bitcoin-rpc-password ord server --http-port 8080
#
# Usage:
#   chmod +x scripts/regtest_e2e.sh
#   ./scripts/regtest_e2e.sh
#
# ============================================================================

set -euo pipefail

# ── Configuration ──────────────────────────────────────────────────────────

PRUNE="cargo run -p prune --bin prune --"
RPC_ARGS="--rpc-url http://127.0.0.1:18443 --rpc-user ord --rpc-pass ord --network regtest"
BITCOIN_CLI="bitcoin-cli -regtest -rpcuser=ord -rpcpassword=ord"

WALLET_A="/tmp/prune_test_alice/wallet.json"
WALLET_B="/tmp/prune_test_bob/wallet.json"

RUNE_ID="0x01"

# ── Cleanup ────────────────────────────────────────────────────────────────

echo "=== pRune E2E Regtest Test (Sprint 6) ==="
echo ""
echo "Cleaning up previous test state..."
rm -rf /tmp/prune_test_alice /tmp/prune_test_bob
echo ""

# ── Step 1: Create wallets ────────────────────────────────────────────────

echo "--- Step 1: Creating wallets ---"
echo ""

echo "[Alice]"
$PRUNE --wallet $WALLET_A generate-keys
echo ""

echo "[Bob]"
$PRUNE --wallet $WALLET_B generate-keys
echo ""

# Extract Bob's public key for transfers
BOB_PK=$($PRUNE --wallet $WALLET_B info | grep 'public_key' | awk '{print $2}')
echo "Bob's public key: $BOB_PK"
echo ""

# ── Step 2: Fund the Bitcoin Core wallet ──────────────────────────────────

echo "--- Step 2: Mining initial blocks (need 101 for maturity) ---"
MINER_ADDR=$($BITCOIN_CLI getnewaddress)
$BITCOIN_CLI generatetoaddress 101 "$MINER_ADDR" > /dev/null
BALANCE=$($BITCOIN_CLI getbalance)
echo "Miner balance: $BALANCE BTC"
echo ""

# ── Step 3: Shield ────────────────────────────────────────────────────────

echo "--- Step 3: Shield 1000 units of rune $RUNE_ID (Alice) ---"
echo ""
$PRUNE --wallet $WALLET_A broadcast-shield \
    --rune-id $RUNE_ID --amount 1000 $RPC_ARGS
echo ""

# Confirm
echo "Mining 1 block to confirm..."
$BITCOIN_CLI generatetoaddress 1 "$MINER_ADDR" > /dev/null
echo ""

# ── Step 4: Check Alice's notes ──────────────────────────────────────────

echo "--- Step 4: Alice's notes after shield ---"
$PRUNE --wallet $WALLET_A notes
echo ""

# ── Step 5: Transfer 500 to Bob ──────────────────────────────────────────

echo "--- Step 5: Transfer 500 units to Bob ---"
echo ""
$PRUNE --wallet $WALLET_A broadcast-transfer \
    --to "$BOB_PK" --amount 500 --rune-id $RUNE_ID $RPC_ARGS
echo ""

# Confirm
echo "Mining 1 block to confirm..."
$BITCOIN_CLI generatetoaddress 1 "$MINER_ADDR" > /dev/null
echo ""

# ── Step 6: Check Alice's notes after transfer ───────────────────────────

echo "--- Step 6: Alice's notes after transfer ---"
$PRUNE --wallet $WALLET_A notes
echo ""

# ── Step 7: Unshield Alice's remaining balance ───────────────────────────
#
# After the transfer of 500, Alice's original 1000-unit note is spent.
# The circuit_fee = 1000 - 500 = 500 (the remainder exits the shielded pool).
# In this single-output model, Alice has no change note to unshield.
# We demonstrate unshield by first shielding again, then unshielding.

echo "--- Step 7: Shield another 200 units, then unshield ---"
echo ""
$PRUNE --wallet $WALLET_A broadcast-shield \
    --rune-id $RUNE_ID --amount 200 $RPC_ARGS
echo ""

echo "Mining 1 block to confirm..."
$BITCOIN_CLI generatetoaddress 1 "$MINER_ADDR" > /dev/null
echo ""

echo "Alice's notes:"
$PRUNE --wallet $WALLET_A notes
echo ""

# Find the unspent note index for unshield
# The second shield created a new note; use its index
UNSPENT_IDX=$($PRUNE --wallet $WALLET_A notes | grep 'unspent' | tail -1 | awk '{print $1}')
echo "Unshielding note at index: $UNSPENT_IDX"
echo ""

$PRUNE --wallet $WALLET_A broadcast-unshield \
    --note-index "$UNSPENT_IDX" $RPC_ARGS
echo ""

echo "Mining 1 block to confirm..."
$BITCOIN_CLI generatetoaddress 1 "$MINER_ADDR" > /dev/null
echo ""

# ── Step 8: Final state ──────────────────────────────────────────────────

echo "--- Step 8: Final wallet states ---"
echo ""
echo "[Alice]"
$PRUNE --wallet $WALLET_A info
echo ""
$PRUNE --wallet $WALLET_A notes
echo ""

echo "[Bob]"
$PRUNE --wallet $WALLET_B info
echo ""
echo "(Bob needs to sync from the indexer to see his incoming note.)"
echo "(In production: prune --wallet $WALLET_B sync --data-file <indexed_data.json>)"
echo ""

# ── Step 9: Transfer with full Groth16 proof ─────────────────────────────

echo "--- Step 9 (optional): Transfer with full Groth16 proof ---"
echo "To run with a real proof (takes ~60s):"
echo ""
echo "  $PRUNE --wallet $WALLET_A broadcast-shield --rune-id $RUNE_ID --amount 100 $RPC_ARGS"
echo "  $BITCOIN_CLI generatetoaddress 1 $MINER_ADDR"
echo "  $PRUNE --wallet $WALLET_A broadcast-transfer --to $BOB_PK --amount 50 --rune-id $RUNE_ID --prove $RPC_ARGS"
echo ""

echo "=== E2E Test Complete ==="
