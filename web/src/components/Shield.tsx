import { useState } from 'react';
import type { WalletKeys } from '../types';

interface Props {
  keys: WalletKeys | null;
  onShield?: (runeId: string, amount: number) => void;
}

export default function Shield({ keys, onShield }: Props) {
  const [runeId, setRuneId] = useState('');
  const [amount, setAmount] = useState('');
  const [status, setStatus] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleShield = async () => {
    if (!keys) {
      setStatus('Generate or load keys first.');
      return;
    }
    if (!runeId || !amount) {
      setStatus('Please fill in all fields.');
      return;
    }

    setLoading(true);
    setStatus(null);

    try {
      // In production, this calls the WASM module to:
      // 1. Create a commitment
      // 2. Encrypt the note
      // 3. Build a Taproot envelope
      // For now, simulate the process
      await new Promise((r) => setTimeout(r, 800));

      setStatus(
        `Shield request created for ${amount} of Rune ${runeId}. ` +
        `Sign the transaction in your UniSat wallet to broadcast.`
      );

      if (onShield) {
        onShield(runeId, Number(amount));
      }
    } catch (e: any) {
      setStatus(`Error: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="panel">
      <h2>Shield Runes</h2>
      <p className="panel-desc">
        Move Runes into the shielded pool. This creates a private note
        commitment and encrypts the note on-chain.
      </p>

      <div className="form-group">
        <label htmlFor="shield-rune-id">Rune ID</label>
        <input
          id="shield-rune-id"
          type="text"
          placeholder="e.g. 840000:1"
          value={runeId}
          onChange={(e) => setRuneId(e.target.value)}
        />
      </div>

      <div className="form-group">
        <label htmlFor="shield-amount">Amount</label>
        <input
          id="shield-amount"
          type="number"
          placeholder="e.g. 1000"
          min="1"
          value={amount}
          onChange={(e) => setAmount(e.target.value)}
        />
      </div>

      <button
        className="btn btn-primary"
        onClick={handleShield}
        disabled={loading || !keys}
      >
        {loading ? 'Creating proof...' : 'Shield'}
      </button>

      {status && <div className="status-msg">{status}</div>}
    </div>
  );
}
