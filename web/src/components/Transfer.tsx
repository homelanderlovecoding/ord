import { useState } from 'react';
import type { WalletKeys, Note } from '../types';

interface Props {
  keys: WalletKeys | null;
  notes: Note[];
  onTransfer?: (recipientPk: string, amount: number) => void;
}

export default function Transfer({ keys, notes, onTransfer }: Props) {
  const [recipientPk, setRecipientPk] = useState('');
  const [amount, setAmount] = useState('');
  const [status, setStatus] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const unspentNotes = notes.filter((n) => !n.spent);
  const totalBalance = unspentNotes.reduce((sum, n) => sum + n.amount, 0);

  const handleTransfer = async () => {
    if (!keys) {
      setStatus('Generate or load keys first.');
      return;
    }
    if (!recipientPk || !amount) {
      setStatus('Please fill in all fields.');
      return;
    }
    if (Number(amount) > totalBalance) {
      setStatus(`Insufficient shielded balance. Available: ${totalBalance}`);
      return;
    }

    setLoading(true);
    setStatus(null);

    try {
      // In production, this calls the WASM module to:
      // 1. Select input notes
      // 2. Compute nullifiers
      // 3. Create output commitments
      // 4. Generate Groth16 proof
      // 5. Build Taproot envelope
      await new Promise((r) => setTimeout(r, 1500));

      setStatus(
        `Transfer of ${amount} prepared for recipient. ` +
        `Sign the transaction in your UniSat wallet to broadcast.`
      );

      if (onTransfer) {
        onTransfer(recipientPk, Number(amount));
      }
    } catch (e: any) {
      setStatus(`Error: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="panel">
      <h2>Private Transfer</h2>
      <p className="panel-desc">
        Transfer shielded Runes to another pRune address. The sender, recipient,
        and amount remain private on-chain.
      </p>

      {unspentNotes.length > 0 && (
        <div className="info-box">
          Shielded balance: <strong>{totalBalance}</strong> across{' '}
          {unspentNotes.length} note(s)
        </div>
      )}

      <div className="form-group">
        <label htmlFor="transfer-recipient">Recipient Public Key</label>
        <input
          id="transfer-recipient"
          type="text"
          placeholder="0x..."
          value={recipientPk}
          onChange={(e) => setRecipientPk(e.target.value)}
          className="mono"
        />
      </div>

      <div className="form-group">
        <label htmlFor="transfer-amount">Amount</label>
        <input
          id="transfer-amount"
          type="number"
          placeholder="e.g. 500"
          min="1"
          value={amount}
          onChange={(e) => setAmount(e.target.value)}
        />
      </div>

      <button
        className="btn btn-primary"
        onClick={handleTransfer}
        disabled={loading || !keys}
      >
        {loading ? 'Generating proof...' : 'Transfer'}
      </button>

      {status && <div className="status-msg">{status}</div>}
    </div>
  );
}
