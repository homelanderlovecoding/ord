import { useState } from 'react';
import type { WalletKeys, Note } from '../types';

interface Props {
  keys: WalletKeys | null;
  notes: Note[];
  onUnshield?: (amount: number, destAddress: string) => void;
}

export default function Unshield({ keys, notes, onUnshield }: Props) {
  const [amount, setAmount] = useState('');
  const [destAddress, setDestAddress] = useState('');
  const [status, setStatus] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const unspentNotes = notes.filter((n) => !n.spent);
  const totalBalance = unspentNotes.reduce((sum, n) => sum + n.amount, 0);

  const handleUnshield = async () => {
    if (!keys) {
      setStatus('Generate or load keys first.');
      return;
    }
    if (!amount || !destAddress) {
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
      // In production: nullify notes, generate proof, build reveal tx
      await new Promise((r) => setTimeout(r, 1200));

      setStatus(
        `Unshield of ${amount} Runes to ${destAddress.slice(0, 12)}... prepared. ` +
        `Sign the transaction in your UniSat wallet to broadcast.`
      );

      if (onUnshield) {
        onUnshield(Number(amount), destAddress);
      }
    } catch (e: any) {
      setStatus(`Error: ${e.message}`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="panel">
      <h2>Unshield Runes</h2>
      <p className="panel-desc">
        Move Runes out of the shielded pool back to a regular Bitcoin address.
      </p>

      {unspentNotes.length > 0 && (
        <div className="info-box">
          Shielded balance: <strong>{totalBalance}</strong> across{' '}
          {unspentNotes.length} note(s)
        </div>
      )}

      <div className="form-group">
        <label htmlFor="unshield-dest">Destination Address</label>
        <input
          id="unshield-dest"
          type="text"
          placeholder="bc1p..."
          value={destAddress}
          onChange={(e) => setDestAddress(e.target.value)}
          className="mono"
        />
      </div>

      <div className="form-group">
        <label htmlFor="unshield-amount">Amount</label>
        <input
          id="unshield-amount"
          type="number"
          placeholder="e.g. 500"
          min="1"
          value={amount}
          onChange={(e) => setAmount(e.target.value)}
        />
      </div>

      <button
        className="btn btn-primary"
        onClick={handleUnshield}
        disabled={loading || !keys}
      >
        {loading ? 'Generating proof...' : 'Unshield'}
      </button>

      {status && <div className="status-msg">{status}</div>}
    </div>
  );
}
