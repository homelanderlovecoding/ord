import { useUnisat } from '../hooks/useUnisat';

interface Props {
  onConnect?: (address: string) => void;
}

export default function WalletConnect({ onConnect }: Props) {
  const { address, balance, connected, error, connect, disconnect } = useUnisat();

  const handleConnect = async () => {
    await connect();
    if (address && onConnect) {
      onConnect(address);
    }
  };

  if (connected && address) {
    return (
      <div className="wallet-bar">
        <div className="wallet-info">
          <span className="wallet-dot" />
          <span className="wallet-address" title={address}>
            {address.slice(0, 8)}...{address.slice(-6)}
          </span>
          <span className="wallet-balance">
            {(balance / 1e8).toFixed(8)} BTC
          </span>
        </div>
        <button className="btn btn-secondary" onClick={disconnect}>
          Disconnect
        </button>
      </div>
    );
  }

  return (
    <div className="wallet-bar">
      <button className="btn btn-primary" onClick={handleConnect}>
        Connect UniSat
      </button>
      {error && <span className="error-text">{error}</span>}
    </div>
  );
}
