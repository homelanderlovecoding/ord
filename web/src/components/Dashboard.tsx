import { useState } from 'react';
import WalletConnect from './WalletConnect';
import Shield from './Shield';
import Transfer from './Transfer';
import Unshield from './Unshield';
import NoteList from './NoteList';
import { usePrune } from '../hooks/usePrune';

type Tab = 'shield' | 'transfer' | 'unshield' | 'notes';

export default function Dashboard() {
  const [activeTab, setActiveTab] = useState<Tab>('shield');
  const { keys, notes, generateKeys } = usePrune();
  const [keysVisible, setKeysVisible] = useState(false);

  const tabs: { id: Tab; label: string }[] = [
    { id: 'shield', label: 'Shield' },
    { id: 'transfer', label: 'Transfer' },
    { id: 'unshield', label: 'Unshield' },
    { id: 'notes', label: 'Notes' },
  ];

  return (
    <div className="dashboard">
      <header className="header">
        <h1>
          <span className="logo-accent">p</span>Rune
        </h1>
        <span className="header-sub">Shielded Runes</span>
      </header>

      <WalletConnect />

      <div className="keys-section">
        {!keys ? (
          <button className="btn btn-secondary" onClick={generateKeys}>
            Generate Shielded Keys
          </button>
        ) : (
          <div className="keys-info">
            <span className="keys-badge">Keys loaded</span>
            <button
              className="btn btn-small"
              onClick={() => setKeysVisible(!keysVisible)}
            >
              {keysVisible ? 'Hide' : 'Show'}
            </button>
            {keysVisible && (
              <div className="keys-detail">
                <div>
                  <strong>Public Key:</strong>{' '}
                  <code>{keys.public_key.slice(0, 20)}...</code>
                </div>
                <div>
                  <strong>Viewing Key:</strong>{' '}
                  <code>{keys.viewing_key.slice(0, 20)}...</code>
                </div>
              </div>
            )}
          </div>
        )}
      </div>

      <nav className="tab-nav">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            className={`tab-btn ${activeTab === tab.id ? 'tab-active' : ''}`}
            onClick={() => setActiveTab(tab.id)}
          >
            {tab.label}
          </button>
        ))}
      </nav>

      <main className="tab-content">
        {activeTab === 'shield' && <Shield keys={keys} />}
        {activeTab === 'transfer' && <Transfer keys={keys} notes={notes} />}
        {activeTab === 'unshield' && <Unshield keys={keys} notes={notes} />}
        {activeTab === 'notes' && <NoteList notes={notes} />}
      </main>
    </div>
  );
}
