import { useState, useCallback } from 'react';
import '../types';

export function useUnisat() {
  const [address, setAddress] = useState<string | null>(null);
  const [balance, setBalance] = useState<number>(0);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const connect = useCallback(async () => {
    if (!window.unisat) {
      setError('UniSat wallet not found. Please install the extension.');
      return;
    }
    try {
      const accounts = await window.unisat.requestAccounts();
      if (accounts.length > 0) {
        setAddress(accounts[0]);
        setConnected(true);
        const bal = await window.unisat.getBalance();
        setBalance(bal.confirmed);
      }
    } catch (e: any) {
      setError(e.message || 'Failed to connect');
    }
  }, []);

  const disconnect = useCallback(() => {
    setAddress(null);
    setConnected(false);
    setBalance(0);
  }, []);

  return { address, balance, connected, error, connect, disconnect };
}
