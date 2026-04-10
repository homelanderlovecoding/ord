import { useState, useEffect, useCallback } from 'react';
import type { WalletKeys, ShieldResult, TransferResult, Note } from '../types';

let wasmModule: any = null;
let wasmLoading = false;

async function loadWasm(): Promise<any> {
  if (wasmModule) return wasmModule;
  if (wasmLoading) {
    // Wait for existing load
    while (wasmLoading) {
      await new Promise((r) => setTimeout(r, 100));
    }
    return wasmModule;
  }
  wasmLoading = true;
  try {
    // Dynamic import of the WASM package — served from /wasm/ in public dir
    // @ts-ignore - Module path resolved at runtime
    const wasm = await import(/* @vite-ignore */ '/wasm/prune_wasm.js');
    if (wasm.default && typeof wasm.default === 'function') {
      await wasm.default(); // Initialize WASM binary
    }
    wasmModule = wasm;
    return wasm;
  } catch (e) {
    console.warn('WASM module not available, using mock mode:', e);
    return null;
  } finally {
    wasmLoading = false;
  }
}

const STORAGE_KEY = 'prune_spending_key';
const NOTES_KEY = 'prune_notes';

export function usePrune() {
  const [ready, setReady] = useState(false);
  const [wasmAvailable, setWasmAvailable] = useState(false);
  const [keys, setKeys] = useState<WalletKeys | null>(null);
  const [notes, setNotes] = useState<Note[]>([]);
  const [loading, setLoading] = useState(false);

  // Load WASM + restore keys from localStorage
  useEffect(() => {
    (async () => {
      const wasm = await loadWasm();
      setWasmAvailable(!!wasm);

      // Restore keys from localStorage
      const savedSk = localStorage.getItem(STORAGE_KEY);
      if (savedSk && wasm) {
        try {
          const result = wasm.keys_from_spending_key(savedSk);
          setKeys(result);
        } catch (e) {
          console.error('Failed to restore keys:', e);
        }
      }

      // Restore notes
      const savedNotes = localStorage.getItem(NOTES_KEY);
      if (savedNotes) {
        try {
          setNotes(JSON.parse(savedNotes));
        } catch {}
      }

      setReady(true);
    })();
  }, []);

  // Persist notes to localStorage
  useEffect(() => {
    if (notes.length > 0) {
      localStorage.setItem(NOTES_KEY, JSON.stringify(notes));
    }
  }, [notes]);

  const generateKeys = useCallback(() => {
    if (!wasmModule) return null;
    const result = wasmModule.generate_keys();
    setKeys(result);
    localStorage.setItem(STORAGE_KEY, result.spending_key);
    return result;
  }, []);

  const loadKeys = useCallback((skHex: string) => {
    if (!wasmModule) return null;
    const result = wasmModule.keys_from_spending_key(skHex);
    setKeys(result);
    localStorage.setItem(STORAGE_KEY, skHex);
    return result;
  }, []);

  const shield = useCallback(
    async (runeIdHex: string, amount: number): Promise<ShieldResult | null> => {
      if (!wasmModule || !keys) return null;
      setLoading(true);
      try {
        const result = wasmModule.create_shield(
          keys.spending_key,
          runeIdHex,
          BigInt(amount)
        );

        // Track the new note locally
        const newNote: Note = {
          rune_id: runeIdHex,
          amount,
          blinding: '', // Not exposed to frontend
          owner_pk: keys.public_key,
          note_index: notes.length,
          commitment: result.commitment,
          nullifier: '',
          spent: false,
        };
        setNotes((prev) => [...prev, newNote]);

        return result;
      } catch (e: any) {
        console.error('Shield failed:', e);
        throw e;
      } finally {
        setLoading(false);
      }
    },
    [keys, notes]
  );

  const transfer = useCallback(
    async (
      recipientPkHex: string,
      amount: number,
      runeIdHex: string,
      noteIndex: number
    ): Promise<TransferResult | null> => {
      if (!wasmModule || !keys) return null;
      setLoading(true);
      try {
        const note = notes[noteIndex];
        if (!note || note.spent) throw new Error('Note not available');

        const result = wasmModule.create_transfer(
          keys.spending_key,
          runeIdHex,
          recipientPkHex,
          BigInt(amount),
          JSON.stringify(note),
          JSON.stringify({ leaves: notes.map((n) => n.commitment) })
        );

        // Mark input note spent, add output note if self-transfer
        setNotes((prev) =>
          prev.map((n, i) => (i === noteIndex ? { ...n, spent: true } : n))
        );

        return result;
      } catch (e: any) {
        console.error('Transfer failed:', e);
        throw e;
      } finally {
        setLoading(false);
      }
    },
    [keys, notes]
  );

  const clearWallet = useCallback(() => {
    localStorage.removeItem(STORAGE_KEY);
    localStorage.removeItem(NOTES_KEY);
    setKeys(null);
    setNotes([]);
  }, []);

  return {
    ready,
    wasmAvailable,
    keys,
    notes,
    loading,
    generateKeys,
    loadKeys,
    shield,
    transfer,
    clearWallet,
    setNotes,
  };
}
