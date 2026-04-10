export interface WalletKeys {
  spending_key: string;
  viewing_key: string;
  nullifier_key: string;
  public_key: string;
  x25519_public_key: string;
}

export interface ShieldResult {
  commitment: string;
  encrypted_note: string;
  envelope_hex: string;
}

export interface TransferResult {
  nullifier: string;
  out_commitment: string;
  encrypted_note: string;
  anchor: string;
  fee: number;
  envelope_hex: string;
}

export interface Note {
  rune_id: string;
  amount: number;
  blinding: string;
  owner_pk: string;
  note_index: number;
  commitment: string;
  nullifier: string;
  spent: boolean;
}

export interface UniSatAPI {
  requestAccounts(): Promise<string[]>;
  getAccounts(): Promise<string[]>;
  getBalance(): Promise<{ confirmed: number; unconfirmed: number; total: number }>;
  getNetwork(): Promise<string>;
  signPsbt(psbtHex: string): Promise<string>;
  pushTx(rawTxHex: string): Promise<string>;
}

declare global {
  interface Window {
    unisat?: UniSatAPI;
  }
}
