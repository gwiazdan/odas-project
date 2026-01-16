'use client';

import React, { createContext, useContext, useState, ReactNode } from 'react';

interface KeyContext {
  decryptedPrivateKey: string | null;
  setDecryptedPrivateKey: (key: string | null) => void;
  clearKeys: () => void;
}

const CryptoContext = createContext<KeyContext | undefined>(undefined);

export function CryptoProvider({ children }: { children: ReactNode }) {
  const [decryptedPrivateKey, setDecryptedPrivateKey] = useState<string | null>(null);

  const clearKeys = () => {
    setDecryptedPrivateKey(null);
  };

  return (
    <CryptoContext.Provider value={{ decryptedPrivateKey, setDecryptedPrivateKey, clearKeys }}>
      {children}
    </CryptoContext.Provider>
  );
}

export function useCryptoContext() {
  const context = useContext(CryptoContext);
  if (!context) {
    throw new Error('useCryptoContext must be used within CryptoProvider');
  }
  return context;
}
