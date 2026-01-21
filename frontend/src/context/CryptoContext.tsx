'use client';

import { createContext, useContext, useState, useEffect, ReactNode } from 'react';
import { validatePrivateKey } from '@/lib/crypto';

interface KeyContext {
  decryptedPrivateKey: string | null;
  privateKeyPEM: string | null;
  setDecryptedPrivateKey: (key: string | null) => void;
  clearKeys: () => void;
  isLoading: boolean;
}

const CryptoContext = createContext<KeyContext | undefined>(undefined);

const DB_NAME = 'SafeMessageCrypto';
const DB_VERSION = 1;
const STORE_NAME = 'keys';
const PRIVATE_KEY_ID = 'privateKey';

// IndexedDB helpers
const openDB = (): Promise<IDBDatabase> => {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, DB_VERSION);

    request.onerror = () => reject(request.error);
    request.onsuccess = () => resolve(request.result);

    request.onupgradeneeded = (event) => {
      const db = (event.target as IDBOpenDBRequest).result;
      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
    };
  });
};

const savePrivateKeyToDB = async (key: string): Promise<void> => {
  const db = await openDB();
  return new Promise((resolve, reject) => {
    const transaction = db.transaction(STORE_NAME, 'readwrite');
    const store = transaction.objectStore(STORE_NAME);
    const request = store.put(key, PRIVATE_KEY_ID);

    request.onsuccess = () => resolve();
    request.onerror = () => reject(request.error);
  });
};

const loadPrivateKeyFromDB = async (): Promise<string | null> => {
  try {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const transaction = db.transaction(STORE_NAME, 'readonly');
      const store = transaction.objectStore(STORE_NAME);
      const request = store.get(PRIVATE_KEY_ID);

      request.onsuccess = () => resolve(request.result || null);
      request.onerror = () => reject(request.error);
    });
  } catch {
    return null;
  }
};

const clearPrivateKeyFromDB = async (): Promise<void> => {
  try {
    const db = await openDB();
    return new Promise((resolve, reject) => {
      const transaction = db.transaction(STORE_NAME, 'readwrite');
      const store = transaction.objectStore(STORE_NAME);
      const request = store.delete(PRIVATE_KEY_ID);

      request.onsuccess = () => resolve();
      request.onerror = () => reject(request.error);
    });
  } catch {
    // Silent error - It is better not to inform user
  }
};

export function CryptoProvider({ children }: { children: ReactNode }) {
  const [decryptedPrivateKey, setDecryptedPrivateKeyState] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Load private key from IndexedDB on mount
  useEffect(() => {
    const loadKey = async () => {
      const key = await loadPrivateKeyFromDB();
      if (key) {
        // Validate the key before setting it
        const isValid = await validatePrivateKey(key);
        if (isValid) {
          setDecryptedPrivateKeyState(key);
        } else {
          await clearPrivateKeyFromDB();
        }
      }
      setIsLoading(false);
    };

    loadKey();
  }, []);

  const setDecryptedPrivateKey = async (key: string | null) => {
    if (key) {
      try {
        // Validate key before saving
        const isValid = await validatePrivateKey(key);
        if (!isValid) {
          throw new Error('Invalid private key - failed validation');
        }

        await savePrivateKeyToDB(key);
        // Set state AFTER successful DB save to ensure it's persisted
        setDecryptedPrivateKeyState(key);
      } catch (error) {
        throw error; // Propagate error so login can handle it
      }
    } else {
      await clearPrivateKeyFromDB();
      setDecryptedPrivateKeyState(null);
    }
  };

  const clearKeys = async () => {
    setDecryptedPrivateKeyState(null);
    await clearPrivateKeyFromDB();
  };

  return (
    <CryptoContext.Provider value={{
      decryptedPrivateKey,
      privateKeyPEM: decryptedPrivateKey,
      setDecryptedPrivateKey,
      clearKeys,
      isLoading
    }}>
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
