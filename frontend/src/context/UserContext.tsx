'use client';

import { createContext, useContext, useState, ReactNode } from 'react';
import { useCryptoContext } from './CryptoContext';

interface User {
  id: number;
  email: string;
  first_name: string;
  last_name: string;
  public_key: string;
  is_2fa_enabled?: boolean;
  csrf_token?: string;
}

export interface UserData extends User {
  encrypted_private_key: string;
  pbkdf2_salt: string;
}

interface UserContextType {
  user: User | null;
  setUser: (user: User | null) => void;
  logout: () => void;
  csrfToken: string | null;
}

const UserContext = createContext<UserContextType | undefined>(undefined);

function UserProviderContent({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [csrfToken, setCsrfToken] = useState<string | null>(null);
  const { clearKeys } = useCryptoContext();

  const setUserWithToken = (newUser: User | null) => {
    setUser(newUser);
    setCsrfToken(newUser?.csrf_token || null);
  };

  const logout = async () => {
    setUser(null);
    setCsrfToken(null);
    await clearKeys();
  };

  return (
    <UserContext.Provider value={{ user, setUser: setUserWithToken, logout, csrfToken }}>
      {children}
    </UserContext.Provider>
  );
}

export function UserProvider({ children }: { children: ReactNode }) {
  return <UserProviderContent>{children}</UserProviderContent>;
}

export function useUserContext() {
  const context = useContext(UserContext);
  if (context === undefined) {
    throw new Error('useUserContext must be used within UserProvider');
  }
  return context;
}
