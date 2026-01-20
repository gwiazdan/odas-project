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
}

interface UserContextType {
  user: User | null;
  setUser: (user: User | null) => void;
  logout: () => void;
}

const UserContext = createContext<UserContextType | undefined>(undefined);

function UserProviderContent({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const { clearKeys } = useCryptoContext();

  const logout = async () => {
    setUser(null);
    await clearKeys();
  };

  return (
    <UserContext.Provider value={{ user, setUser, logout }}>
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
