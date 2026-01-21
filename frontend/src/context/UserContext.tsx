'use client';
import { createContext, useContext, useState, ReactNode, useEffect } from 'react';
import { useCryptoContext } from './CryptoContext';
import { useRouter } from 'next/navigation';
import { clear } from 'console';

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
  isLoading: boolean;
  setUser: (user: User | null) => void;
  logout: () => void;
  csrfToken: string | null;
}

const UserContext = createContext<UserContextType | undefined>(undefined);

function UserProviderContent({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [csrfToken, setCsrfToken] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const { clearKeys } = useCryptoContext();
  const router = useRouter();

  useEffect(() => {
    const initUser = async () => {
      try {
        // First check if user exists in localStorage
        const saved = localStorage.getItem('user');

        if (!saved) {
          // No user in localStorage, not logged in
          setIsLoading(false);
          return;
        }

        const parsedUser = JSON.parse(saved) as User;

        // Try to verify session with the server (uses HTTP-only cookie)
        try {
          const res = await fetch('/api/v1/auth/verify-session', {
            credentials: 'include',
          });

          if (res.ok) {
            // Session is valid, restore user
            setUser(parsedUser);
            setCsrfToken(parsedUser.csrf_token || null);
          } else {
            // Session is invalid or doesn't exist
            console.warn('Session verification failed with status:', res.status);
            localStorage.removeItem('user');
            setUser(null);
            setCsrfToken(null);
            await clearKeys();
          }
        } catch (err) {
          console.error('Session verification error:', err);
          // Network error - clear everything to be safe
          localStorage.removeItem('user');
          setUser(null);
          setCsrfToken(null);
          await clearKeys();
        }
      } catch (err) {
        console.error('Error in initUser:', err);
        localStorage.removeItem('user');
        setUser(null);
        setCsrfToken(null);
        await clearKeys();
      } finally {
        setIsLoading(false);
      }
    };
    initUser();
  }, [clearKeys]);

  const setUserWithToken = (newUser: User | null) => {
    setUser(newUser);
    setCsrfToken(newUser?.csrf_token || null);

    // Persist user to localStorage
    if (newUser) {
      localStorage.setItem('user', JSON.stringify(newUser));
    } else {
      localStorage.removeItem('user');
    }
  };

  const logout = async () => {
    localStorage.removeItem('user');
    setUser(null);
    setCsrfToken(null);
    await clearKeys();
  };

  return (
    <UserContext.Provider value={{ user, isLoading, setUser: setUserWithToken, logout, csrfToken }}>
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
