'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { sanitizeInput, isValidEmail } from '@/lib/security';
import { decryptPrivateKey, validatePrivateKey } from '@/lib/crypto';
import { useCryptoContext } from '@/context/CryptoContext';
import { useUserContext } from '@/context/UserContext';
import TwoFactorPrompt from '@/components/TwoFactorPrompt';

export default function LoginPage() {
  const router = useRouter();
  const { setDecryptedPrivateKey } = useCryptoContext();
  const { setUser } = useUserContext();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [validationErrors, setValidationErrors] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(false);
  const [pendingToken, setPendingToken] = useState<string | null>(null);
  const [savedPassword, setSavedPassword] = useState<string>('');

  const handleKeyPress = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && !loading) {
      handleSubmit(e as unknown as React.FormEvent);
    }
  };

  const validateForm = (): boolean => {
    const errors: Record<string, string> = {};

    if (!email.trim()) {
      errors.email = 'Email is required';
    } else if (!isValidEmail(email.trim())) {
      errors.email = 'Invalid email format';
    }

    if (!password) {
      errors.password = 'Password is required';
    }

    setValidationErrors(errors);
    return Object.keys(errors).length === 0;
  };

  const handleTwoFactorSuccess = async (userData: any) => {
    try {
      setUser({
        id: userData.id,
        email: userData.email,
        first_name: userData.first_name,
        last_name: userData.last_name,
        public_key: userData.public_key,
        is_2fa_enabled: userData.is_2fa_enabled,
      });

      if (!userData.encrypted_private_key || !userData.pbkdf2_salt) {
        throw new Error('Encrypted private key not available from server');
      }

      const decrypted = await decryptPrivateKey(
        userData.encrypted_private_key,
        userData.pbkdf2_salt,
        savedPassword,
      );

      if (!decrypted) {
        throw new Error('Failed to decrypt private key');
      }

      const isValid = await validatePrivateKey(decrypted);
      if (!isValid) {
        throw new Error('Decrypted private key is invalid or corrupted');
      }

      await setDecryptedPrivateKey(decrypted);
      await new Promise(resolve => setTimeout(resolve, 100));

      router.push('/inbox');
    } catch (decryptErr) {
      console.error('Private key decryption failed:', decryptErr);
      setError('Failed to decrypt private key. Wrong password or corrupted data.');
      setPendingToken(null);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setError('');
    setValidationErrors({});

    if (!validateForm()) {
      return;
    }

    setLoading(true);

    try {
      const sanitizedEmail = sanitizeInput(email.trim().toLowerCase());
      const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/v1/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify({
          email: sanitizedEmail,
          password: password,
        }),
      });

      if (!response.ok) {
        const data = await response.json();

        if (response.status === 429) {
          setError('Too many login attempts. Please try again later.');
        } else {
          setError(data.detail || 'Login failed. Please try again.');
        }
        return;
      }

      const data = await response.json();

      // Check if 2FA is required
      if (data.requires_2fa && data.pending_token) {
        setSavedPassword(password);
        setPendingToken(data.pending_token);
        return;
      }

      // No 2FA - proceed with normal login
      const userData = data.user;
      setUser({
        id: userData.id,
        email: userData.email,
        first_name: userData.first_name,
        last_name: userData.last_name,
        public_key: userData.public_key,
        is_2fa_enabled: userData.is_2fa_enabled,
      });

      try {
        if (!userData.encrypted_private_key || !userData.pbkdf2_salt) {
          throw new Error('Encrypted private key not available from server');
        }

        const decrypted = await decryptPrivateKey(
          userData.encrypted_private_key,
          userData.pbkdf2_salt,
          password,
        );

        if (!decrypted) {
          throw new Error('Failed to decrypt private key');
        }

        // Validate the decrypted private key
        const isValid = await validatePrivateKey(decrypted);
        if (!isValid) {
          throw new Error('Decrypted private key is invalid or corrupted');
        }

        await setDecryptedPrivateKey(decrypted);

        await new Promise(resolve => setTimeout(resolve, 100));
      } catch (decryptErr) {
        console.error('Private key decryption failed:', decryptErr);
        setError('Failed to decrypt private key. Wrong password or corrupted data.');
        setLoading(false);
        return;
      }

      router.push('/inbox');
    } catch (err) {
      setError('An error occurred. Please try again.');
      console.error('Login error:', err);
    } finally {
      setLoading(false);
    }
  };

  return (
    <>
      <div className="w-full rounded-lg shadow border md:mt-0 sm:max-w-md xl:p-0 bg-neutral-900 border-gray-800">
        <div className="p-6 space-y-4 md:space-y-6 sm:p-8">
          <h1 className="text-xl font-bold leading-tight tracking-tight text-white md:text-2xl text-center">
            Login to your account
          </h1>

          {error && (
            <div className="bg-red-900 border border-red-700 text-red-100 px-4 py-3 rounded">
              {error}
            </div>
          )}

          <form className="space-y-4 md:space-y-6" onSubmit={handleSubmit}>
            {/* Email */}
            <div>
              <label htmlFor="email" className="block mb-2 text-sm font-medium text-white">
                Email
              </label>
              <input
                type="email"
                name="email"
                id="email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
                onKeyDown={handleKeyPress}
                className={`bg-neutral-800 border ${
                  validationErrors.email ? 'border-red-500' : 'border-gray-800'
                } text-white rounded-lg focus:border-white block w-full p-2.5 placeholder-gray-400 outline-none transition`}
                placeholder="your@email.com"
                disabled={loading}
                required
              />
              {validationErrors.email && (
                <p className="text-red-400 text-xs mt-1">{validationErrors.email}</p>
              )}
            </div>

            {/* Password */}
            <div>
              <label htmlFor="password" className="block mb-2 text-sm font-medium text-white">
                Password
              </label>
              <input
                type="password"
                name="password"
                id="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                onKeyDown={handleKeyPress}
                className={`bg-neutral-800 border ${
                  validationErrors.password ? 'border-red-500' : 'border-gray-800'
                } text-white rounded-lg focus:border-white block w-full p-2.5 placeholder-gray-400 outline-none transition`}
                placeholder="••••••••"
                disabled={loading}
                required
              />
              {validationErrors.password && (
                <p className="text-red-400 text-xs mt-1">{validationErrors.password}</p>
              )}
            </div>

            {/* Submit Button */}
            <button
              type="submit"
              disabled={loading}
              className="w-full text-black bg-white hover:bg-gray-200 disabled:bg-gray-400 focus:outline-none font-medium rounded-lg text-sm px-5 py-2.5 text-center transition duration-200 cursor-pointer"
            >
              {loading ? 'Signing in...' : 'Sign in'}
            </button>
          </form>

          <p className="text-sm font-light text-gray-400 text-center">
            Don&apos;t have an account?{' '}
            <Link href="/signup" className="font-medium text-white hover:underline">
              Sign up
            </Link>
          </p>
        </div>
      </div>

      {/* 2FA Modal */}
      {pendingToken && (
        <TwoFactorPrompt
          pendingToken={pendingToken}
          onSuccess={handleTwoFactorSuccess}
          onCancel={() => {
            setPendingToken(null);
            setSavedPassword('');
            setLoading(false);
          }}
        />
      )}
    </>
  );
}
