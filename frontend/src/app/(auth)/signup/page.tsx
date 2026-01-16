'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { sanitizeInput, isValidEmail, isValidPassword, isValidName, passwordsMatch } from '@/lib/security';
import { PasswordStrengthIndicator } from '@/components/PasswordStrengthIndicator';
import { decryptPrivateKey } from '@/lib/crypto';
import { useCryptoContext } from '@/context/CryptoContext';

export default function SignupPage() {
  const router = useRouter();
  const { setDecryptedPrivateKey } = useCryptoContext();
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [error, setError] = useState('');
  const [validationErrors, setValidationErrors] = useState<Record<string, string>>({});
  const [loading, setLoading] = useState(false);

  const handleKeyPress = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && !loading) {
      handleSubmit(e as unknown as React.FormEvent);
    }
  };

  const validateForm = (): boolean => {
    const errors: Record<string, string> = {};

    // Validate names
    if (!firstName.trim()) {
      errors.firstName = 'First name is required';
    } else if (!isValidName(firstName.trim())) {
      errors.firstName = 'Invalid first name';
    }

    if (!lastName.trim()) {
      errors.lastName = 'Last name is required';
    } else if (!isValidName(lastName.trim())) {
      errors.lastName = 'Invalid last name';
    }

    // Validate email
    if (!email.trim()) {
      errors.email = 'Email is required';
    } else if (!isValidEmail(email.trim())) {
      errors.email = 'Invalid email format';
    }

    // Validate password strength
    if (!password) {
      errors.password = 'Password is required';
    } else {
      const { isPasswordValid } = isValidPassword(password);
      if (!isPasswordValid) {
        errors.password = 'Password is too weak';
      }
    }

    // Validate password match
    if (!passwordsMatch(password, confirmPassword)) {
      errors.confirmPassword = 'Passwords do not match';
    }

    setValidationErrors(errors);
    return Object.keys(errors).length === 0;
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
      // Sanitize inputs before sending
      const sanitizedData = {
        first_name: sanitizeInput(firstName.trim()),
        last_name: sanitizeInput(lastName.trim()),
        email: sanitizeInput(email.trim().toLowerCase()),
        password: password,
      };

      const response = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/v1/auth/signup`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        credentials: 'include',
        body: JSON.stringify(sanitizedData),
      });

      if (!response.ok) {
        const data = await response.json();
        setError(data.detail || 'Signup failed. Please try again.');
        return;
      }

      const data = await response.json();

      // Decrypt private key locally with password
      try {
        if (data.encrypted_private_key && data.pbkdf2_salt) {
          const decrypted = await decryptPrivateKey(
            data.encrypted_private_key,
            data.pbkdf2_salt,
            password,
          );
          setDecryptedPrivateKey(decrypted);
        }
      } catch (decryptErr) {
        console.warn('Failed to decrypt private key:', decryptErr);
      }

      // Redirect to login on success
      router.push('/login?registered=true');
    } catch {
      setError('An error occurred. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="w-full rounded-lg shadow border md:mt-0 sm:max-w-md xl:p-0 bg-neutral-900 border-gray-800">
      <div className="p-6 space-y-4 md:space-y-6 sm:p-8">
        <h1 className="text-xl font-bold leading-tight tracking-tight text-white md:text-2xl text-center">
          Create Account
        </h1>

        {error && (
          <div className="bg-red-900 border border-red-700 text-red-100 px-4 py-3 rounded">
            {error}
          </div>
        )}

        <form className="space-y-4 md:space-y-6" onSubmit={handleSubmit}>
          {/* First Name */}
          <div>
            <label htmlFor="firstName" className="block mb-2 text-sm font-medium text-white">
              First Name
            </label>
            <input
              type="text"
              name="firstName"
              id="firstName"
              value={firstName}
              onChange={(e) => setFirstName(e.target.value)}
              onKeyPress={handleKeyPress}
              className={`bg-neutral-800 border ${
                validationErrors.firstName ? 'border-red-500' : 'border-gray-800'
              } text-white rounded-lg focus:border-white block w-full p-2.5 placeholder-gray-400 outline-none transition`}
              placeholder="John"
              disabled={loading}
              required
            />
            {validationErrors.firstName && (
              <p className="text-red-400 text-xs mt-1">{validationErrors.firstName}</p>
            )}
          </div>

          {/* Last Name */}
          <div>
            <label htmlFor="lastName" className="block mb-2 text-sm font-medium text-white">
              Last Name
            </label>
            <input
              type="text"
              name="lastName"
              id="lastName"
              value={lastName}
              onChange={(e) => setLastName(e.target.value)}
              onKeyPress={handleKeyPress}
              className={`bg-neutral-800 border ${
                validationErrors.lastName ? 'border-red-500' : 'border-gray-800'
              } text-white rounded-lg focus:border-white block w-full p-2.5 placeholder-gray-400 outline-none transition`}
              placeholder="Doe"
              disabled={loading}
              required
            />
            {validationErrors.lastName && (
              <p className="text-red-400 text-xs mt-1">{validationErrors.lastName}</p>
            )}
          </div>

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
              onKeyPress={handleKeyPress}
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
              onKeyPress={handleKeyPress}
              className={`bg-neutral-800 border ${
                validationErrors.password ? 'border-red-500' : 'border-gray-800'
              } text-white rounded-lg focus:border-white block w-full p-2.5 placeholder-gray-400 outline-none transition`}
              placeholder="••••••••"
              disabled={loading}
              required
            />
            {password && <PasswordStrengthIndicator password={password} />}
            {validationErrors.password && (
              <p className="text-red-400 text-xs mt-1">{validationErrors.password}</p>
            )}
          </div>

          {/* Confirm Password */}
          <div>
            <label htmlFor="confirmPassword" className="block mb-2 text-sm font-medium text-white">
              Confirm Password
            </label>
            <input
              type="password"
              name="confirmPassword"
              id="confirmPassword"
              value={confirmPassword}
              onChange={(e) => setConfirmPassword(e.target.value)}
              onKeyPress={handleKeyPress}
              className={`bg-neutral-800 border ${
                validationErrors.confirmPassword ? 'border-red-500' : 'border-gray-800'
              } text-white rounded-lg focus:border-white block w-full p-2.5 placeholder-gray-400 outline-none transition`}
              placeholder="••••••••"
              disabled={loading}
              required
            />
            {validationErrors.confirmPassword && (
              <p className="text-red-400 text-xs mt-1">{validationErrors.confirmPassword}</p>
            )}
          </div>

          {/* Submit Button */}
          <button
            type="submit"
            disabled={loading}
            className="w-full text-black bg-white hover:bg-gray-200 disabled:bg-gray-400 focus:outline-none cursor-pointer font-medium rounded-lg text-sm px-5 py-2.5 text-center transition duration-200"
          >
            {loading ? 'Creating account...' : 'Sign Up'}
          </button>
        </form>

        <p className="text-sm font-light text-gray-400 text-center">
          Already have an account?{' '}
          <Link href="/login" className="font-medium text-white hover:underline">
            Login
          </Link>
        </p>
      </div>
    </div>
  );
}
