'use client';

import { useState } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/navigation';
import { sanitizeInput, isValidEmail } from '@/lib/security';

export default function LoginPage() {
  const router = useRouter();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
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
      const response = await fetch('/api/v1/auth/login', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          email: sanitizedEmail,
          password: password,
        }),
      });

      if (!response.ok) {
        const data = await response.json();

        // Handle rate limiting
        if (response.status === 429) {
          setError('Too many login attempts. Please try again later.');
        } else {
          // Generic error message for security
          setError(data.detail || 'Login failed. Please try again.');
        }
        return;
      }

      const data = await response.json();

      // Store token securely
      if (data.access_token) {
        localStorage.setItem('access_token', data.access_token);
        localStorage.setItem('token_type', data.token_type);
      }

      // Redirect to inbox on success
      router.push('/inbox');
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
            {validationErrors.password && (
              <p className="text-red-400 text-xs mt-1">{validationErrors.password}</p>
            )}
          </div>

          {/* Submit Button */}
          <button
            type="submit"
            disabled={loading}
            className="w-full text-black bg-white hover:bg-gray-200 disabled:bg-gray-400 focus:outline-none font-medium rounded-lg text-sm px-5 py-2.5 text-center transition duration-200"
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
  );
}
