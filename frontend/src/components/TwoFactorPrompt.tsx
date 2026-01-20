'use client';

import { useState } from 'react';

interface TwoFactorPromptProps {
  pendingToken: string;
  onSuccess: (userData: any) => void;
  onCancel: () => void;
}

export default function TwoFactorPrompt({ pendingToken, onSuccess, onCancel }: TwoFactorPromptProps) {
  const [totpCode, setTotpCode] = useState('');
  const [backupCode, setBackupCode] = useState('');
  const [useBackupCode, setUseBackupCode] = useState(false);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  const handleVerify = async () => {
    setError('');

    const code = useBackupCode ? backupCode.trim() : totpCode.trim();
    if (!code) {
      setError('Please enter a code');
      return;
    }

    setLoading(true);
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL;
      const response = await fetch(`${apiUrl}/api/v1/auth/login/verify-2fa`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          pending_token: pendingToken,
          totp_code: useBackupCode ? null : code,
          backup_code: useBackupCode ? code : null,
        }),
      });

      if (!response.ok) {
        const data = await response.json();
        if (response.status === 429) {
          setError('Too many attempts. Please try again later.');
        } else {
          setError(data.detail || 'Invalid code');
        }
        return;
      }

      const data = await response.json();
      onSuccess(data);
    } catch (err) {
      console.error('2FA verification error:', err);
      setError('An error occurred. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleKeyPress = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && !loading) {
      handleVerify();
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Blurred backdrop */}
      <div
        className="absolute inset-0 bg-black/50 backdrop-blur-sm"
        onClick={onCancel}
      />

      {/* Modal */}
      <div className="relative bg-neutral-900 border border-gray-800 rounded-lg shadow-2xl w-full max-w-md mx-4">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-800">
          <h2 className="text-xl font-bold text-white">Two-Factor Authentication</h2>
          <button
            onClick={onCancel}
            className="flex text-gray-400 hover:text-white transition-colors w-7 h-7 rounded-full bg-neutral-800 items-center justify-center cursor-pointer"
          >
            <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>
        </div>

        {/* Content */}
        <div className="p-6 space-y-4">
          {error && (
            <div className="bg-red-900/20 border border-red-600 rounded-md p-3 text-red-300 text-sm">
              {error}
            </div>
          )}

          {!useBackupCode ? (
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Enter 6-digit code from your authenticator app
              </label>
              <input
                type="text"
                value={totpCode}
                onChange={(e) => setTotpCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                onKeyDown={handleKeyPress}
                placeholder="000000"
                maxLength={6}
                className="w-full px-4 py-3 bg-neutral-800 border border-gray-600 rounded-md text-white text-center text-2xl tracking-widest placeholder-gray-500 focus:outline-none focus:border-white focus:ring-1 focus:ring-white"
                disabled={loading}
                autoFocus
              />
            </div>
          ) : (
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-2">
                Enter backup code
              </label>
              <input
                type="text"
                value={backupCode}
                onChange={(e) => setBackupCode(e.target.value)}
                onKeyDown={handleKeyPress}
                placeholder="Backup code"
                className="w-full px-4 py-2 bg-neutral-800 border border-gray-600 rounded-md text-white placeholder-gray-500 focus:outline-none focus:border-white focus:ring-1 focus:ring-white"
                disabled={loading}
                autoFocus
              />
            </div>
          )}

          <button
            onClick={() => {
              setUseBackupCode(!useBackupCode);
              setTotpCode('');
              setBackupCode('');
              setError('');
            }}
            className="text-sm text-gray-300 hover:text-white transition-colors cursor-pointer tracking-wide font-semibold"
          >
            {useBackupCode ? 'Use authenticator app' : 'Use backup code instead'}
          </button>
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-gray-700 flex items-center justify-end space-x-3">
          <button
            onClick={onCancel}
            disabled={loading}
            className="px-4 py-2 bg-neutral-800 hover:bg-gray-700 text-gray-300 rounded-md transition-colors disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
          >
            Cancel
          </button>
          <button
            onClick={handleVerify}
            disabled={loading || (!totpCode && !backupCode)}
            className="px-6 py-2 bg-white hover:bg-gray-200 disabled:bg-gray-600 disabled:cursor-not-allowed text-black rounded-md transition-colors font-medium cursor-pointer"
          >
            {loading ? 'Verifying...' : 'Verify'}
          </button>
        </div>
      </div>
    </div>
  );
}
