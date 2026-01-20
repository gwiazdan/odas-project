'use client';

import { useState, useEffect } from 'react';
import QRCode from 'qrcode';
import { useUserContext } from '@/context/UserContext';

interface TwoFactorSetupProps {
  onClose: () => void;
  onSuccess?: () => void;
}

export default function TwoFactorSetup({ onClose, onSuccess }: TwoFactorSetupProps) {
  const { user } = useUserContext();
  const [step, setStep] = useState<'loading' | 'scan' | 'verify' | 'backup-codes' | 'disable-confirm'>('loading');
  const [tempSecret, setTempSecret] = useState('');
  const [otpauthUrl, setOtpauthUrl] = useState('');
  const [qrDataUrl, setQrDataUrl] = useState('');
  const [verifyCode, setVerifyCode] = useState('');
  const [disableCode, setDisableCode] = useState('');
  const [backupCodes, setBackupCodes] = useState<string[]>([]);
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    // Check if 2FA is already enabled
    if (user?.is_2fa_enabled) {
      setStep('disable-confirm');
    } else {
      initiate2FA();
    }
  }, [user?.is_2fa_enabled]);

  const initiate2FA = async () => {
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL;
      const response = await fetch(`${apiUrl}/api/v1/auth/2fa/initiate`, {
        method: 'POST',
        credentials: 'include',
      });

      if (!response.ok) {
        throw new Error('Failed to initiate 2FA');
      }

      const data = await response.json();
      setTempSecret(data.temp_secret);
      setOtpauthUrl(data.otpauth_url);

      // Generate QR code
      const qrData = await QRCode.toDataURL(data.otpauth_url, {
        width: 256,
        margin: 2,
      });
      setQrDataUrl(qrData);
      setStep('scan');
    } catch (err) {
      console.error('Failed to initiate 2FA:', err);
      setError('Failed to start 2FA setup. Please try again.');
      setStep('scan');
    }
  };

  const handleVerify = async () => {
    setError('');

    if (verifyCode.length !== 6) {
      setError('Please enter a 6-digit code');
      return;
    }

    setLoading(true);
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL;
      const response = await fetch(`${apiUrl}/api/v1/auth/2fa/activate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          temp_secret: tempSecret,
          totp_code: verifyCode,
        }),
      });

      if (!response.ok) {
        const data = await response.json();
        let errorMessage = 'Invalid code';
        if (data.detail) {
          if (typeof data.detail === 'string') {
            errorMessage = data.detail;
          } else if (Array.isArray(data.detail)) {
            errorMessage = data.detail.map((err: any) => err.msg || JSON.stringify(err)).join(', ');
          } else {
            errorMessage = JSON.stringify(data.detail);
          }
        }
        setError(errorMessage);
        return;
      }

      const data = await response.json();
      setBackupCodes(data.backup_codes);
      setStep('backup-codes');
    } catch (err) {
      console.error('Failed to verify code:', err);
      setError('An error occurred. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const handleFinish = () => {
    if (onSuccess) {
      onSuccess();
    }
    onClose();
  };

  const handleDisable = async () => {
    if (disableCode.length !== 6) {
      setError('Please enter a 6-digit code');
      return;
    }

    setLoading(true);
    setError('');
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL;
      const response = await fetch(`${apiUrl}/api/v1/auth/2fa/disable`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          totp_code: disableCode,
        }),
      });

      if (!response.ok) {
        const data = await response.json();
        let errorMessage = 'Failed to disable 2FA';
        if (data.detail) {
          if (typeof data.detail === 'string') {
            errorMessage = data.detail;
          } else if (Array.isArray(data.detail)) {
            errorMessage = data.detail.map((err: any) => err.msg || JSON.stringify(err)).join(', ');
          } else {
            errorMessage = JSON.stringify(data.detail);
          }
        }
        setError(errorMessage);
        return;
      }

      if (onSuccess) {
        onSuccess();
      }
      onClose();
    } catch (err) {
      console.error('Failed to disable 2FA:', err);
      setError('Failed to disable 2FA. Please try again.');
    } finally {
      setLoading(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const handleKeyPress = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter' && !loading && verifyCode.length === 6) {
      handleVerify();
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      {/* Blurred backdrop */}
      <div
        className="absolute inset-0 bg-black/50 backdrop-blur-sm"
        onClick={step === 'backup-codes' ? undefined : onClose}
      />

      {/* Modal */}
      <div className="relative bg-neutral-900 border border-gray-800 rounded-lg shadow-2xl w-full max-w-2xl mx-4 max-h-[90vh] overflow-y-auto">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-800 sticky top-0 bg-neutral-900 z-10">
          <h2 className="text-xl font-bold text-white">
            {step === 'disable-confirm' ? 'Disable Two-Factor Authentication' : 'Enable Two-Factor Authentication'}
          </h2>
          {step !== 'backup-codes' && (
            <button
              onClick={onClose}
              className="flex text-gray-400 hover:text-white transition-colors w-7 h-7 rounded-full bg-neutral-800 items-center justify-center cursor-pointer"
            >
              <svg className="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          )}
        </div>

        {/* Content */}
        <div className="p-6">
          {step === 'loading' && (
            <div className="flex items-center justify-center py-12">
              <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
            </div>
          )}

          {step === 'disable-confirm' && (
            <div className="space-y-6">
              <div className="bg-red-900/20 border border-red-700 rounded-lg p-4 flex gap-4">
                <svg className='w-6 h-6 text-red-700' viewBox="0 0 32 32" xmlns="http://www.w3.org/2000/svg" fill="none">
                  <path stroke="currentColor" strokeLinecap="round" strokeLinejoin="round" strokeWidth="2" d="M15.12 4.623a1 1 0 011.76 0l11.32 20.9A1 1 0 0127.321 27H4.679a1 1 0 01-.88-1.476l11.322-20.9zM16 18v-6"/>
                  <path fill="currentColor" d="M17.5 22.5a1.5 1.5 0 11-3 0 1.5 1.5 0 013 0z"/>
                </svg>
                <div>
                  <h3 className="text-red-200 font-semibold mb-1">Disable 2FA</h3>
                  <p className="text-red-200 text-sm">
                    Are you sure you want to disable two-factor authentication? Your account will be less secure.
                  </p>
                </div>
              </div>

              {error && (
                <div className="bg-red-900/20 border border-red-600 rounded-md p-3 text-red-300 text-sm">
                  {error}
                </div>
              )}

              <div className="text-center space-y-4">
                <p className="text-gray-300">
                  Enter the 6-digit code from your authenticator app to confirm
                </p>

                <input
                  type="text"
                  value={disableCode}
                  onChange={(e) => setDisableCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  placeholder="000000"
                  maxLength={6}
                  className="w-full max-w-xs mx-auto px-4 py-3 bg-neutral-800 border border-gray-600 rounded-md text-white text-center text-2xl tracking-widest placeholder-gray-500 focus:outline-none focus:border-white focus:ring-1 focus:ring-white"
                  disabled={loading}
                  autoFocus
                />
              </div>

              <div className="flex gap-3">
                <button
                  onClick={onClose}
                  className="flex-1 px-4 py-2 bg-neutral-700 hover:bg-neutral-800 text-white rounded-md transition-colors cursor-pointer"
                  disabled={loading}
                >
                  Cancel
                </button>
                <button
                  onClick={handleDisable}
                  className="flex-1 px-4 py-2 bg-red-700 hover:bg-red-700/50 text-white rounded-md transition-colors cursor-pointer disabled:opacity-50 disabled:cursor-not-allowed"
                  disabled={loading || disableCode.length !== 6}
                >
                  {loading ? 'Disabling...' : 'Disable 2FA'}
                </button>
              </div>

              {error && <p className="text-red-400 text-sm">{error}</p>}
            </div>
          )}

          {step === 'scan' && (
            <div className="space-y-6">
              {error && (
                <div className="bg-red-900/20 border border-red-600 rounded-md p-3 text-red-300 text-sm">
                  {error}
                </div>
              )}

              <div className="text-center space-y-4">
                <p className="text-gray-300">
                  Scan this QR code with your authenticator app (Google Authenticator, Authy, etc.)
                </p>

                {qrDataUrl && (
                  <div className="flex justify-center">
                    <img src={qrDataUrl} alt="QR Code" className="rounded-lg border-4 border-gray-700" />
                  </div>
                )}

                <div className="pt-4">
                  <p className="text-sm text-gray-400 mb-2">Or enter this key manually:</p>
                  <div className="flex items-center justify-center gap-2">
                    <code className="px-4 py-2 bg-neutral-800 border border-gray-600 rounded text-white font-mono text-sm">
                      {tempSecret}
                    </code>
                    <button
                      onClick={() => copyToClipboard(tempSecret)}
                      className="p-2 bg-neutral-800 hover:bg-gray-700 border border-gray-600 rounded transition-colors"
                      title="Copy to clipboard"
                    >
                      <svg className="w-4 h-4 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                      </svg>
                    </button>
                  </div>
                </div>
              </div>

              <button
                onClick={() => setStep('verify')}
                className="w-full px-6 py-3 bg-white hover:bg-gray-200 text-black rounded-md transition-colors font-medium cursor-pointer"
              >
                Continue to Verification
              </button>
            </div>
          )}

          {step === 'verify' && (
            <div className="space-y-6">
              {error && (
                <div className="bg-red-900/20 border border-red-600 rounded-md p-3 text-red-300 text-sm">
                  {error}
                </div>
              )}

              <div className="text-center space-y-4">
                <p className="text-gray-300">
                  Enter the 6-digit code from your authenticator app to verify the setup
                </p>

                <input
                  type="text"
                  value={verifyCode}
                  onChange={(e) => setVerifyCode(e.target.value.replace(/\D/g, '').slice(0, 6))}
                  onKeyDown={handleKeyPress}
                  placeholder="000000"
                  maxLength={6}
                  className="w-full max-w-xs mx-auto px-4 py-3 bg-neutral-800 border border-gray-600 rounded-md text-white text-center text-2xl tracking-widest placeholder-gray-500 focus:outline-none focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                  disabled={loading}
                  autoFocus
                />
              </div>

              <div className="flex gap-3">
                <button
                  onClick={() => {
                    setStep('scan');
                    setVerifyCode('');
                    setError('');
                  }}
                  disabled={loading}
                  className="flex-1 px-4 py-2 bg-neutral-800 hover:bg-gray-700 text-gray-300 rounded-md transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  Back
                </button>
                <button
                  onClick={handleVerify}
                  disabled={loading || verifyCode.length !== 6}
                  className="flex-1 px-6 py-2 bg-white hover:bg-gray-200 disabled:bg-gray-600 disabled:cursor-not-allowed text-black rounded-md transition-colors font-medium cursor-pointer"
                >
                  {loading ? 'Verifying...' : 'Verify & Enable'}
                </button>
              </div>
            </div>
          )}

          {step === 'backup-codes' && (
            <div className="space-y-6">
              <div className="bg-yellow-900/20 border border-yellow-600 rounded-md p-4">
                <div className="flex items-start gap-3">
                  <svg className="w-6 h-6 text-yellow-500 flex-shrink-0 mt-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
                  </svg>
                  <div>
                    <h3 className="text-yellow-200 font-semibold mb-1">Save Your Backup Codes</h3>
                    <p className="text-yellow-200 text-sm">
                      Store these codes in a safe place. Each code can be used once if you lose access to your authenticator app.
                    </p>
                  </div>
                </div>
              </div>

              <div className="bg-neutral-800 border border-gray-600 rounded-lg p-4">
                <div className="grid grid-cols-2 gap-3">
                  {backupCodes.map((code, index) => (
                    <div
                      key={index}
                      className="flex items-center justify-between p-3 bg-gray-700 rounded border border-gray-600"
                    >
                      <code className="text-white font-mono text-sm">{code}</code>
                      <button
                        onClick={() => copyToClipboard(code)}
                        className="ml-2 p-1 hover:bg-gray-600 rounded transition-colors"
                        title="Copy"
                      >
                        <svg className="w-4 h-4 text-gray-300" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                        </svg>
                      </button>
                    </div>
                  ))}
                </div>

                <button
                  onClick={() => copyToClipboard(backupCodes.join('\n'))}
                  className="mt-4 w-full px-4 py-2 bg-neutral-700 hover:bg-gray-600 text-gray-300 rounded-md transition-colors text-sm"
                >
                  Copy All Codes
                </button>
              </div>

              <button
                onClick={handleFinish}
                className="w-full px-6 py-3 bg-white hover:bg-gray-200 text-black rounded-md transition-colors font-medium cursor-pointer"
              >
                Done
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
