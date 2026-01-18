'use client';

import { useCallback, useEffect, useState } from 'react';
import { useCryptoContext } from '@/context/CryptoContext';
import { decryptMessage, verifySignature } from '@/lib/crypto';

interface MessageAttachment {
  name: string;
  size: number;
  type: string;
  data: string;
}

interface MessagePayload {
  subject: string;
  content: string;
  attachments: MessageAttachment[];
}

interface MessageData {
  id: number;
  sender_id: number;
  sender: {
    id: number;
    email: string;
    first_name: string;
    last_name: string;
    public_key: string;
  };
  recipient_id: number;
  payload: string;
  signature: string;
  is_read: boolean;
  created_at: string;
  read_at: string | null;
}

interface MessageViewerProps {
  messageId: number;
  onClose: () => void;
}

export default function MessageViewer({ messageId, onClose }: MessageViewerProps) {
  const { privateKeyPEM } = useCryptoContext();
  const [message, setMessage] = useState<MessageData | null>(null);
  const [decryptedPayload, setDecryptedPayload] = useState<MessagePayload | null>(null);
  const [signatureValid, setSignatureValid] = useState<boolean>(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchMessage = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);
      const response = await fetch(
        `http://localhost:8000/api/v1/messages/${messageId}`,
        {
          credentials: 'include',
        }
      );

      if (response.ok) {
        const data = await response.json();
        setMessage(data);
        if (privateKeyPEM && data.payload) {
          try {
            const decryptedStr = await decryptMessage(
              typeof data.payload === 'string' ? data.payload : JSON.stringify(data.payload),
              privateKeyPEM
            );
            const decrypted = JSON.parse(decryptedStr);
            setDecryptedPayload(decrypted);

            const isValid = await verifySignature(
              decryptedStr,
              data.signature,
              data.sender.public_key
            );
            setSignatureValid(isValid);
          } catch (decryptErr) {
            console.error('Failed to decrypt message:', decryptErr);
            setError('Failed to decrypt message. Private key may be invalid.');
          }
        }
      } else {
        setError('Failed to load message');
      }
    } catch (err) {
      setError('Failed to load message');
      console.error('Failed to fetch message:', err);
    } finally {
      setLoading(false);
    }
  }, [messageId, privateKeyPEM]);

  useEffect(() => {
    fetchMessage();
  }, [messageId, fetchMessage]);

  const downloadAttachment = (attachment: MessageAttachment) => {
    try {
      const dataClean = (attachment.data || '').replace(/\s/g, '');
      const byteCharacters = atob(dataClean);
      const byteNumbers = new Array(byteCharacters.length);
      for (let i = 0; i < byteCharacters.length; i++) {
        byteNumbers[i] = byteCharacters.charCodeAt(i);
      }
      const byteArray = new Uint8Array(byteNumbers);
      const blob = new Blob([byteArray], { type: attachment.type });

      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = attachment.name;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      console.error('Failed to download attachment:', err);
    }
  };

  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    return date.toLocaleString('en-US', {
      year: 'numeric',
      month: 'long',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    });
  };

  return (
    <div
      className="fixed inset-0 bg-black/40 backdrop-blur-md flex items-center justify-center z-50 p-4"
      onClick={onClose}
    >
      <div
        className="bg-neutral-900 rounded-lg shadow-2xl max-w-4xl w-full max-h-[90vh] overflow-hidden border border-gray-800"
        onClick={(e) => e.stopPropagation()}
      >
        {loading ? (
          <div className="p-6 flex items-center justify-center">
            <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500"></div>
          </div>
        ) : error ? (
          <div className="p-6">
            <div className="flex justify-between items-start mb-4">
              <h2 className="text-2xl font-bold text-white">Error</h2>
              <button
                onClick={onClose}
                className="text-gray-400 hover:text-white transition-colors"
              >
                <svg
                  className="w-6 h-6"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M6 18L18 6M6 6l12 12"
                  />
                </svg>
              </button>
            </div>
          </div>
        ) : message ? (
          <div className="flex flex-col h-full max-h-[90vh]">
            {/* Header */}
            <div className="flex justify-between items-start p-6 border-b border-gray-700">
              <div className="flex-1">
                <div className="flex items-center gap-2 mb-2">
                  <h2 className="text-2xl font-bold text-white">
                    {decryptedPayload?.subject || '(No subject)'}
                  </h2>
                  {signatureValid ? (
                    <div className="flex items-center text-green-500" title="Signature verified">
                      <svg
                        className="w-5 h-5"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
                        />
                      </svg>
                      <span className="ml-1 text-sm">Verified</span>
                    </div>
                  ) : (
                    <div className="flex items-center text-red-500" title="Signature invalid">
                      <svg
                        className="w-5 h-5"
                        fill="none"
                        stroke="currentColor"
                        viewBox="0 0 24 24"
                      >
                        <path
                          strokeLinecap="round"
                          strokeLinejoin="round"
                          strokeWidth={2}
                          d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
                        />
                      </svg>
                      <span className="ml-1 text-sm">Invalid</span>
                    </div>
                  )}
                </div>
                <div className="text-gray-400 text-sm space-y-1">
                  <div>
                    <span className="font-medium">From:</span>{' '}
                    {message.sender.first_name} {message.sender.last_name} (
                    {message.sender.email})
                  </div>
                  <div>
                    <span className="font-medium">Date:</span>{' '}
                    {formatDate(message.created_at)}
                  </div>
                  {message.read_at && (
                    <div>
                      <span className="font-medium">Read:</span>{' '}
                      {formatDate(message.read_at)}
                    </div>
                  )}
                </div>
              </div>
              <button
                onClick={onClose}
                className="rounded-full w-7 h-7 flex justify-center items-center bg-neutral-800 text-gray-400 hover:text-white transition-colors ml-4 cursor-pointer"
              >
                <svg
                  className="w-6 h-6"
                  fill="none"
                  stroke="currentColor"
                  viewBox="0 0 24 24"
                >
                  <path
                    strokeLinecap="round"
                    strokeLinejoin="round"
                    strokeWidth={2}
                    d="M6 18L18 6M6 6l12 12"
                  />
                </svg>
              </button>
            </div>

            {/* Content */}
            <div className="flex-1 overflow-y-auto p-6">
              <div className="prose prose-invert max-w-none">
                <div className="text-gray-300 whitespace-pre-wrap">
                  {decryptedPayload?.content || 'Unable to decrypt message'}
                </div>
              </div>
            </div>

            {/* Attachments */}
            {decryptedPayload?.attachments && decryptedPayload.attachments.length > 0 && (
              <div className="border-t border-gray-700 p-6">
                <h3 className="text-lg font-semibold text-white mb-4">
                  Attachments ({decryptedPayload.attachments.length})
                </h3>
                <div className="space-y-2">
                  {decryptedPayload.attachments.map((attachment: MessageAttachment, index: number) => (
                    <div
                      key={index}
                      className="flex items-center justify-between p-3 bg-gray-700 rounded-lg hover:bg-gray-600 transition-colors"
                    >
                      <div className="flex items-center space-x-3">
                        <svg
                          className="w-5 h-5 text-blue-400"
                          fill="none"
                          stroke="currentColor"
                          viewBox="0 0 24 24"
                        >
                          <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            strokeWidth={2}
                            d="M15.172 7l-6.586 6.586a2 2 0 102.828 2.828l6.414-6.586a4 4 0 00-5.656-5.656l-6.415 6.585a6 6 0 108.486 8.486L20.5 13"
                          />
                        </svg>
                        <div>
                          <div className="text-white font-medium">
                            {attachment.name}
                          </div>
                          <div className="text-gray-400 text-sm">
                            {formatFileSize(attachment.size)} • {attachment.type}
                          </div>
                        </div>
                      </div>
                      <button
                        onClick={() => downloadAttachment(attachment)}
                        className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg transition-colors flex items-center space-x-2"
                      >
                        <svg
                          className="w-4 h-4"
                          fill="none"
                          stroke="currentColor"
                          viewBox="0 0 24 24"
                        >
                          <path
                            strokeLinecap="round"
                            strokeLinejoin="round"
                            strokeWidth={2}
                            d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4"
                          />
                        </svg>
                        <span>Download</span>
                      </button>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        ) : null}
      </div>
    </div>
  );
}
