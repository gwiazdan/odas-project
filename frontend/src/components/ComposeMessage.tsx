'use client';

import { useState, useRef, DragEvent } from 'react';
import { sanitizeInput, isValidEmail } from '@/lib/security';
import { useCryptoContext } from '@/context/CryptoContext';
import { useUserContext } from '@/context/UserContext';
import { encryptMessage } from '@/lib/crypto';
import MessageSuccessScreen from './MessageSuccessScreen';

interface ComposeMessageProps {
  onClose: () => void;
}

export default function ComposeMessage({ onClose }: ComposeMessageProps) {
  const { privateKeyPEM } = useCryptoContext();
  const { user, csrfToken } = useUserContext();
  const [recipient, setRecipient] = useState('');
  const [subject, setSubject] = useState('');
  const [content, setContent] = useState('');
  const [attachments, setAttachments] = useState<File[]>([]);
  const [isDragging, setIsDragging] = useState(false);
  const [isSending, setIsSending] = useState(false);
  const [error, setError] = useState('');
  const [showSuccessScreen, setShowSuccessScreen] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const handleDragOver = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(true);
  };

  const handleDragLeave = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  };

  const handleDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);

    const files = Array.from(e.dataTransfer.files);
    setAttachments(prev => [...prev, ...files]);
  };

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) {
      const files = Array.from(e.target.files);
      setAttachments(prev => [...prev, ...files]);
    }
  };

  const removeAttachment = (index: number) => {
    setAttachments(prev => prev.filter((_, i) => i !== index));
  };

  const handleSend = async () => {
    setError('');

    // Sanitize inputs
    const sanitizedRecipient = sanitizeInput(recipient.trim());
    const sanitizedSubject = sanitizeInput(subject.trim());
    const sanitizedContent = sanitizeInput(content.trim());

    // Validate total attachment size (50MB cap)
    const totalSize = attachments.reduce((sum, file) => sum + file.size, 0);
    if (totalSize > 50 * 1024 * 1024) {
      setError('Max 50MB total attachments');
      return;
    }

    // Validate
    if (!sanitizedRecipient || !sanitizedContent) {
      setError('Please fill in recipient and message content');
      return;
    }

    if (!isValidEmail(sanitizedRecipient)) {
      setError('Please enter a valid email address');
      return;
    }

    if (!user || !privateKeyPEM) {
      setError('Session expired. Please log in again.');
      return;
    }

    setIsSending(true);
    try {
      const apiUrl = process.env.NEXT_PUBLIC_API_URL;
      if (!apiUrl) {
        setError('API URL not configured');
        setIsSending(false);
        return;
      }

      const verifyResponse = await fetch(
        `${apiUrl}/api/v1/auth/verify-recipient?email=${encodeURIComponent(sanitizedRecipient)}`,
        { credentials: 'include' }
      );

      if (!verifyResponse.ok) {
        if (verifyResponse.status === 404) {
          setError('Recipient not found');
        } else {
          setError('Error verifying recipient');
        }
        setIsSending(false);
        return;
      }

      const keyData = await verifyResponse.json();
      const recipientId = keyData.id;
      const recipientPublicKey = keyData.public_key;

      // Encode attachments to base64 in streaming chunks to avoid call stack issues
      const attachmentPromises = attachments.map(async (file) => {
        const buffer = await file.arrayBuffer();
        const bytes = new Uint8Array(buffer);
        const chunks: string[] = [];
        const chunkSize = 8192;
        for (let i = 0; i < bytes.length; i += chunkSize) {
          chunks.push(String.fromCharCode(...bytes.subarray(i, i + chunkSize)));
        }
        const data = btoa(chunks.join(''));

        return {
          name: file.name,
          size: file.size,
          type: file.type,
          data,
        };
      });

      const attachmentObjects = await Promise.all(attachmentPromises);

      // Encrypt payload WITH attachment data included
      const { encryptedMessage: encryptedForRecipient, signature } = await encryptMessage(
        JSON.stringify({
          subject: sanitizedSubject,
          content: sanitizedContent,
          attachments: attachmentObjects,
        }),
        recipientPublicKey,
        privateKeyPEM
      );

      const { encryptedMessage: encryptedForSender } = await encryptMessage(
        JSON.stringify({
          subject: sanitizedSubject,
          content: sanitizedContent,
          attachments: attachmentObjects,
        }),
        user.public_key,
        privateKeyPEM
      );

      const sendResponse = await fetch(`${apiUrl}/api/v1/messages/send`, {
        method: 'POST',
        credentials: 'include',
        headers: {
          'Content-Type': 'application/json',
          ...(csrfToken && { 'X-CSRF-Token': csrfToken }),
        },
        body: JSON.stringify({
          recipient_id: recipientId,
          payload_recipient: encryptedForRecipient,
          payload_sender: encryptedForSender,
          signature,
        }),
      });

      if (!sendResponse.ok) {
        let errorDetail = 'Error sending message';
        try {
          const errorData = await sendResponse.json();
          if (errorData.detail) {
            if (typeof errorData.detail === 'string') {
              errorDetail = errorData.detail;
            } else if (Array.isArray(errorData.detail)) {
              // Handle FastAPI validation error format
              errorDetail = errorData.detail.map((err: Record<string, unknown>) => {
                if (err.msg) return `${err.loc}: ${err.msg}`;
                return JSON.stringify(err);
              }).join(', ');
            } else {
              errorDetail = JSON.stringify(errorData.detail);
            }
          }
        } catch {
          // If can't parse JSON, use status text
          errorDetail = sendResponse.statusText || 'Error sending message';
        }
        throw new Error(errorDetail);
      }

      // Success - show success screen
      setShowSuccessScreen(true);
      setSubject('');
      setContent('');
      setAttachments([]);
    } catch (err) {
      let errorMessage = 'Error sending message';

      if (err instanceof Error) {
        errorMessage = err.message;
      } else if (typeof err === 'string') {
        errorMessage = err;
      } else if (err && typeof err === 'object') {
        const errObj = err as Record<string, unknown>;
        if ('message' in errObj) {
          errorMessage = String(errObj.message);
        } else {
          errorMessage = JSON.stringify(err);
        }
      }
      setRecipient('');
      setError(errorMessage);
    } finally {
      setIsSending(false);
    }
  };

  const handleSuccessClose = () => {
    setShowSuccessScreen(false);
    onClose();
  };

  return (
    <>
      <MessageSuccessScreen
        isOpen={showSuccessScreen}
        recipientEmail={recipient}
        onClose={handleSuccessClose}
      />
      <div className="fixed inset-0 z-50 flex items-center justify-center">
        {/* Blurred backdrop */}
        <div
          className="absolute inset-0 bg-black/50 backdrop-blur-sm"
          onClick={onClose}
        />

        {/* Modal */}
        <div
          className="relative bg-neutral-900 border border-gray-800 rounded-lg shadow-2xl w-full max-w-3xl mx-4 max-h-[90vh] flex flex-col"
          onDragOver={handleDragOver}
          onDragLeave={handleDragLeave}
          onDrop={handleDrop}
        >
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-800">
          <h2 className="text-xl font-bold text-white">New Message</h2>
          <button
            onClick={onClose}
            className="flex text-gray-400 hover:text-white transition-colors w-7 h-7 rounded-full bg-neutral-800 items-center justify-center cursor-pointer"
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

        {/* Form */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          {/* Error message */}
          {error && (
            <div className="bg-red-900/20 border border-red-600 rounded-md p-3 text-red-300 text-sm">
              {error}
            </div>
          )}

          {/* Recipient */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Recipient
            </label>
            <input
              type="email"
              value={recipient}
              onChange={(e) => setRecipient(e.target.value)}
              placeholder="email@example.com"
              className="w-full px-4 py-2 bg-neutral-800 border border-gray-600 rounded-md text-white placeholder-gray-500 focus:outline-none focus:border-white focus:ring-1 focus:ring-white"
            />
          </div>

          {/* Subject */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Subject
            </label>
            <input
              type="text"
              value={subject}
              onChange={(e) => setSubject(e.target.value)}
              placeholder="Message subject"
              className="w-full px-4 py-2 bg-neutral-800 border border-gray-600 rounded-md text-white placeholder-gray-500 focus:outline-none focus:border-white focus:ring-1 focus:ring-white"
            />
          </div>

          {/* Content */}
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-2">
              Message
            </label>
            <textarea
              value={content}
              onChange={(e) => setContent(e.target.value)}
              placeholder="Type your message..."
              rows={12}
              className="w-full px-4 py-2 bg-neutral-800 border border-gray-600 rounded-md text-white placeholder-gray-500 focus:outline-none focus:border-white focus:ring-1 focus:ring-white resize-none"
            />
          </div>

          {/* Attachments preview */}
          {attachments.length > 0 && (
            <div className="bg-neutral-800 border border-gray-600 rounded-md p-4">
              <h3 className="text-sm font-medium text-gray-300 mb-2">
                Attachments ({attachments.length})
              </h3>
              <div className="space-y-2">
                {attachments.map((file, index) => (
                  <div
                    key={index}
                    className="flex items-center justify-between bg-gray-700 px-3 py-2 rounded"
                  >
                    <div className="flex items-center space-x-2 min-w-0 flex-1">
                      <div className="text-gray-400 shrink-0" style={{ width: '16px', height: '16px' }}>
                        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                          <path d="m16 6-8.414 8.586a2 2 0 0 0 2.829 2.829l8.414-8.586a4 4 0 1 0-5.657-5.657l-8.379 8.551a6 6 0 1 0 8.485 8.485l8.379-8.551"/>
                        </svg>
                      </div>
                      <span className="text-sm text-gray-200 truncate">
                        {file.name}
                      </span>
                      <span className="text-xs text-gray-400 shrink-0">
                        ({(file.size / 1024).toFixed(1)} KB)
                      </span>
                    </div>
                    <button
                      onClick={() => removeAttachment(index)}
                      className="ml-2 text-gray-400 hover:text-red-400 transition-colors shrink-0"
                    >
                      <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                        <path d="M18 6 6 18"/><path d="m6 6 12 12"/>
                      </svg>
                    </button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Drag and drop indicator */}
          {isDragging && (
            <div className="absolute inset-0 bg-blue-500/10 border-2 border-dashed border-blue-500 rounded-lg flex items-center justify-center pointer-events-none">
              <p className="text-blue-400 text-lg font-semibold">
                Drop files here
              </p>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-gray-700 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <button
              onClick={() => fileInputRef.current?.click()}
              className="flex items-center space-x-2 px-4 py-2 bg-neutral-800 hover:bg-gray-700 text-gray-300 rounded-md transition-colors cursor-pointer"
            >
              <div className="w-6 h-6">
                  <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                    <path d="m16 6-8.414 8.586a2 2 0 0 0 2.829 2.829l8.414-8.586a4 4 0 1 0-5.657-5.657l-8.379 8.551a6 6 0 1 0 8.485 8.485l8.379-8.551"/>
                  </svg>
              </div>
              <span>Attach File</span>
            </button>
            <input
              ref={fileInputRef}
              type="file"
              multiple
              onChange={handleFileSelect}
              className="hidden"
            />
          </div>

          <button
            onClick={handleSend}
            disabled={isSending}
            className="flex items-center space-x-2 px-6 py-2 bg-white hover:bg-gray-300 disabled:bg-gray-600 disabled:cursor-not-allowed text-black rounded-md transition-colors font-medium cursor-pointer"
          >
            <div className="w-6 h-6">
                <svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <path d="m22 2-7 20-4-9-9-4Z"/><path d="M22 2 11 13"/>
                </svg>
            </div>
            <span>{isSending ? 'Sending...' : 'Send'}</span>
          </button>
        </div>
        </div>
      </div>
    </>
  );
}
