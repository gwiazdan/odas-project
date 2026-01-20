'use client';

import { useCallback, useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useUserContext } from '@/context/UserContext';
import { useCryptoContext } from '@/context/CryptoContext';
import MessageViewer from '@/components/MessageViewer';
import { decryptMessage, verifySignature } from '@/lib/crypto';

interface InboxMessage {
  id: number;
  sender_id: number;
  sender_username: string;
  encrypted_payload: string;
  signature: string;
  sender_public_key: string;
  is_read: boolean;
  created_at: string;
}

interface DecryptedInboxMessage extends InboxMessage {
  subject: string;
  content_preview: string;
  has_attachments: boolean;
  attachment_count: number;
  signature_valid: boolean | null;
}

interface InboxResponse {
  messages: InboxMessage[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

export default function InboxPage() {
  const router = useRouter();
  const { user } = useUserContext();
  const { privateKeyPEM, isLoading } = useCryptoContext();
  const [messages, setMessages] = useState<InboxMessage[]>([]);
  const [decryptedMessages, setDecryptedMessages] = useState<DecryptedInboxMessage[]>([]);
  const [selectedIds, setSelectedIds] = useState<Set<number>>(new Set());
  const [currentPage, setCurrentPage] = useState(1);
  const [totalPages, setTotalPages] = useState(1);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [selectedMessage, setSelectedMessage] = useState<number | null>(null);

  useEffect(() => {
    if (!user) {
      router.push('/login');
      return;
    }
  }, [user, router]);

  const fetchInbox = useCallback(async () => {
    try {
      setLoading(true);
      const response = await fetch(
        `http://localhost:8000/api/v1/messages/inbox?page=${currentPage}&page_size=10`,
        {
          credentials: 'include',
        }
      );

      if (response.ok) {
        const data: InboxResponse = await response.json();
        setMessages(data.messages);
        setTotalPages(data.total_pages);
        setTotal(data.total);

        if (privateKeyPEM) {
          const decrypted = await Promise.all(
            data.messages.map(async (msg) => {
              try {
                if (!msg.encrypted_payload) {
                  return {
                    ...msg,
                    subject: '[No payload]',
                    content_preview: 'Message has no content',
                    has_attachments: false,
                    attachment_count: 0,
                    signature_valid: false,
                  };
                }

                const decryptedStr = await decryptMessage(msg.encrypted_payload, privateKeyPEM);
                const payload = JSON.parse(decryptedStr);

                let signatureValid: boolean | null = null;
                try {
                  if (msg.signature && msg.sender_public_key) {
                    signatureValid = await verifySignature(
                      decryptedStr,
                      msg.signature,
                      msg.sender_public_key
                    );
                  } else {
                    signatureValid = false;
                  }
                } catch (err) {
                  console.error('Failed to verify signature:', err);
                  signatureValid = false;
                }

                return {
                  ...msg,
                  subject: payload.subject || '(No subject)',
                  content_preview: payload.content?.substring(0, 200) || '',
                  has_attachments: payload.attachments?.length > 0 || false,
                  attachment_count: payload.attachments?.length || 0,
                  signature_valid: signatureValid,
                };
              } catch (err) {
                console.error('Failed to decrypt message preview:', err);
                return {
                  ...msg,
                  subject: '[Decryption failed]',
                  content_preview: 'Unable to decrypt message',
                  has_attachments: false,
                  attachment_count: 0,
                  signature_valid: false,
                };
              }
            })
          );
          setDecryptedMessages(decrypted);
        }
      }
    } catch (error) {
      console.error('Failed to fetch inbox:', error);
    } finally {
      setLoading(false);
    }
  }, [currentPage, privateKeyPEM]);

  useEffect(() => {
    if (user) {
      fetchInbox();
    }
  }, [currentPage, user, fetchInbox]);

  const toggleSelect = (id: number) => {
    const newSelected = new Set(selectedIds);
    if (newSelected.has(id)) {
      newSelected.delete(id);
    } else {
      newSelected.add(id);
    }
    setSelectedIds(newSelected);
  };

  const toggleSelectAll = () => {
    if (selectedIds.size === decryptedMessages.length) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(decryptedMessages.map((m) => m.id)));
    }
  };

  const handleBulkDelete = async () => {
    if (selectedIds.size === 0) return;

    const confirmed = confirm(
      `Are you sure you want to delete ${selectedIds.size} message(s)?`
    );
    if (!confirmed) return;

    try {
      const response = await fetch(
        'http://localhost:8000/api/v1/messages/bulk-delete',
        {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include',
          body: JSON.stringify({
            message_ids: Array.from(selectedIds),
          }),
        }
      );

      if (response.ok) {
        setSelectedIds(new Set());
        fetchInbox();
      }
    } catch (error) {
      console.error('Failed to delete messages:', error);
    }
  };

  const handleRowClick = (id: number) => {
    setSelectedMessage(id);
  };

  const formatDate = (dateString: string) => {
    const date = new Date(dateString);
    const now = new Date();
    const diff = now.getTime() - date.getTime();
    const days = Math.floor(diff / (1000 * 60 * 60 * 24));

    if (days === 0) return 'Today';
    if (days === 1) return 'Yesterday';
    if (days < 7) return `${days} days ago`;
    if (days < 14) return '1 week ago';
    if (days < 30) return `${Math.floor(days / 7)} weeks ago`;
    return date.toLocaleDateString();
  };

  if (isLoading || !user || !privateKeyPEM) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-center">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-500 mx-auto mb-4"></div>
          <p className="text-gray-400">Loading...</p>
        </div>
      </div>
    );
  }

  if (loading && messages.length === 0) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="text-gray-400">Loading messages...</div>
      </div>
    );
  }

  return (
    <>
      <div className="min-h-screen py-8">
        <div className="px-4 mx-auto max-w-screen-2xl">
          <div className="relative overflow-hidden shadow-xl rounded-lg border border-gray-800">
            {/* Header */}
            <div className="flex flex-col px-6 py-4 space-y-3 lg:flex-row lg:items-center lg:justify-between lg:space-y-0 lg:space-x-4 border-b border-gray-700">
              <div className="flex items-center flex-1 space-x-4">
                <h5 className="text-xl font-semibold text-white">
                  Inbox
                  <span className="ml-2 text-gray-400">({total})</span>
                </h5>
              </div>
              <div className="flex flex-col flex-shrink-0 space-y-3 md:flex-row md:items-center lg:justify-end md:space-y-0 md:space-x-3">
                <button
                  type="button"
                  onClick={handleBulkDelete}
                  disabled={selectedIds.size === 0}
                  className="items-center justify-center px-1 py-1 text-sm font-medium text-white rounded-full bg-neutral-900 hover:bg-neutral-500 cursor-pointer focus:ring-4 focus:ring-red-900 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
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
                      d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"
                    />
                  </svg>
                </button>
              </div>
            </div>

            {/* Table */}
            <div className="overflow-x-auto">
              <table className="w-full text-sm text-left text-gray-400">
                <thead className="text-xs text-gray-300 uppercase">
                  <tr>
                    <th scope="col" className="p-4">
                      <div className="flex items-center">
                        <input
                          id="checkbox-all"
                          type="checkbox"
                          checked={
                            decryptedMessages.length > 0 &&
                            selectedIds.size === decryptedMessages.length
                          }
                          onChange={toggleSelectAll}
                          className="w-4 h-4 bg-gray-700 border-gray-600 rounded text-blue-600 focus:ring-blue-500 focus:ring-2"
                        />
                        <label htmlFor="checkbox-all" className="sr-only">
                          checkbox
                        </label>
                      </div>
                    </th>
                    <th scope="col" className="px-4 py-3">Status</th>
                    <th scope="col" className="px-4 py-3">Subject</th>
                    <th scope="col" className="px-4 py-3">Sender</th>
                    <th scope="col" className="px-4 py-3">
                      Description
                    </th>
                    <th scope="col" className="px-4 py-3">
                      Attachments
                    </th>
                    <th scope="col" className="px-4 py-3">
                      Date
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {decryptedMessages.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="px-4 py-8 text-center text-gray-500">
                        No messages in inbox
                      </td>
                    </tr>
                  ) : (
                    decryptedMessages.map((message) => (
                      <tr
                        key={message.id}
                        onClick={() => {
                          if (message.signature_valid === false) return;
                          handleRowClick(message.id);
                        }}
                        className={`border-b border-gray-700 transition-colors ${
                          !message.is_read ? 'bg-gray-800/50' : ''
                        } ${message.signature_valid === false ? 'cursor-not-allowed opacity-80' : 'cursor-pointer hover:bg-gray-700'}`}
                      >
                        <td className="w-4 px-4 py-3">
                          <div className="flex items-center">
                            <input
                              type="checkbox"
                              checked={selectedIds.has(message.id)}
                              onChange={(e) => {
                                e.stopPropagation();
                                toggleSelect(message.id);
                              }}
                              onClick={(e) => e.stopPropagation()}
                              className="w-4 h-4 bg-gray-700 border-gray-600 rounded text-blue-600 focus:ring-blue-500 focus:ring-2"
                            />
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          {message.signature_valid === false ? (
                            <span className="text-xs text-red-400 font-semibold">Invalid signature</span>
                          ) : message.signature_valid === true ? (
                            <span className="text-xs text-green-400 font-semibold">Verified</span>
                          ) : (
                            <span className="text-xs text-gray-500">Pending</span>
                          )}
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center">
                            {!message.is_read && (
                              <div className="w-2 h-2 bg-blue-500 rounded-full mr-2"></div>
                            )}
                            <span className={`${!message.is_read ? 'text-white font-semibold' : 'text-gray-300'}`}>
                              {message.subject || '(No subject)'}
                            </span>
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <span className={`${!message.is_read ? 'text-gray-200 font-medium' : 'text-gray-400'}`}>
                            {message.sender_username}
                          </span>
                        </td>
                        <td className="px-4 py-3 max-w-md truncate">
                          <span className="text-gray-500">
                            {message.content_preview || '(Empty message)'}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          {message.has_attachments ? (
                            <div className="flex items-center text-white font-bold">
                              <svg
                                className="w-4 h-4 mr-1"
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
                              {message.attachment_count}
                            </div>
                          ) : (
                            <span className="text-gray-600">—</span>
                          )}
                        </td>
                        <td className="px-4 py-3 whitespace-nowrap text-gray-400">
                          {formatDate(message.created_at)}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            {totalPages > 1 && (
              <nav
                className="flex flex-col items-start justify-between p-4 space-y-3 md:flex-row md:items-center md:space-y-0 border-t border-gray-700"
                aria-label="Table navigation"
              >
                <span className="text-sm font-normal text-gray-400">
                  Showing{' '}
                  <span className="font-semibold text-white">
                    {(currentPage - 1) * 10 + 1}-
                    {Math.min(currentPage * 10, total)}
                  </span>{' '}
                  of <span className="font-semibold text-white">{total}</span>
                </span>
                <ul className="inline-flex items-stretch -space-x-px">
                  <li>
                    <button
                      onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                      disabled={currentPage === 1}
                      className="flex items-center justify-center h-full py-1.5 px-3 text-gray-400 bg-gray-800 rounded-l-lg border border-gray-700 hover:bg-gray-700 hover:text-white disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      <span className="sr-only">Previous</span>
                      <svg
                        className="w-5 h-5"
                        fill="currentColor"
                        viewBox="0 0 20 20"
                      >
                        <path
                          fillRule="evenodd"
                          d="M12.707 5.293a1 1 0 010 1.414L9.414 10l3.293 3.293a1 1 0 01-1.414 1.414l-4-4a1 1 0 010-1.414l4-4a1 1 0 011.414 0z"
                          clipRule="evenodd"
                        />
                      </svg>
                    </button>
                  </li>
                  {[...Array(Math.min(5, totalPages))].map((_, i) => {
                    const pageNum = i + 1;
                    return (
                      <li key={pageNum}>
                        <button
                          onClick={() => setCurrentPage(pageNum)}
                          className={`flex items-center justify-center px-3 py-2 text-sm leading-tight border border-gray-700 ${
                            currentPage === pageNum
                              ? 'text-white bg-blue-600 hover:bg-blue-700'
                              : 'text-gray-400 bg-gray-800 hover:bg-gray-700 hover:text-white'
                          }`}
                        >
                          {pageNum}
                        </button>
                      </li>
                    );
                  })}
                  <li>
                    <button
                      onClick={() =>
                        setCurrentPage((p) => Math.min(totalPages, p + 1))
                      }
                      disabled={currentPage === totalPages}
                      className="flex items-center justify-center h-full py-1.5 px-3 text-gray-400 bg-gray-800 rounded-r-lg border border-gray-700 hover:bg-gray-700 hover:text-white disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      <span className="sr-only">Next</span>
                      <svg
                        className="w-5 h-5"
                        fill="currentColor"
                        viewBox="0 0 20 20"
                      >
                        <path
                          fillRule="evenodd"
                          d="M7.293 14.707a1 1 0 010-1.414L10.586 10 7.293 6.707a1 1 0 011.414-1.414l4 4a1 1 0 010 1.414l-4 4a1 1 0 01-1.414 0z"
                          clipRule="evenodd"
                        />
                      </svg>
                    </button>
                  </li>
                </ul>
              </nav>
            )}
          </div>
        </div>
      </div>

      {/* Message Viewer Modal */}
      {selectedMessage && (
        <MessageViewer
          messageId={selectedMessage}
          onClose={() => {
            setSelectedMessage(null);
            fetchInbox();
          }}
        />
      )}
    </>
  );
}
