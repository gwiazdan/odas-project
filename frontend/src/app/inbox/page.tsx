'use client';

import { useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useUserContext } from '@/context/UserContext';
import { sanitizeInput } from '@/lib/security';

interface Message {
  id: number;
  sender_id: number;
  sender: {
    id: number;
    first_name: string;
    last_name: string;
    email: string;
  };
  subject: string;
  is_read: boolean;
  created_at: string;
}

export default function InboxPage() {
  const router = useRouter();
  const { user } = useUserContext();
  const [showWelcome, setShowWelcome] = useState(true);

  useEffect(() => {
    // Hide welcome message after 5 seconds
    const timer = setTimeout(() => {
      setShowWelcome(false);
    }, 5000);

    return () => clearTimeout(timer);
  }, []);

  if (!user) {
    return <div className="p-8">Loading...</div>;
  }

  return (
    <div className="p-8">
      <h1 className="text-3xl font-bold mb-6 tracking-wider">Inbox</h1>

      {showWelcome && (
        <div className="bg-green-900 border border-green-700 text-green-100 px-4 py-3 rounded mb-6 animate-pulse">
          <p className="font-semibold">Welcome, {sanitizeInput(`${user.first_name} ${user.last_name}`)}!</p>
          <p className="text-sm text-green-200">{sanitizeInput(user.email)}</p>
        </div>
      )}

      <div className="space-y-2">
        <h2 className="text-xl font-bold text-white mb-4">Messages (0)</h2>
        <p className="text-gray-400">No messages yet</p>
      </div>
    </div>
  );
}
