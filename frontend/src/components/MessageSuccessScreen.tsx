import React from 'react';

interface MessageSuccessScreenProps {
  isOpen: boolean;
  recipientEmail: string;
  onClose: () => void;
}

const MessageSuccessScreen: React.FC<MessageSuccessScreenProps> = ({ isOpen, recipientEmail, onClose }) => {
  if (!isOpen) return null;

  return (
    <>
      {/* Overlay blur background */}
      <div
        className="fixed inset-0 z-[60] bg-black/50 backdrop-blur-sm"
        onClick={onClose}
      />

      {/* Modal card */}
      <div className="fixed inset-0 z-[70] flex items-center justify-center p-4">
        <div className="w-full max-w-md bg-neutral-900 border border-gray-800 rounded-lg p-8">
          {/* Checkmark */}
          <div className="flex justify-center mb-6">
            <div className="w-16 h-16 rounded-full bg-green-300/20 flex items-center justify-center">
              <svg
                className="w-10 h-10 text-green-300"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
              >
                <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
                <polyline points="22 4 12 14.01 9 11.01" />
              </svg>
            </div>
          </div>

          {/* Message */}
          <div className="text-center space-y-4">
            <h2 className="text-2xl font-bold text-white">Message Sent!</h2>
            <p className="text-gray-400">Your message has been successfully sent.</p>

            {/* Recipient Email */}
            <div className="bg-neutral-800 border border-gray-700 rounded-lg p-4 mt-6">
              <p className="text-xs text-gray-500 mb-1">Recipient</p>
              <p className="text-lg font-semibold text-white break-all">
                {recipientEmail}
              </p>
            </div>

            {/* Message */}
            <p className="text-sm text-gray-400 pt-4">
              The recipient will receive your encrypted message shortly.
            </p>
          </div>

          {/* Button */}
          <button
            onClick={onClose}
            className="w-full mt-8 px-5 py-2.5 rounded-lg bg-white text-black hover:bg-gray-300 font-semibold transition-colors cursor-pointer"
          >
            Back to Inbox
          </button>
        </div>
      </div>
    </>
  );
};

export default MessageSuccessScreen;
