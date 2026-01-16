'use client';
import { PasswordRequirements } from '@/lib/security';
import zxcvbn from 'zxcvbn';

interface PasswordStrengthIndicatorProps {
  password: string;
}

export function PasswordStrengthIndicator({ password }: PasswordStrengthIndicatorProps) {
  const analysis = zxcvbn(password);
  const requirements: PasswordRequirements = {
    minLength: password.length >= 8,
    hasUppercase: /[A-Z]/.test(password),
    hasLowercase: /[a-z]/.test(password),
    hasNumbers: /\d/.test(password),
    hasSpecialChars: /[!@#$%^&*()_+\-=\[\]{};:'",.<>?/\\|`~]/.test(password),
  };

  const strengthScore = analysis.score
  const strengthLevels = ['Very Weak', 'Weak', 'Fair', 'Good', 'Strong'];
  const strengthColors = ['bg-gray-500', 'bg-red-500', 'bg-yellow-500', 'bg-blue-500', 'bg-green-500'];
  const textColors = ['text-gray-400', 'text-red-400', 'text-yellow-400', 'text-blue-400', 'text-green-400'];


  return (
    <div className="mt-3">
      {/* Strength bars */}
      <div className="flex gap-1 mb-3">
        {[0, 1, 2, 3, 4].map((index) => (
          <div
            key={index}
            className={`h-2 flex-1 rounded-full transition-colors ${
              index < strengthScore + 1 ? strengthColors[strengthScore] || strengthColors[0] : 'bg-gray-700'
            }`}
          />
        ))}
      </div>

      {/* Strength label */}
      <div className="mb-3">
        <span className="text-sm text-gray-300">Strength: </span>
        <span className={`text-sm font-semibold ${textColors[strengthScore]}`}>
          {strengthLevels[strengthScore]}
        </span>
      </div>

      {/* Requirements checklist */}
      <div className="space-y-2">
        <h4 className="text-sm font-medium text-gray-300">Password must contain:</h4>
        <ul className="space-y-1 text-sm">
          <RequirementItem
            met={requirements.minLength}
            text="At least 8 characters"
          />
          <RequirementItem
            met={requirements.hasUppercase}
            text="Uppercase letter (A-Z)"
          />
          <RequirementItem
            met={requirements.hasLowercase}
            text="Lowercase letter (a-z)"
          />
          <RequirementItem
            met={requirements.hasNumbers}
            text="Number (0-9)"
          />
          <RequirementItem
            met={requirements.hasSpecialChars}
            text="Special character (!@#$%^&*)"
          />
        </ul>
      </div>
    </div>
  );
}

function RequirementItem({ met, text }: { met: boolean; text: string }) {
  return (
    <li className={`flex items-center gap-2 ${met ? 'text-green-400' : 'text-gray-500'}`}>
      {met ? (
        <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
          <path fillRule="evenodd" d="M16.707 5.293a1 1 0 010 1.414l-8 8a1 1 0 01-1.414 0l-4-4a1 1 0 011.414-1.414L8 12.586l7.293-7.293a1 1 0 011.414 0z" clipRule="evenodd" />
        </svg>
      ) : (
        <svg className="w-4 h-4" fill="currentColor" viewBox="0 0 20 20">
          <path fillRule="evenodd" d="M4.293 4.293a1 1 0 011.414 0L10 8.586l4.293-4.293a1 1 0 111.414 1.414L11.414 10l4.293 4.293a1 1 0 01-1.414 1.414L10 11.414l-4.293 4.293a1 1 0 01-1.414-1.414L8.586 10 4.293 5.707a1 1 0 010-1.414z" clipRule="evenodd" />
        </svg>
      )}
      <span>{text}</span>
    </li>
  );
}
