import DOMPurify from 'dompurify';
import zxcvbn from 'zxcvbn';

export interface PasswordRequirements {
  minLength: boolean;
  hasUppercase: boolean;
  hasLowercase: boolean;
  hasNumbers: boolean;
  hasSpecialChars: boolean;
}

// Sanitize user input to prevent XSS attacks
export function sanitizeInput(input: string): string {
  return DOMPurify.sanitize(input, {
    ALLOWED_TAGS: [],
    ALLOWED_ATTR: [],
  });
}

// Converts special characters to HTML entities
export function escapeHtml(text: string): string {
  const map: Record<string, string> = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;',
  };
  return text.replace(/[&<>"']/g, (char) => map[char]);
}

// Validate email format
export function isValidEmail(email: string): boolean {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  return emailRegex.test(email);
}

// Check password strength
export function isValidPassword(password: string): {
  isPasswordValid: boolean
} {
  const analysis = zxcvbn(password);
  const requirements: PasswordRequirements = {
    minLength: password.length >= 8,
    hasUppercase: /[A-Z]/.test(password),
    hasLowercase: /[a-z]/.test(password),
    hasNumbers: /\d/.test(password),
    hasSpecialChars: /[!@#$%^&*()_+\-=\[\]{};:'",.<>?/\\|`~]/.test(password),
  };

  const meetsAllRequirements = Object.values(requirements).every(Boolean);
  const isStrong = analysis.score > 3;

  const isPasswordValid = meetsAllRequirements && isStrong;
  return {
    isPasswordValid
  };
}

// Validate name fields
export function isValidName(name: string): boolean {
  const nameRegex = /^[a-zA-Z\s'-]{2,50}$/;
  return nameRegex.test(name);
}

// Check if passwords match
export function passwordsMatch(password: string, confirmPassword: string): boolean {
  return password === confirmPassword && password.length > 0;
}
