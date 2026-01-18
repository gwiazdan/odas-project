import { sanitizeInput } from './security';

// Format user display name with sanitization
export function formatUserDisplayName(firstName: string, lastName: string): string {
  return `${sanitizeInput(firstName)} ${sanitizeInput(lastName)}`.trim();
}

// Format message subject with sanitization
export function formatMessageSubject(subject: string): string {
  return sanitizeInput(subject);
}

// Format attachment filename with sanitization
export function formatFilename(filename: string): string {
  return sanitizeInput(filename);
}

// Format email for display with sanitization
export function formatEmail(email: string): string {
  return sanitizeInput(email);
}
