import crypto from 'node:crypto';
import { env } from '../config/env.js';

const ALGORITHM = 'aes-256-gcm';
const MASTER_KEY = Buffer.from(env.ENCRYPTION_KEY, 'hex');

/**
 * Encrypts plaintext into format: ivHex:authTagHex:ciphertextHex
 */
export function encryptField(plaintext: string): string {
  const iv = crypto.randomBytes(12); // 96-bit random IV
  const cipher = crypto.createCipheriv(ALGORITHM, MASTER_KEY, iv);
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');

  return `${iv.toString('hex')}:${authTag}:${encrypted}`;
}

/**
 * Verifies the GCM authTag and decrypts back to UTF-8 plaintext
 */
export function decryptField(
  payload: string): string {

  const [ivHex, authTagHex, encryptedHex] = payload.split(':');

  if (!ivHex || !authTagHex || !encryptedHex) {
    throw new Error('Integrity error: Invalid encrypted payload format');
  }

  const decipher = crypto.createDecipheriv(
    ALGORITHM,
    MASTER_KEY,
    Buffer.from(ivHex, 'hex')
  );
  decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));

  let decrypted = decipher.update(encryptedHex, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

/**
 * Builds a safe masked hint showing only the last 4 characters (e.g., "****6655")
 */
export function createMaskedPreview(secret: string): string {
  const trimmed = secret.trim();
  if (trimmed.length <= 4) {
    return '****';
  }
  return `****${trimmed.slice(-4)}`;
}