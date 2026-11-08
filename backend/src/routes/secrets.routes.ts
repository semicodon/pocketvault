import { Router, Request, Response } from 'express';
import argon2 from 'argon2';
import { z } from 'zod';
import { prisma } from '../db/prisma.js';
import { encryptField, decryptField, createMaskedPreview } from '../utils/crypto.js';
import { requireAuth } from '../middleware/auth.js';
import { strictSecurityLimiter } from '../middleware/rateLimiter.js';

export const secretsRouter = Router();

// All routes in this router require a valid 15m Bearer Access Token
secretsRouter.use(requireAuth);

const createSecretSchema = z.object({
  title: z.string().min(2, 'Title is required').max(80).trim(),
  secretValue: z.string().min(4, 'Secret value must be at least 4 characters').max(2000),
});

const revealSecretSchema = z.object({
  password: z.string().min(1, 'Current password is required for step-up verification'),
});

// **************************************
// 1. GET /api/secrets
// Returns ONLY masked previews (never touches encryptedValue!)
// **************************************

secretsRouter.get('/', async (req: Request, res: Response) => {
  const secrets = await prisma.vaultSecret.findMany({
    where: { userId: req.user!.id },
    orderBy: { createdAt: 'desc' },
    select: {
      id: true,
      title: true,
      maskedPreview: true,
      createdAt: true,
      // SECURITY: encryptedValue is strictly excluded!
    },
  });

  res.json({ secrets });
});

// **************************************
// 2. POST /api/secrets
// Encrypts secret with AES-256-GCM before saving to SQLite
// **************************************

secretsRouter.post('/', async (req: Request, res: Response) => {
  const parsed = createSecretSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({
      error: 'Invalid secret format',
      details: parsed.error.flatten().fieldErrors,
    });
    return;
  }

  const { title, secretValue } = parsed.data;

  // Encrypt with AES-256-GCM (iv:authTag:ciphertext) & build safe last-4 preview
  const encryptedValue = encryptField(secretValue);
  const maskedPreview = createMaskedPreview(secretValue);

  const newSecret = await prisma.vaultSecret.create({
    data: {
      userId: req.user!.id,
      title,
      encryptedValue,
      maskedPreview,
    },
    select: {
      id: true,
      title: true,
      maskedPreview: true,
      createdAt: true,
    },
  });

  res.status(201).json({ secret: newSecret });
});

// **************************************
// 3. POST /api/secrets/:id/reveal
// Step-Up Password Auth + In-RAM Decryption
// **************************************

secretsRouter.post(
  '/:id/reveal',
  strictSecurityLimiter,
  async (req: Request, res: Response) => {
    const parsed = revealSecretSchema.safeParse(req.body);
    if (!parsed.success) {
      res.status(400).json({ error: 'Password is required for step-up authentication' });
      return;
    }

    const secretId = req.params.id;
    const userId = req.user!.id;

    // Fetch both the secret and the user's passwordHash
    const [secret, user] = await Promise.all([
      prisma.vaultSecret.findUnique({ where: { id: secretId } }),
      prisma.user.findUnique({ where: { id: userId } }),
    ]);

    // Anti-BOLA / Anti-IDOR Check: Return 404 if missing OR owned by someone else
    if (!secret || secret.userId !== userId || !user) {
      res.status(404).json({ error: 'Vault secret not found' });
      return;
    }

    // Step-Up Verification: Verify user's password with Argon2id before decrypting
    const isPasswordValid = await argon2.verify(user.passwordHash, parsed.data.password);
    if (!isPasswordValid) {
      res.status(403).json({ error: 'Step-up authentication failed: Incorrect password' });
      return;
    }

    // Decrypt in RAM and verify GCM authTag integrity seal
    const plaintextValue = decryptField(secret.encryptedValue);

    // Forbid browsers & proxies from writing decrypted secret to disk cache
    res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, private');
    res.setHeader('Pragma', 'no-cache');

    res.json({
      id: secret.id,
      title: secret.title,
      plaintextValue,
    });
  }
);

// **************************************
// 4. DELETE /api/secrets/:id
// BOLA-Protected Secret Deletion
// **************************************

secretsRouter.delete('/:id', async (req: Request, res: Response) => {
  const secretId = req.params.id;
  const userId = req.user!.id;

  const existing = await prisma.vaultSecret.findUnique({ where: { id: secretId } });
  if (!existing || existing.userId !== userId) {
    res.status(404).json({ error: 'Vault secret not found' });
    return;
  }

  await prisma.vaultSecret.delete({ where: { id: secretId } });
  res.status(204).send();
});