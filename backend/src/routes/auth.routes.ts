import { Router, Request, Response } from 'express';
import argon2 from 'argon2';
import jwt from 'jsonwebtoken';
import crypto from 'node:crypto';
import { z } from 'zod';
import { prisma } from '../db/prisma.js';
import { env } from '../config/env.js';
import {
  storeRefreshSession,
  isRefreshSessionValid,
  revokeRefreshSession,
  revokeAllUserSessions,
} from '../db/sessionStore.js';
import { strictSecurityLimiter } from '../middleware/rateLimiter.js';

export const authRouter = Router();

const REFRESH_COOKIE_NAME = 'pocketvault_refresh';
const ACCESS_TOKEN_TTL = '15m';
const REFRESH_TOKEN_TTL_SECONDS = 7 * 24 * 60 * 60; // 7 days


const credentialsSchema = z.object({
  email: z.string().email().transform((e) => e.toLowerCase().trim()),
  password: z
    .string()
    .min(10, 'Password must be at least 10 characters long')
    .regex(/[A-Z]/, 'Password must contain at least one uppercase letter')
    .regex(/[0-9]/, 'Password must contain at least one number'),
});

const loginSchema = z.object({
  email: z.string().email().transform((e) => e.toLowerCase().trim()),
  password: z.string().min(1),
});

function setRefreshCookie(
  res: Response,
  refreshToken: string): void {
    res.cookie(REFRESH_COOKIE_NAME, refreshToken, {
      httpOnly: true, // Invisible to JavaScript (blocks XSS theft)
      secure: env.NODE_ENV === 'production',
      sameSite: 'strict', // Blocks cross-site CSRF requests
      path: '/api/auth', // Cookie is ONLY sent to /api/auth/* endpoints
      maxAge: REFRESH_TOKEN_TTL_SECONDS * 1000,
    });
}

// **************************************
// 1. POST /api/auth/register
// **************************************

authRouter.post('/register', strictSecurityLimiter, async (req: Request, res: Response) => {
  const parsed = credentialsSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({
      error: 'Validation failed',
      details: parsed.error.flatten().fieldErrors,
    });
    return;
  }

  const { email, password } = parsed.data;

  const existing = await prisma.user.findUnique({ where: { email } });
  if (existing) {
    res.status(409).json({ error: 'Unable to register with the provided email' });
    return;
  }

  const passwordHash = await argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 65536, // 64 MB memory cost (GPU cracking defense)
    timeCost: 3,
  });

  const user = await prisma.user.create({
    data: { email, passwordHash },
    select: { id: true, email: true, createdAt: true },
  });

  res.status(201).json({ user });
});

// **************************************
// 2. POST /api/auth/login
// **************************************

authRouter.post('/login', strictSecurityLimiter, async (req: Request, res: Response) => {

  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) {
    res.status(400).json({ error: 'Invalid credentials format' });
    return;
  }

  const { email, password } = parsed.data;

  // 1. Find user by email
  const user = await prisma.user.findUnique({ where: { email } });

  if (!user) {
    res.status(401).json({ error: 'Invalid email or password' });
    return;
  }

  // 2. Verify password by Argon2 - secure password hashing
  const isPasswordValid = await argon2.verify(user.passwordHash, password);
  if (!isPasswordValid) {
    res.status(401).json({ error: 'Invalid email or password' });
    return;
  }

  // 3. Validated - Issue 15m Access Token + 7d Single-Use Refresh Token (JTI)
  const jti = crypto.randomUUID();

  const accessToken = jwt.sign({
    sub: user.id,
    email: user.email
  },
    env.JWT_ACCESS_SECRET, {
    expiresIn: ACCESS_TOKEN_TTL,
  });
  const refreshToken = jwt.sign({
    sub: user.id,
    jti },
    env.JWT_REFRESH_SECRET, {
    expiresIn: REFRESH_TOKEN_TTL_SECONDS,
  });

  storeRefreshSession(user.id, jti, REFRESH_TOKEN_TTL_SECONDS);
  setRefreshCookie(res, refreshToken);

  res.json({
    accessToken,
    user: { id: user.id, email: user.email },
  });
});

// **************************************
// 3. POST /api/auth/refresh (Silent Refresh + Single-Use JTI Rotation)
// **************************************

authRouter.post('/refresh', async (req: Request, res: Response) => {
  const token = req.cookies?.[REFRESH_COOKIE_NAME];
  if (!token) {
    res.status(401).json({ error: 'Missing refresh cookie' });
    return;
  }

  try {
    const decoded = jwt.verify(token, env.JWT_REFRESH_SECRET) as { sub: string; jti: string };
    const isValid = isRefreshSessionValid(decoded.sub, decoded.jti);

    if (!isValid) {
      // Stolen/reused refresh token detected! Kill all active sessions for this user.
      console.warn(`⚠️ SECURITY ALERT: Refresh token reuse detected for user ${decoded.sub}`);
      revokeAllUserSessions(decoded.sub);
      res.clearCookie(REFRESH_COOKIE_NAME, { path: '/api/auth' });
      res.status(401).json({ error: 'Session revoked due to security policy' });
      return;
    }

    const user = await prisma.user.findUnique({
      where: { id: decoded.sub },
      select: { id: true, email: true },
    });

    if (!user) {
      res.status(401).json({ error: 'User no longer exists' });
      return;
    }

    // Rotate JTI: shred the old ticket and mint a brand-new one
    revokeRefreshSession(user.id, decoded.jti);
    const newJti = crypto.randomUUID();

    // Generate new access token from .env to the user
    const newAccessToken = jwt.sign({
        sub: user.id,
        email: user.email
      },
      env.JWT_ACCESS_SECRET, {
        expiresIn: ACCESS_TOKEN_TTL,
    });
    // Generate new refresh token unique to the user
    const newRefreshToken = jwt.sign({
        sub: user.id,
        jti: newJti
      },
      env.JWT_REFRESH_SECRET, {
        expiresIn: REFRESH_TOKEN_TTL_SECONDS,
    });

    storeRefreshSession(user.id, newJti, REFRESH_TOKEN_TTL_SECONDS);
    setRefreshCookie(res, newRefreshToken);

    res.json({
      accessToken: newAccessToken,
      user,
    });
  } catch {
    res.clearCookie(REFRESH_COOKIE_NAME, { path: '/api/auth' });
    res.status(401).json({ error: 'Invalid or expired refresh token' });
  }
});

// **************************************
// 4. POST /api/auth/logout
// **************************************

authRouter.post('/logout', (req: Request, res: Response) => {
  const token = req.cookies?.[REFRESH_COOKIE_NAME];
  if (token) {
    try {
      const decoded = jwt.verify(token, env.JWT_REFRESH_SECRET) as { sub: string; jti: string };
      revokeRefreshSession(decoded.sub, decoded.jti);
    } catch {
      // Ignore expired token on logout
    }
  }

  res.clearCookie(REFRESH_COOKIE_NAME, { path: '/api/auth' });
  res.status(204).send();
});