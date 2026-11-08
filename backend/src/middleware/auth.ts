import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { env } from '../config/env';

export interface AccessTokenPayload {
  sub: string;
  email: string;
}

declare global {
  namespace Express {
    interface Request {
      user?: {
        id: string;
        email: string;
      }
    }
  }
}

/**
 * extracts the short-lived `Bearer Access Token` from the `Authorization` header, verifies its cryptographic signature using` env.JWT_ACCESS_SECRET`, and attaches the verified req.user = { id, email } identity to the `Express Request` object. Downstream routes only trust req.user.id.
 */
export function requireAuth(req: Request, res: Response, next: NextFunction): void {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    res.status(401).json({ error: 'Authentication required: Missing Bearer token' });
    return;
  }

  const token = authHeader.slice(7);
  try {
    const decoded = jwt.verify(token, env.JWT_ACCESS_SECRET) as AccessTokenPayload;
    req.user = {
      id: decoded.sub,
      email: decoded.email,
    };
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired access token' });
  }
}