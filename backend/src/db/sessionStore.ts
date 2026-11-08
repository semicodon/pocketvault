interface SessionRecord {
  userId: string;
  expiresAt: number;
}

// Key format: "userId:jti"
const activeSessions = new Map<string, SessionRecord>();

/**
 * Stores a valid Refresh Token JTI in memory with a strict TTL (Time-To-Live)
 */
export function storeRefreshSession(
  userId: string,
  jti: string,
  ttlSeconds: number): void {

  const key = `${userId}:${jti}`;
  activeSessions.set(
    key, {
    userId,
    expiresAt: Date.now() + ttlSeconds * 1000,
  });
}

/**
 * Checks if a Refresh Token JTI is currently active and has not expired
 */
export function isRefreshSessionValid(userId: string, jti: string): boolean {
  const key = `${userId}:${jti}`;
  const session = activeSessions.get(key);

  if (!session) {
    return false;
  }

  if (Date.now() > session.expiresAt) {
    activeSessions.delete(key);
    return false;
  }

  return true;
}

/**
 * Instantly revokes a single Refresh Token JTI (used during rotation or logout)
 */
export function revokeRefreshSession(userId: string, jti: string): void {
  const key = `${userId}:${jti}`;
  activeSessions.delete(key);
}

/**
 * Emergency Nuclear Option: Revokes ALL active sessions for a compromised user
 */
export function revokeAllUserSessions(userId: string): void {
  for (const [key, session] of activeSessions.entries()) {
    if (session.userId === userId) {
      activeSessions.delete(key);
    }
  }
}