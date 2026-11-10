export interface AuthUser {
  id: string;
  email: string;
}

/**
 * Access Token - Private Module Closure Vault
 * Invisible to `window`, `localStorage`, `sessionStorage`, and `document.cookie`.

 * Refresh Promise - Single-Flight Refresh Lock
 * Prevents two concurrent components from firing duplicate /auth/refresh calls
 * and accidentally triggering backend JTI reuse detection!
 */

let accessToken: string | null = null;

let refreshPromise: Promise<AuthUser | null> | null = null;

export function setMemoryToken(token: string | null): void {
  accessToken = token;
}
export function clearMemoryToken(): void {
  accessToken = null;
}
export function hasMemoryToken(): boolean {
  return accessToken !== null;
}

/**
 * Uses the browser's HttpOnly Refresh Cookie to silently obtain a new 15m RAM token and rotate the single-use JTI session ticket.
 */
export async function attemptSilentRefresh(): Promise<AuthUser | null> {
  if (refreshPromise) {
    return refreshPromise;
  }

  refreshPromise = (async () => {
    try {
      const res = await fetch('/api/auth/refresh', {
        method: 'POST',
        credentials: 'include', // Sends HttpOnly cookie automatically
      });

      if (!res.ok) {
        accessToken = null;
        return null;
      }

      // Parse JSON response from backend, containing new access token and user data
      const data = (await res.json()) as {
        accessToken: string;
        user: AuthUser
      };
      accessToken = data.accessToken;
      return data.user;

    } catch {
      accessToken = null;
      return null;

    } finally {
      refreshPromise = null;
    }
  })();

  return refreshPromise;
}


/**
 * Wrapper around fetch() that automatically attaches the closure Bearer JWT
 * and transparently performs a single silent refresh if a 15m token expires (401).
 */
export async function secureFetch(
  endpoint: string,
  options: RequestInit ={},
  isRetry = false
): Promise<Response> {

  const headers = new Headers(options.headers);

  if (options.body && !headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  if (accessToken) {
    headers.set('Authorization', `Bearer ${accessToken}`);
  }

  const response = await fetch(
    endpoint, {
      ...options,
      headers,
      credentials: 'include'
    }
  );

  // If 15m Access Token expired, silently refresh once and retry the original request
  if (
    response.status === 401 &&
    !isRetry &&
    !endpoint.includes('/auth/login') &&
    !endpoint.includes('/auth/register') &&
    !endpoint.includes('/auth/refresh')
  ) {

    const refreshedUser = await attemptSilentRefresh();
    if (refreshedUser && accessToken) {
      return secureFetch(endpoint, options, true);
    }

  }

  return response;
}