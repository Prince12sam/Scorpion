// Simple auth token helpers for Scorpion UI

const ACCESS_TOKEN_KEY = process.env.ACCESS_TOKEN_KEY || 'scorpion_access_token';
const REFRESH_TOKEN_KEY = 'scorpion_refresh_token';

export function getAccessToken() {
  try {
    return localStorage.getItem(ACCESS_TOKEN_KEY) || '';
  } catch {
    return '';
  }
}

export function getRefreshToken() {
  try {
    return localStorage.getItem(REFRESH_TOKEN_KEY) || '';
  } catch {
    return '';
  }
}

export function setTokens({ accessToken, refreshToken }) {
  try {
    if (accessToken) localStorage.setItem(ACCESS_TOKEN_KEY, accessToken);
    if (refreshToken) localStorage.setItem(REFRESH_TOKEN_KEY, refreshToken);
  } catch {
    // ignore storage errors
  }
}

export function clearTokens() {
  try {
    localStorage.removeItem(ACCESS_TOKEN_KEY);
    localStorage.removeItem(REFRESH_TOKEN_KEY);
  } catch {
    // ignore
  }
  try {
    if (typeof window !== 'undefined') {
      window.dispatchEvent(new Event('scorpion-auth-logout'));
    }
  } catch {
    // ignore
  }
}

export function isAuthenticated() {
  return !!getAccessToken();
}

// -------- Token Refresh Logic --------
let refreshInFlight = null;

async function requestTokenRefresh() {
  const rt = getRefreshToken();
  if (!rt) throw new Error('No refresh token');
  const res = await fetch('/api/auth/refresh', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refreshToken: rt })
  });
  if (!res.ok) {
    throw new Error('Refresh failed');
  }
  const data = await res.json();
  if (!data?.tokens?.accessToken) {
    throw new Error('Invalid refresh response');
  }
  setTokens({ accessToken: data.tokens.accessToken, refreshToken: data.tokens.refreshToken });
  return data.tokens.accessToken;
}

async function getOrRefreshAccessToken() {
  if (refreshInFlight) {
    try {
      return await refreshInFlight;
    } catch (e) {
      throw e;
    }
  }
  refreshInFlight = requestTokenRefresh()
    .catch((e) => {
      clearTokens();
      throw e;
    })
    .finally(() => {
      refreshInFlight = null;
    });
  return refreshInFlight;
}

// Patch window.fetch to add Authorization header when token exists
export function installFetchAuthInterceptor() {
  if (typeof window === 'undefined' || typeof window.fetch !== 'function') return;
  const originalFetch = window.fetch;

  // Avoid double-install
  if (originalFetch.__scorpionAuthPatched) return;

  const patched = async (input, init = {}) => {
    let token = getAccessToken();
    let url = '';
    try {
      if (typeof input === 'string') url = input;
      else if (input && typeof input === 'object' && 'url' in input) url = input.url;
    } catch {}

    const isApiCall = typeof url === 'string' && (url.startsWith('/api') || url.startsWith('http://localhost:') || url.startsWith('http://127.0.0.1:'));

    // Prepare request with Authorization header when needed
    const prepareInitWithAuth = (tkn, originalInit) => {
      const headers = new Headers(originalInit?.headers || (input?.headers || {}));
      if (tkn && isApiCall && !headers.has('Authorization')) {
        headers.set('Authorization', `Bearer ${tkn}`);
      }
      return { ...originalInit, headers };
    };

    const markRetry = (originalInit) => {
      const headers = new Headers(originalInit?.headers || {});
      headers.set('X-Scorpion-Retry', '1');
      return { ...originalInit, headers };
    };

    const hasRetried = (() => {
      try {
        const h = init?.headers || (input?.headers || {});
        const headers = new Headers(h);
        return headers.get('X-Scorpion-Retry') === '1';
      } catch { return false; }
    })();

    // First attempt
    const firstInit = prepareInitWithAuth(token, init);
    let response = await originalFetch(input, firstInit);

    // If unauthorized and API call, try refresh once
    if (isApiCall && response.status === 401 && !hasRetried && getRefreshToken()) {
      try {
        token = await getOrRefreshAccessToken();
        const retryInit = markRetry(prepareInitWithAuth(token, init));
        response = await originalFetch(input, retryInit);
      } catch (e) {
        // Refresh failed → ensure logout state
        clearTokens();
        return response; // return original 401
      }
    }

    return response;
  };

  patched.__scorpionAuthPatched = true;
  window.fetch = patched;
}
