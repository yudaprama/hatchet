const SESSION_TOKEN_KEY = 'kawai:kratos-session-token';
const KRATOS_URL =
  import.meta.env.VITE_KRATOS_URL ??
  'https://backend.kawai.pro/.ory/kratos/public';

type OidcFlow = {
  ui: { action: string };
  session_token_exchange_code?: string;
};

export function getKawaiSessionToken(): string | null {
  try {
    return localStorage.getItem(SESSION_TOKEN_KEY);
  } catch {
    return null;
  }
}

export function setKawaiSessionToken(token: string): void {
  try {
    localStorage.setItem(SESSION_TOKEN_KEY, token);
  } catch {
    // Keep the token in memory only when browser storage is unavailable.
  }
}

export function clearKawaiSessionToken(): void {
  try {
    localStorage.removeItem(SESSION_TOKEN_KEY);
  } catch {
    // Storage may be unavailable in privacy-restricted browser contexts.
  }
}

export function kawaiAuthHeaders(): Record<string, string> {
  const token = getKawaiSessionToken();
  return token ? { 'X-Session-Token': token } : {};
}

export async function startKawaiSocialLogin(
  kind: 'login' | 'registration',
  provider: 'google' | 'github',
): Promise<string> {
  const popup = window.open(
    'about:blank',
    'kawai-oidc',
    'width=500,height=700',
  );
  if (!popup) {
    throw new Error(
      'Popup blocked. Allow pop-ups for this site and try again.',
    );
  }

  try {
    const returnTo = `${window.location.origin}/oidc-callback`;
    const initResponse = await fetch(
      `${KRATOS_URL}/self-service/${kind}/api` +
        `?return_session_token_exchange_code=true&return_to=${encodeURIComponent(returnTo)}`,
      { headers: { Accept: 'application/json' } },
    );
    if (!initResponse.ok) {
      throw new Error(
        `Kratos auth initialization failed (${initResponse.status})`,
      );
    }

    const flow = (await initResponse.json()) as OidcFlow;
    if (!flow.session_token_exchange_code) {
      throw new Error('Kratos returned no session token exchange code');
    }

    const submitResponse = await fetch(flow.ui.action, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json',
      },
      body: JSON.stringify({ method: 'oidc', provider }),
    });
    const submitBody = (await submitResponse.json().catch(() => ({}))) as {
      redirect_browser_to?: string;
    };
    if (!submitBody.redirect_browser_to) {
      throw new Error(
        `Kratos did not return an OAuth redirect (${submitResponse.status})`,
      );
    }

    const returnCode = await waitForOidcCallback(
      popup,
      submitBody.redirect_browser_to,
    );
    const exchangeResponse = await fetch(
      `${KRATOS_URL}/sessions/token-exchange` +
        `?init_code=${encodeURIComponent(flow.session_token_exchange_code)}` +
        `&return_to_code=${encodeURIComponent(returnCode)}`,
      { headers: { Accept: 'application/json' } },
    );
    if (!exchangeResponse.ok) {
      throw new Error(
        `Kratos token exchange failed (${exchangeResponse.status})`,
      );
    }

    const exchange = (await exchangeResponse.json()) as {
      session_token?: string;
    };
    if (!exchange.session_token) {
      throw new Error('Kratos token exchange returned no session token');
    }
    return exchange.session_token;
  } catch (error) {
    popup.close();
    throw error;
  }
}

function waitForOidcCallback(popup: Window, authUrl: string): Promise<string> {
  popup.location.href = authUrl;

  return new Promise((resolve, reject) => {
    let settled = false;
    const timer = window.setInterval(() => {
      if (popup.closed) {
        finish();
        reject(new Error('Sign-in cancelled'));
      }
    }, 500);

    const onMessage = (event: MessageEvent) => {
      if (event.origin !== window.location.origin) return;
      const data = event.data as {
        source?: string;
        code?: string;
        error?: string;
      } | null;
      if (!data || data.source !== 'kawai-oidc') return;
      finish();
      if (data.code) resolve(data.code);
      else reject(new Error(data.error ?? 'Sign-in failed'));
    };

    function finish() {
      if (settled) return;
      settled = true;
      window.clearInterval(timer);
      window.removeEventListener('message', onMessage);
      popup.close();
    }

    window.addEventListener('message', onMessage);
  });
}
