const SESSION_TOKEN_KEY = 'kawai:kratos-session-token';
const KRATOS_URL =
  import.meta.env.VITE_KRATOS_URL ??
  'https://backend.kawai.pro/.ory/kratos/public';

export function isPublicAuthPath(pathname = window.location.pathname): boolean {
  return pathname === '/oidc-callback' || pathname.startsWith('/auth/');
}

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

    // Kratos intentionally requires a browser navigation for OIDC. Posting
    // this as fetch returns 422 browser_location_change_required, even though
    // the response contains a valid redirect URL. Submit a normal HTML form
    // in the popup so Kratos can redirect the browser to Google directly.
    submitOidcForm(popup, flow.ui.action, provider);

    const returnCode = await waitForOidcCallback(popup);
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

function submitOidcForm(
  popup: Window,
  action: string,
  provider: 'google' | 'github',
): void {
  const document = popup.document;
  document.open();
  document.write('<!doctype html><html><body></body></html>');
  document.close();

  const form = document.createElement('form');
  form.method = 'POST';
  form.action = action;
  form.style.display = 'none';

  const method = document.createElement('input');
  method.name = 'method';
  method.value = 'oidc';
  form.appendChild(method);

  const providerInput = document.createElement('input');
  providerInput.name = 'provider';
  providerInput.value = provider;
  form.appendChild(providerInput);

  document.body.appendChild(form);
  form.submit();
}

function waitForOidcCallback(popup: Window): Promise<string> {
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
