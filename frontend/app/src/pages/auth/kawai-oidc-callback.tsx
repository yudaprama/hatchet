import { useEffect } from 'react';

export function KawaiOidcCallback() {
  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    const code = params.get('code');
    const error = params.get('error_description') ?? params.get('error');

    if (window.opener) {
      window.opener.postMessage(
        {
          source: 'kawai-oidc',
          code: code ?? undefined,
          error: error ?? undefined,
        },
        window.location.origin,
      );
      window.close();
    } else {
      window.location.replace('/auth/login');
    }
  }, []);

  return (
    <div className="flex h-dvh items-center justify-center text-sm text-muted-foreground">
      You can close this window.
    </div>
  );
}
