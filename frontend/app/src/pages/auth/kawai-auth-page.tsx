import { AuthLayout } from './components/auth-layout';
import { AuthLegalText } from './components/auth-legal-text';
import { Button } from '@/components/v1/ui/button';
import { HatchetLogo } from '@/components/v1/ui/hatchet-logo';
import { Icons } from '@/components/v1/ui/icons';
import { setKawaiSessionToken, startKawaiSocialLogin } from '@/lib/kawai-auth';
import { appRoutes } from '@/router';
import { useQueryClient } from '@tanstack/react-query';
import { Link, useNavigate } from '@tanstack/react-router';
import { useState } from 'react';

export function KawaiAuthPage({ mode }: { mode: 'login' | 'registration' }) {
  const navigate = useNavigate();
  const queryClient = useQueryClient();
  const [busy, setBusy] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function signIn(provider: 'google' | 'github') {
    if (busy) return;
    setBusy(provider);
    setError(null);
    try {
      const token = await startKawaiSocialLogin(mode, provider);
      setKawaiSessionToken(token);
      await queryClient.invalidateQueries();
      await navigate({ to: appRoutes.authenticatedRoute.to });
    } catch (cause) {
      const message = cause instanceof Error ? cause.message : 'Sign-in failed';
      if (message !== 'Sign-in cancelled') setError(message);
    } finally {
      setBusy(null);
    }
  }

  return (
    <AuthLayout>
      <div className="flex w-full flex-col gap-3 text-center lg:text-left">
        <div className="flex justify-center pb-3 lg:hidden">
          <HatchetLogo className="h-8 w-auto" />
        </div>
        <div className="flex w-full flex-col items-center gap-2 lg:flex-row lg:justify-between">
          <h2 className="text-2xl font-semibold tracking-tight">
            {mode === 'login' ? 'Log in to continue' : 'Create an account'}
          </h2>
          <div className="text-center text-sm text-muted-foreground lg:text-right">
            {mode === 'login' ? (
              <>
                Don&apos;t have an account?{' '}
                <Link
                  to={appRoutes.authRegisterRoute.to}
                  className="font-semibold text-primary underline"
                >
                  Sign up
                </Link>
              </>
            ) : (
              <>
                Already have an account?{' '}
                <Link
                  to={appRoutes.authLoginRoute.to}
                  className="font-semibold text-primary underline"
                >
                  Log in
                </Link>
              </>
            )}
          </div>
        </div>
      </div>

      {error && <div className="text-sm text-destructive">{error}</div>}
      <div className="grid gap-3 sm:grid-flow-col">
        <Button
          variant="outline"
          fullWidth
          disabled={busy !== null}
          onClick={() => void signIn('google')}
        >
          <Icons.google className="size-4" />
          {busy === 'google' ? 'Connecting…' : 'Continue with Google'}
        </Button>
        <Button
          variant="outline"
          fullWidth
          disabled={busy !== null}
          onClick={() => void signIn('github')}
        >
          <Icons.gitHub className="size-4" />
          {busy === 'github' ? 'Connecting…' : 'Continue with GitHub'}
        </Button>
      </div>
      <div className="pt-3 space-y-5">
        <AuthLegalText />
      </div>
    </AuthLayout>
  );
}
