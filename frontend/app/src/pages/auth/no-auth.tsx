import api from '@/lib/api';
import { controlPlaneApi, fetchControlPlaneStatus } from '@/lib/api/api';
import queryClient from '@/query-client';
import { appRoutes } from '@/router';
import { redirect } from '@tanstack/react-router';
import { AxiosError, isAxiosError } from 'axios';
import { getKawaiSessionToken } from '@/lib/kawai-auth';

const noAuthMiddleware = async () => {
  try {
    const { isControlPlaneEnabled } = await fetchControlPlaneStatus();
    const user = await queryClient.fetchQuery({
      queryKey: ['user:get'],
      queryFn: async () =>
        (
          await (isControlPlaneEnabled
            ? controlPlaneApi.cloudUserGetCurrent()
            : api.userGetCurrent())
        ).data,
    });

    if (user) {
      throw redirect({ to: appRoutes.authenticatedRoute.to });
    }
  } catch (error) {
    if (error instanceof Response) {
      throw error;
    } else if (isAxiosError(error)) {
      const axiosErr = error as AxiosError;

      if (axiosErr.response?.status === 403) {
        return;
      } else {
        throw error;
      }
    }
  }
};

export async function loader() {
  // The auth screen is public. Avoid probing protected Hatchet endpoints when
  // there is no Kawai session; those probes only produce expected 401s.
  if (!getKawaiSessionToken()) {
    return null;
  }
  await noAuthMiddleware();
  return null;
}
