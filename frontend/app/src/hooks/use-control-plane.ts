import { controlPlaneMetaQuery } from '@/lib/api/api';
import { inferControlPlaneEnabled } from '@/lib/api/control-plane-status';
import { useQuery } from '@tanstack/react-query';
import { useLocation } from '@tanstack/react-router';
import { useMemo } from 'react';
import { isPublicAuthPath } from '@/lib/kawai-auth';

export default function useControlPlane() {
  const pathname = useLocation({ select: (location) => location.pathname });
  const isPublicAuthRoute = isPublicAuthPath(pathname);
  const result = useQuery({
    ...controlPlaneMetaQuery,
    enabled: !isPublicAuthRoute,
    refetchOnMount: 'always',
  });

  const isControlPlaneEnabled = useMemo(
    () => inferControlPlaneEnabled(result.data?.data),
    [result.data?.data],
  );

  return {
    isControlPlaneEnabled,
    isControlPlaneLoading: result.isLoading,
    controlPlaneMeta: result.data?.data,
  };
}
