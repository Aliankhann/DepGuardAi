import { useState, useEffect, useCallback } from 'react';
import { useAuth0 } from '@auth0/auth0-react';
import { fetchAlerts } from '../lib/api';
import { AlertSummary } from '../types/api';

export function useAlerts(repoId: number) {
  const { getAccessTokenSilently } = useAuth0();
  const [alerts, setAlerts] = useState<AlertSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  const loadAlerts = useCallback(async () => {
    try {
      setLoading(true);
      const token = await getAccessTokenSilently();
      const data = await fetchAlerts(token, repoId);
      setAlerts(data);
      setError(null);
    } catch (err: any) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, [getAccessTokenSilently, repoId]);

  useEffect(() => {
    if (repoId) {
      loadAlerts();
    }
  }, [loadAlerts, repoId]);

  return { alerts, loading, error, refetch: loadAlerts };
}
