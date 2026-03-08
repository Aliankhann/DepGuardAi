import { useState, useEffect, useCallback } from 'react';
import { useAuth0 } from '@auth0/auth0-react';
import { fetchRepos, createRepo } from '../lib/api';
import { Repository } from '../types/api';

export function useRepos() {
  const { getAccessTokenSilently } = useAuth0();
  const [repos, setRepos] = useState<Repository[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);

  const loadRepos = useCallback(async () => {
    try {
      setLoading(true);
      const token = await getAccessTokenSilently();
      const data = await fetchRepos(token);
      setRepos(data);
      setError(null);
    } catch (err: any) {
      setError(err);
    } finally {
      setLoading(false);
    }
  }, [getAccessTokenSilently]);

  useEffect(() => {
    loadRepos();
  }, [loadRepos]);

  const addRepo = async (name: string, localPath: string) => {
    const token = await getAccessTokenSilently();
    const newRepo = await createRepo(token, name, localPath);
    setRepos((prev) => [newRepo, ...prev]);
    return newRepo;
  };

  return { repos, loading, error, refetch: loadRepos, createRepo: addRepo };
}
