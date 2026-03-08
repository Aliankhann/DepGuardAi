import { useState, useCallback } from 'react';
import { useAuth0 } from '@auth0/auth0-react';
import { triggerScan, fetchScanStatus } from '../lib/api';
import { ScanRun } from '../types/api';

export function useScan() {
  const { getAccessTokenSilently } = useAuth0();
  const [scanStatus, setScanStatus] = useState<ScanRun | null>(null);
  const [currentAgent, setCurrentAgent] = useState<string | null>(null);

  const triggerAndPoll = useCallback(async (repoId: number) => {
    try {
      const token = await getAccessTokenSilently();
      const { id: scanId } = await triggerScan(token, repoId);
      
      return new Promise<ScanRun>((resolve, reject) => {
        const poll = async () => {
          try {
            const status = await fetchScanStatus(token, scanId);
            setScanStatus(status);
            setCurrentAgent(status.current_agent);
            
            if (status.status === 'complete' || status.status === 'failed') {
              resolve(status);
            } else {
              setTimeout(poll, 2000);
            }
          } catch (err) {
            reject(err);
          }
        };
        poll();
      });
    } catch (err) {
      throw err;
    }
  }, [getAccessTokenSilently]);

  return { scanStatus, currentAgent, triggerAndPoll };
}
