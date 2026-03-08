import { AlertSummary, AlertDetail, Repository, ScanRun, Remediation } from '../types/api';

const BASE_URL = import.meta.env.VITE_API_URL ?? 'http://localhost:8000';

async function fetchWithAuth(url: string, token: string, options: RequestInit = {}) {
  const headers = new Headers(options.headers);
  headers.set('Authorization', `Bearer ${token}`);
  if (!headers.has('Content-Type')) {
    headers.set('Content-Type', 'application/json');
  }

  const response = await fetch(`${BASE_URL}${url}`, {
    ...options,
    headers,
  });

  if (!response.ok) {
    const errorText = await response.text();
    throw new Error(`API Error: ${response.status} - ${errorText}`);
  }

  return response.json();
}

export async function fetchRepos(token: string): Promise<Repository[]> {
  return fetchWithAuth('/repos', token);
}

export async function createRepo(token: string, name: string, local_path: string): Promise<Repository> {
  return fetchWithAuth('/repos', token, {
    method: 'POST',
    body: JSON.stringify({ name, local_path }),
  });
}

export async function triggerScan(token: string, repoId: number): Promise<{ id: number }> {
  return fetchWithAuth(`/repos/${repoId}/scan`, token, {
    method: 'POST',
  });
}

export async function fetchScanStatus(token: string, scanId: number): Promise<ScanRun> {
  return fetchWithAuth(`/scans/${scanId}/status`, token);
}

export async function fetchAlerts(token: string, repoId: number): Promise<AlertSummary[]> {
  return fetchWithAuth(`/repos/${repoId}/alerts`, token);
}

export async function fetchAlertDetail(token: string, alertId: number): Promise<AlertDetail> {
  return fetchWithAuth(`/alerts/${alertId}`, token);
}

export async function fetchRemediation(token: string, alertId: number): Promise<Remediation> {
  return fetchWithAuth(`/alerts/${alertId}/remediation`, token);
}
