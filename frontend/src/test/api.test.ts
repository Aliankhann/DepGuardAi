/**
 * Unit tests for lib/api.ts
 *
 * Mocks globalThis.fetch with vi.fn() to verify:
 * - Authorization header is always sent
 * - Content-Type is set to application/json
 * - Correct HTTP method and URL are used per function
 * - Non-ok responses throw an Error with status + body
 * - Successful responses return parsed JSON
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  fetchRepos,
  createRepo,
  triggerScan,
  fetchScanStatus,
  fetchAlerts,
  fetchAlertDetail,
  fetchRemediation,
} from "../lib/api";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeOkResponse(body: unknown): Response {
  return {
    ok: true,
    status: 200,
    json: () => Promise.resolve(body),
    text: () => Promise.resolve(JSON.stringify(body)),
  } as unknown as Response;
}

function makeErrorResponse(status: number, body: string): Response {
  return {
    ok: false,
    status,
    json: () => Promise.reject(new Error("not json")),
    text: () => Promise.resolve(body),
  } as unknown as Response;
}

const TOKEN = "test-bearer-token";

beforeEach(() => {
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// Authorization header
// ---------------------------------------------------------------------------

describe("fetchWithAuth — Authorization header", () => {
  it("always sets Authorization: Bearer <token>", async () => {
    const mockFetch = vi.fn().mockResolvedValue(makeOkResponse([]));
    vi.stubGlobal("fetch", mockFetch);

    await fetchRepos(TOKEN);

    const [, options] = mockFetch.mock.calls[0];
    const headers = options.headers as Headers;
    expect(headers.get("Authorization")).toBe(`Bearer ${TOKEN}`);
  });

  it("sets Content-Type: application/json by default", async () => {
    const mockFetch = vi.fn().mockResolvedValue(makeOkResponse([]));
    vi.stubGlobal("fetch", mockFetch);

    await fetchRepos(TOKEN);

    const [, options] = mockFetch.mock.calls[0];
    const headers = options.headers as Headers;
    expect(headers.get("Content-Type")).toBe("application/json");
  });

  it("uses the token passed in, not a hardcoded value", async () => {
    const mockFetch = vi.fn().mockResolvedValue(makeOkResponse([]));
    vi.stubGlobal("fetch", mockFetch);

    const customToken = "my-custom-token-xyz";
    await fetchRepos(customToken);

    const [, options] = mockFetch.mock.calls[0];
    const headers = options.headers as Headers;
    expect(headers.get("Authorization")).toBe(`Bearer ${customToken}`);
  });
});

// ---------------------------------------------------------------------------
// Error handling
// ---------------------------------------------------------------------------

describe("fetchWithAuth — error handling", () => {
  it("throws on 401 response", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(makeErrorResponse(401, "Unauthorized")));
    await expect(fetchRepos(TOKEN)).rejects.toThrow("API Error: 401");
  });

  it("throws on 404 response", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(makeErrorResponse(404, "Not found")));
    await expect(fetchAlertDetail(TOKEN, 999)).rejects.toThrow("API Error: 404");
  });

  it("throws on 500 response", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(makeErrorResponse(500, "Internal Server Error")));
    await expect(fetchRepos(TOKEN)).rejects.toThrow("API Error: 500");
  });

  it("includes response body text in the error message", async () => {
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(makeErrorResponse(422, "Validation failed")));
    await expect(fetchRepos(TOKEN)).rejects.toThrow("Validation failed");
  });
});

// ---------------------------------------------------------------------------
// fetchRepos
// ---------------------------------------------------------------------------

describe("fetchRepos", () => {
  it("calls GET /repos", async () => {
    const mockFetch = vi.fn().mockResolvedValue(makeOkResponse([]));
    vi.stubGlobal("fetch", mockFetch);

    await fetchRepos(TOKEN);

    const [url, options] = mockFetch.mock.calls[0];
    expect(url).toContain("/repos");
    expect(options.method).toBeUndefined(); // default GET
  });

  it("returns parsed JSON array", async () => {
    const repos = [{ id: 1, name: "my-app" }];
    vi.stubGlobal("fetch", vi.fn().mockResolvedValue(makeOkResponse(repos)));

    const result = await fetchRepos(TOKEN);
    expect(result).toEqual(repos);
  });
});

// ---------------------------------------------------------------------------
// createRepo
// ---------------------------------------------------------------------------

describe("createRepo", () => {
  it("calls POST /repos with name and local_path in body", async () => {
    const mockFetch = vi.fn().mockResolvedValue(makeOkResponse({ id: 1, name: "app" }));
    vi.stubGlobal("fetch", mockFetch);

    await createRepo(TOKEN, "app", "/code/app");

    const [url, options] = mockFetch.mock.calls[0];
    expect(url).toContain("/repos");
    expect(options.method).toBe("POST");
    const body = JSON.parse(options.body as string);
    expect(body.name).toBe("app");
    expect(body.local_path).toBe("/code/app");
  });
});

// ---------------------------------------------------------------------------
// triggerScan
// ---------------------------------------------------------------------------

describe("triggerScan", () => {
  it("calls POST /repos/{id}/scan", async () => {
    const mockFetch = vi.fn().mockResolvedValue(makeOkResponse({ id: 42, status: "pending" }));
    vi.stubGlobal("fetch", mockFetch);

    await triggerScan(TOKEN, 5);

    const [url, options] = mockFetch.mock.calls[0];
    expect(url).toContain("/repos/5/scan");
    expect(options.method).toBe("POST");
  });
});

// ---------------------------------------------------------------------------
// fetchScanStatus
// ---------------------------------------------------------------------------

describe("fetchScanStatus", () => {
  it("calls GET /scans/{id}/status", async () => {
    const mockFetch = vi.fn().mockResolvedValue(makeOkResponse({ id: 7, status: "complete" }));
    vi.stubGlobal("fetch", mockFetch);

    await fetchScanStatus(TOKEN, 7);

    const [url] = mockFetch.mock.calls[0];
    expect(url).toContain("/scans/7/status");
  });
});

// ---------------------------------------------------------------------------
// fetchAlerts
// ---------------------------------------------------------------------------

describe("fetchAlerts", () => {
  it("calls GET /repos/{id}/alerts", async () => {
    const mockFetch = vi.fn().mockResolvedValue(makeOkResponse([]));
    vi.stubGlobal("fetch", mockFetch);

    await fetchAlerts(TOKEN, 3);

    const [url] = mockFetch.mock.calls[0];
    expect(url).toContain("/repos/3/alerts");
  });
});

// ---------------------------------------------------------------------------
// fetchAlertDetail
// ---------------------------------------------------------------------------

describe("fetchAlertDetail", () => {
  it("calls GET /alerts/{id}", async () => {
    const mockFetch = vi.fn().mockResolvedValue(makeOkResponse({ id: 9 }));
    vi.stubGlobal("fetch", mockFetch);

    await fetchAlertDetail(TOKEN, 9);

    const [url] = mockFetch.mock.calls[0];
    expect(url).toContain("/alerts/9");
  });
});

// ---------------------------------------------------------------------------
// fetchRemediation
// ---------------------------------------------------------------------------

describe("fetchRemediation", () => {
  it("calls GET /alerts/{id}/remediation", async () => {
    const mockFetch = vi.fn().mockResolvedValue(makeOkResponse({ id: 2 }));
    vi.stubGlobal("fetch", mockFetch);

    await fetchRemediation(TOKEN, 2);

    const [url] = mockFetch.mock.calls[0];
    expect(url).toContain("/alerts/2/remediation");
  });
});
