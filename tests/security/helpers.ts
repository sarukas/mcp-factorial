/**
 * Security Test Helpers
 *
 * Utilities for crafting adversarial Bearer tokens and making HTTP requests
 * against the live MCP server for security testing.
 *
 * Factorial's OAuth2 server issues opaque Bearer tokens, not JWTs, so the
 * JWT-crafting helpers here act as fuzz inputs — we expect the server to
 * treat them all as unknown tokens and return 401 via the Factorial token
 * verification path.
 */

import * as jose from 'jose';
import { expect } from 'vitest';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

export const MCP_SERVER_URL =
  process.env.MCP_SERVER_URL ?? 'https://mcp-factorial-production.up.railway.app';
export const MCP_ENDPOINT = `${MCP_SERVER_URL}/mcp`;
export const HEALTH_ENDPOINT = `${MCP_SERVER_URL}/healthz`;
export const OAUTH_METADATA_ENDPOINT = `${MCP_SERVER_URL}/.well-known/oauth-authorization-server`;
export const RESOURCE_METADATA_ENDPOINT = `${MCP_SERVER_URL}/.well-known/oauth-protected-resource/mcp`;
export const REGISTER_ENDPOINT = `${MCP_SERVER_URL}/register`;
export const AUTHORIZE_ENDPOINT = `${MCP_SERVER_URL}/authorize`;
export const TOKEN_ENDPOINT = `${MCP_SERVER_URL}/token`;

/** Realistic-looking issuer — not the real Factorial issuer. */
const FAKE_ISSUER = 'https://fake-oauth.example.com';

/** Baseline JWT payload shape. */
const BASE_PAYLOAD = {
  sub: 'fake-user-id-12345',
  email: 'attacker@evil.com',
  aud: 'authenticated',
  role: 'authenticated',
  iss: FAKE_ISSUER,
  iat: Math.floor(Date.now() / 1000),
  exp: Math.floor(Date.now() / 1000) + 3600,
};

// ---------------------------------------------------------------------------
// Key generation (cached per test run)
// ---------------------------------------------------------------------------

let _rsaKeyPair: CryptoKeyPair | null = null;
let _ecKeyPair: CryptoKeyPair | null = null;

export async function getRSAKeyPair(): Promise<CryptoKeyPair> {
  if (!_rsaKeyPair) {
    _rsaKeyPair = await jose.generateKeyPair('RS256');
  }
  return _rsaKeyPair;
}

export async function getECKeyPair(): Promise<CryptoKeyPair> {
  if (!_ecKeyPair) {
    _ecKeyPair = await jose.generateKeyPair('ES256');
  }
  return _ecKeyPair;
}

// ---------------------------------------------------------------------------
// JWT Crafting Utilities (adversarial — all expected to be rejected as 401)
// ---------------------------------------------------------------------------

export async function craftSelfSignedRSA(
  payloadOverrides: Record<string, unknown> = {}
): Promise<string> {
  const { privateKey } = await getRSAKeyPair();
  const payload = { ...BASE_PAYLOAD, ...payloadOverrides };
  return new jose.SignJWT(payload)
    .setProtectedHeader({ alg: 'RS256', typ: 'JWT' })
    .sign(privateKey);
}

export async function craftSelfSignedEC(
  payloadOverrides: Record<string, unknown> = {}
): Promise<string> {
  const { privateKey } = await getECKeyPair();
  const payload = { ...BASE_PAYLOAD, ...payloadOverrides };
  return new jose.SignJWT(payload)
    .setProtectedHeader({ alg: 'ES256', typ: 'JWT' })
    .sign(privateKey);
}

export function craftNoneAlgJWT(payloadOverrides: Record<string, unknown> = {}): string {
  const header = { alg: 'none', typ: 'JWT' };
  const payload = { ...BASE_PAYLOAD, ...payloadOverrides };
  return `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(payload))}.`;
}

export function craftNoneAlgEmptySignature(
  payloadOverrides: Record<string, unknown> = {}
): string {
  const header = { alg: 'none', typ: 'JWT' };
  const payload = { ...BASE_PAYLOAD, ...payloadOverrides };
  return `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(payload))}`;
}

export async function craftHS256JWT(
  payloadOverrides: Record<string, unknown> = {}
): Promise<string> {
  const secret = new TextEncoder().encode('attacker-controlled-secret-key-for-hs256');
  const payload = { ...BASE_PAYLOAD, ...payloadOverrides };
  return new jose.SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256', typ: 'JWT' })
    .sign(secret);
}

export async function craftExpiredJWT(): Promise<string> {
  return craftSelfSignedRSA({
    iat: Math.floor(Date.now() / 1000) - 7200,
    exp: Math.floor(Date.now() / 1000) - 3600,
  });
}

export async function craftFutureJWT(): Promise<string> {
  return craftSelfSignedRSA({
    nbf: Math.floor(Date.now() / 1000) + 86400,
    iat: Math.floor(Date.now() / 1000) + 86400,
    exp: Math.floor(Date.now() / 1000) + 172800,
  });
}

export async function craftWrongIssuerJWT(): Promise<string> {
  return craftSelfSignedRSA({ iss: 'https://evil-issuer.example.com' });
}

export async function craftWrongAudienceJWT(): Promise<string> {
  return craftSelfSignedRSA({ aud: 'wrong-audience-client-id' });
}

export async function craftTamperedJWT(): Promise<string> {
  const validToken = await craftSelfSignedRSA({ email: 'original@example.com' });
  const parts = validToken.split('.');
  const payload = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8'));
  payload.email = 'tampered@evil.com';
  payload.role = 'service_role';
  return `${parts[0]}.${base64url(JSON.stringify(payload))}.${parts[2]}`;
}

// ---------------------------------------------------------------------------
// HTTP Helpers
// ---------------------------------------------------------------------------

interface HTTPResponse {
  status: number;
  headers: Headers;
  body: unknown;
  rawBody: string;
}

export async function sendMCPRequest(
  token: string | null,
  body?: unknown,
  options: { method?: string; contentType?: string; headers?: Record<string, string> } = {}
): Promise<HTTPResponse> {
  const method = options.method || 'POST';
  const headers: Record<string, string> = {
    'Content-Type': options.contentType || 'application/json',
    Accept: 'application/json, text/event-stream',
    ...options.headers,
  };

  if (token !== null) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  const fetchOptions: RequestInit = { method, headers };
  if (body !== undefined && method !== 'GET') {
    fetchOptions.body = typeof body === 'string' ? body : JSON.stringify(body);
  }

  const response = await fetch(MCP_ENDPOINT, fetchOptions);
  const rawBody = await response.text();

  let parsedBody: unknown;
  try {
    parsedBody = JSON.parse(rawBody);
  } catch {
    parsedBody = rawBody;
  }

  return { status: response.status, headers: response.headers, body: parsedBody, rawBody };
}

export async function sendRequest(
  url: string,
  options: RequestInit = {}
): Promise<HTTPResponse> {
  const response = await fetch(url, options);
  const rawBody = await response.text();

  let parsedBody: unknown;
  try {
    parsedBody = JSON.parse(rawBody);
  } catch {
    parsedBody = rawBody;
  }

  return { status: response.status, headers: response.headers, body: parsedBody, rawBody };
}

export async function sendHealthCheck(): Promise<HTTPResponse> {
  return sendRequest(HEALTH_ENDPOINT);
}

export async function sendMCPRequestRawAuth(
  authHeaderValue: string | null,
  body?: unknown
): Promise<HTTPResponse> {
  const headers: Record<string, string> = {
    'Content-Type': 'application/json',
    Accept: 'application/json, text/event-stream',
  };
  if (authHeaderValue !== null) {
    headers['Authorization'] = authHeaderValue;
  }

  const response = await fetch(MCP_ENDPOINT, {
    method: 'POST',
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  const rawBody = await response.text();

  let parsedBody: unknown;
  try {
    parsedBody = JSON.parse(rawBody);
  } catch {
    parsedBody = rawBody;
  }

  return { status: response.status, headers: response.headers, body: parsedBody, rawBody };
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function base64url(str: string): string {
  return Buffer.from(str)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

export function randomGarbage(length: number): string {
  const chars =
    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars[Math.floor(Math.random() * chars.length)];
  }
  return result;
}

/**
 * Verify an error response doesn't leak sensitive information.
 */
export function assertNoInfoLeak(rawBody: string): void {
  const lowerBody = rawBody.toLowerCase();
  // Stack traces
  expect(lowerBody).not.toContain('at object.');
  expect(lowerBody).not.toContain('at module.');
  expect(lowerBody).not.toContain('at async');
  expect(lowerBody).not.toContain('node_modules');
  // File paths
  expect(lowerBody).not.toContain('/app/src/');
  expect(lowerBody).not.toContain('/app/dist/');
  expect(lowerBody).not.toContain('c:\\users\\');
  // Environment secrets
  expect(lowerBody).not.toContain('factorial_oauth_client_secret');
  expect(lowerBody).not.toContain('factorial_api_key');
  expect(lowerBody).not.toContain('client_secret');
}

/**
 * Our server uses the SDK's OAuth error shape:
 *   { error: "invalid_token", error_description: "..." }
 * but unknown-session / malformed-request endpoints use JSON-RPC shape:
 *   { jsonrpc: "2.0", error: { code, message }, id }
 * This helper accepts either and checks that *some* error signal is present.
 */
export function expectErrorShape(body: unknown): void {
  expect(typeof body).toBe('object');
  expect(body).not.toBeNull();
  const b = body as Record<string, unknown>;
  expect(b).toHaveProperty('error');
  // error can be a string (OAuth error code) or object (JSON-RPC error)
  const errorField = b.error;
  expect(['string', 'object']).toContain(typeof errorField);
}
