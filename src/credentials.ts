/**
 * Credential abstraction for per-user OAuth2 and shared API key modes.
 *
 * Uses AsyncLocalStorage to propagate per-request credentials through the
 * call stack without modifying every API function signature.
 *
 * - HTTP transport (per-user): credentials come from AuthInfo (Bearer token)
 * - stdio transport (shared):  credentials come from FACTORIAL_API_KEY env var
 */

import { AsyncLocalStorage } from 'node:async_hooks';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { getApiKey } from './config.js';

export type Credentials =
  | { mode: 'api-key'; apiKey: string }
  | { mode: 'bearer'; accessToken: string };

const credentialStore = new AsyncLocalStorage<Credentials>();

/**
 * Run a function with credentials bound to the current async context.
 * All downstream calls to getCurrentCredentials() will return these creds.
 */
export function withCredentials<T>(creds: Credentials, fn: () => T | Promise<T>): T | Promise<T> {
  return credentialStore.run(creds, fn);
}

/**
 * Get credentials from the current async context.
 * Returns undefined if no credentials have been set (falls back in factorialRequest).
 */
export function getCurrentCredentials(): Credentials | undefined {
  return credentialStore.getStore();
}

/**
 * Build credentials from the MCP request's AuthInfo.
 * Falls back to env-based API key when authInfo is absent (stdio mode).
 */
export function credentialsFromAuthInfo(authInfo?: AuthInfo): Credentials {
  if (authInfo?.token) {
    return { mode: 'bearer', accessToken: authInfo.token };
  }
  return credentialsFromEnv();
}

/**
 * Build credentials from environment variables (stdio / shared-key mode).
 */
export function credentialsFromEnv(): Credentials {
  return { mode: 'api-key', apiKey: getApiKey() };
}
