/**
 * OAuth2 provider that proxies authentication to Factorial's OAuth2 server.
 *
 * Uses the MCP SDK's ProxyOAuthServerProvider to handle the full OAuth2
 * authorization code flow, with Factorial as the upstream authorization server.
 *
 * Dynamic Client Registration (RFC 7591) is supported locally: Factorial has
 * no DCR endpoint, so the /register endpoint here accepts any metadata and
 * returns the configured Factorial client_id/client_secret to every caller.
 * Each registered redirect_uri is remembered so the authorize handler's
 * validation passes; Factorial itself still enforces its own redirect_uri
 * whitelist at the upstream, so MCP client callback URLs must be registered
 * with the Factorial OAuth app.
 */

import { ProxyOAuthServerProvider } from '@modelcontextprotocol/sdk/server/auth/providers/proxyProvider.js';
import { InvalidTokenError } from '@modelcontextprotocol/sdk/server/auth/errors.js';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { debug } from './config.js';

const FACTORIAL_AUTHORIZE_URL = 'https://api.factorialhr.com/oauth/authorize';
const FACTORIAL_TOKEN_URL = 'https://api.factorialhr.com/oauth/token';
const FACTORIAL_VERIFY_URL =
  'https://api.factorialhr.com/api/2025-10-01/resources/employees/employees';

// Short TTL cache for upstream token verification results. Every MCP request
// runs bearer auth, and without caching we'd hit Factorial's API on every tool
// call. 60s is short enough to catch revocations quickly.
const VERIFY_CACHE_TTL_MS = 60_000;
const verifyCache = new Map<string, { authInfo: AuthInfo; cachedAt: number }>();

/**
 * Create the OAuth provider that proxies to Factorial.
 *
 * Requires FACTORIAL_OAUTH_CLIENT_ID and FACTORIAL_OAUTH_CLIENT_SECRET
 * to be set in environment variables.
 */
export function createFactorialOAuthProvider(): ProxyOAuthServerProvider {
  const clientId = process.env.FACTORIAL_OAUTH_CLIENT_ID;
  const clientSecret = process.env.FACTORIAL_OAUTH_CLIENT_SECRET;

  if (!clientId || !clientSecret) {
    throw new Error(
      'FACTORIAL_OAUTH_CLIENT_ID and FACTORIAL_OAUTH_CLIENT_SECRET are required for HTTP transport with OAuth2.'
    );
  }

  const registeredRedirectUris = new Set<string>();

  const buildClientInfo = (): OAuthClientInformationFull => ({
    client_id: clientId,
    client_secret: clientSecret,
    redirect_uris: [...registeredRedirectUris],
    client_name: 'Factorial HR MCP Server',
    grant_types: ['authorization_code', 'refresh_token'],
    response_types: ['code'],
    token_endpoint_auth_method: 'client_secret_post',
  });

  const provider = new ProxyOAuthServerProvider({
    endpoints: {
      authorizationUrl: FACTORIAL_AUTHORIZE_URL,
      tokenUrl: FACTORIAL_TOKEN_URL,
    },

    verifyAccessToken: async (token: string): Promise<AuthInfo> => {
      const now = Date.now();
      const cached = verifyCache.get(token);
      if (cached && now - cached.cachedAt < VERIFY_CACHE_TTL_MS) {
        return cached.authInfo;
      }

      debug('Verifying access token against Factorial API');
      const response = await fetch(FACTORIAL_VERIFY_URL, {
        method: 'GET',
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: 'application/json',
        },
      });

      if (!response.ok) {
        verifyCache.delete(token);
        // Must throw an InvalidTokenError — the SDK's bearerAuth middleware
        // only produces a 401 for this subclass. A generic Error becomes 500,
        // which violates RFC 6750 and confuses MCP clients into retrying.
        throw new InvalidTokenError(`Upstream token verification failed: ${response.status}`);
      }

      // We don't know the upstream token's real expiry from the opaque Bearer
      // string. Pick a safe short window so the middleware's expiresAt check
      // passes; we re-verify against Factorial on every non-cached request.
      const authInfo: AuthInfo = {
        token,
        clientId,
        scopes: ['read', 'write'],
        expiresAt: Math.floor(now / 1000) + 3600,
      };
      verifyCache.set(token, { authInfo, cachedAt: now });
      return authInfo;
    },

    getClient: (requestedClientId: string): Promise<OAuthClientInformationFull | undefined> => {
      if (requestedClientId !== clientId) {
        return Promise.resolve(undefined);
      }
      return Promise.resolve(buildClientInfo());
    },
  });

  // ProxyOAuthServerProvider only exposes clientsStore.registerClient when an
  // upstream registrationUrl is configured. Factorial has none, so we replace
  // the getter with a local DCR implementation that hands back the configured
  // Factorial credentials and records the client's redirect_uris.
  Object.defineProperty(provider, 'clientsStore', {
    configurable: true,
    get() {
      return {
        getClient: (requestedClientId: string): Promise<OAuthClientInformationFull | undefined> => {
          if (requestedClientId !== clientId) return Promise.resolve(undefined);
          return Promise.resolve(buildClientInfo());
        },
        registerClient: (
          client: OAuthClientInformationFull
        ): Promise<OAuthClientInformationFull> => {
          for (const uri of client.redirect_uris ?? []) {
            registeredRedirectUris.add(uri);
          }
          debug(`DCR: registered redirect_uris=${JSON.stringify(client.redirect_uris)}`);
          return Promise.resolve({
            ...client,
            client_id: clientId,
            client_secret: clientSecret,
            client_id_issued_at: Math.floor(Date.now() / 1000),
            client_secret_expires_at: 0,
            token_endpoint_auth_method: 'client_secret_post',
          });
        },
      };
    },
  });

  return provider;
}
