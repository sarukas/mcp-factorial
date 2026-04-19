/**
 * OAuth2 provider that proxies authentication to Factorial's OAuth2 server.
 *
 * Uses the MCP SDK's ProxyOAuthServerProvider to handle the full OAuth2
 * authorization code flow, with Factorial as the upstream authorization server.
 */

import { ProxyOAuthServerProvider } from '@modelcontextprotocol/sdk/server/auth/providers/proxyProvider.js';
import type { OAuthClientInformationFull } from '@modelcontextprotocol/sdk/shared/auth.js';
import type { AuthInfo } from '@modelcontextprotocol/sdk/server/auth/types.js';
import { debug } from './config.js';

const FACTORIAL_AUTHORIZE_URL = 'https://api.factorialhr.com/oauth/authorize';
const FACTORIAL_TOKEN_URL = 'https://api.factorialhr.com/oauth/token';

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

  return new ProxyOAuthServerProvider({
    endpoints: {
      authorizationUrl: FACTORIAL_AUTHORIZE_URL,
      tokenUrl: FACTORIAL_TOKEN_URL,
    },

    /**
     * Verify an access token by calling Factorial's API.
     * If the token is valid, Factorial returns user info; otherwise 401.
     */
    verifyAccessToken: async (token: string): Promise<AuthInfo> => {
      debug('Verifying access token against Factorial API');

      const response = await fetch(
        'https://api.factorialhr.com/api/2025-10-01/resources/employees/employees',
        {
          method: 'GET',
          headers: {
            Authorization: `Bearer ${token}`,
            Accept: 'application/json',
          },
        }
      );

      if (!response.ok) {
        throw new Error(`Token verification failed: ${response.status}`);
      }

      return {
        token,
        clientId,
        scopes: ['read', 'write'],
      };
    },

    /**
     * Return client information for the configured OAuth application.
     * Since we have a single Factorial OAuth app, we just return its info.
     */
    getClient: (requestedClientId: string): Promise<OAuthClientInformationFull | undefined> => {
      if (requestedClientId !== clientId) {
        return Promise.resolve(undefined);
      }

      return Promise.resolve({
        client_id: clientId,
        client_secret: clientSecret,
        redirect_uris: [],
        client_name: 'Factorial HR MCP Server',
        grant_types: ['authorization_code', 'refresh_token'],
        response_types: ['code'],
        token_endpoint_auth_method: 'client_secret_post',
      });
    },
  });
}
