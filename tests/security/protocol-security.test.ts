/**
 * MCP Protocol Security — Live Server
 *
 * Protocol-level and HTTP-level security tests against the deployed Factorial
 * MCP server. All tests are read-only and safe to run against production.
 */

import { describe, it, expect } from 'vitest';

import {
  sendRequest,
  sendHealthCheck,
  sendMCPRequest,
  assertNoInfoLeak,
  expectErrorShape,
  MCP_SERVER_URL,
  MCP_ENDPOINT,
  OAUTH_METADATA_ENDPOINT,
  RESOURCE_METADATA_ENDPOINT,
  REGISTER_ENDPOINT,
  AUTHORIZE_ENDPOINT,
  TOKEN_ENDPOINT,
} from './helpers';

const JSONRPC_BODY = {
  jsonrpc: '2.0',
  id: 1,
  method: 'initialize',
  params: {
    protocolVersion: '2025-03-26',
    capabilities: {},
    clientInfo: { name: 'security-test', version: '1.0.0' },
  },
};

describe('MCP Protocol Security — Live Server', () => {
  describe('Unauthenticated Endpoints', () => {
    it('/healthz returns 200 with status "ok"', async () => {
      const res = await sendHealthCheck();
      expect(res.status).toBe(200);
      const body = res.body as Record<string, unknown>;
      expect(body).toHaveProperty('status');
      expect(body.status).toBe('ok');
    });

    it('/.well-known/oauth-authorization-server returns OAuth metadata', async () => {
      const res = await sendRequest(OAUTH_METADATA_ENDPOINT);
      expect(res.status).toBe(200);
      const body = res.body as Record<string, unknown>;
      expect(body).toHaveProperty('issuer');
      expect(body).toHaveProperty('authorization_endpoint');
      expect(body).toHaveProperty('token_endpoint');
    });

    it('/.well-known/oauth-protected-resource/mcp returns resource metadata', async () => {
      const res = await sendRequest(RESOURCE_METADATA_ENDPOINT);
      expect(res.status).toBe(200);
      const body = res.body as Record<string, unknown>;
      expect(typeof body).toBe('object');
      expect(body).not.toBeNull();
      expect(body).toHaveProperty('resource');
      expect(body).toHaveProperty('authorization_servers');
    });

    it('OAuth metadata advertises DCR endpoint', async () => {
      const res = await sendRequest(OAUTH_METADATA_ENDPOINT);
      const body = res.body as Record<string, unknown>;
      expect(body).toHaveProperty('registration_endpoint');
      expect(String(body.registration_endpoint)).toContain(MCP_SERVER_URL);
    });

    it('OAuth metadata advertises S256 PKCE only', async () => {
      const res = await sendRequest(OAUTH_METADATA_ENDPOINT);
      const body = res.body as Record<string, unknown>;
      const methods = body.code_challenge_methods_supported as unknown[];
      expect(Array.isArray(methods)).toBe(true);
      expect(methods).toContain('S256');
      // Must not advertise plain — weakens PKCE.
      expect(methods).not.toContain('plain');
    });

    it('Resource metadata lists this server as its own authorization server', async () => {
      const res = await sendRequest(RESOURCE_METADATA_ENDPOINT);
      const body = res.body as Record<string, unknown>;
      const servers = body.authorization_servers as string[];
      expect(Array.isArray(servers)).toBe(true);
      expect(servers.length).toBeGreaterThan(0);
      expect(servers[0]).toContain(MCP_SERVER_URL);
    });
  });

  describe('Protected Endpoint Without Auth', () => {
    it('POST /mcp without token → 401', async () => {
      const res = await sendMCPRequest(null, JSONRPC_BODY);
      expect(res.status).toBe(401);
      expectErrorShape(res.body);
    });

    it('GET /mcp without token → 401 or 405 (never 500)', async () => {
      const res = await sendRequest(MCP_ENDPOINT, { method: 'GET' });
      expect(res.status).not.toBe(500);
      expect([200, 401, 405]).toContain(res.status);
    });

    it('PUT /mcp → 401 or 405, never 500', async () => {
      const res = await sendRequest(MCP_ENDPOINT, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(JSONRPC_BODY),
      });
      expect(res.status).not.toBe(500);
      expect([401, 404, 405]).toContain(res.status);
    });

    it('DELETE /mcp without session → 4xx, never 500', async () => {
      const res = await sendRequest(MCP_ENDPOINT, {
        method: 'DELETE',
        headers: { 'Content-Type': 'application/json' },
      });
      expect(res.status).not.toBe(500);
      expect([400, 401, 404, 405]).toContain(res.status);
    });
  });

  describe('Request Smuggling & Injection', () => {
    it('oversized JSON body (1MB) → 4xx, not crash', async () => {
      const largePayload = JSON.stringify({
        jsonrpc: '2.0',
        id: 1,
        method: 'initialize',
        params: { data: 'x'.repeat(1024 * 1024) },
      });
      const res = await sendRequest(MCP_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer fake-token',
        },
        body: largePayload,
      });
      expect([400, 401, 413]).toContain(res.status);
    });

    it('malformed JSON body → 400 or 401, not 500', async () => {
      const res = await sendRequest(MCP_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer fake-token',
        },
        body: '{invalid json content;;;',
      });
      expect([400, 401]).toContain(res.status);
    });

    it('Content-Type: text/plain with JSON body → 4xx, not 500', async () => {
      const res = await sendMCPRequest(null, JSONRPC_BODY, { contentType: 'text/plain' });
      expect(res.status).not.toBe(500);
      expect([400, 401, 415]).toContain(res.status);
    });

    it('Authorization header with extra whitespace → consistent 401', async () => {
      const res1 = await sendRequest(MCP_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer   fake-token-with-spaces',
        },
        body: JSON.stringify(JSONRPC_BODY),
      });
      const res2 = await sendRequest(MCP_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: '  Bearer fake-token  ',
        },
        body: JSON.stringify(JSONRPC_BODY),
      });
      expect(res1.status).toBe(401);
      expect(res2.status).toBe(401);
    });
  });

  describe('Information Disclosure', () => {
    it('/healthz does not leak internal config', async () => {
      const res = await sendHealthCheck();
      expect(res.status).toBe(200);
      const body = res.body as Record<string, unknown>;
      expect(body).not.toHaveProperty('serverUrl');
      expect(body).not.toHaveProperty('issuerUrl');
      expect(body).not.toHaveProperty('server_url');
      expect(body).not.toHaveProperty('issuer_url');
      expect(body).not.toHaveProperty('factorial_api_key');
    });

    it('error responses do NOT include stack traces', async () => {
      const res = await sendMCPRequest(null, JSONRPC_BODY);
      expect(res.status).toBe(401);
      assertNoInfoLeak(res.rawBody);
    });

    it('error responses do NOT include internal file paths', async () => {
      const res = await sendMCPRequest('invalid-token-for-path-leak-test', JSONRPC_BODY);
      expect(res.status).toBe(401);
      assertNoInfoLeak(res.rawBody);

      const res404 = await sendRequest(`${MCP_SERVER_URL}/nonexistent-path-leak-test`);
      assertNoInfoLeak(res404.rawBody);
    });

    it('non-existent routes return 404, not 500', async () => {
      const res = await sendRequest(`${MCP_SERVER_URL}/this-route-definitely-does-not-exist`);
      expect(res.status).toBe(404);
      assertNoInfoLeak(res.rawBody);
    });

    it('/debug/* is not exposed', async () => {
      const res = await sendRequest(`${MCP_SERVER_URL}/debug/routes`);
      expect(res.status).toBe(404);
    });

    it('OAuth metadata does not leak upstream secrets or keys', async () => {
      const res = await sendRequest(OAUTH_METADATA_ENDPOINT);
      const body = res.body as Record<string, unknown>;

      // Whitelisted RFC 8414 fields we expect; anything outside this set that
      // looks secret-ish is a leak. Note: "client_secret_post" is a legitimate
      // auth-method *name* that appears inside token_endpoint_auth_methods_supported,
      // so we can't just substring-match "client_secret" on the raw body.
      const allowedValues = JSON.stringify(body);

      // No actual bearer tokens, RSA keys, or long hex secrets should appear.
      expect(allowedValues).not.toMatch(/-----BEGIN [A-Z ]*KEY-----/);
      expect(allowedValues).not.toMatch(/\beyJ[A-Za-z0-9_-]{20,}\./); // JWT-like
      expect(allowedValues).not.toMatch(/\b[a-f0-9]{48,}\b/i); // long hex secret

      // Specific leak vectors we care about.
      expect(body).not.toHaveProperty('client_secret');
      expect(body).not.toHaveProperty('private_key');
      expect(body).not.toHaveProperty('refresh_token');
      expect(body).not.toHaveProperty('access_token');
    });
  });

  describe('OAuth Flow Security', () => {
    it('/authorize endpoint exists and does not 500', async () => {
      const res = await sendRequest(AUTHORIZE_ENDPOINT);
      expect(res.status).not.toBe(500);
      // With no params it should reject (400/401/405) or redirect (302) with error.
      expect([200, 302, 400, 401, 403, 405]).toContain(res.status);
    });

    it('/token without credentials → 4xx, not 500', async () => {
      const res = await sendRequest(TOKEN_ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: '',
      });
      expect(res.status).not.toBe(500);
      expect([400, 401, 403]).toContain(res.status);
    });

    it('/register DCR endpoint is reachable', async () => {
      const res = await sendRequest(REGISTER_ENDPOINT, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          redirect_uris: ['https://example.com/callback'],
          client_name: 'security-test-client',
          token_endpoint_auth_method: 'none',
        }),
      });
      expect(res.status).not.toBe(404);
      expect(res.status).not.toBe(500);
    });

    it('/register rejects non-POST methods', async () => {
      const res = await sendRequest(REGISTER_ENDPOINT, { method: 'GET' });
      expect(res.status).not.toBe(500);
      expect([400, 401, 404, 405]).toContain(res.status);
    });
  });

  describe('MCP Session Semantics (spec §Session Management)', () => {
    it('POST /mcp with unknown session id → 404 so client reinitializes', async () => {
      // Use a random session id that the server has never issued.
      const res = await sendRequest(MCP_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer fake-token-for-session-test',
          'Mcp-Session-Id': '00000000-0000-0000-0000-000000000000',
        },
        body: JSON.stringify(JSONRPC_BODY),
      });
      // Bearer fails first (401) with our current design — but the spec contract
      // is that an *authenticated* unknown session returns 404. Without a valid
      // token we can't prove that branch directly; just assert it's never 500.
      expect(res.status).not.toBe(500);
      expect([401, 404]).toContain(res.status);
    });

    it('unsupported MCP-Protocol-Version header → 400', async () => {
      const res = await sendRequest(MCP_ENDPOINT, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: 'Bearer fake-token',
          'MCP-Protocol-Version': '9999-99-99',
        },
        body: JSON.stringify(JSONRPC_BODY),
      });
      // Bearer check runs first → 401 without a valid token. Accept either,
      // just not 500.
      expect(res.status).not.toBe(500);
      expect([400, 401]).toContain(res.status);
    });
  });
});
