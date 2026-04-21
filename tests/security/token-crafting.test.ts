/**
 * Token Crafting Attacks — Live Server
 *
 * Adversarial Bearer token tests against the deployed Factorial MCP server.
 * All tests are read-only (upstream Factorial rejects unknown tokens) and
 * safe to run against production. Each test sends a crafted token and
 * verifies the server responds with 401 and a spec-compliant shape.
 */

import { describe, it, expect } from 'vitest';

import {
  sendMCPRequest,
  sendMCPRequestRawAuth,
  craftSelfSignedRSA,
  craftSelfSignedEC,
  craftNoneAlgJWT,
  craftNoneAlgEmptySignature,
  craftHS256JWT,
  craftExpiredJWT,
  craftFutureJWT,
  craftWrongIssuerJWT,
  craftWrongAudienceJWT,
  craftTamperedJWT,
  randomGarbage,
  assertNoInfoLeak,
  expectErrorShape,
  RESOURCE_METADATA_ENDPOINT,
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

describe('Token Crafting Attacks — Live Server', () => {
  describe('Missing/Malformed Tokens', () => {
    it('no Authorization header → 401 with OAuth error', async () => {
      const res = await sendMCPRequest(null, JSONRPC_BODY);
      expect(res.status).toBe(401);
      expectErrorShape(res.body);
      const body = res.body as Record<string, unknown>;
      // Our server emits SDK's OAuth shape: error="invalid_token", error_description contains hint
      expect(String(body.error_description ?? body.error).toLowerCase()).toMatch(
        /missing authorization|missing bearer|no.*token/
      );
    });

    it('empty Authorization header value → 401', async () => {
      const res = await sendMCPRequestRawAuth('', JSONRPC_BODY);
      expect(res.status).toBe(401);
      expectErrorShape(res.body);
    });

    it('"Basic base64data" auth scheme → 401', async () => {
      const base64Creds = Buffer.from('user:password').toString('base64');
      const res = await sendMCPRequestRawAuth(`Basic ${base64Creds}`, JSONRPC_BODY);
      expect(res.status).toBe(401);
      expectErrorShape(res.body);
    });

    it('"Bearer" with no token after it → 401', async () => {
      const res = await sendMCPRequestRawAuth('Bearer ', JSONRPC_BODY);
      expect(res.status).toBe(401);
      expectErrorShape(res.body);
    });

    it('random garbage string as token → 401', async () => {
      const res = await sendMCPRequest(randomGarbage(64), JSONRPC_BODY);
      expect(res.status).toBe(401);
      expectErrorShape(res.body);
    });

    it('truncated JWT — single segment → 401', async () => {
      const res = await sendMCPRequest('eyJhbGciOiJSUzI1NiJ9', JSONRPC_BODY);
      expect(res.status).toBe(401);
      expectErrorShape(res.body);
    });

    it('truncated JWT — two segments, missing signature → 401', async () => {
      const res = await sendMCPRequest(
        'eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0',
        JSONRPC_BODY
      );
      expect(res.status).toBe(401);
      expectErrorShape(res.body);
    });

    it('extremely long token (10KB) → 401, not 413 or 500', async () => {
      const longToken = randomGarbage(10240);
      const res = await sendMCPRequest(longToken, JSONRPC_BODY);
      expect(res.status).toBe(401);
      expectErrorShape(res.body);
    });

    it('token with null bytes → rejected cleanly', async () => {
      const tokenWithNulls =
        'eyJhbGci\0OiJSUzI1NiJ9.\0eyJzdWIi\0OiIxMjM0NTY3ODkwIn0.\0abc';
      try {
        const res = await sendMCPRequest(tokenWithNulls, JSONRPC_BODY);
        // If the request goes through (some fetch implementations strip nulls),
        // it must be rejected, not crashed.
        expect(res.status).toBe(401);
      } catch (err) {
        // Expected: fetch rejects null bytes in headers as invalid input.
        expect(String(err)).toMatch(/invalid/i);
      }
    });
  });

  describe('Crafted JWT Attacks', () => {
    it('self-signed RSA JWT → 401', async () => {
      const token = await craftSelfSignedRSA();
      const res = await sendMCPRequest(token, JSONRPC_BODY);
      expect(res.status).toBe(401);
      expectErrorShape(res.body);
    });

    it('self-signed EC JWT → 401', async () => {
      const token = await craftSelfSignedEC();
      const res = await sendMCPRequest(token, JSONRPC_BODY);
      expect(res.status).toBe(401);
      expectErrorShape(res.body);
    });

    it('"alg": "none" with trailing dot → 401', async () => {
      const token = craftNoneAlgJWT();
      const res = await sendMCPRequest(token, JSONRPC_BODY);
      expect(res.status).toBe(401);
      expectErrorShape(res.body);
    });

    it('"alg": "none" with empty signature → 401', async () => {
      const token = craftNoneAlgEmptySignature();
      const res = await sendMCPRequest(token, JSONRPC_BODY);
      expect(res.status).toBe(401);
      expectErrorShape(res.body);
    });

    it('HS256 symmetric key (algorithm confusion) → 401', async () => {
      const token = await craftHS256JWT();
      const res = await sendMCPRequest(token, JSONRPC_BODY);
      expect(res.status).toBe(401);
      expectErrorShape(res.body);
    });

    it('expired JWT → 401', async () => {
      const token = await craftExpiredJWT();
      const res = await sendMCPRequest(token, JSONRPC_BODY);
      expect(res.status).toBe(401);
      expectErrorShape(res.body);
    });

    it('not-yet-valid JWT (nbf in future) → 401', async () => {
      const token = await craftFutureJWT();
      const res = await sendMCPRequest(token, JSONRPC_BODY);
      expect(res.status).toBe(401);
      expectErrorShape(res.body);
    });

    it('wrong issuer claim → 401', async () => {
      const token = await craftWrongIssuerJWT();
      const res = await sendMCPRequest(token, JSONRPC_BODY);
      expect(res.status).toBe(401);
      expectErrorShape(res.body);
    });

    it('wrong audience claim → 401', async () => {
      const token = await craftWrongAudienceJWT();
      const res = await sendMCPRequest(token, JSONRPC_BODY);
      expect(res.status).toBe(401);
      expectErrorShape(res.body);
    });

    it('tampered JWT (payload modified after signing) → 401', async () => {
      const token = await craftTamperedJWT();
      const res = await sendMCPRequest(token, JSONRPC_BODY);
      expect(res.status).toBe(401);
      expectErrorShape(res.body);
    });
  });

  describe('Response Format Compliance (MCP spec 2025-06-18 + RFC 9728)', () => {
    let responses: Awaited<ReturnType<typeof sendMCPRequest>>[] = [];

    const getResponses = async () => {
      if (responses.length > 0) return responses;
      const tokens = [
        null,
        randomGarbage(64),
        await craftSelfSignedRSA(),
        craftNoneAlgJWT(),
        await craftHS256JWT(),
      ];
      responses = await Promise.all(
        tokens.map(token => sendMCPRequest(token, JSONRPC_BODY))
      );
      return responses;
    };

    it('all 401 responses include WWW-Authenticate header', async () => {
      const allResponses = await getResponses();
      for (const res of allResponses) {
        expect(res.status).toBe(401);
        const wwwAuth = res.headers.get('www-authenticate');
        expect(wwwAuth, 'WWW-Authenticate header must be present').toBeTruthy();
      }
    });

    it('WWW-Authenticate contains resource_metadata URL (RFC 9728 §5.1)', async () => {
      const allResponses = await getResponses();
      for (const res of allResponses) {
        const wwwAuth = res.headers.get('www-authenticate') || '';
        expect(wwwAuth).toContain('resource_metadata');
        expect(wwwAuth).toContain(RESOURCE_METADATA_ENDPOINT);
      }
    });

    it('response body is JSON with error field', async () => {
      const allResponses = await getResponses();
      for (const res of allResponses) {
        expectErrorShape(res.body);
      }
    });

    it('no stack traces or internal details leaked', async () => {
      const allResponses = await getResponses();
      for (const res of allResponses) {
        assertNoInfoLeak(res.rawBody);
      }
    });

    it('no server version info leaked in body', async () => {
      const allResponses = await getResponses();
      for (const res of allResponses) {
        const raw = res.rawBody.toLowerCase();
        expect(raw).not.toMatch(/express[\s/]*\d/);
        expect(raw).not.toMatch(/node[\s/]*v?\d/);
      }
    });

    it('X-Powered-By header is not exposed', async () => {
      const allResponses = await getResponses();
      for (const res of allResponses) {
        const xPoweredBy = res.headers.get('x-powered-by');
        expect(xPoweredBy, 'X-Powered-By header should be disabled').toBeNull();
      }
    });
  });
});
