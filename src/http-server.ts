#!/usr/bin/env node

/**
 * MCP Server for FactorialHR — Streamable HTTP transport with OAuth2.
 *
 * Uses Express with the MCP SDK's auth infrastructure:
 * - mcpAuthRouter: handles OAuth2 discovery, authorization, and token endpoints
 * - requireBearerAuth: validates Bearer tokens on /mcp requests
 * - ProxyOAuthServerProvider: proxies OAuth2 to Factorial's authorization server
 *
 * Each authenticated request carries the user's Factorial access token,
 * which is used for all API calls (per-user permissions).
 *
 * Environment variables:
 *   PORT                          — listen port (default 3000)
 *   MCP_ISSUER_URL                — public URL of this server (for OAuth metadata)
 *   FACTORIAL_OAUTH_CLIENT_ID     — Factorial OAuth2 client ID (required)
 *   FACTORIAL_OAUTH_CLIENT_SECRET — Factorial OAuth2 client secret (required)
 *
 * All standard FACTORIAL_* env vars apply (see .env.example).
 */

import { loadEnv } from './config.js';

// Load environment variables before other imports
loadEnv();

import express from 'express';
import { randomUUID } from 'node:crypto';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { mcpAuthRouter } from '@modelcontextprotocol/sdk/server/auth/router.js';
import { requireBearerAuth } from '@modelcontextprotocol/sdk/server/auth/middleware/bearerAuth.js';
import { isInitializeRequest } from '@modelcontextprotocol/sdk/types.js';
import { cache } from './cache.js';
import { createServer } from './server.js';
import { createFactorialOAuthProvider } from './factorial-oauth-provider.js';

const PORT = parseInt(process.env.PORT || '3000', 10);
const MCP_PATH = '/mcp';

// Derive issuer URL from environment or fall back to localhost
const issuerUrl = new URL(process.env.MCP_ISSUER_URL || `http://localhost:${PORT}`);

// Create OAuth provider that proxies to Factorial
const oauthProvider = createFactorialOAuthProvider();

// Track active transports for cleanup
const transports = new Map<string, StreamableHTTPServerTransport>();

const app = express();

// Trust the single upstream proxy (Railway, Fly, Heroku, K8s ingress, etc.)
// so req.ip reflects the real client from X-Forwarded-For. express-rate-limit
// refuses to run without this set when X-Forwarded-For is present.
app.set('trust proxy', 1);

// Parse JSON bodies (needed for MCP protocol messages)
app.use(express.json());

// Health check — unauthenticated, used by Kubernetes probes
app.get('/healthz', (_req, res) => {
  res.json({ status: 'ok' });
});

// Mount OAuth2 endpoints (/.well-known/*, /authorize, /token, /register)
app.use(
  mcpAuthRouter({
    provider: oauthProvider,
    issuerUrl,
  })
);

// Bearer auth middleware for MCP endpoint
const bearerAuth = requireBearerAuth({
  verifier: oauthProvider,
});

// MCP endpoint — POST (new session or existing session message)
app.post(MCP_PATH, bearerAuth, async (req, res) => {
  const sessionId = req.headers['mcp-session-id'] as string | undefined;

  if (sessionId && transports.has(sessionId)) {
    const transport = transports.get(sessionId)!;
    await transport.handleRequest(req, res, req.body);
    return;
  }

  if (!sessionId && isInitializeRequest(req.body)) {
    // New session. StreamableHTTPServerTransport assigns sessionId inside
    // handleRequest on the initialize call, so we register the transport via
    // the onsessioninitialized callback rather than reading sessionId before
    // handleRequest (which would always be undefined at that point).
    const transport: StreamableHTTPServerTransport = new StreamableHTTPServerTransport({
      sessionIdGenerator: () => randomUUID(),
      onsessioninitialized: (newSessionId: string) => {
        transports.set(newSessionId, transport);
      },
    });

    transport.onclose = () => {
      if (transport.sessionId) {
        transports.delete(transport.sessionId);
      }
    };

    const server = createServer();
    await server.connect(transport);

    // Pass req.body explicitly — express.json() has already consumed the
    // stream, so the transport cannot re-read it from req.
    await transport.handleRequest(req, res, req.body);
    return;
  }

  // Any other shape (unknown session id, or non-initialize without a session)
  res.status(400).json({
    jsonrpc: '2.0',
    error: {
      code: -32000,
      message: 'Bad Request: No valid session ID provided',
    },
    id: null,
  });
});

// MCP endpoint — GET (SSE stream for existing session)
app.get(MCP_PATH, bearerAuth, async (req, res) => {
  const sessionId = req.headers['mcp-session-id'] as string | undefined;
  if (sessionId && transports.has(sessionId)) {
    const transport = transports.get(sessionId)!;
    await transport.handleRequest(req, res);
    return;
  }
  res.status(400).json({ error: 'Missing or invalid mcp-session-id header.' });
});

// MCP endpoint — DELETE (session termination)
app.delete(MCP_PATH, bearerAuth, async (req, res) => {
  const sessionId = req.headers['mcp-session-id'] as string | undefined;
  if (sessionId && transports.has(sessionId)) {
    const transport = transports.get(sessionId)!;
    await transport.handleRequest(req, res);
    return;
  }
  res.status(404).json({ error: 'Session not found.' });
});

// Graceful shutdown
function shutdown() {
  console.error('Shutting down...');
  for (const transport of transports.values()) {
    transport.close().catch(() => {});
  }
  transports.clear();
  cache.clear();
  process.exit(0);
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

app.listen(PORT, () => {
  console.error(`Factorial HR MCP server (HTTP + OAuth2) listening on port ${PORT}`);
  console.error(`  MCP endpoint: ${MCP_PATH}`);
  console.error(`  OAuth issuer: ${issuerUrl.href}`);
  console.error(`  Health check: /healthz`);
});
