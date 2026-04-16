#!/usr/bin/env node

/**
 * MCP Server for FactorialHR — Streamable HTTP transport entry point.
 *
 * Designed for remote deployment (Kubernetes, Docker, etc.).
 * Each inbound request creates a stateful MCP session backed by a
 * StreamableHTTPServerTransport from the official MCP SDK.
 *
 * Environment variables:
 *   PORT              — listen port (default 3000)
 *   MCP_HEALTH_PATH   — health endpoint path (default /healthz)
 *
 * All standard FACTORIAL_* env vars apply (see .env.example).
 */

import { loadEnv } from './config.js';

// Load environment variables before other imports
loadEnv();

import { createServer as createHttpServer, IncomingMessage, ServerResponse } from 'node:http';
import { randomUUID } from 'node:crypto';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { cache } from './cache.js';
import { createServer } from './server.js';

const PORT = parseInt(process.env.PORT || '3000', 10);
const HEALTH_PATH = process.env.MCP_HEALTH_PATH || '/healthz';
const MCP_PATH = '/mcp';

// Track active transports for cleanup
const transports = new Map<string, StreamableHTTPServerTransport>();

async function handleRequest(req: IncomingMessage, res: ServerResponse): Promise<void> {
  // Health check — used by Kubernetes liveness/readiness probes
  if (req.url === HEALTH_PATH) {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ status: 'ok' }));
    return;
  }

  // Only handle the MCP endpoint
  if (req.url !== MCP_PATH) {
    res.writeHead(404);
    res.end('Not found');
    return;
  }

  // Parse the request body for POST requests
  if (req.method === 'POST') {
    const sessionId = req.headers['mcp-session-id'] as string | undefined;
    let transport: StreamableHTTPServerTransport;

    if (sessionId && transports.has(sessionId)) {
      // Reuse existing session
      transport = transports.get(sessionId)!;
    } else if (!sessionId) {
      // New session — create transport and wire up a fresh MCP server
      transport = new StreamableHTTPServerTransport({
        sessionIdGenerator: () => randomUUID(),
      });

      const server = createServer();
      await server.connect(transport);

      // Track and clean up on close
      if (transport.sessionId) {
        transports.set(transport.sessionId, transport);
      }
      transport.onclose = () => {
        if (transport.sessionId) {
          transports.delete(transport.sessionId);
        }
      };
    } else {
      // Invalid session ID
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(
        JSON.stringify({
          error: 'Session not found. Start a new session without mcp-session-id header.',
        })
      );
      return;
    }

    await transport.handleRequest(req, res);
    return;
  }

  if (req.method === 'GET') {
    // GET on /mcp is used for SSE stream in existing sessions
    const sessionId = req.headers['mcp-session-id'] as string | undefined;
    if (sessionId && transports.has(sessionId)) {
      const transport = transports.get(sessionId)!;
      await transport.handleRequest(req, res);
      return;
    }
    res.writeHead(400, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Missing or invalid mcp-session-id header.' }));
    return;
  }

  if (req.method === 'DELETE') {
    // Session termination
    const sessionId = req.headers['mcp-session-id'] as string | undefined;
    if (sessionId && transports.has(sessionId)) {
      const transport = transports.get(sessionId)!;
      await transport.handleRequest(req, res);
      return;
    }
    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Session not found.' }));
    return;
  }

  res.writeHead(405);
  res.end('Method not allowed');
}

const httpServer = createHttpServer((req, res) => {
  handleRequest(req, res).catch(err => {
    console.error('Unhandled request error:', err);
    if (!res.headersSent) {
      res.writeHead(500);
      res.end('Internal server error');
    }
  });
});

// Graceful shutdown
function shutdown() {
  console.error('Shutting down...');
  for (const transport of transports.values()) {
    transport.close().catch(() => {});
  }
  transports.clear();
  cache.clear();
  httpServer.close(() => process.exit(0));
  // Force exit after 10s if connections don't drain
  setTimeout(() => process.exit(1), 10_000).unref();
}

process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);

httpServer.listen(PORT, () => {
  console.error(`Factorial HR MCP server (HTTP) listening on port ${PORT}`);
  console.error(`  MCP endpoint: ${MCP_PATH}`);
  console.error(`  Health check: ${HEALTH_PATH}`);
});
