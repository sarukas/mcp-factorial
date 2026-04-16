#!/usr/bin/env node

/**
 * MCP Server for FactorialHR — stdio transport entry point.
 *
 * For HTTP transport (Kubernetes / remote deployment), use src/http-server.ts instead.
 */

import { loadEnv } from '../config.js';

// Load environment variables before other imports
loadEnv();

import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { cache } from '../cache.js';
import { createServer } from '../server.js';

const server = createServer();

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);

  // Clear cache on shutdown
  process.on('SIGINT', () => {
    cache.clear();
    process.exit(0);
  });

  process.on('SIGTERM', () => {
    cache.clear();
    process.exit(0);
  });
}

main().catch(error => {
  console.error('Fatal error:', error);
  process.exit(1);
});

// Export server for testing
export { server };
