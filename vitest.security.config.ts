import { defineConfig } from 'vitest/config';

/**
 * Live-server security tests. These hit the deployed Factorial MCP server
 * (default https://mcp-factorial-production.up.railway.app — override with
 * MCP_SERVER_URL env) with adversarial inputs.
 *
 * Kept separate from the default unit-test config so `npm test` stays fast
 * and hermetic. Run with `npm run test:security`.
 */
export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/security/**/*.test.ts'],
    exclude: ['node_modules', 'dist'],
    testTimeout: 30000,
    hookTimeout: 30000,
    pool: 'forks',
    fileParallelism: false,
  },
});
