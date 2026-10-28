import { defineConfig } from 'vitest/config';
import { MOD_ENV } from './tests/fixtures/mod-env.ts';

// The repository contains an embedded static-site checkout whose node:test files are
// intentionally run by that checkout's own CI. Keep the Helper suite deterministic and
// avoid treating those files as Vitest suites when running `npm test` at the repository root.
export default defineConfig({
  test: {
    env: MOD_ENV,
    include: ['tests/**/*.test.ts'],
    exclude: ['site-publish/**', 'node_modules/**'],
    pool: 'forks',
    maxWorkers: 1,
  },
});
