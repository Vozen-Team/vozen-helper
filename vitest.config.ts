import { defineConfig } from 'vitest/config';
import { MOD_ENV } from './tests/fixtures/mod-env.js';

export default defineConfig({ test: { env: MOD_ENV } });
