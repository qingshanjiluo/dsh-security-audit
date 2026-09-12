/**
 * tsdown entry configuration for the host-only security audit plugin: the
 * bundle keeps the Cordis/dsh-tools surface external and emits types.
 * @module
 */
import { defineConfig } from 'tsdown'

export default defineConfig({
  entry: { index: 'src/index.ts' },
  outDir: 'lib',
  format: ['esm'],
  platform: 'node',
  target: 'es2022',
  external: [/^@deepseek-ai\//, /^node:/],
  dts: true,
  clean: true,
  tsconfig: 'tsconfig.json',
})
