import { defineConfig } from 'tsup'

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    'integrations/nextjs/index': 'src/integrations/nextjs/index.ts',
    'integrations/ollama/index': 'src/integrations/ollama/index.ts',
    'integrations/anthropic/index': 'src/integrations/anthropic/index.ts',
  },
  format: ['cjs', 'esm'],
  dts: true,
  clean: true,
  sourcemap: true,
  splitting: false,
  treeshake: true,
  target: 'es2022',
  outDir: 'dist',
})
