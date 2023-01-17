import {defineConfig} from 'tsup';

export default defineConfig({
  dts: true,
  outDir: 'lib',
  entryPoints: ['src/index.ts'],
  format: ['cjs', 'esm'],
  outExtension({format}) {
    return {
      js: `.${format}.js`,
    };
  },
});
