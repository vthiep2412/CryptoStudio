import { resolve } from 'path';
import { defineConfig } from 'vite';

export default defineConfig({
  // Vite root can be the project root
  base: './',
  build: {
    rollupOptions: {
      input: {
        main: resolve(import.meta.dirname, 'index.html'),
        pgp: resolve(import.meta.dirname, 'pgp-gen.html'),
      },
    },
  },
  server: {
    open: true, // Automatically open browser on dev start
  }
});
