import { resolve } from 'path';
import { defineConfig } from 'vite';

export default defineConfig({
  // Vite root can be the project root
  base: './',
  build: {
    rollupOptions: {
      input: {
        main: resolve(__dirname, 'index.html'),
        pgp: resolve(__dirname, 'pgp-gen.html'),
      },
    },
  },
  server: {
    open: true, // Automatically open browser on dev start
  }
});
