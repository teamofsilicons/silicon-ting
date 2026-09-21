import { defineConfig } from 'vite';
import solid from 'vite-plugin-solid';

export default defineConfig({
  plugins: [solid()],
  server: { proxy: { '/v1': { target: process.env.TING_DEV_API || 'http://127.0.0.1:8080', ws: true } } },
  build: { target: 'es2022' },
});
