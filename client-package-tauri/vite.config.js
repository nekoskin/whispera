import { defineConfig } from 'vite';

export default defineConfig({
  // prevent vite from obscuring rust errors
  clearScreen: false,
  // Tauri expects a fixed port, fail if that port is not available
  server: {
    port: 1420,
    strictPort: true,
    host: '127.0.0.1', // Listen on IPv4
    watch: {
      // Tell vite to ignore watching `src-tauri`
      ignored: ['**/src-tauri/**'],
    },
  },
  root: './src', // Serve files from src directory
  build: {
    outDir: '../dist', // Match tauri.conf.json build.frontendDist
    emptyOutDir: true,
  },
});

