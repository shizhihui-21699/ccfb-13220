import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// The Go server embeds web/dist and serves it at /. Single-file output keeps
// the embed simple: one JS and one CSS asset next to index.html.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: '../internal/server/dist',
    emptyOutDir: true,
    assetsInlineLimit: 0,
    rollupOptions: {
      output: {
        entryFileNames: 'app.js',
        assetFileNames: 'app.[ext]',
        chunkFileNames: 'chunk-[name].js',
      },
    },
  },
  server: {
    proxy: { '/api': 'http://127.0.0.1:8765' },
  },
})
