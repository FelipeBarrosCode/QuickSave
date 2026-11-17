import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  clearScreen: false,
  server: {
    host: '127.0.0.1',
    port: 1420,
    strictPort: true,
    watch: { ignored: ['**/src-tauri/**'] },
  },
  build: {
    target: ['es2022', 'chrome105', 'safari15'],
    sourcemap: false,
  },
  test: {
    environment: 'jsdom',
    restoreMocks: true,
    clearMocks: true,
    maxWorkers: 2,
    minWorkers: 1,
    include: ['src/**/*.test.{ts,tsx}'],
  },
})
