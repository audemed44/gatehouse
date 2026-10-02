import preact from "@preact/preset-vite";
import { defineConfig } from "vite";

export default defineConfig({
  plugins: [preact()],
  build: { outDir: "../web/dist", emptyOutDir: true, assetsInlineLimit: 0 },
  server: {
    // `npm run dev` proxies the API to a local `gatehouse` admin port (or GATEHOUSE_URL).
    // Keep the Host header: Gatehouse refuses writes whose Origin doesn't match it.
    proxy: {
      "/api": { target: process.env.GATEHOUSE_URL ?? "http://localhost:8081", changeOrigin: false },
    },
  },
  test: { environment: "jsdom" },
});
