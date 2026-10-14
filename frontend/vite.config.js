import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// In development the API runs on :4000 (npm run dev:api).
const API = process.env.VITE_API_PROXY || "http://localhost:4000";
const proxied = ["/api", "/scan_stream", "/scan", "/scans", "/scan-results", "/scan-progress", "/health"];

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: Object.fromEntries(
      proxied.map((path) => [
        // Exact-prefix keys; /scans and /scan-* also start with /scan, which is intended.
        path === "/scan" ? "^/scan(/|$)" : path,
        { target: API, changeOrigin: true },
      ])
    ),
  },
  build: {
    target: "es2022",
    sourcemap: true,
  },
});
