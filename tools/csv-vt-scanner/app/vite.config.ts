import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import path from "path";

const pagesBase = process.env.GITHUB_PAGES === "true" ? "/soc-automation-hub/" : "./";

export default defineConfig({
  root: path.resolve(__dirname),
  base: pagesBase,
  plugins: [react()],
  clearScreen: false,
  server: {
    port: 1421,
    strictPort: true,
  },
  envPrefix: ["VITE_", "TAURI_"],
  build: {
    target: "esnext",
    outDir: path.resolve(__dirname, "../dist"),
    emptyOutDir: true,
  },
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  test: {
    include: ["../tests/**/*.test.ts"],
  },
});
