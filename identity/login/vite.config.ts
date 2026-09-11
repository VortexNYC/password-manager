import path from "node:path"
import { fileURLToPath } from "node:url"
import { tanstackRouter } from "@tanstack/router-plugin/vite"
import react from "@vitejs/plugin-react"
import { defineConfig } from "vite"

const root = path.dirname(fileURLToPath(import.meta.url))

export default defineConfig({
  plugins: [
    tanstackRouter({
      routesDirectory: path.join(root, "src/routes"),
      generatedRouteTree: path.join(root, "src/routeTree.gen.ts"),
    }),
    react(),
  ],
  server: {
    port: 4455,
    strictPort: true,
  },
  preview: {
    port: 4455,
  },
})
