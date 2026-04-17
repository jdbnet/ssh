import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig, type Plugin } from "vite";
import vue from "@vitejs/plugin-vue";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const staticRoot = path.resolve(__dirname, "../static");

function servePwaFromStatic(): Plugin {
  return {
    name: "serve-pwa-from-static",
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        const url = req.url?.split("?")[0] ?? "";
        if (url !== "/manifest.webmanifest" && url !== "/sw.js") {
          next();
          return;
        }
        const name = url.slice(1);
        const filePath = path.join(staticRoot, name);
        if (!fs.existsSync(filePath)) {
          next();
          return;
        }
        const body = fs.readFileSync(filePath);
        const type = name.endsWith(".webmanifest")
          ? "application/manifest+json"
          : "application/javascript";
        res.setHeader("Content-Type", type);
        res.end(body);
      });
    },
  };
}

export default defineConfig({
  plugins: [vue(), servePwaFromStatic()],
  resolve: {
    alias: { "@": path.resolve(__dirname, "src") },
  },
  build: {
    outDir: "../static/dist",
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      "/api": "http://127.0.0.1:5000",
      "/ws": {
        target: "ws://127.0.0.1:5000",
        ws: true,
      },
    },
  },
});
