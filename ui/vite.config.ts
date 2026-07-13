import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";
import path from "node:path";

// Inject a restrictive Content Security Policy into the PACKAGED build only.
// A CUI desktop app should not allow remote script/resource loads; this caps
// what a would-be injected payload could do (notably connect-src, which limits
// exfiltration to the local sidecar). Build-only (apply:"build") so Vite's dev
// server — which needs inline scripts + a ws:// HMR socket — is left untouched
// and HMR keeps working. connect-src allows loopback on ANY port because the
// sidecar binds a random port per launch (CCIS_PORT handshake); style-src keeps
// 'unsafe-inline' because Tailwind + a few dynamic style={{}} usages require it.
function prodCspPlugin(): Plugin {
  const csp = [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self' http://127.0.0.1:* http://localhost:*",
    "object-src 'none'",
    "base-uri 'none'",
    "frame-ancestors 'none'",
  ].join("; ");
  return {
    name: "prod-csp-meta",
    apply: "build",
    transformIndexHtml(html) {
      return html.replace(
        "</title>",
        `</title>\n    <meta http-equiv="Content-Security-Policy" content="${csp}" />`,
      );
    },
  };
}

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react(), prodCspPlugin()],
  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },
  server: {
    port: 5173,
    strictPort: true,
  },
  // Electron loads the built renderer from file:// in prod, so base must be relative
  base: "./",
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
});
