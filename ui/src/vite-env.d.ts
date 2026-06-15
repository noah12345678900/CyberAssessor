/// <reference types="vite/client" />

interface ImportMetaEnv {
  /**
   * Set to "1" in `.env.local` (or your shell) to bypass the Electron-only
   * guard in [main.tsx](./main.tsx) and let the UI mount in a plain browser
   * tab. Native file dialogs and OS keyring will not work — this is an
   * escape hatch for sidecar HTTP testing, not a supported runtime mode.
   */
  readonly VITE_ALLOW_BROWSER?: "1";
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
