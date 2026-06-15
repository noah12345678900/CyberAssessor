/**
 * Preload bridge — runs with Node access but in an isolated context.
 *
 * Exposes a narrow `window.ccis` API to the renderer so the React app can
 * reach the sidecar URL and open native dialogs without ever touching
 * Node directly.
 */

import { contextBridge, ipcRenderer, webUtils } from "electron";

type FileFilter = { name: string; extensions: string[] };

// Sync IPC for the (static) sidecar URL. Main only creates the window after
// the sidecar is up, so this resolves immediately to a real URL.
const sidecarUrl: string = (ipcRenderer.sendSync("ccis:sidecar-url-sync") as string) ?? "";

contextBridge.exposeInMainWorld("ccis", {
  sidecarUrl,
  openFolder: (): Promise<string | null> => ipcRenderer.invoke("ccis:open-folder"),
  openFile: (filters?: FileFilter[]): Promise<string | null> =>
    ipcRenderer.invoke("ccis:open-file", filters),

  /**
   * Resolve an absolute filesystem path for a File object dragged into the
   * renderer. Electron 32 deprecated the synchronous `File.path` property —
   * the supported replacement is `webUtils.getPathForFile()`, which is only
   * available in this preload context. The React drag-drop zone calls this
   * to convert HTML5 File objects (from `e.dataTransfer.files`) into the
   * absolute paths the sidecar's path-based ingest endpoint expects.
   */
  getDroppedFilePath: (file: File): string => webUtils.getPathForFile(file),

  /**
   * Custom window-control bridge. Replaces the native `titleBarOverlay`
   * buttons so the React app can draw min/max/close with the same shadcn
   * radii and palette as the rest of the UI. See WindowControls.tsx.
   *
   * `isMaximized()` is sync (sendSync) so the initial render lands with the
   * correct icon without a flash; `onMaximizedChange` subscribes to the
   * main-process push for subsequent transitions.
   */
  windowControls: {
    minimize: (): void => ipcRenderer.send("ccis:window-minimize"),
    toggleMaximize: (): void => ipcRenderer.send("ccis:window-maximize-toggle"),
    close: (): void => ipcRenderer.send("ccis:window-close"),
    isMaximized: (): boolean =>
      (ipcRenderer.sendSync("ccis:window-is-maximized-sync") as boolean) ?? false,
    onMaximizedChange: (cb: (maximized: boolean) => void): (() => void) => {
      const listener = (_evt: unknown, maximized: boolean) => cb(maximized);
      ipcRenderer.on("ccis:window-maximized-changed", listener);
      return () => ipcRenderer.off("ccis:window-maximized-changed", listener);
    },
  },
});
