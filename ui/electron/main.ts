/**
 * Electron main process.
 *
 * Responsibilities:
 *   1. Spawn the Python FastAPI sidecar (`uvicorn` via the project venv) on a
 *      random port and capture the port from its stdout (`CCIS_PORT=<n>`).
 *   2. Create the BrowserWindow with the preload bridge that exposes
 *      `window.ccis.sidecarUrl` plus native file/folder dialogs to React.
 *   3. Tear the sidecar down cleanly on quit.
 */

import { app, BrowserWindow, Menu, dialog, ipcMain, shell } from "electron";
import { execSync, spawn, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";

const isDev = !app.isPackaged;
const DEV_URL = "http://localhost:5173";
const SIDECAR_PORT_RE = /CCIS_PORT=(\d+)/;

// Opt in early to the warning channels we actually want to act on in dev.
// Cheaper to surface these now (when one of us is in front of the window) than
// to discover a deprecated API after Electron yanks it in a major bump.
//
//   * ELECTRON_ENABLE_SECURITY_WARNINGS — Electron's renderer security audit
//     (insecure CSP, allowRunningInsecureContent, missing contextIsolation,
//     etc.). Already on by default in dev, but force it on so it survives
//     anyone setting NODE_ENV=production locally to test builds.
//   * process.traceDeprecation — prints a stack trace the first time any
//     deprecated Node / Electron API fires, instead of a one-line warning
//     with no callsite. Without this, "(node:1234) [DEP0123] DeprecationWarning"
//     gives you no way to find the offending caller.
//   * process.traceProcessWarnings — same idea, but for the broader
//     process-warning bucket (unhandled promise rejections, etc.).
//
// All dev-only — packaged builds skip the noise.
if (isDev) {
  process.env.ELECTRON_ENABLE_SECURITY_WARNINGS = "true";
  process.traceDeprecation = true;
  process.traceProcessWarnings = true;
}

// Resolve the repo root from this file's compiled location:
//   ui/dist-electron/main.js  ->  ../..  (two levels up to repo root)
// Off-by-one here is silent-killer territory on Windows: spawn() with a
// non-existent cwd reports ENOENT on the *command*, not on cwd, which
// masquerades as a "uv.exe not found" error and sends you chasing PATH bugs
// that don't exist.
const REPO_ROOT = path.resolve(__dirname, "..", "..");
const BACKEND_DIR = path.join(REPO_ROOT, "backend");
// __dirname is ui/dist-electron/, so ../public reaches ui/public/.
const ICON_PATH = path.join(__dirname, "..", "public", "logo.ico");
// Stable AppUserModelID — Windows uses this to group taskbar buttons under
// the right icon. Without setting this explicitly, Electron apps inherit the
// default "electron.app.<name>" ID and Windows shows the default Electron
// icon in the taskbar even after BrowserWindow.icon is set.
const APP_USER_MODEL_ID = "ai.nuon.cybersecurity-assessor";

// Where we stash the live sidecar's PID so the NEXT launch can reap a tree
// orphaned by a crash/force-quit that skipped our normal teardown. Lives in
// the same per-user dir the backend already uses for config.toml + the DB, so
// there's no new directory convention to learn.
const PID_FILE = path.join(os.homedir(), ".cybersecurity-assessor", "sidecar.pid");

let sidecar: ChildProcess | null = null;
let sidecarUrl: string | null = null;
let mainWindow: BrowserWindow | null = null;

function resolveUvPath(): string {
  // Node's spawn with shell:false uses CreateProcess on Windows and does NOT
  // search PATHEXT, so "uv" without ".exe" fails — and even "uv.exe" can fail
  // when launched from a tooling chain (corepack → npm → node → electron)
  // that drops user-level PATH entries. Resolve through cmd.exe `where`
  // first; only if that fails do we fall back to the bare name and let
  // CreateProcess try whatever PATH it inherits.
  if (process.platform !== "win32") return "uv";
  try {
    const out = execSync("where uv.exe", { encoding: "utf8" }).split(/\r?\n/);
    const first = out.find((p) => p.trim().length > 0);
    if (first) return first.trim();
  } catch {
    // fall through — let spawn try PATH lookup itself
  }
  return "uv.exe";
}

function spawnSidecar(): Promise<string> {
  return new Promise((resolve, reject) => {
    // Two spawn strategies depending on whether we're running from source
    // (dev) or from an installed build (packaged):
    //
    //   DEV       -> `uv run --no-sync python -m cybersecurity_assessor.server`
    //                from the backend/ source tree. The venv is already
    //                populated; --no-sync avoids re-resolution (fatal on this
    //                machine — see UV_OFFLINE notes below).
    //   PACKAGED  -> the PyInstaller onedir frozen exe shipped under
    //                resources/cybersec-server/. The venv is NOT bundled (it
    //                depends on a base Python install), and BACKEND_DIR would
    //                resolve inside app.asar where there's no source to run.
    //                The frozen exe is fully self-contained: no Python, no uv,
    //                no PATH assumptions. args=[] because the entry point calls
    //                run() directly with no CLI flags.
    let cmd: string;
    let args: string[];
    let sidecarCwd: string;
    let useShell: boolean;

    if (isDev) {
      cmd = resolveUvPath();
      // --no-sync: skip the dependency-resolution+install step on every spawn.
      // The venv is already populated by `uv sync` at install time, so re-doing
      // it on each launch is wasted work AND fatal on this corporate machine:
      // uv re-resolves for every supported Python version (3.12..3.15+), and
      //   (a) the Nexus mirror's TLS cert fails OpenSSL validation, AND
      //   (b) even with UV_OFFLINE=1, a newer-Python wheel for some dev-extra
      //       package may not be cached, so the dev-extra resolution gives up.
      // --no-dev only excludes dev *installs*, not dev *resolution*, so it does
      // not avoid (b). --no-sync sidesteps both problems entirely.
      args = ["run", "--no-sync", "python", "-m", "cybersecurity_assessor.server"];
      sidecarCwd = BACKEND_DIR;
      // shell:true on Windows is required when `cmd` resolves to a pip
      // entry-point shim (e.g. ...\Python314\Scripts\uv.exe). Those shims are
      // tiny launcher .exes that work fine from a real shell but fail with
      // ENOENT when Node's CreateProcess invokes them directly with shell:false.
      // Symptom we hit: `spawn ...uv.exe ENOENT` despite `uv --version` working
      // from bash and the file being a valid 67MB executable.
      //
      // The cost of shell:true is that args get re-parsed by cmd.exe, so we
      // quote the executable path to handle spaces, and our args here are
      // safe literal strings (no user input concatenated in).
      useShell = process.platform === "win32";
    } else {
      // electron-builder copies backend/dist/cybersec-server/ to
      // <resources>/cybersec-server/ (see ui/electron-builder.json
      // extraResources). process.resourcesPath points at the app's resources
      // dir in a packaged build.
      const bundleDir = path.join(process.resourcesPath, "cybersec-server");
      const exeName =
        process.platform === "win32" ? "cybersec-server.exe" : "cybersec-server";
      cmd = path.join(bundleDir, exeName);
      args = [];
      // The frozen onedir exe loads its sibling _internal/ DLLs relative to its
      // own location regardless of cwd, but set cwd to the bundle dir anyway so
      // any relative paths resolve predictably.
      sidecarCwd = bundleDir;
      // No shim indirection for a real PyInstaller exe — spawn it directly.
      useShell = false;
    }
    // Mirror the Electron-side "opt in early to warnings" policy on the Python
    // sidecar in dev:
    //   PYTHONDEVMODE=1 turns on the CPython development checks (extra
    //     ResourceWarnings, debug allocator, asyncio debug mode, default
    //     warning filter that surfaces DeprecationWarning).
    //   PYTHONWARNINGS=default shows each unique deprecation once instead of
    //     swallowing them silently — pairs with PYTHONDEVMODE.
    // Packaged builds (isDev=false) skip these so end-users don't see the noise.
    const childEnv: NodeJS.ProcessEnv = {
      ...process.env,
      PYTHONUNBUFFERED: "1",
      // uv re-resolves build-system requires (hatchling) on every `uv run`,
      // which hits the corporate Nexus mirror — and that mirror's TLS cert
      // fails OpenSSL validation ("invalid peer certificate: UnknownIssuer").
      // The venv already has everything installed, so go offline: no network
      // hits, no SSL handshake. launch-electron.mjs sets this too, but doing
      // it here as well means we survive any launch path (npm run dev, VS Code
      // launch task, packaged build) — not just the wrapper script.
      UV_OFFLINE: process.env.UV_OFFLINE || "1",
      // Hand the sidecar our own PID so its watchdog thread can self-exit
      // when this Electron process dies. EDR on locked-down endpoints
      // protects python.exe from outside termination (taskkill /F →
      // Access Denied even for the parent), so self-termination is the
      // only reliable teardown. Covers both graceful quit and crash.
      CCIS_PARENT_PID: String(process.pid),
    };
    if (isDev) {
      childEnv.PYTHONDEVMODE = "1";
      childEnv.PYTHONWARNINGS = "default";
    }

    const child = spawn(useShell ? `"${cmd}"` : cmd, args, {
      cwd: sidecarCwd,
      env: childEnv,
      shell: useShell,
    });
    sidecar = child;
    // Persist the PID so a crashed/force-quit session can be reaped on next
    // launch. On win32+shell:true this is the cmd.exe wrapper's PID, which is
    // exactly what killProcessTree(/T) needs to walk down to uv -> python.
    if (typeof child.pid === "number") writeSidecarPid(child.pid);

    let buffered = "";
    const onStdout = (chunk: Buffer) => {
      const text = chunk.toString();
      buffered += text;
      process.stdout.write(`[sidecar] ${text}`);
      const m = SIDECAR_PORT_RE.exec(buffered);
      if (m) {
        const port = Number(m[1]);
        child.stdout?.off("data", onStdout);
        resolve(`http://127.0.0.1:${port}`);
      }
    };

    child.stdout?.on("data", onStdout);
    child.stderr?.on("data", (c: Buffer) => process.stderr.write(`[sidecar!] ${c}`));
    child.on("exit", (code, sig) => {
      console.error(`[sidecar] exited code=${code} sig=${sig}`);
      sidecar = null;
      // The tracked process is gone; drop its stale PID so a later reap pass
      // doesn't tree-kill a recycled, unrelated PID.
      clearSidecarPid();
    });
    child.on("error", (err) => reject(err));

    // Fail if the port banner never arrives. The deadline has to cover a COLD
    // start: on a fresh/empty DB the sidecar runs the full Alembic chain
    // (0001 -> head) plus catalog seeding before it binds a port, which on this
    // machine takes well over 15s. A warm DB makes those migrations no-ops and
    // boots in ~2-3s, so this longer ceiling only ever bites the first launch
    // after a wipe — and SIGTERM-ing a sidecar that was about to succeed (as the
    // old 15s limit did) just makes the wipe look like a hard failure. 60s gives
    // the one-time migration room while still surfacing a truly dead sidecar.
    setTimeout(() => {
      if (!sidecarUrl) reject(new Error("Sidecar did not print CCIS_PORT within 60s"));
    }, 60_000);
  });
}

// Kill a process AND every descendant. This is the whole ballgame on Windows:
// in dev we spawn with shell:true (see spawnSidecar), so `child.pid` is the
// cmd.exe wrapper, and uv -> python run as its grandchildren. A plain
// `child.kill()` reaps only cmd.exe and orphans the python sidecar, which then
// squats on its random port forever (the bug this function exists to fix).
//
//   * win32  -> `taskkill /PID <pid> /T /F`. /T walks the child tree, /F forces
//               termination. Synchronous (execSync) so it completes inside the
//               quit/exit handlers, which don't await async work.
//   * posix  -> negative PID signals the whole process group. Falls back to a
//               direct kill if the group send fails (e.g. not a group leader).
//
// Best-effort throughout: a process that already exited makes taskkill exit
// non-zero / process.kill throw ESRCH, both of which are fine to swallow.
function killProcessTree(pid: number): void {
  if (!pid || pid <= 0) return;
  if (process.platform === "win32") {
    try {
      execSync(`taskkill /PID ${pid} /T /F`, { stdio: "ignore" });
    } catch {
      /* already gone, or access-denied on a process we don't own */
    }
    return;
  }
  // POSIX: try the process group first (negative pid), then the bare pid.
  try {
    process.kill(-pid, "SIGTERM");
  } catch {
    try {
      process.kill(pid, "SIGTERM");
    } catch {
      /* already gone */
    }
  }
}

function writeSidecarPid(pid: number): void {
  try {
    fs.mkdirSync(path.dirname(PID_FILE), { recursive: true });
    fs.writeFileSync(PID_FILE, String(pid), "utf8");
  } catch (err) {
    // Non-fatal: losing the PID file just means a future crash-orphan won't be
    // auto-reaped. The app still runs; we log so it's diagnosable.
    console.error("[main] could not write sidecar PID file:", err);
  }
}

function clearSidecarPid(): void {
  try {
    fs.rmSync(PID_FILE, { force: true });
  } catch {
    /* ignore */
  }
}

// On startup, kill any sidecar tree left behind by a previous session that
// didn't shut down cleanly (crash, force-quit, OS kill). Reading a PID we
// wrote last run and tree-killing it is safe even if that PID has since been
// recycled by an unrelated process — extremely unlikely within one user's
// session lifetime, and taskkill on a foreign PID we lack rights to just
// no-ops. Runs before we spawn the fresh sidecar so we never have two bound.
function reapStaleSidecar(): void {
  let raw: string;
  try {
    raw = fs.readFileSync(PID_FILE, "utf8").trim();
  } catch {
    return; // no PID file -> nothing to reap
  }
  const pid = Number(raw);
  if (Number.isInteger(pid) && pid > 0) {
    console.log(`[main] reaping stale sidecar tree from prior session (pid=${pid})`);
    killProcessTree(pid);
  }
  clearSidecarPid();
}

function killSidecar() {
  if (sidecar) {
    const pid = sidecar.pid;
    if (typeof pid === "number") killProcessTree(pid);
    sidecar = null;
  }
  clearSidecarPid();
}

async function createWindow() {
  // Kill the default File/Edit/View/Window/Help menu. None of its entries are
  // wired to anything in this app and the grey banner reads as "stock Electron
  // demo" rather than a finished product. Same call VS Code / Slack / Linear
  // make for the same reason.
  Menu.setApplicationMenu(null);

  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1100,
    minHeight: 700,
    title: "Cybersecurity Assessor",
    backgroundColor: "#061a30", // nuon --navy-deep (matches body background to prevent flash)
    icon: ICON_PATH,
    //
    // Hidden title bar — no native window controls, no title text, no menu
    // strip. Both the drag region AND the minimize/maximize/close buttons
    // are rendered by the React app (see ui/src/components/WindowControls.tsx
    // and the DragStrip in App.tsx). We used to use `titleBarOverlay` here,
    // but its buttons are drawn by Windows and only `color` / `symbolColor`
    // are configurable — the shape is OS-dictated and clashes with our
    // rounded shadcn aesthetic. Custom HTML controls give us pixel parity.
    titleBarStyle: "hidden",
    autoHideMenuBar: true, // belt-and-suspenders for Alt-key reveal
    webPreferences: {
      preload: path.join(__dirname, "preload.js"),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: false,
    },
  });

  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: "deny" };
  });

  // Push maximize-state changes to the renderer so the custom WindowControls
  // can flip its icon between "maximize" (square) and "restore" (overlapping
  // squares) without polling. Sent on both transitions; React picks them up
  // via window.ccis.windowControls.onMaximizedChange().
  const pushMaxState = () => {
    mainWindow?.webContents.send("ccis:window-maximized-changed", mainWindow!.isMaximized());
  };
  mainWindow.on("maximize", pushMaxState);
  mainWindow.on("unmaximize", pushMaxState);

  // Setting the application menu to null also strips the built-in reload /
  // devtools accelerators. Re-bind them by hand so Ctrl+R, Ctrl+Shift+R, F5,
  // and F12 still work — same shortcuts users expect from VS Code / Chrome.
  mainWindow.webContents.on("before-input-event", (event, input) => {
    if (input.type !== "keyDown") return;
    const ctrlOrMeta = input.control || input.meta;
    const key = input.key.toLowerCase();

    // Reload: Ctrl+R, F5
    if ((ctrlOrMeta && key === "r" && !input.shift) || key === "f5") {
      event.preventDefault();
      mainWindow?.webContents.reload();
      return;
    }
    // Hard reload (ignore cache): Ctrl+Shift+R, Shift+F5
    if ((ctrlOrMeta && input.shift && key === "r") || (input.shift && key === "f5")) {
      event.preventDefault();
      mainWindow?.webContents.reloadIgnoringCache();
      return;
    }
    // Toggle DevTools: F12, Ctrl+Shift+I
    if (key === "f12" || (ctrlOrMeta && input.shift && key === "i")) {
      event.preventDefault();
      mainWindow?.webContents.toggleDevTools();
      return;
    }
  });

  if (isDev) {
    await mainWindow.loadURL(DEV_URL);
    mainWindow.webContents.openDevTools({ mode: "detach" });
  } else {
    await mainWindow.loadFile(path.join(__dirname, "..", "dist", "index.html"));
  }
}

// IPC: preload calls this synchronously to populate window.ccis.sidecarUrl
ipcMain.on("ccis:sidecar-url-sync", (evt) => {
  evt.returnValue = sidecarUrl;
});

// Window controls — replaces the native titleBarOverlay buttons so the
// React app can render its own min/max/close that match the design language.
// Sender-window resolution (BrowserWindow.fromWebContents) means these work
// regardless of how many windows are open and don't capture the closure
// over `mainWindow` (which can be null during teardown).
ipcMain.on("ccis:window-minimize", (evt) => {
  BrowserWindow.fromWebContents(evt.sender)?.minimize();
});
ipcMain.on("ccis:window-maximize-toggle", (evt) => {
  const w = BrowserWindow.fromWebContents(evt.sender);
  if (!w) return;
  if (w.isMaximized()) w.unmaximize();
  else w.maximize();
});
ipcMain.on("ccis:window-close", (evt) => {
  BrowserWindow.fromWebContents(evt.sender)?.close();
});
ipcMain.on("ccis:window-is-maximized-sync", (evt) => {
  evt.returnValue = BrowserWindow.fromWebContents(evt.sender)?.isMaximized() ?? false;
});

// Raise the main window before opening a native dialog. On Windows, dialogs
// parented to an unfocused BrowserWindow can open BEHIND it — the user clicks
// the Ingest button, sees nothing happen, and eventually clicks elsewhere
// which silently cancels the dialog. Restoring + focusing first guarantees
// the dialog comes to the top.
function raiseMainWindow(): void {
  if (!mainWindow || mainWindow.isDestroyed()) return;
  if (mainWindow.isMinimized()) mainWindow.restore();
  mainWindow.focus();
}

ipcMain.handle("ccis:open-folder", async () => {
  raiseMainWindow();
  const res = await dialog.showOpenDialog(mainWindow!, {
    properties: ["openDirectory"],
  });
  return res.canceled || res.filePaths.length === 0 ? null : res.filePaths[0];
});

ipcMain.handle(
  "ccis:open-file",
  async (_evt, filters?: { name: string; extensions: string[] }[]) => {
    raiseMainWindow();
    const res = await dialog.showOpenDialog(mainWindow!, {
      properties: ["openFile"],
      filters,
    });
    return res.canceled || res.filePaths.length === 0 ? null : res.filePaths[0];
  },
);

app.whenReady().then(async () => {
  // Must run before any BrowserWindow so Windows picks up our identity for
  // taskbar grouping + jump-list. Setting it here (rather than at module load)
  // also dodges a Linux warning when the API is unavailable.
  if (process.platform === "win32") {
    app.setAppUserModelId(APP_USER_MODEL_ID);
  }

  // Reap any sidecar orphaned by a previous crash/force-quit BEFORE spawning a
  // fresh one, so we never have two sidecars fighting over the DB / ports.
  reapStaleSidecar();

  try {
    sidecarUrl = await spawnSidecar();
    console.log(`[main] sidecar ready at ${sidecarUrl}`);
  } catch (err) {
    console.error("[main] sidecar failed to start:", err);
    dialog.showErrorBox(
      "Backend failed to start",
      `Could not spawn the Python sidecar.\n\n${(err as Error).message}\n\n` +
        `Make sure 'uv' is on PATH and 'backend/' has its dependencies installed (\`uv sync\`).`,
    );
  }

  await createWindow();

  app.on("activate", () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

app.on("window-all-closed", () => {
  killSidecar();
  if (process.platform !== "darwin") app.quit();
});

app.on("before-quit", killSidecar);
process.on("exit", killSidecar);
