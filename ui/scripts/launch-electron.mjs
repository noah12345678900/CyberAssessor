// Launch Electron with a clean env that does NOT leak ELECTRON_RUN_AS_NODE
// from the parent process. Claude Code (and other Electron-hosted shells)
// export ELECTRON_RUN_AS_NODE=1, which causes our `electron .` invocation
// to start as plain Node and silently never open a window. cross-env on
// Windows can only set vars, not delete them, so we do it here.
import { spawn } from "node:child_process";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const electronPath = require("electron"); // resolves to electron's binary

const env = { ...process.env };
delete env.ELECTRON_RUN_AS_NODE;
delete env.ELECTRON_NO_ATTACH_CONSOLE;
env.NODE_ENV = env.NODE_ENV || "development";
// uv re-resolves build-system requires (hatchling) on every `uv run` and the
// corporate Nexus mirror fails SSL cert validation. The venv already has
// everything installed, so go offline — no network hits, no SSL handshake.
env.UV_OFFLINE = env.UV_OFFLINE || "1";

const child = spawn(electronPath, ["."], {
  stdio: "inherit",
  env,
  windowsHide: false,
});

child.on("exit", (code) => process.exit(code ?? 0));
child.on("error", (err) => {
  console.error("[launch-electron] failed to spawn electron:", err);
  process.exit(1);
});
