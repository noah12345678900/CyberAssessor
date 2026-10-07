import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const scriptDir = path.dirname(fileURLToPath(import.meta.url));
const uiDir = path.resolve(scriptDir, "..");
const packageJson = JSON.parse(
  fs.readFileSync(path.join(uiDir, "package.json"), "utf8"),
);
const entryPath = path.join(uiDir, packageJson.main);
const entry = fs.readFileSync(entryPath, "utf8");
const commonJsOutput =
  entry.includes('Object.defineProperty(exports, "__esModule"') ||
  entry.includes("require(");

if (
  packageJson.type === "module" &&
  packageJson.main.endsWith(".js") &&
  commonJsOutput
) {
  throw new Error(
    `${packageJson.main} is CommonJS output but package.json declares type=module. ` +
      "Electron will crash with 'exports is not defined'.",
  );
}

if (!commonJsOutput) {
  throw new Error(
    `${packageJson.main} no longer looks like CommonJS output; review the Electron module configuration.`,
  );
}

console.log(`Electron entry module check passed: ${packageJson.main}`);
