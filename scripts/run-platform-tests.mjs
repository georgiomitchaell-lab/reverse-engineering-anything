#!/usr/bin/env node

import { spawn } from "node:child_process";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(join(fileURLToPath(new URL(".", import.meta.url)), ".."));

if (process.platform === "win32") {
  // Build *after* build:cached: its prebuild hook clears dist/, so compiling
  // the native helper from a pretest hook would erase it before Vitest starts.
  await import("./prepare-platform-tests.mjs");
  process.env.REA_WINDOWS_AUTHORITY_PATH = join(
    root,
    "dist",
    "native",
    "windows",
    "rea_windows_authority.exe",
  );
}

const vitest = join(root, "node_modules", "vitest", "vitest.mjs");
const child = spawn(process.execPath, [vitest, "run", ...process.argv.slice(2)], {
  cwd: root,
  env: process.env,
  stdio: "inherit",
  windowsHide: true,
});

const exitCode = await new Promise((resolveExit) => {
  child.once("error", (error) => {
    console.error("Could not start Vitest:", error);
    resolveExit(1);
  });
  child.once("close", (code) => resolveExit(code ?? 1));
});
process.exitCode = exitCode;
