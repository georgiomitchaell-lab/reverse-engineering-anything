#!/usr/bin/env node

import { mkdir, access } from "node:fs/promises";
import { spawnSync } from "node:child_process";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
if (process.platform !== "win32") {
  throw new Error("The Windows native authority helper can only be built on Windows.");
}

const source = join(root, "native", "windows", "rea_windows_authority.cpp");
const outputDirectory = join(root, "dist", "native", "windows");
const output = join(outputDirectory, "rea_windows_authority.exe");
await mkdir(outputDirectory, { recursive: true });
try {
  await access(source);
} catch {
  throw new Error(`Native helper source not found: ${source}`);
}

const result = spawnSync(
  "cl.exe",
  [
    "/nologo",
    "/std:c++17",
    "/EHsc",
    "/W4",
    source,
    `/Fo${outputDirectory}\\`,
    `/Fe:${output}`,
    "/link",
    "advapi32.lib",
  ],
  { cwd: root, encoding: "utf8", stdio: "inherit", windowsHide: true },
);
if (result.error) throw result.error;
if (result.status !== 0) {
  throw new Error(`cl.exe failed to build native authority helper (exit ${result.status}).`);
}
await access(output);
process.stdout.write(`Windows native helper built: ${output}\n`);
process.stdout.write("Set REA_WINDOWS_AUTHORITY_PATH to this executable to enable Job Object launches.\n");
