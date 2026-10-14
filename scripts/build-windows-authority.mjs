#!/usr/bin/env node

import { mkdir, access, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
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

const compilerArgs = [
  "/nologo",
  "/std:c++17",
  "/EHsc",
  "/W4",
  source,
  `/Fo${outputDirectory}\\`,
  `/Fe:${output}`,
  "/link",
  "advapi32.lib",
];

// Support ordinary PowerShell as well as Visual Studio Developer PowerShell.
// cl.exe alone is insufficient: INCLUDE/LIB and the linker environment must be
// initialized by VsDevCmd.bat. Honor an already initialized developer shell.
let result;
if (process.env.VCToolsInstallDir && process.env.WindowsSdkDir) {
  result = spawnSync("cl.exe", compilerArgs, {
    cwd: root,
    encoding: "utf8",
    stdio: "inherit",
    windowsHide: true,
  });
} else {
  const vswhere = join(
    process.env["ProgramFiles(x86)"] ?? "C:\\Program Files (x86)",
    "Microsoft Visual Studio",
    "Installer",
    "vswhere.exe",
  );
  let installationPath;
  try {
    const found = spawnSync(
      vswhere,
      ["-latest", "-products", "*", "-requires", "Microsoft.VisualStudio.Component.VC.Tools.x86.x64", "-property", "installationPath"],
      { cwd: root, encoding: "utf8", windowsHide: true },
    );
    if (found.status === 0) installationPath = found.stdout.trim();
  } catch {
    // Report a single actionable error below.
  }
  if (!installationPath) {
    throw new Error(
      "Visual Studio C++ Build Tools were not found. Install the 'Desktop development with C++' workload or run this command from x64 Native Tools/Developer PowerShell.",
    );
  }

  const developerCommand = join(installationPath, "Common7", "Tools", "VsDevCmd.bat");
  const quote = (value) => `"${String(value).replaceAll('"', '""')}"`;
  // Use a temporary .cmd file to avoid cmd.exe /c nested-quote ambiguity
  // when the repository or Visual Studio installation path contains spaces.
  const buildCommandFile = join(
    tmpdir(),
    `rea-build-windows-authority-${process.pid}.cmd`,
  );
  const script = [
    "@echo off",
    `call ${quote(developerCommand)} -no_logo -arch=x64 -host_arch=x64`,
    "if errorlevel 1 exit /b %errorlevel%",
    `cl.exe ${compilerArgs.map(quote).join(" ")}`,
    "exit /b %errorlevel%",
    "",
  ].join("\r\n");
  try {
    await writeFile(buildCommandFile, script, "utf8");
    result = spawnSync(
      process.env.ComSpec ?? "cmd.exe",
      ["/d", "/c", buildCommandFile],
      { cwd: root, encoding: "utf8", stdio: "inherit", windowsHide: true },
    );
  } finally {
    await rm(buildCommandFile, { force: true });
  }
}
if (result.error) throw result.error;
if (result.status !== 0) {
  throw new Error(`Windows native authority build failed (exit ${result.status}).`);
}
await access(output);
process.stdout.write(`Windows native helper built: ${output}\n`);
process.stdout.write("Set REA_WINDOWS_AUTHORITY_PATH to this executable to enable Job Object launches.\n");
