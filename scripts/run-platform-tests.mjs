#!/usr/bin/env node

import { spawn } from "node:child_process";
import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { parse } from "yaml";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const vitest = join(root, "node_modules", "vitest", "vitest.mjs");

const runVitest = async (args) =>
  new Promise((resolveExit, reject) => {
    const child = spawn(process.execPath, [vitest, ...args], {
      cwd: root,
      env: process.env,
      stdio: "inherit",
      windowsHide: true,
    });
    child.once("error", reject);
    child.once("close", (code) => resolveExit(code ?? 1));
  });

if (process.platform !== "win32") {
  process.exitCode = await runVitest(["run", ...process.argv.slice(2)]);
} else {
  // Windows is validated with the repository's curated native lane. Running
  // Linux/macOS integration fixtures on Windows creates unrelated host failures.
  // Keep the test list canonical by reading the same workflow command the
  // curatedWindowsLane test validates.
  await import("./prepare-platform-tests.mjs");
  process.env.REA_WINDOWS_AUTHORITY_PATH = join(
    root,
    "dist",
    "native",
    "windows",
    "rea_windows_authority.exe",
  );

  const workflow = parse(
    await readFile(join(root, ".github", "workflows", "ci.yml"), "utf8"),
  );
  const curatedCommand = workflow.jobs?.["windows-curated"]?.steps
    ?.map((step) => step.run)
    .find((value) => value?.includes("npx vitest run"));
  if (typeof curatedCommand !== "string")
    throw new Error("Could not find the curated Windows test command");
  const paths = curatedCommand
    .split(/\s+/u)
    .filter((token) => token.endsWith(".test.ts"));
  if (paths.length === 0)
    throw new Error("The curated Windows test command contains no test files");

  const curatedExit = await runVitest([
    "run",
    "--coverage.enabled=false",
    ...paths,
  ]);
  if (curatedExit !== 0) {
    process.exitCode = curatedExit;
  } else {
    // The PTY lifecycle regression uses a mocked process boundary and is also
    // run without the optional native authority in local Windows verification.
    // Keep the authority enabled for curated security tests, then remove the
    // override before this isolated ConPTY regression to avoid native-helper
    // initialization interfering with Vitest's worker process.
    delete process.env.REA_WINDOWS_AUTHORITY_PATH;
    process.exitCode = await runVitest([
      "run",
      "--coverage.enabled=false",
      "tests/boundary/process/processCaptureLifecycle.test.ts",
      "-t",
      "distinguishes timeout from cancellation and cleans both runs",
    ]);
  }
}
