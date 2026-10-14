#!/usr/bin/env node

import { execFile } from "node:child_process";
import { access, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";

import { Client } from "@modelcontextprotocol/client";
import { StdioClientTransport } from "@modelcontextprotocol/client/stdio";

import { verifyCompleteToolCatalog } from "./lib/verify-package-core.mjs";
import { completeVerifierRun, createVerifierRun } from "./lib/verifier-run.mjs";

const exec = promisify(execFile);
const verifierRun = createVerifierRun();
const root = process.cwd();
const workspace = await mkdtemp(join(tmpdir(), "rea-windows-package-"));
const prefix = join(workspace, "prefix");

try {
  const packed = JSON.parse(
    (
      await npm(
        ["pack", "--json", "--silent", "--pack-destination", workspace],
        root,
      )
    ).stdout,
  );
  const packageResult = Array.isArray(packed)
    ? packed[0]
    : (packed?.["rea-agents"] ?? Object.values(packed ?? {})[0]);
  const packageFilename =
    typeof packageResult?.filename === "string"
      ? packageResult.filename
      : `${packageResult?.name}-${packageResult?.version}.tgz`;
  if (
    packageResult === undefined ||
    typeof packageFilename !== "string" ||
    !Array.isArray(packageResult.files)
  )
    throw new Error(
      `npm pack returned invalid metadata: ${JSON.stringify(packed)}`,
    );
  const packagedPaths = new Set(packageResult.files.map(({ path }) => path));
  for (const required of [
    "bridge/ghidra/ReaGhidraBridge.java",
    "dist/main.js",
    "dist/cli.js",
    "dist/native/windows/rea_windows_authority.exe",
    "scripts/rea.mjs",
  ])
    if (!packagedPaths.has(required))
      throw new Error(`Windows package omitted ${required}`);

  const tarball = join(workspace, packageFilename);
  await access(tarball);
  await npm(
    ["install", "--no-package-lock", "--no-save", "--prefix", prefix, tarball],
    workspace,
  );
  const installedRoot = join(prefix, "node_modules", "rea-agents");
  const entry = join(installedRoot, "scripts", "rea.mjs");
  const nativeHelper = join(
    installedRoot,
    "dist",
    "native",
    "windows",
    "rea_windows_authority.exe",
  );

  // Verify the installed artifact, not just the source-tree helper. The DACL
  // operation must return its native verification marker before the package
  // can claim private-runtime ACL support.
  const privateProbe = join(workspace, "private-runtime-dacl-probe");
  const daclProbe = await exec(
    nativeHelper,
    ["create-private-dir", privateProbe],
    { windowsHide: true },
  );
  const daclResult = JSON.parse(daclProbe.stdout);
  if (
    daclResult?.ok !== true ||
    daclResult?.operation !== "create-private-dir" ||
    daclResult?.dacl !== "verified-protected"
  )
    throw new Error(
      "Packaged native helper did not verify the private runtime DACL",
    );

  if (daclResult?.path_admission !== "handle-relative-no-reparse")
    throw new Error(
      "Packaged helper did not attest handle-relative path admission",
    );

  // A junction is an unprivileged Windows reparse-point fixture. The helper
  // must reject a parent component opened relative to its validated handle.
  const junctionTarget = join(workspace, "junction-target");
  const junctionPath = join(workspace, "junction-parent");
  const junctionProbe = join(junctionPath, "must-not-be-created");
  await import("node:fs/promises").then(({ mkdir }) => mkdir(junctionTarget));
  const junction = await exec(
    process.env.ComSpec ?? "cmd.exe",
    ["/d", "/c", "mklink", "/J", junctionPath, junctionTarget],
    { windowsHide: true },
  );
  if (junction.code !== undefined && junction.code !== 0)
    throw new Error(
      "Could not create Windows junction fixture for reparse test",
    );
  let rejectedJunction = false;
  try {
    await exec(nativeHelper, ["create-private-dir", junctionProbe], {
      windowsHide: true,
    });
  } catch (error) {
    rejectedJunction = true;
    if (
      !String(error?.stderr ?? "").includes("reject_parent_reparse_component")
    )
      throw new Error(
        "Native helper failed the junction probe for an unexpected reason",
      );
  }
  if (!rejectedJunction)
    throw new Error(
      "Packaged native helper followed a junction parent component",
    );
  try {
    await import("node:fs/promises").then(({ access }) =>
      access(junctionProbe),
    );
    throw new Error(
      "Native helper unexpectedly created a directory through a junction",
    );
  } catch (error) {
    if (error?.code !== "ENOENT")
      throw error;
  }

  // The provider's stdout is a protocol stream. The native supervisor must
  // not append helper status JSON to the child output.
  const jobProbe = await exec(
    nativeHelper,
    [
      "run-job",
      "--parent-pid",
      String(process.pid),
      "--",
      process.env.ComSpec ?? "cmd.exe",
      "/d",
      "/c",
      "echo REA_JOB_STDOUT_OK",
    ],
    { windowsHide: true },
  );
  if (jobProbe.stdout.trim() !== "REA_JOB_STDOUT_OK")
    throw new Error(
      "Packaged Job Object helper contaminated or lost provider stdout",
    );

  const environment = {
    ...process.env,
    REA_ANALYSIS_PROVIDER: "auto",
  };
  // Exercise packaged helper discovery instead of accidentally relying on the
  // developer's REA_WINDOWS_AUTHORITY_PATH override.
  delete environment.REA_WINDOWS_AUTHORITY_PATH;
  const help = await exec(process.execPath, [entry, "--help"], {
    env: environment,
    windowsHide: true,
  });
  if (
    !/^\s{2}inspect\s/mu.test(help.stdout) ||
    !/^\s{2}decompile\s/mu.test(help.stdout) ||
    !/^\s{2}providers\s/mu.test(help.stdout)
  )
    throw new Error("Packaged Windows CLI help omitted analysis commands");

  const server = new StdioClientTransport({
    command: process.execPath,
    args: [entry, "mcp"],
    env: environment,
    stderr: "pipe",
  });
  const client = new Client({ name: "rea-windows-package", version: "1.0.0" });
  let toolCount = 0;
  try {
    await client.connect(server);
    toolCount = (await verifyCompleteToolCatalog(client)).length;
  } finally {
    await client.close();
  }

  process.stdout.write(
    `${JSON.stringify({
      verifier_run: await completeVerifierRun(verifierRun),
      ok: true,
      platform: process.platform,
      package: packageResult.filename,
      tools: toolCount,
      ghidra_bridge: "present",
    })}\n`,
  );
} finally {
  await rm(workspace, { recursive: true, force: true });
}

function npm(arguments_, cwd) {
  const npmExecPath = process.env.npm_execpath;
  return npmExecPath === undefined
    ? exec(process.platform === "win32" ? "npm.cmd" : "npm", arguments_, {
        cwd,
        windowsHide: true,
      })
    : exec(process.execPath, [npmExecPath, ...arguments_], {
        cwd,
        windowsHide: true,
      });
}
