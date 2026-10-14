import { readFile } from "node:fs/promises";
import { join } from "node:path";
import process from "node:process";

import { exec } from "./lib/verify-package-core.mjs";
import { verifyPackedBridge } from "./verify-packed-bridge.mjs";

/** Create a tarball and assert production packaging constraints. */
export async function verifyPackagePack({ root, workspace }) {
  const npmCli = process.env.npm_execpath;
  const packCommand = npmCli
    ? process.execPath
    : process.platform === "win32"
      ? "npm.cmd"
      : "npm";
  const packArgs = npmCli ? [npmCli, "pack", "--silent"] : ["pack", "--silent"];
  const tarball = (
    await exec(packCommand, packArgs, {
      cwd: root,
      shell: process.platform === "win32" && !npmCli,
    })
  ).stdout.trim();
  const packedFiles = (
    await exec("tar", ["-tf", join(root, tarball)])
  ).stdout.split("\n");
  const packedManifest = JSON.parse(
    (await exec("tar", ["-xOf", join(root, tarball), "package/package.json"]))
      .stdout,
  );
  const sourceManifest = JSON.parse(
    await readFile(join(root, "package.json"), "utf8"),
  );
  if (
    packedManifest.scripts?.postinstall !== undefined ||
    packedManifest.dependencies?.["node-pty"] !== undefined ||
    packedManifest.dependencies?.["@lydell/node-pty"] !==
      sourceManifest.dependencies?.["@lydell/node-pty"]
  )
    throw new Error("package retained a lifecycle-dependent PTY installation");
  if (
    packedManifest.bin?.rea !== "scripts/rea.mjs" ||
    packedManifest.bin?.["rea-agents"] !== "scripts/rea.mjs"
  )
    throw new Error("package did not expose both rea command entry points");
  if (packedManifest.mcpName !== "io.github.morluto/rea")
    throw new Error("package did not retain its MCP Registry ownership marker");
  if (
    packedFiles.some(
      (path) => path.includes("__pycache__") || path.endsWith(".pyc"),
    )
  ) {
    throw new Error("package contained generated Python bytecode");
  }
  await verifyPackedBridge({ root, workspace, tarball, packedFiles });
  return { tarball };
}
