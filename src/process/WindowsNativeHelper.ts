import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Resolve the explicitly configured native helper or the helper shipped beside
 * the compiled package. An explicit path is honored as-is so a bad override
 * fails visibly instead of silently switching binaries.
 */
export const resolveWindowsNativeHelperPath = (): string | undefined => {
  const configured = process.env.REA_WINDOWS_AUTHORITY_PATH?.trim();
  if (configured) return resolve(configured);
  if (process.platform !== "win32") return undefined;

  const moduleDirectory = dirname(fileURLToPath(import.meta.url));
  const packaged = resolve(
    moduleDirectory,
    "..",
    "native",
    "windows",
    "rea_windows_authority.exe",
  );
  if (existsSync(packaged)) return packaged;

  // Source-tree test/dev execution uses src/process rather than dist/process.
  const sourceTreeBuild = resolve(
    moduleDirectory,
    "..",
    "..",
    "dist",
    "native",
    "windows",
    "rea_windows_authority.exe",
  );
  return existsSync(sourceTreeBuild) ? sourceTreeBuild : undefined;
};
