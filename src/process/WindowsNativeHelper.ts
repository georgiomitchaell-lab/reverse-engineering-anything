import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

/**
 * Resolve the explicitly configured native helper or the helper shipped beside
 * the compiled package. An explicit path is honored as-is so a bad override
 * fails visibly instead of silently switching binaries.
 */
export const resolveWindowsNativeHelperPath = (
  allowSourceTreeBuild = false,
): string | undefined => {
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

  // Private-runtime DACL creation may explicitly opt into the local build when
  // called from source-tree development. Provider process spawning must not:
  // discovering dist/ there would silently change mocked launches to native.
  if (allowSourceTreeBuild) {
    const sourceTreeBuild = resolve(
      moduleDirectory,
      "..",
      "..",
      "dist",
      "native",
      "windows",
      "rea_windows_authority.exe",
    );
    if (existsSync(sourceTreeBuild)) return sourceTreeBuild;
  }
  return undefined;
};
