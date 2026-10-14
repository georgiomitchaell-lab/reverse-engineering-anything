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
  // Only the installed/compiled module may activate the packaged helper.
  // Do not discover dist/ from src/ during tests or source-tree development:
  // that silently changes mocked process launches into native launches.
  return existsSync(packaged) ? packaged : undefined;
};
