import { execFile } from "node:child_process";
import { chmod, mkdtemp, rm } from "node:fs/promises";
import { isAbsolute, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { randomUUID } from "node:crypto";

import {
  windowsNativeCapabilities,
  type WindowsNativeCapability,
} from "./WindowsAuthority.js";

/** Filesystem coordinates for one provider-owned private runtime directory. */
export interface PrivateRuntimeRootOptions {
  readonly parent?: string;
  readonly prefix?: string;
  /** Platform override used by deterministic boundary tests. */
  readonly platform?: NodeJS.Platform;
}

/** Provider-neutral security status for one runtime-root implementation. */
export type PrivateRuntimeRootCapability =
  | WindowsNativeCapability
  | {
      readonly available: true;
      readonly reason: null;
      readonly proof: "posix-mode-0700";
    };

/** Report whether the complete private-runtime security proof is available. */
export const privateRuntimeRootCapability = (
  platform: NodeJS.Platform = process.platform,
): PrivateRuntimeRootCapability =>
  platform === "win32"
    ? windowsNativeCapabilities(platform).private_runtime_dacl
    : { available: true, reason: null, proof: "posix-mode-0700" };

/** Expected failure when a runtime root's privacy boundary is unavailable. */
export class PrivateRuntimeRootUnavailableError extends Error {
  readonly code = "private-runtime-root-authority-unavailable";

  constructor(message: string) {
    super(message);
    this.name = "PrivateRuntimeRootUnavailableError";
  }
}

/**
 * Owns one private runtime directory and removes it idempotently.
 *
 * POSIX uses mode 0700. Windows must use the compiled native helper, which
 * creates a new directory with a protected DACL and verifies the resulting
 * security descriptor before this method returns. The Windows capability
 * report remains conservative until all required native controls are proven.
 */
export class PrivateRuntimeRoot {
  #closePromise: Promise<void> | undefined;

  private constructor(readonly path: string) {}

  /** Allocate a new private runtime root without performing protocol work. */
  static async create(
    options: PrivateRuntimeRootOptions = {},
  ): Promise<PrivateRuntimeRoot> {
    const platform = options.platform ?? process.platform;
    if (platform === "win32") {
      const path = await createWindowsPrivateRuntimeRoot(options);
      return new PrivateRuntimeRoot(path);
    }

    const capability = privateRuntimeRootCapability(platform);
    if (!capability.available)
      throw new PrivateRuntimeRootUnavailableError(capability.reason);
    const path = await mkdtemp(
      join(options.parent ?? tmpdir(), options.prefix ?? "rea-provider-"),
    );
    try {
      await chmod(path, 0o700);
      return new PrivateRuntimeRoot(path);
    } catch (cause: unknown) {
      await rm(path, { recursive: true, force: true });
      throw cause;
    }
  }

  /** Remove the runtime root; concurrent and repeated callers share cleanup. */
  close(): Promise<void> {
    this.#closePromise ??= rm(this.path, { recursive: true, force: true });
    return this.#closePromise;
  }
}

/** Create a DACL-protected directory only through the verified native helper. */
const createWindowsPrivateRuntimeRoot = async (
  options: PrivateRuntimeRootOptions,
): Promise<string> => {
  const configuredHelper = process.env.REA_WINDOWS_AUTHORITY_PATH;
  if (
    typeof configuredHelper !== "string" ||
    configuredHelper.trim().length === 0 ||
    !isAbsolute(configuredHelper)
  ) {
    throw new PrivateRuntimeRootUnavailableError(
      windowsNativeCapabilities("win32").private_runtime_dacl.reason ??
        "An absolute REA_WINDOWS_AUTHORITY_PATH is required for Windows DACL enforcement",
    );
  }

  const helper = resolve(configuredHelper);
  const parent = resolve(options.parent ?? tmpdir());
  const prefix = options.prefix ?? "rea-provider-";
  // UUID uniqueness prevents replacing an existing path; the native helper
  // itself refuses to create a directory if that path already exists.
  const path = join(parent, `${prefix}${randomUUID()}`);
  const output = await runNativePrivateDirectoryCreation(helper, path);
  let result: unknown;
  try {
    result = JSON.parse(output);
  } catch {
    throw new PrivateRuntimeRootUnavailableError(
      "Windows native helper returned invalid DACL verification output",
    );
  }
  if (
    typeof result !== "object" ||
    result === null ||
    !("ok" in result) ||
    result.ok !== true ||
    !("operation" in result) ||
    result.operation !== "create-private-dir" ||
    !("dacl" in result) ||
    result.dacl !== "verified-protected"
  ) {
    throw new PrivateRuntimeRootUnavailableError(
      "Windows native helper did not prove a protected private runtime DACL",
    );
  }
  return path;
};

const runNativePrivateDirectoryCreation = (
  helper: string,
  path: string,
): Promise<string> =>
  new Promise((resolveOutput, reject) => {
    execFile(
      helper,
      ["create-private-dir", path],
      { windowsHide: true, timeout: 10_000, maxBuffer: 64 * 1024 },
      (error, stdout, stderr) => {
        if (error) {
          reject(
            new PrivateRuntimeRootUnavailableError(
              stderr.trim() || `Windows native DACL creation failed: ${error.message}`,
            ),
          );
          return;
        }
        resolveOutput(stdout);
      },
    );
  });
