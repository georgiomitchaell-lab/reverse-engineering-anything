#!/usr/bin/env node

// Full boundary tests exercise private runtime directories. On Windows those
// directories must be created by the packaged native authority, not by chmod.
// Build the helper before Vitest so npm test works from a clean checkout and
// does not depend on having run the package verifier first.
if (process.platform === "win32") {
  await import("./build-windows-authority.mjs");
}
