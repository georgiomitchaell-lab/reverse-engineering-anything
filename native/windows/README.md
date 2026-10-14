# REA Windows native authority helper

This directory contains the native Windows authority boundary used by REA.
Build with a Visual Studio Developer PowerShell for x64:
  cl /nologo /std:c++17 /EHsc /W4 rea_windows_authority.cpp /link advapi32.lib

The `run-job` command requires the supervisor PID and monitors that process.
If the supervisor exits, the helper terminates the entire Job Object. Its stdout
is reserved for the provider protocol; helper diagnostics go to stderr.

The private-directory creation path now performs a fail-closed preflight that
rejects existing reparse-point path components and unsupported non-drive paths.
This is defense in depth only: path-based preflight followed by path-based
creation has a time-of-check/time-of-use race and is **not** a complete
reparse-safe admission guarantee.

The helper deliberately does not claim reparse-safe path admission. Production
capability must remain unavailable until directory traversal and creation are
performed relative to validated directory handles with no-reparse semantics,
and Windows tests prove junction/symlink rejection including race-safe behavior.
