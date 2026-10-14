# REA Windows native authority helper

This directory contains the native Windows authority boundary used by REA.
Build with a Visual Studio Developer PowerShell for x64:
  cl /nologo /std:c++17 /EHsc /W4 rea_windows_authority.cpp /link advapi32.lib

The `run-job` command requires the supervisor PID and monitors that process.
If the supervisor exits, the helper terminates the entire Job Object. Its stdout
is reserved for the provider protocol; helper diagnostics go to stderr.

The helper deliberately does not claim reparse-safe path admission yet. That
capability requires handle-relative traversal with no-reparse semantics and
must not be inferred from an lstat/check-then-open sequence.
