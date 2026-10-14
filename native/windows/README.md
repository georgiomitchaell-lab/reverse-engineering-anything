# REA Windows native authority helper

This directory contains the native Windows authority boundary used by REA.
Build with a Visual Studio Developer PowerShell for x64:
  cl /nologo /std:c++17 /EHsc /W4 rea_windows_authority.cpp /link advapi32.lib

The `run-job` command requires the supervisor PID and monitors that process.
If the supervisor exits, the helper terminates the entire Job Object. Its stdout
is reserved for the provider protocol; helper diagnostics go to stderr.

Private-directory admission uses handle-relative NT file operations. Each
existing parent component is opened relative to the previously validated
directory handle with `FILE_OPEN_REPARSE_POINT`, then rejected if the handle
identifies a reparse point or a non-directory. The final directory is created
relative to that held parent handle with `FILE_CREATE` (never open-or-create),
and its protected DACL is verified through the returned handle rather than by
reopening the path. This avoids the former path-based check/use traversal race.

The packaged Windows verifier now checks the success marker and creates a
junction fixture to assert that a path through a reparse-point parent fails
closed. Windows native capability reporting remains unavailable until this
updated native helper is built and the packaged verifier succeeds on Windows;
the source change alone is not runtime proof.
