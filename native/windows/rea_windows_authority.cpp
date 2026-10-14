#define UNICODE
#define _UNICODE
#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <string>
#include <vector>
#include <iostream>

#pragma comment(lib, "advapi32.lib")

static std::wstring quoteArg(const std::wstring& s) {
  if (s.find_first_of(L" \t\n\v\"") == std::wstring::npos) return s;
  std::wstring out = L"\"";
  size_t slashes = 0;
  for (wchar_t c : s) {
    if (c == L'\\') { ++slashes; continue; }
    if (c == L'"') {
      out.append(slashes * 2 + 1, L'\\');
      out.push_back(c);
      slashes = 0;
      continue;
    }
    out.append(slashes, L'\\');
    slashes = 0;
    out.push_back(c);
  }
  out.append(slashes * 2, L'\\');
  out.push_back(L'"');
  return out;
}

static int fail(const wchar_t* where, DWORD e = GetLastError()) {
  std::wcerr << L"{\"ok\":false,\"operation\":\"" << where
             << L"\",\"win32_error\":" << e << L"}\n";
  return 1;
}

static int createPrivateDir(const wchar_t* path) {
  PSECURITY_DESCRIPTOR sd = nullptr;
  // Protected DACL: SYSTEM and the directory owner only; inheritable to children.
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
      L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;OW)", SDDL_REVISION_1, &sd, nullptr))
    return fail(L"build_dacl");
  SECURITY_ATTRIBUTES sa{};
  sa.nLength = sizeof(sa);
  sa.lpSecurityDescriptor = sd;
  sa.bInheritHandle = FALSE;
  BOOL created = CreateDirectoryW(path, &sa);
  DWORD createError = created ? ERROR_SUCCESS : GetLastError();
  LocalFree(sd);
  if (!created) return fail(L"create_private_dir", createError);

  PACL dacl = nullptr;
  PSECURITY_DESCRIPTOR check = nullptr;
  DWORD e = GetNamedSecurityInfoW(const_cast<LPWSTR>(path), SE_FILE_OBJECT,
      DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
      nullptr, nullptr, &dacl, nullptr, &check);
  if (e != ERROR_SUCCESS) {
    RemoveDirectoryW(path);
    return fail(L"verify_dacl", e);
  }
  SECURITY_DESCRIPTOR_CONTROL control{};
  DWORD revision = 0;
  BOOL gotControl = GetSecurityDescriptorControl(check, &control, &revision);
  bool protectedDacl = gotControl && (control & SE_DACL_PROTECTED) != 0;
  bool hasSystem = false, hasOwnerRights = false;
  bool exactAcl = dacl != nullptr && dacl->AceCount == 2;
  if (dacl) {
    for (DWORD i = 0; i < dacl->AceCount; ++i) {
      void* raw = nullptr;
      if (!GetAce(dacl, i, &raw)) {
        exactAcl = false;
        continue;
      }
      auto* header = static_cast<ACE_HEADER*>(raw);
      if (header->AceType != ACCESS_ALLOWED_ACE_TYPE ||
          header->AceFlags != (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)) {
        exactAcl = false;
        continue;
      }
      auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
      if (ace->Mask != FILE_ALL_ACCESS) exactAcl = false;
      PSID sid = reinterpret_cast<PSID>(&ace->SidStart);
      if (IsWellKnownSid(sid, WinLocalSystemSid)) {
        if (hasSystem) exactAcl = false;
        hasSystem = true;
      }
      LPWSTR sidString = nullptr;
      if (ConvertSidToStringSidW(sid, &sidString)) {
        // S-1-3-4 is OWNER RIGHTS.
        if (wcscmp(sidString, L"S-1-3-4") == 0) {
          if (hasOwnerRights) exactAcl = false;
          hasOwnerRights = true;
        }
        LocalFree(sidString);
      }
    }
  }
  if (check) LocalFree(check);
  if (!protectedDacl || !exactAcl || !hasSystem || !hasOwnerRights) {
    RemoveDirectoryW(path);
    return fail(L"verify_dacl_contents", ERROR_ACCESS_DENIED);
  }
  std::wcout << L"{\"ok\":true,\"operation\":\"create-private-dir\",\"dacl\":\"verified-protected\"}\n";
  return 0;
}

static int runInJob(int argc, wchar_t** argv) {
  if (argc < 4 || wcscmp(argv[2], L"--") != 0) {
    std::wcerr << L"Usage: rea_windows_authority.exe run-job -- <exe> [args...]\n";
    return 2;
  }
  std::wstring command;
  for (int i = 3; i < argc; ++i) {
    if (!command.empty()) command.push_back(L' ');
    command += quoteArg(argv[i]);
  }

  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  if (!job) return fail(L"create_job");
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation,
      &limits, sizeof(limits))) {
    DWORD e = GetLastError(); CloseHandle(job); return fail(L"configure_job", e);
  }

  STARTUPINFOW si{};
  si.cb = sizeof(si);
  si.dwFlags = STARTF_USESTDHANDLES;
  si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
  si.hStdOutput = GetStdHandle(STD_OUTPUT_HANDLE);
  si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
  PROCESS_INFORMATION pi{};
  std::vector<wchar_t> mutableCommand(command.begin(), command.end());
  mutableCommand.push_back(L'\0');

  // Crucial ordering: create suspended -> assign to Job Object -> resume.
  if (!CreateProcessW(argv[3], mutableCommand.data(), nullptr, nullptr, TRUE,
      CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, nullptr, nullptr, &si, &pi)) {
    DWORD e = GetLastError(); CloseHandle(job); return fail(L"create_suspended", e);
  }
  if (!AssignProcessToJobObject(job, pi.hProcess)) {
    DWORD e = GetLastError();
    TerminateProcess(pi.hProcess, 125);
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess); CloseHandle(job);
    return fail(L"assign_job", e);
  }
  if (ResumeThread(pi.hThread) == static_cast<DWORD>(-1)) {
    DWORD e = GetLastError();
    TerminateJobObject(job, 125);
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess); CloseHandle(job);
    return fail(L"resume_child", e);
  }
  CloseHandle(pi.hThread);
  WaitForSingleObject(pi.hProcess, INFINITE);
  DWORD exitCode = 1;
  if (!GetExitCodeProcess(pi.hProcess, &exitCode)) {
    DWORD e = GetLastError();
    CloseHandle(pi.hProcess); CloseHandle(job); return fail(L"read_exit_code", e);
  }
  CloseHandle(pi.hProcess);
  // Closing the job enforces KILL_ON_JOB_CLOSE for any remaining descendants.
  // Do not write status JSON to stdout: it is the provider's protocol stream.
  CloseHandle(job);
  return static_cast<int>(exitCode);
}

int wmain(int argc, wchar_t** argv) {
  if (argc == 3 && wcscmp(argv[1], L"create-private-dir") == 0)
    return createPrivateDir(argv[2]);
  if (argc >= 4 && wcscmp(argv[1], L"run-job") == 0)
    return runInJob(argc, argv);
  std::wcerr << L"Usage:\n  rea_windows_authority.exe create-private-dir <new-directory>\n"
             << L"  rea_windows_authority.exe run-job -- <exe> [args...]\n";
  return 2;
}
