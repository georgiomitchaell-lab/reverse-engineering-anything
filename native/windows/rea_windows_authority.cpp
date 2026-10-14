#define UNICODE
#define _UNICODE
#include <windows.h>
#include <winternl.h>
#include <aclapi.h>
#include <sddl.h>
#include <string>
#include <vector>
#include <iostream>
#include <cstdlib>

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

// Create/open each path component relative to a validated directory handle.
// NtCreateFile + FILE_OPEN_REPARSE_POINT prevents name resolution from following
// a reparse point between validation and use. The final directory is created
// relative to the held parent handle with FILE_CREATE (never open-or-create).
using NtCreateFileFn = NTSTATUS (NTAPI*)(
  PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK, PLARGE_INTEGER,
  ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
using RtlNtStatusToDosErrorFn = ULONG (WINAPI*)(NTSTATUS);

static DWORD ntError(NTSTATUS status) {
  auto convert = reinterpret_cast<RtlNtStatusToDosErrorFn>(
    GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "RtlNtStatusToDosError"));
  return convert ? convert(status) : ERROR_GEN_FAILURE;
}

static NTSTATUS openRelative(
    NtCreateFileFn ntCreateFile, HANDLE parent, const std::wstring& name,
    ACCESS_MASK access, ULONG disposition, ULONG options,
    PSECURITY_DESCRIPTOR security, HANDLE* output) {
  UNICODE_STRING objectName{};
  if (name.size() > 0x7fff) return static_cast<NTSTATUS>(0xC0000106L);
  objectName.Buffer = const_cast<PWSTR>(name.c_str());
  objectName.Length = static_cast<USHORT>(name.size() * sizeof(wchar_t));
  objectName.MaximumLength = objectName.Length;
  OBJECT_ATTRIBUTES attributes{};
  attributes.Length = sizeof(attributes);
  attributes.RootDirectory = parent;
  attributes.ObjectName = &objectName;
  attributes.Attributes = OBJ_CASE_INSENSITIVE;
  attributes.SecurityDescriptor = security;
  IO_STATUS_BLOCK io{};
  return ntCreateFile(output, access, &attributes, &io, nullptr,
      FILE_ATTRIBUTE_DIRECTORY,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      disposition, options, nullptr, 0);
}

static bool isNotReparseDirectory(HANDLE handle, DWORD* errorOut) {
  FILE_ATTRIBUTE_TAG_INFO info{};
  if (!GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &info, sizeof(info))) {
    *errorOut = GetLastError();
    return false;
  }
  if ((info.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) == 0 ||
      (info.FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
    *errorOut = ERROR_CANT_ACCESS_FILE;
    return false;
  }
  *errorOut = ERROR_SUCCESS;
  return true;
}

static int createPrivateDir(const wchar_t* inputPath) {
  auto ntCreateFile = reinterpret_cast<NtCreateFileFn>(
    GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtCreateFile"));
  if (!ntCreateFile) return fail(L"resolve_nt_create_file", ERROR_PROC_NOT_FOUND);

  DWORD needed = GetFullPathNameW(inputPath, 0, nullptr, nullptr);
  if (needed == 0) return fail(L"resolve_private_path");
  std::vector<wchar_t> buffer(needed + 1);
  DWORD length = GetFullPathNameW(inputPath, static_cast<DWORD>(buffer.size()), buffer.data(), nullptr);
  if (length == 0 || length >= buffer.size())
    return fail(L"resolve_private_path", length == 0 ? GetLastError() : ERROR_FILENAME_EXCED_RANGE);
  std::wstring full(buffer.data(), length);
  if (full.size() < 4 || full[1] != L':' ||
      (full[2] != L'\\' && full[2] != L'/') ||
      full.rfind(L"\\\\", 0) == 0)
    return fail(L"unsupported_private_path", ERROR_INVALID_NAME);

  // Do not accept alternate namespaces or device paths after normalization.
  std::wstring nativeRoot = L"\\??\\";
  nativeRoot.push_back(full[0]);
  nativeRoot += L":\\";
  HANDLE current = INVALID_HANDLE_VALUE;
  NTSTATUS status = openRelative(ntCreateFile, nullptr, nativeRoot,
      FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE,
      FILE_OPEN, FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
      nullptr, &current);
  if (status < 0) return fail(L"open_volume_root", ntError(status));

  PSECURITY_DESCRIPTOR sd = nullptr;
  if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(
      L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;OW)", SDDL_REVISION_1, &sd, nullptr)) {
    DWORD e = GetLastError();
    CloseHandle(current);
    return fail(L"build_dacl", e);
  }

  size_t pos = 3;
  while (pos < full.size()) {
    while (pos < full.size() && (full[pos] == L'\\' || full[pos] == L'/')) ++pos;
    if (pos >= full.size()) break;
    size_t next = full.find_first_of(L"\\/", pos);
    if (next == std::wstring::npos) next = full.size();
    std::wstring component = full.substr(pos, next - pos);
    pos = next;
    if (component.empty() || component == L"." || component == L"..") {
      LocalFree(sd);
      CloseHandle(current);
      return fail(L"invalid_path_component", ERROR_INVALID_NAME);
    }
    const bool final = pos >= full.size();
    HANDLE child = INVALID_HANDLE_VALUE;
    if (final) {
      status = openRelative(ntCreateFile, current, component,
          READ_CONTROL | FILE_READ_ATTRIBUTES | FILE_WRITE_DAC | DELETE | SYNCHRONIZE,
          FILE_CREATE,
          FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
          sd, &child);
      if (status < 0) {
        DWORD e = ntError(status);
        LocalFree(sd);
        CloseHandle(current);
        return fail(L"create_private_dir_relative", e);
      }
      DWORD attrError = ERROR_SUCCESS;
      if (!isNotReparseDirectory(child, &attrError)) {
        FILE_DISPOSITION_INFO disposition{ TRUE };
        SetFileInformationByHandle(child, FileDispositionInfo, &disposition, sizeof(disposition));
        CloseHandle(child);
        LocalFree(sd);
        CloseHandle(current);
        return fail(L"verify_created_directory_handle", attrError);
      }

      PACL dacl = nullptr;
      PSECURITY_DESCRIPTOR check = nullptr;
      DWORD e = GetSecurityInfo(child, SE_FILE_OBJECT,
          DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
          nullptr, nullptr, &dacl, nullptr, &check);
      if (e != ERROR_SUCCESS) {
        FILE_DISPOSITION_INFO disposition{ TRUE };
        SetFileInformationByHandle(child, FileDispositionInfo, &disposition, sizeof(disposition));
        CloseHandle(child);
        LocalFree(sd);
        CloseHandle(current);
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
          if (!GetAce(dacl, i, &raw)) { exactAcl = false; continue; }
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
            if (wcscmp(sidString, L"S-1-3-4") == 0) {
              if (hasOwnerRights) exactAcl = false;
              hasOwnerRights = true;
            }
            LocalFree(sidString);
          }
        }
      }
      LocalFree(check);
      LocalFree(sd);
      CloseHandle(current);
      if (!protectedDacl || !exactAcl || !hasSystem || !hasOwnerRights) {
        FILE_DISPOSITION_INFO disposition{ TRUE };
        SetFileInformationByHandle(child, FileDispositionInfo, &disposition, sizeof(disposition));
        CloseHandle(child);
        return fail(L"verify_dacl_contents", ERROR_ACCESS_DENIED);
      }
      CloseHandle(child);
      std::wcout << L"{\"ok\":true,\"operation\":\"create-private-dir\",\"dacl\":\"verified-protected\",\"path_admission\":\"handle-relative-no-reparse\"}\n";
      return 0;
    }

    status = openRelative(ntCreateFile, current, component,
        FILE_LIST_DIRECTORY | FILE_READ_ATTRIBUTES | FILE_TRAVERSE | SYNCHRONIZE,
        FILE_OPEN,
        FILE_DIRECTORY_FILE | FILE_OPEN_REPARSE_POINT | FILE_SYNCHRONOUS_IO_NONALERT,
        nullptr, &child);
    if (status < 0) {
      DWORD e = ntError(status);
      LocalFree(sd);
      CloseHandle(current);
      return fail(L"open_parent_component", e);
    }
    DWORD attrError = ERROR_SUCCESS;
    if (!isNotReparseDirectory(child, &attrError)) {
      CloseHandle(child);
      LocalFree(sd);
      CloseHandle(current);
      return fail(L"reject_parent_reparse_component", attrError);
    }
    CloseHandle(current);
    current = child;
  }

  LocalFree(sd);
  CloseHandle(current);
  return fail(L"missing_final_component", ERROR_INVALID_NAME);
}

static int runInJob(int argc, wchar_t** argv) {
  if (argc < 6 || wcscmp(argv[2], L"--parent-pid") != 0 ||
      wcscmp(argv[4], L"--") != 0) {
    std::wcerr << L"Usage: rea_windows_authority.exe run-job --parent-pid <pid> -- <exe> [args...]\n";
    return 2;
  }
  wchar_t* pidEnd = nullptr;
  unsigned long parentPid = std::wcstoul(argv[3], &pidEnd, 10);
  if (parentPid == 0 || pidEnd == argv[3] || *pidEnd != L'\0')
    return fail(L"invalid_parent_pid", ERROR_INVALID_PARAMETER);
  HANDLE parentProcess = OpenProcess(SYNCHRONIZE, FALSE, parentPid);
  if (!parentProcess) return fail(L"open_parent_process");

  std::wstring command;
  for (int i = 5; i < argc; ++i) {
    if (!command.empty()) command.push_back(L' ');
    command += quoteArg(argv[i]);
  }

  HANDLE job = CreateJobObjectW(nullptr, nullptr);
  if (!job) {
    DWORD e = GetLastError();
    CloseHandle(parentProcess);
    return fail(L"create_job", e);
  }
  JOBOBJECT_EXTENDED_LIMIT_INFORMATION limits{};
  limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
  if (!SetInformationJobObject(job, JobObjectExtendedLimitInformation,
      &limits, sizeof(limits))) {
    DWORD e = GetLastError();
    CloseHandle(job); CloseHandle(parentProcess);
    return fail(L"configure_job", e);
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
  if (!CreateProcessW(argv[5], mutableCommand.data(), nullptr, nullptr, TRUE,
      CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT, nullptr, nullptr, &si, &pi)) {
    DWORD e = GetLastError();
    CloseHandle(job); CloseHandle(parentProcess);
    return fail(L"create_suspended", e);
  }
  if (!AssignProcessToJobObject(job, pi.hProcess)) {
    DWORD e = GetLastError();
    TerminateProcess(pi.hProcess, 125);
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess); CloseHandle(job);
    CloseHandle(parentProcess);
    return fail(L"assign_job", e);
  }
  if (ResumeThread(pi.hThread) == static_cast<DWORD>(-1)) {
    DWORD e = GetLastError();
    TerminateJobObject(job, 125);
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess); CloseHandle(job);
    CloseHandle(parentProcess);
    return fail(L"resume_child", e);
  }
  CloseHandle(pi.hThread);
  HANDLE waits[2] = { pi.hProcess, parentProcess };
  DWORD waitResult = WaitForMultipleObjects(2, waits, FALSE, INFINITE);
  if (waitResult == WAIT_OBJECT_0 + 1) {
    // If the supervising Node process disappears, tear down the entire job.
    TerminateJobObject(job, 125);
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hProcess); CloseHandle(parentProcess); CloseHandle(job);
    return 125;
  }
  if (waitResult != WAIT_OBJECT_0) {
    DWORD e = GetLastError();
    TerminateJobObject(job, 125);
    WaitForSingleObject(pi.hProcess, 5000);
    CloseHandle(pi.hProcess); CloseHandle(parentProcess); CloseHandle(job);
    return fail(L"wait_for_child_or_parent", e);
  }
  DWORD exitCode = 1;
  if (!GetExitCodeProcess(pi.hProcess, &exitCode)) {
    DWORD e = GetLastError();
    CloseHandle(pi.hProcess); CloseHandle(parentProcess); CloseHandle(job);
    return fail(L"read_exit_code", e);
  }
  CloseHandle(pi.hProcess);
  CloseHandle(parentProcess);
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
             << L"  rea_windows_authority.exe run-job --parent-pid <pid> -- <exe> [args...]\n";
  return 2;
}
