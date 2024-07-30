#include "stdafx.h"

DWORD ProcessID = 6128;
const char *DllName = "C:\\dev\\Dummy_DLL\\x64\\Release\\Dummy_DLL.dll";
const char *ModName = "KERNEL32.DLL";

uintptr_t GetModuleBase(DWORD ProcessID, const char *szModuleName) {
  uintptr_t ModuleBase = 0;
  HANDLE hSnap = CreateToolhelp32Snapshot(
      TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, ProcessID);
  if (hSnap != INVALID_HANDLE_VALUE) {
    MODULEENTRY32 me32;
    me32.dwSize = sizeof(MODULEENTRY32);
    if (Module32First(hSnap, &me32)) {
      do {
        if (strcmp(me32.szModule, szModuleName) == 0) {
          ModuleBase = (uintptr_t)me32.modBaseAddr;
          break;
        }
      } while (Module32Next(hSnap, &me32));
    }
  }
  CloseHandle(hSnap);
  return ModuleBase;
}

int main() {

  HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, ProcessID);

  uintptr_t KernelBase = GetModuleBase(ProcessID, ModName);

  printf("[+] KERNEL32.DLL Base: %llX\n", KernelBase);

  uintptr_t LoadLibraryA = (uintptr_t)(KernelBase + 0x20830);

  printf("[+] LoadLibraryA: %llX\n", LoadLibraryA);

  void *MyBufferSpace =
      VirtualAllocEx(hProcess, nullptr, 42, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

  if (MyBufferSpace == nullptr)
  {
    printf("[-] Failed Allocating Space In Target Process.\n");
    return 0;
  }

  printf("[+] DllStringSpace: %llX\n", (uintptr_t)MyBufferSpace);

  WriteProcessMemory(hProcess, MyBufferSpace, DllName, 42, nullptr);

  /*
    x64 Shell Code. Need to change for x86.
  */
  const char *MyShellCode = "\x48\x8D\x0D\xC9\xFF\xFF\xFF\x48\xBA\x30\x08\x4B"
                            "\xD6\xFA\x7F\x00\x00\xFF\xE2";

  // Adding 48 just to be a few bytes after the string.
  WriteProcessMemory(hProcess, (LPVOID)((uintptr_t)MyBufferSpace + 48),
                     MyShellCode, 19, nullptr);

  /*
    Hijack the thread
  */
  HANDLE hThread = Inject::GetThreadFromProcess(ProcessID);

  if (hThread == INVALID_HANDLE_VALUE)
    return 0;

  CONTEXT ctx = {};
  ctx.ContextFlags = CONTEXT_FULL;

  SuspendThread(hThread);

  GetThreadContext(hThread, &ctx);

  printf("Original RIP: %llX\n", (uintptr_t)ctx.Rip);

  ctx.Rip = ((uintptr_t)MyBufferSpace + 48);

  printf("New RIP: %llX\n", (uintptr_t)ctx.Rip);

  if (!SetThreadContext(hThread, &ctx)) {
    printf("Unable to SetThreadContext\n");
  }

  GetThreadContext(hThread, &ctx);

  printf("Confirmed New RIP: %llX\n", (uintptr_t)ctx.Rip);

  ResumeThread(hThread);

  CloseHandle(hThread);

  CloseHandle(hProcess);

  return 1;
}
