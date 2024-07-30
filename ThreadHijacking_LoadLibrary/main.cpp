#include "stdafx.h"

#include "memoryapi.h"

#pragma comment(lib, "onecore.lib")

DWORD ProcessID = 21040;
const char *DllName = "C:\\dev\\Dummy_DLL\\x64\\Release\\Dummy_DLL.dll";
const char *ModName = "KERNEL32.DLL";

void FakeShellcode() {
  LoadLibraryA(DllName);
  return;
}

int main() {
  printf("Fake Shellcode: %llX\n", (uintptr_t)&FakeShellcode);

  HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, ProcessID);

  uintptr_t KernelBase = Inject::GetModuleBase(ProcessID, ModName);

  printf("[+] KERNEL32.DLL Base: %llX\n", KernelBase);

  uintptr_t LoadLibraryA = (uintptr_t)(KernelBase + 0x20830);

  printf("[+] LoadLibraryA: %llX\n", LoadLibraryA);

  // void *MyBufferSpace =
  //     VirtualAllocEx(hProcess, nullptr, 42, MEM_COMMIT,
  //     PAGE_EXECUTE_READWRITE);
  SYSTEM_INFO SysInfo;
  GetSystemInfo(&SysInfo);
  std::cout << SysInfo.dwAllocationGranularity << std::endl;

  MEM_ADDRESS_REQUIREMENTS MemRequirements = {0};
  MEM_EXTENDED_PARAMETER MemParams = {0};

  MemRequirements.Alignment = 0;
  // MemRequirements.HighestEndingAddress = (PVOID)(uintptr_t)0x00000000;
  MemRequirements.LowestStartingAddress = (PVOID)0x7FF9A0000000;

  MemParams.Type = MemExtendedParameterAddressRequirements;
  MemParams.Pointer = &MemRequirements;

  void *MyBufferSpace =
      VirtualAlloc2(hProcess, nullptr, 65536, MEM_RESERVE | MEM_COMMIT,
                    PAGE_EXECUTE_READWRITE, &MemParams, 1);

  if (MyBufferSpace == nullptr) {
    printf("[-] Failed Allocating Space In Target Process %d\n",
           GetLastError());
    return 0;
  }

  printf("[+] DllStringSpace: %llX\n", (uintptr_t)MyBufferSpace);

  WriteProcessMemory(hProcess, MyBufferSpace, DllName, 42, nullptr);

  /*
    x64 Shell Code. Need to change for x86.
    This is totally hardcoded as of now because I am using absolute jmps /
    addresses. Can be done dynamically if needed
  */
  const char *MyShellCode =
      "\x48\x83\xEC\x28\x48\x8D\x0D\xC5\xFF\xFF\xFF\x48\xBA\x30\x08\x55\xA0\xF9"
      "\x7F\x00\x00\xFF\xD2\x48\x83\xC4\x28\xE9\xB4\x10\x1E\xFE";

  // Adding 48 just to be a few bytes after the string.
  WriteProcessMemory(hProcess, (LPVOID)((uintptr_t)MyBufferSpace + 48),
                     MyShellCode, 32, nullptr);

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
