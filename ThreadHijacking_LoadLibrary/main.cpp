#include "stdafx.h"

#include "memoryapi.h"

#pragma comment(lib, "onecore.lib")

/*
    Declarations from static Inject class
*/
DWORD Inject::ProcessID;
const char *Inject::DllName;
int Inject::DllNameLength;
HANDLE Inject::hProcess;

int main() {
  Inject::Initialize();

  uintptr_t KernelBase =
      Inject::GetModuleBase(Inject::ProcessID, "KERNEL32.DLL");

  printf("[+] KERNEL32.DLL Base: %llX\n\n", KernelBase);

  uintptr_t LoadLibraryA = (uintptr_t)(KernelBase + 0x20830);

  printf("[+] LoadLibraryA: %llX\n\n", LoadLibraryA);

  LPVOID MyBufferSpace = Inject::AllocNearKernel32DLL(Inject::hProcess);

  if (MyBufferSpace == nullptr) {
    printf("[-] Failed Allocating Space In Target Process %d\n\n",
           GetLastError());
    return 0;
  }

  printf("[+] MyBufferSpace: %llX\n\n", (uintptr_t)MyBufferSpace);

  printf("[+] Copying DLL Path Into Target\n\n");

  WriteProcessMemory(Inject::hProcess, MyBufferSpace, Inject::DllName,
                     Inject::DllNameLength, nullptr);

  /*
       Hijack the thread
  */
  HANDLE hThread = Inject::GetThreadFromProcess(Inject::ProcessID);

  if (hThread == INVALID_HANDLE_VALUE)
    return 0;

  CONTEXT ctx = {};
  ctx.ContextFlags = CONTEXT_FULL;

  printf("[+] Suspending Thread\n\n");

  SuspendThread(hThread);

  GetThreadContext(hThread, &ctx);

  printf("[+] Original RIP: %llX\n\n", (uintptr_t)ctx.Rip);

  /*
    x64 Shell Code. Need to change for x86.
  */
  /*
    C1 FF FF FF = Relative Address to Start of String
    B0 10 B5 0F = Relative Address to Original RIP
  */
  char Code[] = {0x48, 0x83, 0xEC, 0x28, 0x48, 0x8D, 0x0D, 0xC1,
                 0xFF, 0xFF, 0xFF, 0x48, 0xBA, 0x30, 0x08, 0xCC,
                 0xB1, 0xFC, 0x7F, 0x00, 0x00, 0xFF, 0xD2, 0x48,
                 0x83, 0xC4, 0x28, 0xE9, 0xB0, 0x10, 0xB5, 0x0F};
  int ShellCodeLength = 32;
  int BufferSpace = 10;

  LPBYTE Ptr = (LPBYTE)Code;

  for (int i = 0; i < ShellCodeLength; i++) {

    // Write address of string
    if (*Ptr == 0x0D && *(Ptr + 1) == 0xC1) {
      uintptr_t Offset = Inject::DllNameLength + BufferSpace + 0xA;

      INT32 MaxInt32 = 0xFFFFFFFF;

      INT32 JumpValue = MaxInt32 - Offset;

      for (int i = 1; i < 5; i++) {
        *(Ptr + i) = (JumpValue >> (8 * (i - 1))) & 0xff;
      }
    }

    // Write address of old RIP
    if (*Ptr == 0xE9) {
      uintptr_t Offset = (uintptr_t)ctx.Rip - (uintptr_t)MyBufferSpace -
                         Inject::DllNameLength - BufferSpace - ShellCodeLength;

      for (int i = 1; i < 5; i++) {
        *(Ptr + i) = (Offset >> (8 * (i - 1))) & 0xff;
      }
    }

    Ptr++;
  }

  printf("[+] Copying Shellcode into Target\n\n");

  WriteProcessMemory(
      Inject::hProcess,
      (LPVOID)((uintptr_t)MyBufferSpace + Inject::DllNameLength + BufferSpace),
      Code, ShellCodeLength, nullptr);

  ctx.Rip = ((uintptr_t)MyBufferSpace + BufferSpace + Inject::DllNameLength);

  printf("[+] New RIP: %llX\n\n", (uintptr_t)ctx.Rip);

  if (!SetThreadContext(hThread, &ctx)) {
    printf("Unable to SetThreadContext\n");
    return 0;
  }

  GetThreadContext(hThread, &ctx);

  printf("[+] Confirmed New RIP: %llX\n\n", (uintptr_t)ctx.Rip);

  printf("[+] Resuming Thread\n\n");

  ResumeThread(hThread);

  printf("[+] Cleaning Up\n\n");

  CloseHandle(hThread);

  CloseHandle(Inject::hProcess);

  printf("[+] Successfully Hijacked Thread and Injected DLL.\n\n");

  Sleep(5000); // Cant free the memory until the user clicks back into the
               // window. Notepad waits for a callback or something. 5s delay to
               // click in, otherwise get fckd

  SYSTEM_INFO SysInfo;
  GetSystemInfo(&SysInfo);
  VirtualFreeEx(Inject::hProcess, MyBufferSpace, 0, MEM_RELEASE);

  return 1;
}
