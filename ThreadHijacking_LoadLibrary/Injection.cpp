#include "stdafx.h"

/*
    brief: Inject Static Class Initialization
*/
bool Inject::Initialize() {
  Inject::DllName= "C:\\dev\\ThreadHijacking_LoadLibrary\\x64\\Release\\Dummy_DLL.dll";

  Inject::DllNameLength = Inject::NumCharsInCharPtr((char *)DllName);

  Inject::ProcessID = 31428;

  Inject::hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, Inject::ProcessID);
  if (hProcess == INVALID_HANDLE_VALUE)
  {
    printf("[-] Error Opening Handle to Target Process!\n\n");
    return 0;
  }

  return 1;
}

/*
    brief: Returns the number of chars in a char*
*/
int Inject::NumCharsInCharPtr(char *array) {
  int numberOfChars = 0;
  while (*array++) {
    numberOfChars++;
  }
  return numberOfChars;
}

/*
    brief: Snapshots all threads, and returns a handle to a thread matching the
   specified ProcessID. Returns INVALID_HANDLE_VALUE if something fails
*/
HANDLE Inject::GetThreadFromProcess(DWORD ProcessID) {

  HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, ProcessID);
  if (hSnap == INVALID_HANDLE_VALUE) {
    printf("Failed Creating Toolhelp32Snapshot: %d\n", GetLastError());
    return INVALID_HANDLE_VALUE;
  }

  THREADENTRY32 te32 = {0};
  te32.dwSize = sizeof(THREADENTRY32);

  if (!Thread32First(hSnap, &te32)) {
    printf("Thread32First Failed! %d\n", GetLastError());
    return INVALID_HANDLE_VALUE;
  };

  do {
    if (te32.th32OwnerProcessID == ProcessID) {
      printf("[+] Found Thread Matching Process ID!\n   [+] Thread ID: %d\n\n",
             te32.th32ThreadID);
      break;
    }
  } while (Thread32Next(hSnap, &te32));

  CloseHandle(hSnap);

  if (te32.th32OwnerProcessID != ProcessID) {
    printf("Couldn't Find Thread with Target Process ID.\n");
    return INVALID_HANDLE_VALUE;
  }

  HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, false, te32.th32ThreadID);
  if (hThread == INVALID_HANDLE_VALUE || hThread == NULL) {
    printf("Failed Opening Target Thread %d\n", GetLastError());
    return 0;
  }

  return hThread;
}

/*
    brief: Returns the address of the start of a module
*/
uintptr_t Inject::GetModuleBase(DWORD ProcessID, const char *szModuleName) {
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

/*
    brief: Allocates memory near the old RIP value
   This makes the shellcode much simpler; only needing E9 jump (offset) instead
   of doing bullshit for an x64 absolute jmp
*/
LPVOID Inject::AllocNearKernel32DLL(HANDLE hProcess) {
  MEM_ADDRESS_REQUIREMENTS MemRequirements = {0};
  MEM_EXTENDED_PARAMETER MemParams = {0};

  MemRequirements.Alignment = 0;
  MemRequirements.LowestStartingAddress = (PVOID)0x00007FFCA0000000;

  MemParams.Type = MemExtendedParameterAddressRequirements;
  MemParams.Pointer = &MemRequirements;

  SYSTEM_INFO SysInfo;
  GetSystemInfo(&SysInfo);

  LPVOID MyBufferSpace = VirtualAlloc2(
      hProcess, nullptr, SysInfo.dwAllocationGranularity,
      MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE, &MemParams, 1);

  return MyBufferSpace;
}
