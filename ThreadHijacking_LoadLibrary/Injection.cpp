#include "stdafx.h"

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
      printf("[+] Found Thread Matching Process ID!\n   [+] Thread ID: %d\n",
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

