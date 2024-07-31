// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <iostream>

#include "processthreadsapi.h"

HWND HandleToWindow = 0;

static BOOL CALLBACK EnumWindowCallback(HWND hwnd, LPARAM lParam) {
  DWORD ProcessId = GetCurrentProcessId();
  DWORD WindowProcessId = 0;
  GetWindowThreadProcessId(hwnd, &WindowProcessId);

  if (ProcessId == WindowProcessId) {
    HandleToWindow = hwnd;
    return 0;
  }

  return 1;
}

void ThreadHijack(HMODULE hModule) {

  EnumWindows(EnumWindowCallback, NULL);

  MessageBoxA(HandleToWindow, "DLL Injected", "Thread Hijacked", MB_OK);

  // FreeLibrary(hModule);

  return;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call,
                      LPVOID lpReserved) {
  switch (ul_reason_for_call) {
  case DLL_PROCESS_ATTACH:
    ThreadHijack(hModule);
    break;
  case DLL_THREAD_ATTACH:
  case DLL_THREAD_DETACH:
  case DLL_PROCESS_DETACH:
    break;
  }
  return TRUE;
}
