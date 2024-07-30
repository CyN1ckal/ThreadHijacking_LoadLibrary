class Inject {
public:
  static HANDLE GetThreadFromProcess(DWORD ProcessID);
  static uintptr_t GetModuleBase(DWORD ProcessID, const char *szModuleName);
  static LPVOID AllocNearKernel32DLL(HANDLE hProcess);


private:
};