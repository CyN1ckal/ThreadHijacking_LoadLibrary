class Inject {
public:
  static HANDLE GetThreadFromProcess(DWORD ProcessID);
  static uintptr_t GetModuleBase(DWORD ProcessID, const char *szModuleName);

private:
};