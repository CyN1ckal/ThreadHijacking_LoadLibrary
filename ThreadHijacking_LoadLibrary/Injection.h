class Inject {
public:
  static bool Initialize();
  static int NumCharsInCharPtr(char *array);

  static HANDLE GetThreadFromProcess(DWORD ProcessID);
  static uintptr_t GetModuleBase(DWORD ProcessID, const char *szModuleName);
  static LPVOID AllocNearOldRIP(HANDLE hProcess);

  static const char *DllName;
  static int DllNameLength;
  static DWORD ProcessID;
  static HANDLE hProcess;

private:
};