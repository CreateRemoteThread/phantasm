typedef struct _PEB
{
  BOOLEAN InheritedAddressSpace;
  BOOLEAN ReadImageFileExecOptions;
  BOOLEAN BeingDebugged;
  BOOLEAN Spare;
  HANDLE Mutant;
  PVOID ImageBaseAddress;
  PVOID LoaderData;
  // PPEB_LDR_DATA LoaderData;
  PVOID ProcessParameters;
  // PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
  PVOID SubSystemData;
  PVOID ProcessHeap;
  PVOID FastPebLock;
  PVOID FastPebLockRoutine;
  // PPEBLOCKROUTINE FastPebLockRoutine;
  PVOID FastPebUnlockRoutine;
  // PPEBLOCKROUTINE FastPebUnlockRoutine; 
  ULONG EnvironmentUpdateCount;
  PVOID KernelCallbackTable;
  // PPVOID KernelCallbackTable;
  PVOID EventLogSection;
  PVOID EventLog;
  PVOID FreeList;
  // PPEB_FREE_BLOCK FreeList; 
  ULONG TlsExpansionCounter;
  PVOID TlsBitmap;
  ULONG TlsBitmapBits[0x2];
  PVOID ReadOnlySharedMemoryBase;
  PVOID ReadOnlySharedMemoryHeap;
  PVOID ReadOnlyStaticServerData;
  // PPVOID ReadOnlyStaticServerData; 
  PVOID AnsiCodePageData;
  PVOID OemCodePageData;
  PVOID UnicodeCaseTableData;
  ULONG NumberOfProcessors;
  ULONG NtGlobalFlag;
  BYTE Spare2[0x4];
  LARGE_INTEGER CriticalSectionTimeout;
  ULONG HeapSegmentReserve;
  ULONG HeapSegmentCommit;
  ULONG HeapDeCommitTotalFreeThreshold;
  ULONG HeapDeCommitFreeBlockThreshold;
  ULONG NumberOfHeaps;
  ULONG MaximumNumberOfHeaps;
  PVOID ProcessHeaps;
  // PPVOID *ProcessHeaps;
  PVOID GdiSharedHandleTable;
  PVOID ProcessStarterHelper;
  PVOID GdiDCAttributeList;
  PVOID LoaderLock;
  ULONG OSMajorVersion;
  ULONG OSMinorVersion;
  ULONG OSBuildNumber;
  ULONG OSPlatformId;
  ULONG ImageSubSystem;
  ULONG ImageSubSystemMajorVersion;
  ULONG ImageSubSystemMinorVersion;
  ULONG GdiHandleBuffer[0x22];
  ULONG PostProcessInitRoutine;
  ULONG TlsExpansionBitmap;
  BYTE TlsExpansionBitmapBits[0x80];
  ULONG SessionId;
} PEB, *PPEB;

typedef struct _LSA_UNICODE_STRING
{
  USHORT Length;
  USHORT MaximumLength;
  PWSTR Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;

typedef struct _PROCESS_PARAMETERS
{
  ULONG AllocationSize;
  ULONG Size;
  ULONG Flags;
  ULONG Reserved;
  LONG Console;
  ULONG ProcessGroup;
  HANDLE hStdInput;
  HANDLE hStdOutput;
  HANDLE hStdError;
  UNICODE_STRING CurrentDir;
  HANDLE CurrentDirectoryHandle;
  UNICODE_STRING LoadSearchPath;
  UNICODE_STRING ImageName;
  UNICODE_STRING CommandLine;
  PWSTR Enviroment;
  ULONG dwX;
  ULONG dwY;
  ULONG dwXSize;
  ULONG dwYSize;
  ULONG dwXCountChars;
  ULONG dwYCountChars;
  ULONG dwFillAttributes;
  ULONG dwFlags;
  ULONG wShowWindow;
  UNICODE_STRING WindowTitle;
  UNICODE_STRING Desktop;
  UNICODE_STRING Reserved1;
  UNICODE_STRING Reserved2;
} PROCESS_PARAMETERS, *PPROCESS_PARAMETERS;

typedef struct _PROCESS_BASIC_INFORMATION
{
  PVOID Reserved1;
  PPEB PebBaseAddress;
  PVOID Reserved2[2];
  ULONG_PTR UniqueProcessId;
  PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

typedef struct _TRACEMODULEINFO
{
  unsigned long startAddress;
  unsigned long endAddress;
} TRACEMODULEINFO;



#define PEEK_AFTER_CALL 5

typedef HANDLE (WINAPI * _OpenThread) (DWORD, BOOL, DWORD);
typedef DWORD (WINAPI * _NtQueryInformationProcess) (HANDLE, DWORD, DWORD, DWORD, DWORD);

void dumpExecuteEnvironment();
void buildExecuteEnvironment(int , char **);
unsigned long getEntryPoint(HANDLE , unsigned long );
int handleFirstException(DEBUG_EVENT *de, int *firstException, unsigned long addressOfEntryPoint, unsigned long processId, HANDLE hProcess,char *oldEntryPoint, TRACEMODULEINFO *ti);
BOOL SetSingleStepMode (HANDLE hThread, BOOL bSet);
void printInstruction(HANDLE hProcess, HANDLE hThread, unsigned long dwThreadId, x86_insn_t *insn, char *tagType);
void buildFunctionHooks();
void lookAhead(HANDLE hProcess, LPVOID eip, x86_insn_t *insn);
void printTimestamp();
int getResponse(char *question);

#define MODE_WRITE 0
#define MODE_READ 1

DWORD useRegister(CONTEXT * c, char *regSelect, DWORD value, int opMode);
int isFlowControl(x86_insn_t *insn);