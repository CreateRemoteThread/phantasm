
typedef struct exportGroupStruct
{
  char *moduleName;
  char *moduleShortName;
  DWORD moduleBase;
  DWORD moduleEnd;
  struct exportStruct *exports;
  struct exportGroupStruct *next;
} exportGroupStruct;

typedef struct exportStruct
{
  char *exportName;
  WORD exportOrdinal;
  DWORD exportAddr;
  struct exportStruct *next;
} exportStruct;

void cleanStructures (exportGroupStruct * e);
exportGroupStruct *scanResolution (HANDLE hProcess, DWORD processId);
exportStruct *scanSingleModule (HANDLE hProcess, DWORD modBaseAddr,
                                DWORD modBaseSize);
exportStruct *scanSingleModule_fixup (HANDLE hProcess, DWORD modBaseAddr,
                                DWORD modBaseSize);
DWORD resolveExport (exportGroupStruct * e, char *dllfunc);
char *resolveAddr (exportGroupStruct * e, DWORD dlladdr);
char *resolveAddrSoft (exportGroupStruct * e, DWORD dlladdr);
char *strtok_r (char *str, const char *delim, char **saveptr);
exportGroupStruct *scanModules (HANDLE hProcess, DWORD processId,
                                int printMode);
char *stristr (char *szStringToBeSearched,
               const char *szSubstringToSearchFor);
