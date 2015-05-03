typedef struct _resolveNode{
    char *funcName;
    unsigned long funcAddr;
    struct _resolveNode *next;
} resolveNode;

typedef struct _funcMaskNode{
    char *funcName;
    char *funcMask;
    char *storMask;
    int argCount;
    struct _funcMaskNode *next;
} funcMaskNode;

char *disassembleSingleInstruction(HANDLE hProcess, unsigned long disasmOffset, unsigned long dwThreadId, x86_insn_t *insn, char *insnBuffer, int *insnLen);
void dumpFunctionArgs(HANDLE hProcess, unsigned long Esp, char *functionName, int argCount, char *functionMask);
void buildArgumentHooks(char *functionPrototypeFile);
void chomp(char *s);
int lookupFunctionAndDump(HANDLE hProcess, char *functionName, unsigned long dwThreadId,unsigned long crashAddress);
BYTE *readUntilZero (HANDLE hProcess, DWORD startAddress);
void setDebugMaskLoader(int i);

#define INSN_BUFFER_LEN 32