#include <windows.h>
#include <psapi.h>
#include "tinker.h"

#if REGISTER_LENGTH == DWORD64
	#define ARCHI 64
	#define PC_REG Rip
#else
	#define ARCHI 32
	#define PC_REG Eip
#endif

#define MAX_CMD 1024

void miniDebugger(PROCESS_INFORMATION *pi, DEBUG_EVENT *de)
{
	HANDLE h = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,FALSE,de.dwThreadId);
	int bCont = 1;
	char *cmd = (char *)malloc(MAX_CMD);

	while (bCont)
	{
		memset(cmd,0,MAX_CMD);
		fgets();
	}

	free(cmd);

	CloseHandle(h);
	return;
}