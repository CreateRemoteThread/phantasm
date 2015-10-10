#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <Winternl.h>

char *exeFileName = NULL;
char *exeWorkingDir = NULL;
char *exeCmdLine = NULL;

// read: http://stackoverflow.com/questions/7446887/get-command-line-string-of-64-bit-process-from-32-bit-process

int main(int argc, char **argv)
{
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	memset(&si,0,sizeof(si));
	si.cb = sizeof(si);
	memset(&pi,0,sizeof(pi));

	int continueDebugging = 1;
	DEBUG_EVENT de;
	memset(&de,0,sizeof(de));

	int mRet = CreateProcess("test64.exe","test64.exe",NULL,NULL,FALSE,DEBUG_PROCESS + CREATE_NEW_CONSOLE,NULL,"c:\\projects\\phantasm\\",&si,&pi);

	PROCESS_BASIC_INFORMATION *pbi = (PROCESS_BASIC_INFORMATION *)malloc(sizeof(PROCESS_BASIC_INFORMATION));
	printf("* peb base = %016x\n",pbi->PebBaseAddress);

	while(continueDebugging)
	{
		WaitForDebugEvent(&de,INFINITE);
		switch(de.dwDebugEventCode)
		{
			case EXIT_PROCESS_DEBUG_EVENT:
				printf("* exit_process\n");
				continueDebugging = 0;
				break;
			case EXCEPTION_DEBUG_EVENT:
				printf("* %016x\n",(DWORD64 )de.u.Exception.ExceptionRecord.ExceptionAddress);
				ContinueDebugEvent (de.dwProcessId, de.dwThreadId,DBG_EXCEPTION_NOT_HANDLED);
				ExitProcess(0);
				break;
			default:
				printf("* +1\n");
				break;
		}
        ContinueDebugEvent (de.dwProcessId, de.dwThreadId,DBG_CONTINUE);
	}

	return 0;
}