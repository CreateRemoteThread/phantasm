#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <Winternl.h>

char *exeFileName = NULL;
char *exeWorkingDir = NULL;
char *exeCmdLine = NULL;

// read: http://stackoverflow.com/questions/7446887/get-command-line-string-of-64-bit-process-from-32-bit-process

void handleFirstException(HANDLE hProcess,int threadId,char firstByte);

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
	size_t bytes_read;

	PROCESS_BASIC_INFORMATION *pbi = (PROCESS_BASIC_INFORMATION *)malloc(sizeof(PROCESS_BASIC_INFORMATION));
	printf("* peb base = %016x\n",pbi->PebBaseAddress);
	PEB pebBuffer;
	ReadProcessMemory(pi.hProcess,pbi->PebBaseAddress,&pebBuffer,sizeof(PEB),&bytes_read);
	char *ImageBaseAddress =  (char *)pebBuffer.Reserved3[1];
	printf("* image base address according to PEB is %016x\n",ImageBaseAddress);

	IMAGE_DOS_HEADER *imgDosHdr = (IMAGE_DOS_HEADER *)malloc(sizeof(IMAGE_DOS_HEADER));
	IMAGE_NT_HEADERS *imgNtHdrs = (IMAGE_NT_HEADERS *)malloc(sizeof(IMAGE_NT_HEADERS));

	ReadProcessMemory(pi.hProcess,ImageBaseAddress,imgDosHdr,sizeof(IMAGE_DOS_HEADER),&bytes_read);
	printf("* reading IMAGE_DOS_HEADER at %016x, magic is %x\n",ImageBaseAddress,imgDosHdr->e_magic);

	ReadProcessMemory(pi.hProcess,ImageBaseAddress + imgDosHdr->e_lfanew,imgNtHdrs,sizeof(IMAGE_NT_HEADERS),&bytes_read);
	printf("* reading IMAGE_NT_HEADERS at %016x, signature is %x\n",ImageBaseAddress + imgDosHdr->e_lfanew,imgNtHdrs->Signature);

	char *entryPoint = ImageBaseAddress + imgNtHdrs->OptionalHeader.AddressOfEntryPoint;
	printf("* entry is %016x\n",entryPoint);

	char firstByte = '\x00';
	ReadProcessMemory(pi.hProcess,entryPoint,&firstByte,1,&bytes_read);
	WriteProcessMemory(pi.hProcess,entryPoint,"\xCC",1,&bytes_read);
	int firstException = 1;

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
				if (firstException == 1 && de.u.Exception.ExceptionRecord.ExceptionAddress == entryPoint)
				{
					handleFirstException(pi.hProcess,de.dwThreadId,firstByte);
					firstException = 0;
				}
				else if (firstException == 1)
				{
					ContinueDebugEvent (de.dwProcessId, de.dwThreadId,DBG_EXCEPTION_NOT_HANDLED);
				}
				else
				{
					printf("* exception... %016x\n",(DWORD64 )de.u.Exception.ExceptionRecord.ExceptionAddress);
					ContinueDebugEvent (de.dwProcessId, de.dwThreadId,DBG_EXCEPTION_NOT_HANDLED);
					ExitProcess(0);
				}
				break;
			default:
				printf("* +1\n");
				break;
		}
        ContinueDebugEvent (de.dwProcessId, de.dwThreadId,DBG_CONTINUE);
	}

	return 0;
}

// remove first exception
void handleFirstException(HANDLE hProcess,int threadId,char firstByte)
{
	HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,FALSE,threadId);
	
	CONTEXT c;
	memset(&c,0,sizeof(CONTEXT));
	c.ContextFlags = CONTEXT_FULL;

	GetThreadContext(hThread,&c);

	// 32-bit i Eip here - but it's always one byte because we write \xcc
	c.Rip -= 1;

	printf("* restoring...\n");
	size_t bytes_written;
	WriteProcessMemory(hProcess,(LPVOID )c.Rip,&firstByte,1,&bytes_written);

	SetThreadContext(hThread,&c);
	
	CloseHandle(hThread);
	return;
}