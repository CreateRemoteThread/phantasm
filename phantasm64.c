#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winternl.h>
#include <psapi.h>

#pragma comment(lib,"psapi.lib")

char *exeFileName = NULL;
char *exeWorkingDir = NULL;
char *exeCmdLine = NULL;

// read: http://stackoverflow.com/questions/7446887/get-command-line-string-of-64-bit-process-from-32-bit-process

void handleFirstException(HANDLE hProcess,int threadId,char firstByte);
void SetSingleStep(HANDLE hThread, int stepmode);

typedef DWORD (WINAPI * _NtQueryInformationProcess) (HANDLE, PROCESSINFOCLASS, PVOID, ULONG,PULONG);

void SetSingleStep(HANDLE hThread, int stepmode)
{
	CONTEXT c;
	memset(&c,0,sizeof(CONTEXT));
	c.ContextFlags = CONTEXT_FULL;
	GetThreadContext(hThread,&c);
	c.EFlags |= 0x00000100;
	SetThreadContext(hThread,&c);
}

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

	_NtQueryInformationProcess NtQueryInformationProcess;
	HMODULE ntDll = LoadLibrary("ntdll");
	NtQueryInformationProcess = (_NtQueryInformationProcess) (GetProcAddress(ntDll, "NtQueryInformationProcess"));

	PROCESS_BASIC_INFORMATION *pbi = (PROCESS_BASIC_INFORMATION *)malloc(sizeof(PROCESS_BASIC_INFORMATION));
	NtQueryInformationProcess(pi.hProcess,ProcessBasicInformation,pbi,sizeof(PROCESS_BASIC_INFORMATION),NULL);

	// int processId = GetProcessId(pi.hProcess);
	//int *u = (int *)(pbi->UniqueProcessId);
	//printf("* getprocessid says %d, peb says %d\n",processId,u[0]);
	printf("* peb base = %016x\n",pbi->PebBaseAddress);
	PEB pebBuffer;
	ReadProcessMemory(pi.hProcess,pbi->PebBaseAddress,&pebBuffer,sizeof(PEB),&bytes_read);
	char *ImageBaseAddress =  (char *)pebBuffer.Reserved3[1];
	printf("* image base address according to PEB is %016x\n",ImageBaseAddress);

	IMAGE_DOS_HEADER *imgDosHdr = (IMAGE_DOS_HEADER *)malloc(sizeof(IMAGE_DOS_HEADER));
	IMAGE_NT_HEADERS *imgNtHdrs = (IMAGE_NT_HEADERS *)malloc(sizeof(IMAGE_NT_HEADERS));

	ReadProcessMemory(pi.hProcess,ImageBaseAddress,imgDosHdr,sizeof(IMAGE_DOS_HEADER),&bytes_read);
	printf("* reading IMAGE_DOS_HEADER at %016x, magic is %x\n",ImageBaseAddress,imgDosHdr->e_magic);
	if (imgDosHdr->e_magic != 0x5a4d)
	{
		return 0;
	}
	ReadProcessMemory(pi.hProcess,ImageBaseAddress + imgDosHdr->e_lfanew,imgNtHdrs,sizeof(IMAGE_NT_HEADERS),&bytes_read);
	printf("* reading IMAGE_NT_HEADERS at %016x, signature is %x\n",ImageBaseAddress + imgDosHdr->e_lfanew,imgNtHdrs->Signature);

	char *entryPoint = ImageBaseAddress + imgNtHdrs->OptionalHeader.AddressOfEntryPoint;
	printf("* entry is %016x\n",entryPoint);

	char firstByte = '\x00';
	ReadProcessMemory(pi.hProcess,entryPoint,&firstByte,1,&bytes_read);
	WriteProcessMemory(pi.hProcess,entryPoint,"\xCC",1,&bytes_read);
	int firstException = 1;

	// messy as fuck, fix it later.
	HANDLE hThread = NULL;
	int expectAccessViolation = FALSE;

	LPVOID moduleAddress[1024];
	DWORD moduleSize[1024];

	memset(moduleAddress,0,sizeof(LPVOID) * 1024);
	memset(moduleSize,0,sizeof(DWORD) * 1024);
	int numModules = 0;

	CONTEXT c;

	LPVOID coreModAddress = NULL;
	DWORD coreModSize = 0;

	DWORD oldProtect = 0;
	DWORD discard;

	while(continueDebugging)
	{
		WaitForDebugEvent(&de,INFINITE);
		if (hThread == NULL)
		{
			hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,FALSE,de.dwThreadId);
		}
		switch(de.dwDebugEventCode)
		{
			case EXIT_PROCESS_DEBUG_EVENT:
				printf("* exit_process\n");
				continueDebugging = 0;
				break;
			case EXCEPTION_DEBUG_EVENT:
				if (firstException == 1 && de.u.Exception.ExceptionRecord.ExceptionAddress == entryPoint)
				{
					printf(" + scan modules\n");
					// -- begin code to scan modules --
					HMODULE hMods[1024];
					MODULEINFO mi;
					DWORD cbNeeded;
					int i;
					EnumProcessModules(pi.hProcess,hMods,sizeof(hMods),&cbNeeded);
					for ( i = 0; i < (cbNeeded / sizeof(HMODULE)); i++ )
					{
						GetModuleInformation(pi.hProcess,hMods[i],&mi,sizeof(mi));
						moduleAddress[numModules] = mi.lpBaseOfDll;
						moduleSize[numModules] = mi.SizeOfImage;
						if(mi.lpBaseOfDll == (LPVOID )ImageBaseAddress)
						{
							printf("C found core module, saving...\n");
							coreModAddress = mi.lpBaseOfDll;
							coreModSize = mi.SizeOfImage;
						}
						printf("M %016x to %016x\n",(DWORD64 )moduleAddress[numModules],(DWORD64 )moduleAddress[numModules] + moduleSize[numModules]);
						numModules++;
					}
					handleFirstException(pi.hProcess,de.dwThreadId,firstByte);
					SetSingleStep(hThread,1);
					firstException = 0;
				}
				else if (firstException == 1) // this should probably be a toggle switch.
				{
					printf("* exception before firstException triggered\n");
					ContinueDebugEvent (de.dwProcessId, de.dwThreadId,DBG_EXCEPTION_NOT_HANDLED);
				}
				else
				{
					if (de.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP)
					{
						c.ContextFlags = CONTEXT_FULL;
						GetThreadContext(hThread,&c);
						printf("+ single step ExceptionAddress = %016x, Rip = %016x\n",de.u.Exception.ExceptionRecord.ExceptionAddress, c.Rip);
						// if the instruction is within our "trace bounds", trace it. otherwise, don't worry.

						SetSingleStep(hThread,1);
						ContinueDebugEvent (de.dwProcessId, de.dwThreadId,DBG_CONTINUE);
					}
					else
					{
						printf("* exception... (%x) %016x\n",de.u.Exception.ExceptionRecord.ExceptionCode,(DWORD64 )de.u.Exception.ExceptionRecord.ExceptionAddress);
						ContinueDebugEvent (de.dwProcessId, de.dwThreadId,DBG_EXCEPTION_NOT_HANDLED);
						if(de.u.Exception.dwFirstChance == 0) // i.e. we didn't handle this.
						{
							printf("* this is a second try exception, failing.");
							ExitProcess(0);
						}
					}

					/*else if (de.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_ACCESS_VIOLATION && expectAccessViolation == TRUE)
					{
						printf("- new instruction at %016x, resetting to %x\n",de.u.Exception.ExceptionRecord.ExceptionAddress, oldProtect);
						VirtualProtectEx(pi.hProcess,coreModAddress,coreModSize,oldProtect,&discard);
						expectAccessViolation = FALSE;
						ContinueDebugEvent (de.dwProcessId, de.dwThreadId,DBG_CONTINUE);
					}*/

				}
				break;
			default:
				ContinueDebugEvent (de.dwProcessId, de.dwThreadId,DBG_EXCEPTION_NOT_HANDLED);
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

	printf("* restoring firstException to %02x\n",(unsigned char )firstByte);
	size_t bytes_written;
	WriteProcessMemory(hProcess,(LPVOID )c.Rip,&firstByte,1,&bytes_written);

	SetThreadContext(hThread,&c);
	
	CloseHandle(hThread);
	return;
}
