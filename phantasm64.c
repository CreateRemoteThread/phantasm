#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <beaengine/beaengine.h>

#include "oracle.h"
#include "tinker.h"

#pragma comment(lib,"psapi.lib")

// switch out for 32-bit.
#define REGISTER_LENGTH DWORD64

#define STATE_NONE 0
#define STATE_STARTCALL 1
#define STATE_CALLDONE 2

char *exeFileName = NULL;
char *exeWorkingDir = NULL;
char *exeCmdLine = NULL;

int flag_displayDisassembly = 1;

// 2048 threads but not necessarily sequential thread id's. wat do...
// http://blogs.technet.com/b/markrussinovich/archive/2009/07/08/3261309.aspx

// read: http://stackoverflow.com/questions/7446887/get-command-line-string-of-64-bit-process-from-32-bit-process

void handleFirstException(HANDLE hProcess,int threadId,char firstByte);
void SetSingleStep(HANDLE hThread, int stepmode);
void lookAhead(HANDLE hProcess, HANDLE hThread, LPVOID pc_, DISASM *d);
char *guessWorkDir (char *path);
void handleSecondTry(HANDLE hProcess,HANDLE hThread,DEBUG_EVENT *de);
void miniDebugger(PROCESS_INFORMATION *pi, DEBUG_EVENT *de);

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
	DISASM d;
	#if REGISTER_LENGTH == DWORD64
		#define ARCHI 64
		#define PC_REG Rip
	#else
		#define ARCHI 32
		#define PC_REG Eip
	#endif
	STARTUPINFO si;
	PROCESS_INFORMATION pi;

	memset(&si,0,sizeof(si));
	si.cb = sizeof(si);
	memset(&pi,0,sizeof(pi));

	int continueDebugging = 1;
	DEBUG_EVENT de;
	memset(&de,0,sizeof(de));

	char *exeFileName = NULL;
	char *exeWorkingDir = NULL;
	char *exeCmdLine = NULL;

	exeFileName = (char *)malloc(MAX_PATH+1);
	// exeWorkingDir = (char *)malloc(MAX_PATH+1);
	exeCmdLine = (char *)malloc(MAX_PATH+1);

	memset(exeFileName,0,MAX_PATH+1);
	// memset(exeWorkingDir,0,MAX_PATH+1);
	memset(exeCmdLine,0,MAX_PATH+1);

    // GetCurrentDirectory(MAX_PATH,exeWorkingDir);

	int exeCmdLineLen = 0;
	int i = 1;

	for(;i < argc;i++)
    {
		exeCmdLineLen += strlen(argv[i]) + 1;
    }

	i = 1;

	for(;i < argc;i++)
    {
        if(exeCmdLine[0] == '\0')
        {
            strcpy(exeCmdLine,argv[i]);
        }
        else
        {
            strcat(exeCmdLine,argv[i]);
        }
        strcat(exeCmdLine," ");
    }

	if(exeCmdLine[0] == '"')
    {
        // printf("* culling cmdline\n");
        i = 1;
        while(exeCmdLine[i++] != '"') {} ;
    }
    else
    {
		if(strstr(exeCmdLine,".exe") != NULL)
		{
			i = (int )(strstr(exeCmdLine,".exe") - (char *)exeCmdLine);
			
			i += 4;
		}
		else
		{
			printf("E:need to specify an exe file\n");
			exit(0);
		}
    }

	/*
	// pretty sure i was high when i wrote this
	if(i == 15)
    {
        printf("E:malloc fails when cmdline is 15 bytes long\n");
		exit(0);
    }
	*/

	exeFileName = (char *)malloc(i + 1);
    memset(exeFileName,0,strlen(exeCmdLine) + 1);
    exeFileName[i] = '\0';
    strcpy(exeFileName,exeCmdLine);

	exeWorkingDir = guessWorkDir(exeFileName);

	printf("* CreateProcess(%s,%s,%s);\n",exeFileName,exeCmdLine,exeWorkingDir);
	int mRet = CreateProcess(exeFileName,exeCmdLine,NULL,NULL,FALSE,DEBUG_PROCESS + CREATE_NEW_CONSOLE,NULL,exeWorkingDir,&si,&pi);
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

	DWORD callState = STATE_NONE;

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
			case LOAD_DLL_DEBUG_EVENT:
				// scanExportTables(pi.hProcess,);
				break;
			case EXCEPTION_DEBUG_EVENT:
				if (firstException == 1 && de.u.Exception.ExceptionRecord.ExceptionAddress == entryPoint)
				{
					printf(" + scan modules\n");
					// -- begin code to scan modules --
					HMODULE hMods[1024];
					MODULEINFO mi;
					DWORD cbNeeded;
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
						#if ARCHI==64
							printf("M %016x to %016x\n",(REGISTER_LENGTH )moduleAddress[numModules],(REGISTER_LENGTH )moduleAddress[numModules] + moduleSize[numModules]);
							numModules++;
						#else
							printf("M %08x to %08x\n",(REGISTER_LENGTH )moduleAddress[numModules],(REGISTER_LENGTH )moduleAddress[numModules] + moduleSize[numModules]);
							numModules++;
						#endif
					}
					// c.ContextFlags = CONTEXT_FULL;
					// GetThreadContext(hThread,&c);
					lookAhead(pi.hProcess,hThread,NULL,&d);
					printf(" %s\n",d.CompleteInstr);
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
						// multithreading makes me a sadpanda.
						lookAhead(pi.hProcess,hThread,NULL,&d);
						printf(" %s\n",d.CompleteInstr);
						if(callState == STATE_NONE)
						{
							// not required
							// lookAhead(pi.hProcess,(LPVOID )c.PC_REG,&d);
							if (d.Instruction.BranchType != 0)
							{
								// printf("+ JMP\n");
								expectAccessViolation = TRUE;
								// printf("C1\n");
								// VirtualProtectEx(pi.hProcess,coreModAddress,coreModSize,PAGE_READWRITE,&oldProtect);
								callState = STATE_STARTCALL;
								SetSingleStep(hThread,1);
							}
							else
							{
								// printf("X");
								SetSingleStep(hThread,1);
							}
						}
						else if(callState == STATE_STARTCALL)
						{
							// printf("C2\n");
							VirtualProtectEx(pi.hProcess,coreModAddress,coreModSize,PAGE_READWRITE,&oldProtect);
							callState = STATE_NONE;
						}
						ContinueDebugEvent (de.dwProcessId, de.dwThreadId,DBG_CONTINUE);
					}
					else if(de.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_ACCESS_VIOLATION && expectAccessViolation == TRUE && ( \
						de.u.Exception.ExceptionRecord.ExceptionAddress > coreModAddress && \
						de.u.Exception.ExceptionRecord.ExceptionAddress < (LPVOID )((REGISTER_LENGTH )coreModAddress + coreModSize )) ){
						if (de.u.Exception.ExceptionRecord.ExceptionAddress)
						{
						}
						printf(" C calling %016x\n",de.u.Exception.ExceptionRecord.ExceptionAddress);
						SetSingleStep(hThread,1);
						expectAccessViolation=FALSE;
						// does this silently fail or break DEP? note to self, check from 32-bit phantasm
						VirtualProtectEx(pi.hProcess,coreModAddress,coreModSize,PAGE_EXECUTE_READWRITE,&oldProtect);
						ContinueDebugEvent (de.dwProcessId, de.dwThreadId,DBG_CONTINUE);
					}
					else
					{
						printf("* exception... (%x) %016x\n",de.u.Exception.ExceptionRecord.ExceptionCode,(REGISTER_LENGTH )de.u.Exception.ExceptionRecord.ExceptionAddress);
						ContinueDebugEvent (de.dwProcessId, de.dwThreadId,DBG_EXCEPTION_NOT_HANDLED);
						if(de.u.Exception.dwFirstChance == 0) // i.e. we didn't handle this.
						{
							handleSecondTry(pi.hProcess,hThread,&de);
							miniDebugger(&pi,&de);
							// ExitProcess(0);
						}
					}
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
	c.PC_REG -= 1;

	printf("* restoring firstException to %02x\n",(unsigned char )firstByte);
	size_t bytes_written;
	WriteProcessMemory(hProcess,(LPVOID )c.PC_REG,&firstByte,1,&bytes_written);

	SetThreadContext(hThread,&c);
	
	CloseHandle(hThread);
	return;
}

void lookAhead(HANDLE hProcess, HANDLE hThread, LPVOID pc_, DISASM *d)
{

	/*
	2.3.11 AVX Instruction Length
	The maximum length of an Intel 64 and IA-32 instruction remains 15 bytes.
	*/
	char memChunk[15];
	size_t bR = 0;

	LPVOID pc = pc_;

	if(pc == NULL && hThread != NULL)
	{
		CONTEXT c;
		c.ContextFlags = CONTEXT_FULL;
		GetThreadContext(hThread,&c);
		pc = (LPVOID )c.PC_REG;
	}

	ReadProcessMemory(hProcess,pc,(LPVOID )memChunk,15,&bR);
	memset(d,0,sizeof(DISASM));
	d->Archi = ARCHI;
	d->EIP = (UIntPtr )memChunk;

	// prettyPrint(memChunk);
	// why does this get pretty-printed twice?☼
	int len = Disasm(d);
	if(flag_displayDisassembly == 1)
	{
		int i = 0;
		printf(" %x:",pc);
		for(; i < len;i++)
		{
			printf("%02x",(unsigned char )memChunk[i]);
		}
		printf(" ");
	}

	return;
}

// nicked this from debugger
// don't touch, it works
char *guessWorkDir (char *path)
{
  char *c = NULL;
  char *p = strrchr (path, '\\');
  if (p == NULL)
    {
      return NULL;
    }
  else
    {
      c = (char *) GlobalAlloc (GPTR, p - path + 2);
      memset (c, 0, (p - path + 2));
      strncpy (c, path, (p - path));
      return c;
    }
}

void handleSecondTry(HANDLE hProcess,HANDLE hThread,DEBUG_EVENT *de)
{
	DISASM d;
	d.Archi = ARCHI;

	CONTEXT c;
	c.ContextFlags = CONTEXT_FULL;
	GetThreadContext(hThread,&c);

	if (ARCHI == 64)
	{
		#if ARCHI == 64
		printf("rax=%016x rbx=%016x rcx=%016x\n",c.Rax,c.Rbx,c.Rcx);
		printf("rdx=%016x rsi=%016x rdi=%016x\n",c.Rdx,c.Rsi,c.Rdi);
		printf(" r8=%016x  r9=%016x r10=%016x\n",c.R8,c.R9,c.R10);
		printf("r11=%016x r12=%016x r13=%016x\n",c.R11,c.R12,c.R13);
		printf("r14=%016x r15=%016x\n",c.R14,c.R15);
		#endif
	}
	else
	{
		#if ARCHI == 32
		printf("eax=%08x ebx=%08x ecx=%08x edx=%08x",c.Eax,c.Ebx,c.Ecx,c.Edx);
		printf("esi=%08x edi=%08x ebp=%08x esp=%08x",c.Esi,c.Edi,c.Ebp,c.Esp);
		#endif
	}

	lookAhead(hProcess,hThread,NULL,&d);
	printf("%s",d.CompleteInstr);

	return;
}
