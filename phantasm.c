/*
    E: error
    I: informational
    C: call
    X: exception
    T: tag
    -: instruction
*/

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <tlhelp32.h>
#include <string.h>
#include <time.h>
#include "libdis/libdis.h"
#include "phantasm.h"
#include "geist.h"
#include "resolute.h"

int quietMode = 1;
int noOpcodes = 0;
int traceAllMode = 0;
int timestamps = 0;

unsigned long tickStart = 0;
unsigned long tickEnd = 0;

// char *lineSep = "I:------------------------------------------------------------------------\n";

char *exeFileName = NULL;
char *exeWorkingDir = NULL;
char *exeCmdLine = NULL;

char *argSpecFile = NULL;

exportGroupStruct *globalExports = NULL;

_NtQueryInformationProcess NtQueryInformationProcess;

x86_insn_t g_insn;

char *hexChars = "0123456789ABCDEF-----";

void usage();

// ****************************************************************** //
/***********************/ int lastCall = 0; /**************************/
/*********************/ unsigned long lastEip; /***********************/
// ****************************************************************** //

int main(int argc, char **argv)
{
	#ifdef SUPERVERBOSE
		printf("** SUPER VERBOSE MODE ACTIVE **\n");
	#endif
    if(argc == 1)
    {
        usage();
        return 0;
    }

    int argc_temp = argc;
    char **argv_temp = argv;

    buildExecuteEnvironment(argc_temp, argv_temp);
    dumpExecuteEnvironment();
    buildFunctionHooks();
    // step 1: load executables, give a break at the entrypoint.

    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    memset(&si,0,sizeof(si));
    si.cb = sizeof(si);
    memset(&pi,0,sizeof(pi));

	x86_init (opt_none, NULL, NULL);

    // distorm_decode(offset, (const unsigned char*)buf, filesize, dt, decodedInstructions, MAX_INSTRUCTIONS, &decodedInstructionsCount);

    // start process

    int mRet = CreateProcess(exeFileName,exeCmdLine,NULL,NULL,FALSE,DEBUG_PROCESS + CREATE_NEW_CONSOLE,NULL,exeWorkingDir,&si,&pi);
    if(mRet == 0)
    {
        printf("E:CreateProcess failed\n");
        exit(0);
    }

	tickStart = GetTickCount();

    HMODULE ntDll = LoadLibrary("ntdll");
    NtQueryInformationProcess = (_NtQueryInformationProcess) (GetProcAddress(ntDll, "NtQueryInformationProcess"));

    DWORD bW = 0;
    PROCESS_BASIC_INFORMATION pib;
    PEB peb;

    memset (&pib, 0, sizeof (pib));
    memset (&peb, 0, sizeof (peb));

    NtQueryInformationProcess (pi.hProcess, 0, (DWORD) & pib, sizeof (pib), (DWORD) & bW);

    printf("I:PROCESS_BASIC_INFORMATION.PebBaseAddress = %08x\n", (unsigned long )pib.PebBaseAddress);
    ReadProcessMemory(pi.hProcess,(LPCVOID )pib.PebBaseAddress, (LPVOID )&peb, sizeof(peb),&bW);
    printf("I:PROCESS_ENVIRONMENT_BLOCK.ImageBaseAddress = %08x\n", (unsigned long )peb.ImageBaseAddress);
    
    unsigned long addressOfEntryPoint = getEntryPoint(pi.hProcess, (unsigned long )peb.ImageBaseAddress);

    char oldEntryPoint = '\0';

    DEBUG_EVENT de;
    int continueWaiting = 1;
    int firstException = 1;

    CONTEXT c;
    c.ContextFlags = CONTEXT_FULL;

    HANDLE hThread = NULL;

    unsigned long instructionCount = 0;
	unsigned long outsideInstructionCount = 0; // for instructions captured with TraceAllMode

    ReadProcessMemory(pi.hProcess,(LPCVOID )addressOfEntryPoint, (LPVOID )&oldEntryPoint, 1,&bW);
    WriteProcessMemory(pi.hProcess,(LPVOID )addressOfEntryPoint,(LPCVOID )"\xCC",1,&bW);

    TRACEMODULEINFO *ti = (TRACEMODULEINFO *)malloc(sizeof(TRACEMODULEINFO));
    memset(ti,0,sizeof(TRACEMODULEINFO));

    // windows should never load faster than this.

    int traceFlag = 0;
    while(continueWaiting)
    {
        WaitForDebugEvent(&de,INFINITE);
        if(firstException)
        {
			// why does this create a fuckton of instructions?
            firstException = handleFirstException(&de,&firstException, addressOfEntryPoint, pi.dwProcessId,pi.hProcess, &oldEntryPoint, ti);
			instructionCount++;
        }
        else
        {
            switch(de.dwDebugEventCode)
            {
                case EXCEPTION_DEBUG_EVENT:
                    if(de.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP /* || de.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT */)
                    {
						// is it just that the exception trace mode is wrong?
                        if(
                            ((unsigned long )de.u.Exception.ExceptionRecord.ExceptionAddress < ti->startAddress
                            ||
                            (unsigned long )de.u.Exception.ExceptionRecord.ExceptionAddress > ti->endAddress)
                            &&
                            (traceFlag == 0)
                        )
                        {
                            if(traceAllMode)
                            {
                                // if this is a 'call' and the last call is <5, 
                                hThread = OpenThread(THREAD_ALL_ACCESS,FALSE,de.dwThreadId);
								outsideInstructionCount++;
                                printInstruction(pi.hProcess, hThread, de.dwThreadId, &g_insn,"-");
                                
                                if(lastCall)
                                {
                                    c.ContextFlags = CONTEXT_FULL;
                                    GetThreadContext(hThread, &c);

                                    // minimize the number of "peek" instances, as this is fucking slow. current peek
                                    // instances = 5, change PEEK_AFTER_CALL in phantasm.h to modify.
                                    x86_insn_t l_insn;
                                    lookAhead(pi.hProcess, (LPVOID )c.Eip, &l_insn);

									// what?
                                    if(l_insn.type == insn_jmp || l_insn.type == insn_call)
                                    {
										if(!quietMode)
										{
											printf("I:call into jump, not attempting to follow\n");
										}
                                        goto printInstruction_skipJump;
                                    }

									if(lastEip != (c.Eip | 0xFFFF0000)) // is this an inter-module call?
                                    {                                 // if this is, we typically won't
                                        SetLastError(0);              // call->jmp, so ignore the jmp.
                                        char *resolvedFunction = resolveAddrSoft(globalExports,(unsigned long )de.u.Exception.ExceptionRecord.ExceptionAddress);
                                        if(GetLastError() == 0)
                                        {
											printTimestamp();
                                            if(lookupFunctionAndDump(pi.hProcess, resolvedFunction, de.dwThreadId,(unsigned long )de.u.Exception.ExceptionRecord.ExceptionAddress) == 0)
                                            {
                                                printf("C:08x:%08x:%s()\n", (unsigned long )de.dwThreadId,(unsigned long )de.u.Exception.ExceptionRecord.ExceptionAddress,resolvedFunction);
                                            }
                                            free(resolvedFunction);
                                        }
                                        else
                                        {
                                            printf("C:%08x:%08x:Unknown()\n",(unsigned long )de.dwThreadId,(unsigned long )de.u.Exception.ExceptionRecord.ExceptionAddress);
                                        }
                                        lastCall = 0;
                                    }
                                }
                                printInstruction_skipJump:;
                                CloseHandle(hThread);

                            }
                            else
                            {
                                if(!quietMode)
                                {
                                    printf("C:call bouncing to %08x, protecting memory space from %08x to %08x\n", (unsigned long )de.u.Exception.ExceptionRecord.ExceptionAddress, ti->startAddress, ti->endAddress);
                                }
								
                                DWORD temp_oldProtect = 0;
								MEMORY_BASIC_INFORMATION memBuf;
								VirtualQueryEx(pi.hProcess,(LPVOID )(ti->startAddress),&memBuf,sizeof(memBuf));

								// the original protection on test2.exe is PAGE_WRITECOPY.
								// printf("I:VirtualProtectEx from %08x to %08x\n", memBuf.BaseAddress, ti->endAddress);
								#ifdef SUPERVERBOSE
									printf("I:VirtualProtectEx from %08x to %08x\n", memBuf.BaseAddress, ti->endAddress);
								#endif
							    if(VirtualProtectEx(pi.hProcess, (LPVOID )(memBuf.BaseAddress), (unsigned long )(ti->endAddress - ti->startAddress), PAGE_READWRITE,&temp_oldProtect) == 0)
								{
									printf("E:VirtualProtextEx to PAGE_READWRITE failed\n");
								}
								
								/*
								// this appears not to work in virtual machines?
								MEMORY_BASIC_INFORMATION mbi;
								VirtualQueryEx(pi.hProcess, memBuf.BaseAddress, &mbi, sizeof(mbi));
								if(mbi.AllocationProtect && PAGE_READWRITE > 0)
								{
									// memory allocation protect is an or-join.
									printf("I: memory protection constant is incorrect, VirtualProtectEx silently failed :new protect is %08x - old protect was %08x\n", (unsigned long )(mbi.AllocationProtect), (unsigned long )(memBuf.AllocationProtect));
								}
								*/

                                traceFlag = 1;
                                SetLastError(0);
                                char *resolvedFunction = resolveAddrSoft(globalExports,(unsigned long )de.u.Exception.ExceptionRecord.ExceptionAddress);
                                if(GetLastError() == 0)
                                {
									printTimestamp();
                                    if(lookupFunctionAndDump(pi.hProcess, resolvedFunction, de.dwThreadId,(unsigned long )de.u.Exception.ExceptionRecord.ExceptionAddress) == 0)
                                    {
                                        printf("C:%08x:%08x:%s()\n",(unsigned long )de.dwThreadId,(unsigned long )de.u.Exception.ExceptionRecord.ExceptionAddress,resolvedFunction);
                                    }

                                    free(resolvedFunction);
                                }
                                else
                                {
                                    printf("E:function could not be resolved\n");
                                }
                            }
                            ContinueDebugEvent (de.dwProcessId, de.dwThreadId,DBG_CONTINUE);
                        }
                        else
                        {
                            // printInstruction_skipJump:;
                            hThread = OpenThread(THREAD_ALL_ACCESS,FALSE,de.dwThreadId);
							// printTimestamp(GetTickCount());
							printInstruction(pi.hProcess, hThread, de.dwThreadId, &g_insn, "-");
                            CloseHandle(hThread);

                            instructionCount++;
                            ContinueDebugEvent (de.dwProcessId, de.dwThreadId,DBG_CONTINUE);
                        }
                    }
                    else if(de.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
                    {
						// printf("* ACCESS VIOLATION\n");
                        if(
                            (unsigned long )de.u.Exception.ExceptionRecord.ExceptionAddress > ti->startAddress
                            &&
                            (unsigned long )de.u.Exception.ExceptionRecord.ExceptionAddress < ti->endAddress
                          )
                        {
							// printf("* unprotecting page %08x to %08x\n", (unsigned long )ti->startAddress, (unsigned long )ti->endAddress);
							#ifdef SUPERVERBOSE
								printf("* unprotecting page %08x to %08x\n", (unsigned long )ti->startAddress, (unsigned long )ti->endAddress);
							#endif
                            DWORD temp_oldProtect;
                            VirtualProtectEx(pi.hProcess, (LPVOID )ti->startAddress, (ti->endAddress - ti->startAddress), PAGE_EXECUTE_READWRITE,&temp_oldProtect);
                            hThread = OpenThread(THREAD_ALL_ACCESS,FALSE,de.dwThreadId);
							// printTimestamp(GetTickCount());
                            printInstruction(pi.hProcess, hThread, de.dwThreadId, &g_insn, "-");
							instructionCount++;
                            CloseHandle(hThread);
                            traceFlag = 0;
                            ContinueDebugEvent (de.dwProcessId, de.dwThreadId,DBG_CONTINUE);
                        }
						else
						{
							printf("X:access violation at %08x\n", (unsigned long )de.u.Exception.ExceptionRecord.ExceptionAddress);
							ContinueDebugEvent (de.dwProcessId, de.dwThreadId,DBG_CONTINUE);
						}
                    }
                    else
                    {
                        if(de.u.Exception.dwFirstChance == 1)
                        {
                            printf("X:exception at %08x\n",(unsigned long )de.u.Exception.ExceptionRecord.ExceptionAddress);
                            ContinueDebugEvent (de.dwProcessId, de.dwThreadId,DBG_EXCEPTION_NOT_HANDLED);
                        }
                        else
                        {
                            x86_insn_t l_insn;
                            lookAhead(pi.hProcess, (LPVOID )c.Eip, &l_insn);
                            // gooby pls
                            printf("X:exception at %08x, second chance\n",(unsigned long )de.u.Exception.ExceptionRecord.ExceptionAddress);
                            memset(&c,0,sizeof(c));
                            c.ContextFlags = CONTEXT_FULL;
                            GetThreadContext(hThread, &c);
                            printf("X:eax=%08x ebx=%08x ecx=%08x edx=%08x\n", c.Eax, c.Ebx, c.Ecx, c.Edx);
                            printf("X:esp=%08x ebp=%08x eip=%08x efl=%08x\n", c.Esp, c.Ebp, c.Eip, c.EFlags);
                            hThread = OpenThread(THREAD_ALL_ACCESS,FALSE,de.dwThreadId);
                            printInstruction(pi.hProcess, hThread, de.dwThreadId, &l_insn,"X");
                            // void printInstruction(pi.hProcess, hThread, unsigned long dwThreadId, x86_insn_t *insn)
                            CloseHandle(hThread);
                            TerminateProcess(pi.hProcess,0);
                            ContinueDebugEvent (de.dwProcessId, de.dwThreadId,DBG_CONTINUE);
                        }
                    }
                    break;
                case LOAD_DLL_DEBUG_EVENT:
                    if (de.u.LoadDll.lpImageName != NULL)
                    {
						 ULONG lpImageName;
						 char UnicodeStr[512];
						 char AsciiStr[256];
						 memset (UnicodeStr, 0, 512);
						 memset (AsciiStr, 0, 256);
						 ReadProcessMemory (pi.hProcess, de.u.LoadDll.lpImageName,
										 &lpImageName, sizeof (lpImageName), NULL);
						 ReadProcessMemory (pi.hProcess, (LPVOID) lpImageName,
										 &UnicodeStr, sizeof (UnicodeStr), NULL);
						 WideCharToMultiByte (CP_ACP, 0, (LPCWSTR) & UnicodeStr, -1,
										   (LPSTR) & AsciiStr, 256, NULL, NULL);
						 if(!quietMode)
						 {
							if(AsciiStr[0] != '\0')
							{
							printTimestamp();
							printf ("* %08x %s\n", de.u.LoadDll.lpBaseOfDll, AsciiStr);
							}
							else
							{
							printTimestamp();
							printf("* %08x [UNKNOWN]\n", de.u.LoadDll.lpBaseOfDll);
							}
						 }
					   }
                      globalExports = scanModules (pi.hProcess, pi.dwProcessId, 0);
                    ContinueDebugEvent(de.dwProcessId,de.dwThreadId,DBG_CONTINUE);
                    break;
                case CREATE_THREAD_DEBUG_EVENT:
                    hThread = de.u.CreateThread.hThread;
                    c.ContextFlags = CONTEXT_FULL;
                    GetThreadContext(hThread,&c);
                    c.EFlags |= 0x00000100;
					if(!quietMode)
				    {
						printTimestamp();
						printf("* new thread:c.Eip = %08x\n", (unsigned long )c.Eip);
					}
					#ifdef SUPERVERBOSE
						printf("* setting single step flag (new thread)\n");
					#endif
                    SetThreadContext(hThread,&c);
                    CloseHandle(hThread);
                    ContinueDebugEvent(de.dwProcessId,de.dwThreadId,DBG_CONTINUE);
                    break;
                case EXIT_THREAD_DEBUG_EVENT:
					if(!quietMode)
					{
					    printTimestamp();
						printf("* leaving thread\n");
					}
                    ContinueDebugEvent(de.dwProcessId,de.dwThreadId,DBG_CONTINUE);
                    break;
                case EXIT_PROCESS_DEBUG_EVENT:
					tickEnd = GetTickCount();
					if(!quietMode)
					{
					    printTimestamp();
						printf("* exit_process_debug_event\n");
					}
                    ContinueDebugEvent (de.dwProcessId, de.dwThreadId,DBG_CONTINUE);
                    continueWaiting = 0;
                    break;
                default:
					if(!quietMode)
					{
					    printTimestamp();
						printf("* unknown debug event, code %08x\n", de.dwDebugEventCode);
					}
                    ContinueDebugEvent (de.dwProcessId, de.dwThreadId,DBG_EXCEPTION_NOT_HANDLED);
                    break;
            }
        }
    }

	// printf(lineSep);
    
	if(traceAllMode)
	{
		printf("I:total instructions (approx): %d\n", instructionCount + outsideInstructionCount);
	}
	else
	{
		printf("I:total instructions: %d\n", instructionCount);
	}
	if(tickEnd < tickStart)
	{
		printf("I:unable to get execution time\n");
	}
	else
	{
		printf("I:time from create to end: %d\n", (unsigned long )(tickEnd - tickStart));
	}
	// printf(lineSep);

    return 0;
}

int handleFirstException(DEBUG_EVENT *de, int *firstException, unsigned long addressOfEntryPoint, unsigned long processId, HANDLE hProcess,char *oldEntryPoint, TRACEMODULEINFO *ti)
{
    DWORD bW = 0;
    int foundBaseModule = 0;
    if(de->dwDebugEventCode == EXCEPTION_DEBUG_EVENT)
    {
        if((unsigned long )de->u.Exception.ExceptionRecord.ExceptionAddress == addressOfEntryPoint && de->u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT)
        {
            MODULEENTRY32 me;
            memset(&me,0,sizeof(me));
            me.dwSize = sizeof(me);
            /************ DETERMINE TRACE AREA **************/
            HANDLE hSnap =  CreateToolhelp32Snapshot (TH32CS_SNAPMODULE + TH32CS_SNAPMODULE32, processId);

            BOOL bCont = Module32First(hSnap, &me);
            if(
                addressOfEntryPoint > (unsigned long )me.modBaseAddr
                &&
                addressOfEntryPoint < (unsigned long )(me.modBaseAddr + me.modBaseSize)
              )
            {
                foundBaseModule = 1;
                bCont = FALSE;
            }
           

            while(bCont)
            {
                Module32Next(hSnap,&me);
                if
                 (
                     addressOfEntryPoint > (unsigned long )me.modBaseAddr
                     &&
                     addressOfEntryPoint < (unsigned long )(me.modBaseAddr + me.modBaseSize)
                 )
                {
                    foundBaseModule = 1;
                    bCont = FALSE;
                }
            }

            if(foundBaseModule == 0)
            {
                printf("E:fatal: entrypoint not in any loaded module\n");
                getc(stdin);
            }
            else
            {
                printf("I:found base module from %08x to %08x\n", (unsigned long )me.modBaseAddr, (unsigned long )(me.modBaseAddr + me.modBaseSize));
                ti->startAddress = (unsigned long )me.modBaseAddr;
                ti->endAddress = (unsigned long )(me.modBaseAddr + me.modBaseSize);
            }
            
            CloseHandle(hSnap);

            /************ FIXUP PROCESS ************/
            WriteProcessMemory(hProcess,(LPVOID )addressOfEntryPoint,(LPCVOID )oldEntryPoint,1,&bW);
            HANDLE hThread = OpenThread(THREAD_ALL_ACCESS,FALSE,de->dwThreadId);
            CONTEXT c;
            memset(&c,0,sizeof(c));
            c.ContextFlags = CONTEXT_FULL;

            GetThreadContext(hThread,&c);
            c.Eip = addressOfEntryPoint;
            c.EFlags |= 0x00000100;

			#ifdef SUPERVERBOSE
				printf("* setting single step flag (handle first exception)\n");
			#endif
            SetThreadContext(hThread,&c);

            printInstruction(hProcess, hThread, de->dwThreadId, &g_insn,"-");
			// instructionCount++;

        /*
            if(!noOpcodes)
            {
                char *tempInstrString = disassembleSingleInstruction(hProcess, c.Eip, de->dwThreadId, &g_insn, NULL,NULL);

                memset(&sprintfInstructionOpcodes,0,(2 * instructionLength) + 1);
                for(i = 0;i < instructionLength;i++)
                {
                    // printf("%02x", (unsigned char )instructionOpcodes[i] / 0x10);
                    sprintfInstructionOpcodes[(2 * i)] = hexChars[(unsigned int )(instructionOpcodes[i] / 0x10)];
                    sprintfInstructionOpcodes[(2 * i) + 1] = hexChars[(unsigned int )(instructionOpcodes[i] % 0x10)];
                }

                sprintfInstructionOpcodes[2 * i] = '\0';

                printTimestamp();
                printf("%s:%08x:%08x:%s:%s\n", tagType, dwThreadId, (unsigned long )c.Eip, &sprintfInstructionOpcodes, tempInstrString);
                free(tempInstrString);
            }
            */

            /*
			if(!noOpcodes)
			{
				char *tempInstrString = disassembleSingleInstruction(hProcess, c.Eip, de->dwThreadId, &g_insn, NULL,NULL);
				printTimestamp();
				printf("-:%08x:%08x:%s\n", de->dwThreadId, (unsigned long )c.Eip, tempInstrString);
				free(tempInstrString);
			}
            */

            // printf("* first exception handled at %08x\n", (unsigned long )de->u.Exception.ExceptionRecord.ExceptionAddress);

            CloseHandle(hThread);

            // resolve structures like a boss.
            globalExports = scanModules (hProcess, processId, 1 - quietMode);

            ContinueDebugEvent (de->dwProcessId, de->dwThreadId,DBG_CONTINUE);
            return 0;
        }
        else
        {
            ContinueDebugEvent (de->dwProcessId, de->dwThreadId,DBG_EXCEPTION_NOT_HANDLED);
        }
        
    }
    else
    {
        ContinueDebugEvent (de->dwProcessId, de->dwThreadId,DBG_CONTINUE);
    }

    return 1;
}

void usage()
{
	printf("* usage: phantasm.exe <args> [command_line]\n");
	printf("**************************************\n");
	printf("  -i : interactive mode\n");
	printf("  -n : do not print opcodes (trace only functions)\n");
	printf("  -t : print timestamps on stuff\n");
	printf("  -a : trace code in all modules (normally just self)\n");
	printf("  -v : verbose output\n");
	return;
}

void buildExecuteEnvironment(int argc, char **argv)
{
    exeWorkingDir = (char *)malloc(MAX_PATH + 1);
    memset(exeWorkingDir,0,MAX_PATH + 1);
    GetCurrentDirectory(MAX_PATH,exeWorkingDir);

    char *temp = (char *)malloc(MAX_PATH);

    int i = 1;
    int exeCmdLineLen = 0;

    if(strcmp(argv[1],"-i") == 0 && argc == 2)
    {
        noOpcodes = 1 - getResponse("* display opcodes [y/n] > ");
        quietMode = 1 - getResponse("* display event messages [y/n] > ");
		setDebugMaskLoader(1 - quietMode);
        timestamps = getResponse("* display timestamps [y/n] > ");
        traceAllMode = getResponse("* trace all modules [y/n] > ");
        printf("* path to custom argfile [default:arghooks.lst] > ");
        memset(temp,0,MAX_PATH);
        fgets(temp,MAX_PATH,stdin);
        chomp(temp);
        if(strlen(temp) == 0)
        {
            argSpecFile = NULL;
        }
        else
        {
            argSpecFile = strdup(temp);
        }

        memset(temp,0,MAX_PATH);
        printf("* path to target executable > ");
        fgets(temp,MAX_PATH,stdin);
        chomp(temp);
        if(strlen(temp) == 0)
        {
            printf("* no exe file entered\n");
            exit(0);
        }
        else
        {
            exeCmdLine = strdup(temp);
            exeCmdLineLen = strlen(exeCmdLine) + 1;
        }

        goto interactiveEnd;
    }

    for(i = 1;i < argc;i++)
    {
		// command-line arguments
		if(strcmp(argv[i],"-n") == 0 || strcmp(argv[i],"-no-opcodes") == 0)
        {
            noOpcodes = 1;
        }
        else if(strcmp(argv[i],"-v") == 0 || strcmp(argv[i],"-verbose") == 0)
        {
            quietMode = 0;
        }
		else if(strcmp(argv[i],"-t") == 0 || strcmp(argv[i],"-timestamps") == 0)
        {
            timestamps = 1;
        }
        else if (strcmp(argv[i],"-a") == 0 || strcmp(argv[i],"-all") == 0)
        {
            traceAllMode = 1;
        }
        else if(strcmp(argv[i],"-argfile") == 0)
        {
            if(i < argc - 1)
            {
                argSpecFile = argv[i + 1];
                i++;
            }
        }
        else
        {
            break;
        }
    }

    int startI = i;

    for(;i < argc;i++)
    {
        exeCmdLineLen += strlen(argv[i]) + 1;
    }

    // don't add one, last char will be '\0' anyway.
    exeCmdLine = (char *)malloc(exeCmdLineLen);
    memset(exeCmdLine,0,exeCmdLineLen);

    i = startI;
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

    interactiveEnd:;
	// printf("* herpaderp %08x - %08x = %08x \n", exeCmdLine, (unsigned long )strstr(exeCmdLine,".exe"), (unsigned long )(strstr(exeCmdLine,".exe") - exeCmdLine));
    free(temp);

    if(exeCmdLineLen != 0)
    {
        exeCmdLine[exeCmdLineLen - 1] = '\0';
    }
    else
    {
        printf("E:no valid executable path supplied\n");
        exit(0);
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
        // while(exeCmdLine[i] != ' ' && exeCmdLine[i] != '\0') {i++;} ;
    }

    // printf("i = %d\n", i);

    // printf("* %s\n", exeCmdLine);
    if(i == 15)
    {
        printf("E:malloc fails when cmdline is 15 bytes long\n");
        // i = 16;
        
        exit(0);
    }
    // printf("* fixme, i = %d, len = %d\n", i, strlen(exeCmdLine));
    exeFileName = (char *)malloc(i + 1);
    memset(exeFileName,0,strlen(exeCmdLine) + 1);
    exeFileName[i] = '\0';
    strcpy(exeFileName,exeCmdLine);
    // printf("* fixdone\n");
    // exeFileName[i] = '\0';

    return;
}

// grab the image size from the exe.

unsigned long getEntryPoint(HANDLE hProcess, unsigned long imageBaseAddress)
{
    IMAGE_DOS_HEADER imgDosHdr;
    IMAGE_NT_HEADERS imgNtHdrs;

    memset(&imgDosHdr,0,sizeof(imgDosHdr));
    memset(&imgNtHdrs,0,sizeof(imgNtHdrs));

    unsigned long bR = 0;

    ReadProcessMemory(hProcess,(LPCVOID )imageBaseAddress,(LPVOID )&imgDosHdr,sizeof(imgDosHdr),&bR);
    ReadProcessMemory(hProcess,(LPCVOID )(imageBaseAddress + imgDosHdr.e_lfanew),(LPVOID )&imgNtHdrs,sizeof(imgNtHdrs),&bR);

    printf("I:imgNtHdrs.OptionalHeader.AddressOfEntryPoint = %08x\n", (unsigned long )imgNtHdrs.OptionalHeader.AddressOfEntryPoint);

    return (unsigned long )(imageBaseAddress + imgNtHdrs.OptionalHeader.AddressOfEntryPoint);
}

void dumpExecuteEnvironment()
{   
    printf("I:File Name: %s\n", exeFileName);
    printf("I:Working Directory: %s\n", exeWorkingDir);
    printf("I:CommandLine: %s\n", exeCmdLine);
    if(exeFileName == NULL)
    {
        exit(0);
    }
    return;
}

void buildFunctionHooks()
{
    if(argSpecFile == NULL)
    {
        buildArgumentHooks("arghooks.lst");
    }
    else
    {
        buildArgumentHooks(argSpecFile);
    }
    return;
}

// SetSingleStep works here.
void printInstruction(HANDLE hProcess, HANDLE hThread, unsigned long dwThreadId, x86_insn_t *insn, char *tagType)
{
    unsigned char sprintfInstructionOpcodes[2 * INSN_BUFFER_LEN + 1];
    unsigned char instructionOpcodes[INSN_BUFFER_LEN];
    int instructionLength = 0;
    int i = 0;

    CONTEXT c;
    c.ContextFlags = CONTEXT_FULL;
    GetThreadContext(hThread,&c);
    c.EFlags |= 0x00000100;
    lastEip = c.Eip | 0xFFFF0000;
    char *tempInstrString = disassembleSingleInstruction(hProcess, c.Eip, dwThreadId, insn, (char *)instructionOpcodes, &instructionLength);
    if(instructionLength == 0)
    {
        printf("E:disassembly failed, debugme (%s:%d)\n",__FILE__,__LINE__);
        exit(0);
        return;
    }

    if (insn->type == insn_call)
    {
        lastCall += PEEK_AFTER_CALL;
    }
    else if(lastCall != 0)
    {
        lastCall--;
    }
	if(!noOpcodes)
	{
        memset(&sprintfInstructionOpcodes,0,(2 * instructionLength) + 1);
        for(i = 0;i < instructionLength;i++)
        {
            // printf("%02x", (unsigned char )instructionOpcodes[i] / 0x10);
            sprintfInstructionOpcodes[(2 * i)] = hexChars[(unsigned int )(instructionOpcodes[i] / 0x10)];
            sprintfInstructionOpcodes[(2 * i) + 1] = hexChars[(unsigned int )(instructionOpcodes[i] % 0x10)];
        }

        sprintfInstructionOpcodes[2 * i] = '\0';

		printTimestamp();
		printf("%s:%08x:%08x:%s:%s", tagType, dwThreadId, (unsigned long )c.Eip, &sprintfInstructionOpcodes, tempInstrString);

		if (insn->type == insn_jcc || insn->type == insn_jmp || insn->type == insn_call)
		{
			// do nothing, do not print extra parameters (for now)
			// because jmp 0x8 [<blah>] looks wierd, next eip will tell us anyway.
		}
		else
		{
			size_t opcount = insn->operand_count;
			x86_oplist_t *oplist = insn->operands;
			x86_op_t operand;
			for(i = 0;i < opcount;i++)
			{
				operand = oplist->op;
				/*
					~ from libdis.h
					enum x86_op_type {
							op_unused = 0,          // empty/unused operand: should never occur 
							op_register = 1,        // CPU register 
							op_immediate = 2,       // Immediate Value 
							op_relative_near = 3,   // Relative offset from IP 
							op_relative_far = 4,    // Relative offset from IP 
							op_absolute = 5,        // Absolute address (ptr16:32) 
							op_expression = 6,      // Address expression (scale/index/base/disp) 
							op_offset = 7,          // Offset from start of segment (m32) 
							op_unknown
					};
				*/
				switch(operand.type)
				{
					case op_unused:
						break;
					case op_register:
						printf (" (%s=0x%x)", operand.data.reg.name,
							   (unsigned long) useRegister (&c, operand.data.reg.name, 0, MODE_READ));
						break;
					case op_immediate:
						break;
					case op_relative_near:
						break;
					case op_relative_far:
						break;
					case op_absolute:
						break;
					case op_offset:
						break;
					case op_expression:
						if(operand.data.expression.base.name[0] != '\0')
						{
							// where is disp?
							if(operand.data.expression.index.name[0] != '\0')
							{
								printf(" (%s+%s*0x%x)",operand.data.expression.base.name,operand.data.expression.index.name,(unsigned long )operand.data.expression.scale);
							}
							else
							{
								// there is no index.
								printf(" (%s*0x%x)",operand.data.expression.base.name,(unsigned long )operand.data.expression.scale);
							}
						}
						break;
					default:
						printf(" [unknown_optype]");
						break;
				}
				oplist = oplist->next;
			}
		}
		printf("\n");
	}
    free(tempInstrString);
	#ifdef SUPERVERBOSE
		printf("* setting single step flag (normal instruction)\n");
	#endif
    SetThreadContext(hThread,&c);
}

void lookAhead(HANDLE hProcess, LPVOID eip, x86_insn_t *insn)
{
    char insBuf[32];
    DWORD bR;

    memset(insBuf,0,32);

    ReadProcessMemory(hProcess, (LPCVOID )eip, insBuf, 13, &bR);

    x86_disasm((unsigned char *)insBuf, bR, 0, 0, insn);

    return;
}

void printTimestamp()
{
	if(timestamps)
	{
		printf("T:%08x:",(unsigned long )(GetTickCount() - tickStart));
	}
	return;
}

int getResponse(char *question)
{
    char temp[128];
    memset(temp,0,128);
    printf("%s",question);
    fgets(temp,127,stdin);
    chomp(temp);

    if(temp[1] != '\0')
    {
        if(temp[0] == 'y' || temp[0] == 'Y')
        {
            return 1;
        }
        else if(temp[0] == 'n' || temp[0] == 'N')
        {
            return 0;
        }
        else
        {
            printf("* expected y/n, got [%c]\n", temp[0]);
            return 0;
        }
    }

    return 0;
}

DWORD useRegister(CONTEXT * c, char *regSelect, DWORD value, int opMode)
{
  DWORD *regPtr = NULL;
  
  if (opMode == MODE_READ)
  {
  if(regSelect[1] == 's' && regSelect[2] == '\0')
  {
	  switch(regSelect[0])
	  {
		  case 'g':
			return c->SegGs;
		  case 'f':
			return c->SegFs;
		  case 's':
			return c->SegSs;
		  case 'c':
			return c->SegCs;
		  case 'd':
			return c->SegDs;
		  case 'e':
			return c->SegEs;
		  default:
			return 0;
	  }
  }
  if(regSelect[0] == 'e')
  {
        /*
        eax
        ebx
        ebp
        ecx
        edx <-- duplicate
        edi
        esi
        esp
        eip
        */
        if(regSelect[1] == 'a')
        {
        return (DWORD )(c->Eax);
        }
        else if(regSelect[1] == 'b')
        {
                if(regSelect[2] == 'x')
                {
                return (DWORD )(c->Ebx);
                }
                else if(regSelect[2] == 'p')
                {
                return (DWORD )(c->Ebp);
                }
                else
                {
                return 0;
                }
        }
        else if(regSelect[1] == 'c')
        {
        return (DWORD )(c->Ecx);
        }
        else if(regSelect[1] == 'd')
        {
                if(regSelect[2] == 'x')
                {
                return (DWORD )(c->Edx);
                }
                else if(regSelect[2] == 'i')
                {
                return (DWORD )(c->Edi);
                }
                else
                {
                return 0;
                }
        }
        else if(regSelect[1] == 'i')
        {
        return (DWORD )(c->Eip);
        }
        else if(regSelect[1] == 's')
        {
                if(regSelect[2] == 'i')
                {
                return (DWORD )(c->Esi);
                }
                else if(regSelect[2] == 'p')
                {
                return (DWORD )(c->Esp);
                }
                else
                {
                return 0;
                }
        }
  }
  else
  {
        /*
        ax
        bx
        cx
        dx
        */
        if(regSelect[1] == 'x')
        {
                if(regSelect[0] == 'a')
                {
                        return ((DWORD )(c->Eax) & 0x0000FFFF);
                }
                else if(regSelect[0] == 'b')
                {
                        return ((DWORD )(c->Ebx) & 0x0000FFFF);
                }
                else if(regSelect[0] == 'c')
                {
                        return ((DWORD )(c->Ecx) & 0x0000FFFF);
                }
                else if(regSelect[0] == 'd')
                {
                        return ((DWORD )(c->Edx) & 0x0000FFFF);
                }
                else
                {
                return 0;
                }

        }
        else if(regSelect[1] == 'h')
        {
                if(regSelect[0] == 'a')
                {
                        return ((DWORD )(c->Eax) & 0x0000FF00) >> 2;
                }
                else if(regSelect[0] == 'b')
                {
                        return ((DWORD )(c->Ebx) & 0x0000FF00) >> 2;
                }
                else if(regSelect[0] == 'c')
                {
                        return ((DWORD )(c->Ecx) & 0x0000FF00) >> 2;
                }
                else if(regSelect[0] == 'd')
                {
                        return ((DWORD )(c->Edx) & 0x0000FF00) >> 2;
                }
                else
                {
                return 0;
                }
        }
        else if(regSelect[1] == 'l')
        {
                if(regSelect[0] == 'a')
                {
                        return ((DWORD )(c->Eax) & 0x000000FF);
                }
                else if(regSelect[0] == 'b')
                {
                        return ((DWORD )(c->Ebx) & 0x000000FF);
                }
                else if(regSelect[0] == 'c')
                {
                        return ((DWORD )(c->Ecx) & 0x000000FF);
                }
                else if(regSelect[0] == 'd')
                {
                        return ((DWORD )(c->Edx) & 0x000000FF);
                }
                else
                {
                return 0;
                }
        }
        else if(regSelect[0] == 's')
        {
                if(regSelect[1] == 'i')
                {
                return ((DWORD )(c->Esi) & 0x0000FFFF);
                }
                else if(regSelect[1] == 'p')
                {
                return ((DWORD )(c->Esp) & 0x0000FFFF);
                }
                else
                {
                return 0;
                }
        }
        else if(regSelect[0] == 'd')
        {
        return ((DWORD )(c->Edi) & 0x0000FFFF);
        }
        else if(regSelect[0] == 'b')
        {
        return ((DWORD )(c->Ebp) & 0x0000FFFF);
        }
        else if(regSelect[0] == 'i')
        {
        return ((DWORD )(c->Eip) & 0x0000FFFF);
        }
  }
  }

  if(regSelect[0] == 'e')
  {
	  if (strcmp (regSelect, "eax") == 0)
		{
		  regPtr = (DWORD *) & (c->Eax);
		}
	  else if (strcmp (regSelect, "ebx") == 0)
		{
		  regPtr = (DWORD *) & (c->Ebx);
		}
	  else if (strcmp (regSelect, "ecx") == 0)
		{
		  regPtr = (DWORD *) & (c->Ecx);
		}
	  else if (strcmp (regSelect, "edx") == 0)
		{
		  regPtr = (DWORD *) & (c->Edx);
		}
	  else if (strcmp (regSelect, "edi") == 0)
		{
		  regPtr = (DWORD *) & (c->Edi);
		}
	  else if (strcmp (regSelect, "esi") == 0)
		{
		  regPtr = (DWORD *) & (c->Esi);
		}
	  else if (strcmp (regSelect, "ebp") == 0)
		{
		  regPtr = (DWORD *) & (c->Ebp);
		}
	  else if (strcmp (regSelect, "eip") == 0)
		{
		  regPtr = (DWORD *) & (c->Eip);
		}
	  else if (strcmp (regSelect, "esp") == 0)
		{
		  regPtr = (DWORD *) & (c->Esp);
		}
	}
  else
    {
      SetLastError (1);
      return 0;
    }
  // either return the DWORD or write to it.
  if (opMode == MODE_READ)
    {
	  printf("* [%s:%d] MODE_READ fell through, this shouldn't happen (register selected was %s)\n",__FILE__,__LINE__,regSelect);
	  SetLastError (1);
      return 0;
    }
  else if (opMode == MODE_WRITE)
    {
      *regPtr = value;
      return value;
    }
  else
    {
      return 0;
    }
}
