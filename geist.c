// geist

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <tlhelp32.h>
#include "libdis/libdis.h"
#include "geist.h"


// no context is here
// optional context gather is faster in 90% of cases imo, test later

#define INSTRBUF_LEN 256

resolveNode *rChain = NULL;
funcMaskNode *funcChain = NULL;

int debugMaskLoader = 0;

void setDebugMaskLoader(int i)
{
	debugMaskLoader = i;
	return;
}

char *disassembleSingleInstruction(HANDLE hProcess, unsigned long disasmOffset, unsigned long dwThreadId, x86_insn_t *insn, char *insnBuffer, int *insnLen)
{
    char insBuf[INSN_BUFFER_LEN];
    char *line = (char *)malloc(INSTRBUF_LEN);
    DWORD size;
    DWORD bR;

    memset(insBuf,0,32);
    memset(line,0, INSTRBUF_LEN);

    ReadProcessMemory(hProcess, (LPCVOID )disasmOffset, insBuf, 13, &bR);

    size = x86_disasm((unsigned char *)insBuf, bR, 0, 0, insn);
    x86_format_insn (insn, line, INSTRBUF_LEN, intel_syntax);

    if(insnBuffer != NULL)
    {
        memcpy(insnBuffer,&insBuf,size);
        if(insnLen != NULL)
        {
            *insnLen = size;
        }
    }

    return line;
}

#define MAX_ARGS_PRINTF 1024

int lookupFunctionAndDump(HANDLE hProcess, char *functionName, unsigned long dwThreadId)
{
    char *funcNamePtr = NULL;
    int i = 0;
    int funcNamePtrLen = strlen(functionName);
    for(;i < funcNamePtrLen;i++)
    {
        if(functionName[i] == '!')
        {
            i++;
            funcNamePtr = (char *)(functionName + i);
            break;
        }
    }

    funcMaskNode *funcHead = funcChain;
    while(funcHead != NULL)
    {
        if(strcmp(funcHead->funcName,funcNamePtr) == 0)
        {
            break;
        }
        funcHead = (funcMaskNode *)funcHead->next;
    }

    if(funcHead == NULL)
    {
        // printf("* could not find");
        return 0;
    }

    CONTEXT c;

    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS,FALSE,dwThreadId);
    c.ContextFlags = CONTEXT_FULL; // grab esp
    GetThreadContext(hThread,&c);
    // c.EFlags |= 0x00000100;
    CloseHandle(hThread);

    unsigned long bR = 0;

    unsigned long *argArray = (unsigned long *)malloc(sizeof(unsigned long ) * funcHead->argCount);
    ReadProcessMemory(hProcess, (LPVOID )(c.Esp + 4), argArray, sizeof(unsigned long ) * funcHead->argCount, &bR);

    char *printFunctionString = (char *)malloc(MAX_ARGS_PRINTF);
    memset(printFunctionString,0,MAX_ARGS_PRINTF);
    char *funcMask = funcHead->funcMask;
    int funcMaskLen = strlen(funcHead->funcMask);

    strcpy(printFunctionString,funcHead->funcName);
    strcat(printFunctionString,"(");
    int argCount = 0;

    // use #define later, after bugs stepped on.
    char *tempPrintBuffer = (char *)malloc(1024);
    memset(tempPrintBuffer,0,1024);
    char *tempBuffer;

    int tempMaxLen = 0;
    for(i = 0;i < funcMaskLen;i++)
    {
        switch(funcMask[i])
        {
            case 's':
                ;
                tempBuffer = (char *)readUntilZero(hProcess, argArray[argCount++]);
                strcat(printFunctionString,"\"");
                strcat(printFunctionString,tempBuffer);
                strcat(printFunctionString,"\"");
                free(tempBuffer);
                break;
            case 'x':
                sprintf(tempPrintBuffer,"%x", argArray[argCount++]);
                strcat(printFunctionString, tempPrintBuffer);
                break;
            case 'd':
                sprintf(tempPrintBuffer,"%d", argArray[argCount++]);
                strcat(printFunctionString, tempPrintBuffer);
                break;
            case 'b':
                ;
                tempBuffer = (char *)malloc(argArray[ funcMask[i + 1] - '0' ]);
                ReadProcessMemory(hProcess, (LPVOID )argArray[i], tempBuffer, argArray[ funcMask[i + 1] - '0' ], &bR);
                int tempC;
                tempMaxLen = argArray[ funcMask[i + 1] - '0' ];
                unsigned char tempX;
                for(tempC = 0;tempC < tempMaxLen - 1;tempC++)
                {
                    tempX = (unsigned char )tempBuffer[tempC];
                    sprintf(tempPrintBuffer,"%02x ",tempX);
                    strcat(printFunctionString,tempPrintBuffer);
                }
                tempX = (unsigned char )tempBuffer[tempC];
                sprintf(tempPrintBuffer,"%02x",tempX);
                strcat(printFunctionString,tempPrintBuffer);
                
                free(tempBuffer);
                i++;
                break;
            default:
                printf("* function mask for %s broken\n", funcHead->funcName);
                break;
        }
        if(i < funcMaskLen - 1)
        {
            strcat(printFunctionString,",");
        }
    }

    strcat(printFunctionString,");");

    printf("C:%s\n", printFunctionString);
    free(tempPrintBuffer);
    free(printFunctionString);
    
    return 1;
}

// this needs to be defined differently. we need to be able to redefine the mask.
#define MAX_FMTSPEC 1024

void buildArgumentHooks(char *functionPrototypeFile)
{
    char storMask[MAX_FMTSPEC];
    char fmtSpec[MAX_FMTSPEC];

    FILE *f = fopen(functionPrototypeFile,"r");
    if(f == NULL)
    {
        printf("E:[%s:%d] cannot open argument spec file %s\n",__FILE__, __LINE__,functionPrototypeFile);
        return;
    }

    // build a new function mask node, add it only at the last min.

    funcMaskNode *funcHead = NULL;

    memset(storMask,0,MAX_FMTSPEC);
    int storCount = 0;

    memset(fmtSpec,0,MAX_FMTSPEC);
    while(fgets(fmtSpec,MAX_FMTSPEC - 1,f))
    {
        chomp(fmtSpec);

        // pass 1 - identify function name

        char *funcName = NULL;

        int i = 0;
        int fmtSpecLen = strlen(fmtSpec);
        if(fmtSpecLen == 0)
        {
            break;
        }

        for(;i < fmtSpecLen;i++)
        {
            if(!isalpha(fmtSpec[i]))
            {
                break;
            }
        }

        if(i != 0)
        {
            funcName = (char *)malloc(i + 1);
            memset(funcName,0,i + 1);
            strncpy(funcName,fmtSpec,i);
        }

        int argCount = 0;
        i = 0;
        int getArgs = 0;

        int maxArgRef = 0;
        int fMallocLen = 0;

        // approximate buffer size to be space between '(' and ')';
        i = 0;
        for(;i < fmtSpecLen;i++)
        {
            if(fmtSpec[i] == '(')
            {
                getArgs = 1;
                fMallocLen++;
            }
            else if(fmtSpec[i] == ')' && getArgs == 1) 
            {
                getArgs = 0;
                break;
            }
            else if(getArgs == 1)
            {
                fMallocLen++;
            }
        }

        // 1 + max number of args.
        char *funcMask = (char *)malloc(fMallocLen);
        memset(funcMask,0,fMallocLen);

        // paste into buffer
        getArgs = 0;
        i = 0;
        int funcMaski = 0;
        for(;i < fmtSpecLen;i++)
        {
            if(fmtSpec[i] == '(')
            {
                // printf("* getargs mode = 1;\n");
                // startArgString = i;
                getArgs = 1;
            }
            else if(getArgs == 1)
            {
                switch( tolower(fmtSpec[i]) )
                {
                    case 'b':
                        ;
                        if(i == fmtSpecLen - 1)
                        {
                            printf("E:binary block with no length specified in %s\n", funcName);
                            exit(0);
                            // last char
                        }
                        else // it is the last character
                        {
                            if(maxArgRef < fmtSpec[i + 1] - '0')
                            {
                                maxArgRef = fmtSpec[i + 1] - '0';
                            }
                            i++;
                        }
                        funcMask[funcMaski++] = 'b';
                        funcMask[funcMaski++] = fmtSpec[i];
                        argCount++;
                        break;
                    case 'x':
                    case 's':
                        funcMask[funcMaski++] = fmtSpec[i];
                        argCount++;
                        break; // do nothing, legit chars.
                    case ' ':
                    case ',':
                        break;
                    case ')':
                        // printf("* getargs mode = 0\n");
                        // endArgString = i;
                        getArgs = 0;
                        break;
                    default:
                        printf("E:unknown character %c in input mask for function %s\n", fmtSpec[i], funcName);
                        exit(0);
                        break;
                }
            }
            // else { pass; }
        }

        if(maxArgRef >= argCount && argCount != 0)
        {
            printf("E:something is broken in func mask for %s, maxArgRef = %d, argCount = %d\n", funcName, maxArgRef, argCount);
            exit(0);
        }

		if(debugMaskLoader)
		{
			printf("I:funcMask for %s is %s\n", funcName, funcMask);
		}
    
        if(funcHead == NULL)
        {
            funcChain = (funcMaskNode *)malloc(sizeof(funcMaskNode));
            funcHead = funcChain;
        }
        else
        {
            funcHead->next = (funcMaskNode *)malloc(sizeof(funcMaskNode));
            funcHead = (funcMaskNode *)funcHead->next;
        }
        
        funcHead->funcName = funcName;
		if(debugMaskLoader)
		{
			printf("I:adding %s with %d arguments\n", funcName, argCount);
		}
        funcHead->funcName = strdup(funcName);
        if(argCount != 0)
        {
            funcHead->funcMask = strdup(funcMask);
        }
        else
        {
            funcHead->funcMask = NULL;
        }
        funcHead->argCount = argCount;
        free(funcMask);
        funcHead->next = NULL;
        // memset(fmtSpec,0,MAX_FMTSPEC);
    }

    fclose(f);
    return;
}

void chomp(char *s)
{
  int i = 0;
  int stop = strlen (s);
  for (i = 0; i < stop; i++)
    {
      if (!(isprint (s[i])) || s[i] == '\r' || s[i] == '\n')
        {
          s[i] = 0;
          return;
        }
    }
}

// this shouldn't happen too often.
BYTE *readUntilZero (HANDLE hProcess, DWORD startAddress)
{
  int currentLength = 1;
  char *p = NULL;
  DWORD bR;

  while (p == NULL || p[currentLength - 1] != '\0')
    {
      currentLength++;
      if (p != NULL)
        {
          free (p);
        }
      p = (char *) malloc (currentLength);
      ReadProcessMemory (hProcess, (LPVOID) startAddress, p, currentLength,
                         &bR);
    }

  return (BYTE *) p;
}
