#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <psapi.h>
#include <ctype.h>
#include "oracle.h"
#include "tinker.h"

#ifdef ARCHI_64
	#define ARCHI 64
	#define PC_REG Rip
	#define REGISTER_LENGTH DWORD64
#else
	#define ARCHI 32
	#define PC_REG Eip
	#define REGISTER_LENGTH DWORD
#endif

#define MAX_CMD 1024

/*
	when we get a crash, drop the user into a "mini debugger" which
	can do super basic crash triage. not intended for use as a full
	debugger.
*/

void miniDebugger(PROCESS_INFORMATION *pi, DEBUG_EVENT *de)
{
	printf(" > starting mini debug shell...\n");

	HANDLE h = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT,FALSE,de->dwThreadId);
	int bCont = 1;
	char *cmd = (char *)malloc(MAX_CMD);

	CONTEXT cx;
	cx.ContextFlags = CONTEXT_FULL;
	GetThreadContext(h,&cx);

	while (bCont)
	{
		printf(" > ");
		memset(cmd,0,MAX_CMD);
		fgets(cmd,MAX_CMD,stdin);
		chomp(cmd);
		char *c = getToken(cmd,0);

		if (c == NULL)
		{
			printf(" - error: user is an idiot\n");	
			exit(0);
		}
		else if(strncmp(c,"d",1) == 0)
		{
			char *addr = (char *)(resolveAddr(&cx,getToken(cmd,1)));
			int dataSize = 1;
			switch (c[1])
			{
				case 'b':
					dataSize = 1;
					break;
				case 'w':
					dataSize = 2;
					break;
				case 'd':
					dataSize = 4;
					break;
				case 'q':
					dataSize = 8;
					break;
				default:
					break;
			}
		}
		else if(strncmp(c,"e",1) == 0)
		{
			char *addr = getToken(cmd,1);
			char *value = getToken(cmd,2);
		}
		else if(strncmp(c,"u",1) == 0)
		{
			char *addr = getToken(cmd,1);
		}
		else if(strncmp(c,"r",1) == 0)
		{
			char *registerName = getToken(cmd,1);
			char *registerValue = getToken(cmd,2);
		}
		else if(strncmp(c,"q",1) == 0)
		{
			bCont = 0;
		}
		else
		{
			printf(" - error: unsupported command %s\n",c);
			printf(" - supported commands are d,e,u,r,q\n");
		}
	}

	free(cmd);

	CloseHandle(h);
	return;
}

char *getToken(char *s,int tokenNum)
{
	int max = strlen(s);
	int i = 0;
	int currentToken = 0;
	int lastSpace = 1;
	for (; i < max; i++)
	{
		if (isspace(s[i]))
		{
			lastSpace = 1;
		}	
		else
		{
			if (lastSpace == 1)
			{
				lastSpace = 0;
				if (currentToken == tokenNum)
				{
					return (char *)(s + i);
				}
			}
		}
	}
	return NULL;
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
