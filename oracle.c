#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winternl.h>
#include <psapi.h>

#ifdef ARCHI_64
	#define ARCHI 64
	#define PC_REG Rip
	#define REGISTER_LENGTH DWORD64
#else
	#define ARCHI 32
	#define PC_REG Eip
	#define REGISTER_LENGTH DWORD
#endif

#if ARCHI == 64
void scanExportTables(HANDLE hProcess)
{
	
}

char *resolve(LPVOID *p)
{
	return NULL;
}
#else
void scanExportTables(HANDLE hProcess)
{

}

char *resolve(LPVOID *p)
{
	return NULL;
}
#endif

unsigned int resolveAddr(CONTEXT *c,char *resolver)
{
	#if ARCHI == 64
	if(resolver[0] == 'r' && strlen(resolver) == 3)
	{
		if(resolver[2] == 'x')
		{
			switch(resolver[1])
			{
				case 'a':
					return c->Rax;
					break;
				case 'b':
					return c->Rbx;
					break;
				case 'c':
					return c->Rcx;
					break;
				case 'd':
					return c->Rdx;
					break;
				default:
					printf(" - unrecognized register '%s'\n",resolver);
					exit(0);
					break;
			}
		}
		else if (resolver[2] == 'p')
		{
			switch(resolver[1])
			{
				case 's':
					return c->Rsp;
					break;
				case 'b':
					return c->Rbp;
					break;
				case 'i':
					return c->Rip;
					break;
				default:
					printf(" - unrecognized register '%s'\n",resolver);
					exit(0);
					break;
			}
		}
		else if(resolver[2] == 'i')
		{
			switch(resolver[1])
			{
				case 'd':
					return c->Rdi;
					break;
				case 's':
					return c->Rsi;
					break;
				default:
					printf(" - unrecognized register '%s'\n",resolver);
					exit(0);
					break;
			}
		}
		else
		{
			long int regnum = strtol((char *)(resolver + 1),NULL,10);
			if(regnum >= 8 && regnum <= 15)
			{
				switch(regnum)
				{	
					case 8:
						return c->R8;
						break;
					case 9:
						return c->R9;
						break;
					case 10:
						return c->R10;
						break;
					case 11:
						return c->R11;
						break;
					case 12:
						return c->R12;
						break;
					case 13:
						return c->R13;
						break;
					case 14:
						return c->R14;
						break;
					case 15:
						return c->R15;
						break;
					default:
						printf(" - unrecognized register 'R%d'\n",regnum);
						exit(0);
						break;
				}
			}
			else
			{
				printf(" - unrecognized register '%s'\n",resolver);
				exit(0);
			}
		}
	}
	else
	{
		return strtol((char *)(resolver),NULL,0);
	}
	#else
	if(resolver[0] == 'e' && strlen(resolver) == 3)
	{
		if(resolver[2] == 'x')
		{
			switch(resolver[1])
			{
				case 'a':
					return c->Eax;
					break;
				case 'b':
					return c->Ebx;
					break;
				case 'c':
					return c->Ecx;
					break;
				case 'd':
					return c->Edx;
					break;
				default:
					printf(" - unrecognized register '%s'\n",resolver);
					exit(0);
					break;
			}
		}
		else if (resolver[2] == 'p')
		{
			switch(resolver[1])
			{
				case 's':
					return c->Esp;
					break;
				case 'b':
					return c->Ebp;
					break;
				case 'i':
					return c->Eip;
					break;
				default:
					printf(" - unrecognized register '%s'\n",resolver);
					exit(0);
					break;
			}
		}
		else if(resolver[2] == 'i')
		{
			switch(resolver[1])
			{
				case 'd':
					return c->Edi;
					break;
				case 's':
					return c->Esi;
					break;
				default:
					printf(" - unrecognized register '%s'\n",resolver);
					exit(0);
					break;
			}
		}
		else
		{
			printf(" - unrecognized register '%s'\n",resolver);
			exit(0);
		}
	}
	else
	{
		return strtol((char *)(resolver),NULL,0);
	}
	#endif
	return 0;
}
