#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <winternl.h>
#include <psapi.h>

#if REGISTER_LENGTH == DWORD64
	#define ARCHI 64
	#define PC_REG Rip
#else
	#define ARCHI 32
	#define PC_REG Eip
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