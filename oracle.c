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
	HMODULE hMods[1024];
	DWORD cbNeeded;
	if (EnumProcessModulesEx(hProcess,hMods,sizeof(hMods),&cbNeeded, LIST_MODULES_ALL) )
	{
		int i = 0;
		DWORD cbMod;
		MODULEINFO mi;
		char modBaseName[MAX_PATH];
		for(;i < cbNeeded;i++)
		{
			GetModuleBaseName(hProcess,hMods[i],modBaseName,MAX_PATH);
			GetModuleInformation(hProcess,hMods[i],&mi,sizeof(mi));
			printf(" oracle:reading %s at %x\n",modBaseName,mi.lpBaseOfDll);
		}
	}
	else
	{
		return;
	}
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