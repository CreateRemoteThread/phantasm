 // testing mode for syswow64 fixup.

#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <tlhelp32.h>
#include "resolute.h"
#include <tchar.h>

#define DEBUG_PRINTF_EXPORTS 0
#define DEBUG_FAILED_READS 0

#define CHAR_TYPE char

CHAR_TYPE *stristr
  (CHAR_TYPE * szStringToBeSearched, const CHAR_TYPE * szSubstringToSearchFor)
{
  CHAR_TYPE *pPos = NULL;
  CHAR_TYPE *szCopy1 = NULL;
  CHAR_TYPE *szCopy2 = NULL;

  // verify parameters
  if (szStringToBeSearched == NULL || szSubstringToSearchFor == NULL)
    {
      return szStringToBeSearched;
    }

  // empty substring - return input (consistent with strstr)
  if (_tcslen (szSubstringToSearchFor) == 0)
    {
      return szStringToBeSearched;
    }

  szCopy1 = _tcslwr (_tcsdup (szStringToBeSearched));
  szCopy2 = _tcslwr (_tcsdup (szSubstringToSearchFor));

  if (szCopy1 == NULL || szCopy2 == NULL)
    {
      // another option is to raise an exception here
      free ((void *) szCopy1);
      free ((void *) szCopy2);
      return NULL;
    }

  pPos = strstr (szCopy1, szCopy2);

  if (pPos != NULL)
    {
      // map to the original string
      pPos = szStringToBeSearched + (pPos - szCopy1);
    }

  free ((void *) szCopy1);
  free ((void *) szCopy2);

  return pPos;
}                               // stristr(...)

#ifdef DEBUG
#undef DEBUG
#endif

// #define DEBUG 0

/*
  BEGIN--
  DO gcc -c resolute.c
  END--
 */

char *
strtoupper (char *dest)
{
  char *localDest = dest;
  while (*localDest != '\0')
    {
      *localDest = toupper (*localDest);
      localDest++;
    }
  return localDest;
}

DWORD convertRVAToReal (DWORD rva, IMAGE_SECTION_HEADER * st,
                        DWORD numberOfSections);
exportStruct *getExports (char *dll);

void
cleanStructures (exportGroupStruct * e)
{
  if (e == NULL)
    {
      printf ("* resolute:cleanStructures - nothing to clean\n");
      return;
    }

  exportGroupStruct *eGP = e;
  exportGroupStruct *tPtr = NULL;
  exportStruct *eP = NULL;
  exportStruct *tempExports = NULL;
  while (eGP != NULL)
    {
      free (eGP->moduleName);
      free (eGP->moduleShortName);
      eP = eGP->exports;
      while (eP != NULL)
        {
          free (eP->exportName);
          tempExports = eP->next;
          free (eP);
          eP = tempExports;
        }
      tPtr = eGP->next;
      free (eGP);
      eGP = tPtr;
    }

  return;
}

exportGroupStruct *
scanModules (HANDLE hProcess, DWORD processId, int printMode)
{
  exportGroupStruct *e =
    (exportGroupStruct *) malloc (sizeof (exportGroupStruct));
  exportGroupStruct *eHead = NULL;
  MODULEENTRY32 me;
  int bCont;
  HANDLE g_hSnap = CreateToolhelp32Snapshot (TH32CS_SNAPMODULE + TH32CS_SNAPMODULE32, processId);

  // printf("scanmodules was here\n");

  memset (&me, 0, sizeof (me));
  me.dwSize = sizeof (me);
  bCont = Module32First (g_hSnap, &me);

  while (bCont)
    {
#ifdef DEBUG
      printf ("*");
#endif
      if (eHead == NULL)
        {
          eHead = e;
        }
      else
        {
          eHead->next =
            (exportGroupStruct *) malloc (sizeof (exportGroupStruct));
          eHead = eHead->next;
        }
      if (printMode == 1)
        {
          printf ("* 0x%08x 0x%08x %s\n", me.modBaseAddr,
                  me.modBaseAddr + me.modBaseSize, me.szExePath);
        }
      eHead->moduleName = strdup (me.szExePath);
      eHead->moduleShortName = strdup (me.szModule);
      eHead->moduleBase = (DWORD) me.modBaseAddr;
      eHead->moduleEnd = (DWORD) me.modBaseAddr + me.modBaseSize;
      eHead->exports =
        scanSingleModule (hProcess, (DWORD) me.modBaseAddr, me.modBaseSize);
      eHead->next = NULL;
      bCont = Module32Next (g_hSnap, &me);
    }

  /*
     exportGroupStruct *eNext = (exportGroupStruct *)malloc(sizeof(exportGroupStruct));
     memset(eNext,0,sizeof(exportGroupStruct));
     eHead->next = eNext;
   */


  CloseHandle(g_hSnap);
  return e;
}

exportStruct *
scanSingleModule (HANDLE hProcess, DWORD modBaseAddr, DWORD modBaseSize)
{
  exportStruct *e = (exportStruct *) malloc (sizeof (exportStruct));
  exportStruct *eHead = NULL;

  // named pMapping to copy/paste hsrv code.
  char *pMapping = (char *) malloc (modBaseSize);
  DWORD bR;

    DWORD oldProtect = 0;
    DWORD reserved1;

  int retVal = ReadProcessMemory (hProcess, (LPVOID) modBaseAddr, pMapping, modBaseSize,&bR);
  // printf(" * SCANSINGLEMODULE %08x %08x %c%c%c%c\n", (unsigned long )modBaseAddr, (unsigned long )pMapping, pMapping[0],pMapping[1],pMapping[2],pMapping[3]);
  if (bR != modBaseSize )
    {
      if(DEBUG_FAILED_READS)
        {
           printf ("* scanSingleModule: could not read all of dll address space at %08x - expected %08x, got %08x [readprocessmemory returned %d]\n",(unsigned long )modBaseAddr, (unsigned long )modBaseSize, (unsigned long )bR, retVal);

           if(retVal == 0)
             {
                 void *buf;
                 DWORD le = GetLastError ();
                 FormatMessage (FORMAT_MESSAGE_ALLOCATE_BUFFER |
                                FORMAT_MESSAGE_FROM_SYSTEM |
                                FORMAT_MESSAGE_IGNORE_INSERTS,
                                NULL, le, 0, (LPTSTR) & buf, 0, NULL);
                 printf ("* [%d] ReadProcessMemory failed with %s (%08x)\n",
                         __LINE__, buf, le);
                 LocalFree (buf);
             }
        }

      VirtualProtectEx (hProcess, (LPVOID) modBaseAddr, modBaseSize,oldProtect, &reserved1);

        int successfulReads = 0;
        int unsuccessfulReads = 0;
        DWORD bytesRead = 0;
        int i = 0;
        for(i = 0;i < modBaseSize/1024;i++)
        {
            bytesRead = 0;
            ReadProcessMemory(hProcess,(unsigned char *)modBaseAddr + (i * 1024),pMapping + i * 1024,1024,&bytesRead);
            if(bytesRead != 1024)
            {
                unsuccessfulReads++;
            }
            else
            {
                successfulReads++;
            }
        }

        if(!(modBaseSize % (i * 1024) == 0))
        {
            ReadProcessMemory(hProcess,(unsigned char *)modBaseAddr + (i * 1024),pMapping + i * 1024,modBaseSize - i * 1024,&bytesRead);
            if(bytesRead == 0)
            {
                unsuccessfulReads++;
            }
            else
            {
                successfulReads++;
            }
        }

    }
  if (pMapping[0] != 'M' || pMapping[1] != 'Z')
  {
	  // printf("* skipping module\n");
	  return NULL;
  }

  VirtualProtectEx (hProcess, (LPVOID) modBaseAddr, modBaseSize,oldProtect, &reserved1);
  
  // read dllz!

  IMAGE_DOS_HEADER *dosHdr = (IMAGE_DOS_HEADER *) pMapping;
  IMAGE_NT_HEADERS *ntHdrs =
    (IMAGE_NT_HEADERS *) (pMapping + dosHdr->e_lfanew);

#ifdef DEBUG
  printf ("* 0x%08x\n",
          ntHdrs->OptionalHeader.DataDirectory[0].VirtualAddress);
#endif

  IMAGE_EXPORT_DIRECTORY *expDir =
    (IMAGE_EXPORT_DIRECTORY *) (pMapping +
                                ntHdrs->OptionalHeader.DataDirectory[0].
                                VirtualAddress);

  if (ntHdrs->OptionalHeader.DataDirectory[0].VirtualAddress == 0)
    {
      return NULL;
    }
  else
    {
      IMAGE_THUNK_DATA *nameChain =
        (IMAGE_THUNK_DATA *) (pMapping + expDir->AddressOfNames);
      // funcChain effectively is nameOrdChain
      DWORD *funcChain = (DWORD *) (pMapping + expDir->AddressOfFunctions);
      WORD *nameOrdChain = (WORD *) (pMapping + expDir->AddressOfNameOrdinals);
      int i;

      // printf ("* (%d exports, base %d)\n", expDir->NumberOfFunctions, expDir->Base);

#ifdef DEBUG
      printf ("(%d exports)", expDir->NumberOfNames);
#endif

    WORD lastOrdinal = 0;

    for(i = 0;i < expDir->NumberOfFunctions;i++)
      {
          WORD currentNameOrdinal = nameOrdChain[i];

          /*
          if(currentNameOrdinal < lastOrdinal)
          {
              printf("* SSM off-by-one, breaking for [resolute.c:%d], current ordinal %d\n", __LINE__, currentNameOrdinal);
              break;
          }
          else
          {
              lastOrdinal = currentNameOrdinal;
          }
          */

          char *strOffset;
          if (nameChain[(short )currentNameOrdinal].u1.AddressOfData == 0 || currentNameOrdinal > (unsigned short )expDir->NumberOfNames)
            {
              strOffset = NULL;
            }
          else
            {
              strOffset = (char *) (pMapping + nameChain[i].u1.AddressOfData);
            }

          DWORD fAddr = funcChain[currentNameOrdinal];

          // a function should never be exported to an address of zero in a legit dll.

          if(fAddr == 0)
          {
              break;
          }

          if (eHead == NULL)
            {
              eHead = e;                     // issue could be here. why?
              memset(e,0,sizeof(exportStruct));
            }
          else
            {
              eHead->next = (exportStruct *) malloc (sizeof (exportStruct));
              memset (eHead->next, 0, sizeof (exportStruct));
              eHead = eHead->next;
            }
          
          if (strOffset == NULL)
            {
              eHead->exportName = NULL;
              // printf("* unnamed exported at %08x\n", strOffset);
              break;
            }
          else
            {
              eHead->exportName = strdup (strOffset);
              eHead->exportAddr = fAddr;
              if(DEBUG_PRINTF_EXPORTS)
                {
                    printf("* [%04d:NAME ORD:%08d] %s exported at %08x\n", i,currentNameOrdinal,strOffset, (unsigned long )fAddr);
                }
            }
      }

      if (eHead != NULL)
        {
          /*
          eHead->next = (exportStruct *) malloc (sizeof (exportStruct));
          eHead = eHead->next;
          memset (eHead, 0, sizeof (exportStruct));
          */
          eHead->next = NULL;
        }
      else
        {
          free (pMapping);
          return NULL;
        }
    }

  free (pMapping);
  return e;
}

char *
resolveAddrSoft (exportGroupStruct * e, DWORD dlladdr)
{
  exportGroupStruct *eGP = e;
  DWORD lastAddr = 0;
  exportStruct *lastE = NULL;

	// printf ("* resolving address %08x\n", dlladdr);

#ifdef DEBUG
  printf ("* resolving address %08x\n", dlladdr);
#endif

  while (eGP != NULL)
    {
	  // printf("* scanning %08x-%08x\n",eGP->moduleBase, eGP->moduleEnd);
      if (eGP->moduleBase <= dlladdr && eGP->moduleEnd >= dlladdr)
        {
          if (dlladdr == eGP->moduleBase)
            {
              return strdup (eGP->moduleName);
            }
          exportStruct *eP = eGP->exports;
          while (eP != NULL)
            {
#ifdef DEBUG
              printf ("* %08x\n", eP->exportAddr);
#endif
              if (eGP->moduleBase + eP->exportAddr == dlladdr)
                {
                  if(eP->exportName != NULL)
                    {
                      int newStringLength = strlen (eGP->moduleName) + strlen (eP->exportName) + 2;
                      char *dllAndExport = (char *) malloc (newStringLength);
                      memset (dllAndExport, 0, newStringLength);
                      // copy string to destination
                      strcpy (dllAndExport, eGP->moduleShortName);
                      strcat (dllAndExport, "!");
                      strcat (dllAndExport, eP->exportName);
                      return dllAndExport;
                    }
                    else
                    {
                      char *dllAndExport = (char *)strdup("unknown!unknown");
                      return dllAndExport;
                    }
                }
              else if (eGP->moduleBase + eP->exportAddr >= lastAddr
                       && eGP->moduleBase + eP->exportAddr <= dlladdr)
                {
                  lastAddr = eGP->moduleBase + eP->exportAddr;
                  lastE = eP;
                }
              eP = eP->next;
            }

          if (lastAddr != 0)
            {
              eP = lastE;
              if(eP->exportName != NULL)               // I AM TERRIBLE.
                {
                  // eP = lastE;
                  int newStringLength = strlen (eGP->moduleName) + strlen (eP->exportName) + 10;
                  char *dllAndExport = (char *) malloc (newStringLength);
                  memset (dllAndExport, 0, newStringLength);
                  sprintf (dllAndExport, "%s!%s+0x%04x", eGP->moduleShortName,
                           eP->exportName, dlladdr - lastAddr);
                  return dllAndExport;
                }
               else
                {
                   printf("lol\n");
                   char *dllAndExport = (char *)strdup("unknown!unknown");
                   return dllAndExport;
                }
            }

    /*
#ifdef DEBUG
          printf ("* couldn't resolve address\n");
#endif
          printf("* first SETLASTERROR\n");
          SetLastError (1);
          return NULL;
          */
        }
      eGP = eGP->next;
    }

#ifdef DEBUG
  printf ("* no module contains this address");
#endif

  SetLastError (1);
  return NULL;
}

char *
resolveAddr (exportGroupStruct * e, DWORD dlladdr)
{
  exportGroupStruct *eGP = e;

#ifdef DEBUG
  printf ("* resolving address %08x\n", dlladdr);
#endif

  while (eGP != NULL)
    {
      if (eGP->moduleBase <= dlladdr && eGP->moduleEnd >= dlladdr)
        {
          if (dlladdr == eGP->moduleBase)
            {
              return strdup (eGP->moduleName);
            }
          exportStruct *eP = eGP->exports;
          while (eP != NULL)
            {
#ifdef DEBUG
              printf ("* %08x\n", eP->exportAddr);
#endif
              if (eGP->moduleBase + eP->exportAddr == dlladdr)
                {
                  if(eP->exportName != NULL)
                    {
                      int newStringLength =
                        strlen (eGP->moduleName) + strlen (eP->exportName) + 2;
                      char *dllAndExport = (char *) malloc (newStringLength);
                      memset (dllAndExport, 0, newStringLength);
                      // copy string to destination
                      strcpy (dllAndExport, eGP->moduleShortName);
                      strcat (dllAndExport, "!");
                      strcat (dllAndExport, eP->exportName);
                      return dllAndExport;
                    }
                  else
                    {
                      char *dllAndExport = (char *)strdup("unknown!unknown");
                      return dllAndExport;
                    }
                }
              eP = eP->next;
            }
#ifdef DEBUG
          printf ("* couldn't resolve address\n");
#endif
          SetLastError (1);
          return NULL;
        }
      eGP = eGP->next;
    }

#ifdef DEBUG
  printf ("* no module contains this address");
#endif

  SetLastError (1);
  return NULL;
}

DWORD
resolveExport (exportGroupStruct * e, char *dllfunc)
{
  char **resolveExportContext = NULL;
  char *dllName = NULL, *fName = NULL;
  int i = 0;
  int searchModule = 0;

  dllName = dllfunc;

  while (dllName[i++] != '!' && dllName[i++] != '\0')
    {
      if (i == strlen (dllName))
        {
          searchModule = 1;
        }
    }
  dllName[i - 1] = 0;

  fName = dllName + strlen (dllName) + 1;

  if (dllName == NULL || strlen (dllName) == 0 || fName == NULL
      || strlen (fName) == 0)
    {
      SetLastError (1);
      return 0;
    }

#ifdef DEBUG
  printf ("* resolving %s in %s\n", fName, dllName);
#endif

  exportGroupStruct *eGP = e;

  DWORD closestExport = 0;

  while (eGP != NULL)
    {
      if (eGP->moduleName != NULL
          && (stristr (eGP->moduleName, dllName) != NULL))
        {
          if (searchModule == 1)
            {
              return eGP->moduleBase;
            }

          exportStruct *eP = eGP->exports;
          if (eP == NULL)
            {
              printf ("* resolveExport : %s exports nothing\n",
                      eGP->moduleName);
              printf("* try 'l' to refresh export listing structures\n");
            }
          while (eP != NULL)
            {
              if (eP->exportName != 0 && strcmpi (fName, eP->exportName) == 0)
                {
                  return eP->exportAddr + eGP->moduleBase;
                }
              else if ((eP->exportOrdinal != 0)
                       && atoi (fName) == eP->exportOrdinal)
                {
                  return eP->exportAddr + eGP->moduleBase;
                }
              eP = eP->next;
            }
          SetLastError (1);
          printf ("* resolveExport : export not found in %s\n",
                  eGP->moduleName);
          return 0;
        }
      eGP = eGP->next;
    }

  SetLastError (1);
  return 0;
}

char *
strtok_r (char *str, const char *delim, char **saveptr)
{
  char *token;
  if (str)
    *saveptr = str;
  token = *saveptr;

  if (!token)
    return NULL;

  token += strspn (token, delim);
  *saveptr = strpbrk (token, delim);
  if (*saveptr)
    *(*saveptr)++ = '\0';

  return *token ? token : NULL;
}
