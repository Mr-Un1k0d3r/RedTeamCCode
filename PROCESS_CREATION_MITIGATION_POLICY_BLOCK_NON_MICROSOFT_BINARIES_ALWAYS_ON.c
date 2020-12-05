#define _WIN32_WINNT 0x0a00

#include <Windows.h>
#include <stdio.h>

#define PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON (0x00000001ull << 44)

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

        CreateProcess(argv[0], args, NULL, NULL, TRUE, EXTENDED_STARTUPINFO_PRESENT, NULL, NULL, &si, &pi);
        GlobalFree(args);
        ExitProcess(0);
    } else {
        // We have the argument so PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON is now on
        // Do some dirty stuff here
        printf("shellcode");
    }

    return 0;
}
