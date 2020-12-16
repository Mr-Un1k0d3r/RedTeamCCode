#include <Windows.h>
#include <stdio.h>

DWORD StringToShellcode(CHAR *string, CHAR *shellcode) {
    DWORD dwSize = strlen(string) / 4;
    DWORD i = 2;
    DWORD j = 0;

    for(i; i <= strlen(string) - 2; i += 4) {
        unsigned char *clone;
        clone = (unsigned char*)GlobalAlloc(GPTR, strlen(string));
        strcpy(clone, string + i);
        clone[2] = 0x00;
        shellcode[j] = (unsigned char)strtol(clone, NULL, 16);
        j++;
        GlobalFree(clone);
    }
    return dwSize;
}

int main(int argc, char **argv) {
        DWORD dwSize = 0;
        CHAR *payload = argv[1];
        CHAR *shellcode = VirtualAlloc(NULL, strlen(payload) / 4, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        dwSize = StringToShellcode(payload, shellcode);
        printf("Running shellcode. Shellcode size 0x%x (%d) bytes.\n", dwSize, dwSize);
        asm (
                "mov %0, %%rax\n\t"
                "push %%rax\n\t"
                "ret\n\t"
                :
                : "r"(shellcode)
        );

        // pretty much never going to reach this point
        printf("Process completed\n");
        return 0;
}
