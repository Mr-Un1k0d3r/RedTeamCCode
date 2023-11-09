#include <windows.h>
#include <stdio.h>
#include <processenv.h>

int main() {
    LPCH env = GetEnvironmentStrings();
    while(env[0] != 0x00) {
        printf("%s\n", env);
        env += strlen(env) + 1;
    }
    return 0;
}
