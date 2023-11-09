#include <windows.h>
#include <stdio.h>
#include <processenv.h>

int main() {
    LPCH env = GetEnvironmentStrings();
    while(TRUE) {
        printf("%s\n", env);
        env += strlen(env) + 1;
        if(env[0] == 0x00) {
            break;
        }
    }
    return 0;
}
