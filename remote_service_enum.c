#include <windows.h>
#include <stdio.h>

int main(int argc, char **argv) {

    BYTE sid[SECURITY_MAX_SID_SIZE];
    DWORD sidSize = sizeof(sid);
    char domainName[256];
    DWORD domainNameSize = sizeof(domainName);
    SID_NAME_USE snu;

    BOOL bResult = FALSE;
    CHAR serviceName[256];
    snprintf(serviceName, 255, "Nt Service\\%s", argv[2]);

    if(strcmp(argv[1], ".") == 0) {
        argv[1] = NULL;
    }

    if(argc > 3) {
        CHAR* domain = argv[3];
        CHAR* username = argv[4];
        CHAR* password = argv[5];

        HANDLE hToken = NULL;
        printf("Username was provided attempting to call LogonUserA\n");
        bResult = LogonUserA(username, domain, password, LOGON32_LOGON_NEW_CREDENTIALS, LOGON32_PROVIDER_DEFAULT, &hToken);
        if(!bResult) {
            printf("LogonUserA failed %ld\n", GetLastError());
            ExitProcess(0);
        }

        bResult = FALSE;
        bResult = ImpersonateLoggedOnUser(hToken);
        if(!bResult) {
            printf("ImpersonateLoggedOnUser failed %ld\n", GetLastError());
            ExitProcess(0);
        }
        CloseHandle(hToken);

    }

    if(LookupAccountNameA(argv[1], serviceName, sid, &sidSize, domainName, &domainNameSize, &snu)) {  
        printf("%s was found\n", argv[2]);
    }

    return 0;
}
