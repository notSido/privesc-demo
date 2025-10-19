/*
 * Vulnerable Service Setup
 * This creates a deliberately misconfigured service for educational demonstration
 *
 * RUN THIS AS ADMINISTRATOR to set up the vulnerable environment
 */

#include <windows.h>
#include <stdio.h>
#include <aclapi.h>

void CreateVulnerableService() {
    SC_HANDLE hSCManager;
    SC_HANDLE hService;

    printf("[*] Creating vulnerable service for demonstration...\n");

    // Open Service Control Manager
    hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCManager == NULL) {
        printf("[!] Failed to open SCManager: %lu\n", GetLastError());
        return;
    }

    // Get current directory for the service executable
    char servicePath[MAX_PATH];
    GetCurrentDirectory(MAX_PATH, servicePath);
    strcat(servicePath, "\\vuln_service.exe");

    printf("[*] Service will be located at: %s\n", servicePath);

    // Delete service if it already exists
    hService = OpenService(hSCManager, "VulnDemoService", SERVICE_ALL_ACCESS);
    if (hService != NULL) {
        SERVICE_STATUS status;
        ControlService(hService, SERVICE_CONTROL_STOP, &status);
        DeleteService(hService);
        CloseServiceHandle(hService);
        printf("[*] Removed existing service\n");
    }

    // Create the service
    hService = CreateService(
        hSCManager,
        "VulnDemoService",                      // Service name
        "Vulnerable Demo Service",               // Display name
        SERVICE_ALL_ACCESS,
        SERVICE_WIN32_OWN_PROCESS,
        SERVICE_DEMAND_START,                    // Manual start
        SERVICE_ERROR_NORMAL,
        servicePath,
        NULL, NULL, NULL, NULL, NULL
    );

    if (hService == NULL) {
        printf("[!] Failed to create service: %lu\n", GetLastError());
        CloseServiceHandle(hSCManager);
        return;
    }

    printf("[+] Service created successfully\n");

    // Now make it vulnerable by setting weak permissions
    printf("[*] Setting weak permissions (allowing SERVICE_CHANGE_CONFIG for Users)...\n");

    EXPLICIT_ACCESS ea[2];
    PACL pOldAcl = NULL;
    PACL pNewAcl = NULL;
    PSECURITY_DESCRIPTOR pSD = NULL;
    SID_IDENTIFIER_AUTHORITY SIDAuthWorld = SECURITY_WORLD_SID_AUTHORITY;
    SID_IDENTIFIER_AUTHORITY SIDAuthNT = SECURITY_NT_AUTHORITY;
    PSID pEveryoneSID = NULL;
    PSID pAuthenticatedUsersSID = NULL;

    // Create SIDs
    AllocateAndInitializeSid(&SIDAuthWorld, 1, SECURITY_WORLD_RID,
                             0, 0, 0, 0, 0, 0, 0, &pEveryoneSID);

    AllocateAndInitializeSid(&SIDAuthNT, 1, SECURITY_AUTHENTICATED_USER_RID,
                             0, 0, 0, 0, 0, 0, 0, &pAuthenticatedUsersSID);

    // Get current DACL
    DWORD dwSize = 0;
    if (!QueryServiceObjectSecurity(hService, DACL_SECURITY_INFORMATION, NULL, 0, &dwSize)) {
        if (GetLastError() == ERROR_INSUFFICIENT_BUFFER) {
            pSD = (PSECURITY_DESCRIPTOR)LocalAlloc(LPTR, dwSize);
            if (pSD && QueryServiceObjectSecurity(hService, DACL_SECURITY_INFORMATION, pSD, dwSize, &dwSize)) {
                BOOL bDaclPresent = FALSE;
                BOOL bDaclDefaulted = FALSE;
                GetSecurityDescriptorDacl(pSD, &bDaclPresent, &pOldAcl, &bDaclDefaulted);
            }
        }
    }

    // Setup permissions for Everyone group
    ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS) * 2);

    // Everyone gets dangerous permissions
    ea[0].grfAccessPermissions = SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG | SERVICE_START | SERVICE_STOP | READ_CONTROL;
    ea[0].grfAccessMode = GRANT_ACCESS;
    ea[0].grfInheritance = NO_INHERITANCE;
    ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[0].Trustee.ptstrName = (LPTSTR)pEveryoneSID;

    // Authenticated Users also get permissions
    ea[1].grfAccessPermissions = SERVICE_QUERY_CONFIG | SERVICE_CHANGE_CONFIG | SERVICE_START | SERVICE_STOP | READ_CONTROL;
    ea[1].grfAccessMode = GRANT_ACCESS;
    ea[1].grfInheritance = NO_INHERITANCE;
    ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
    ea[1].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
    ea[1].Trustee.ptstrName = (LPTSTR)pAuthenticatedUsersSID;

    // Merge with existing ACL
    if (SetEntriesInAcl(2, ea, pOldAcl, &pNewAcl) == ERROR_SUCCESS) {
        // Set the ACL on the service
        DWORD result = SetSecurityInfo(
            hService,
            SE_SERVICE,
            DACL_SECURITY_INFORMATION,
            NULL,
            NULL,
            pNewAcl,
            NULL
        );

        if (result == ERROR_SUCCESS) {
            printf("[+] Weak permissions set successfully!\n");
            printf("[+] Everyone and Authenticated Users can now modify this service\n");
        } else {
            printf("[!] Failed to set permissions: %lu\n", result);
        }

        LocalFree(pNewAcl);
    } else {
        printf("[!] Failed to create ACL: %lu\n", GetLastError());
    }

    if (pSD) LocalFree(pSD);
    if (pEveryoneSID) FreeSid(pEveryoneSID);
    if (pAuthenticatedUsersSID) FreeSid(pAuthenticatedUsersSID);

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);

    printf("\n[SUCCESS] Vulnerable environment set up!\n");
    printf("Now run privesc_demo.exe as a STANDARD USER to see the exploit work.\n");
}

void CreateDummyServiceExecutable() {
    printf("[*] Creating dummy service executable...\n");

    // Create a minimal service executable
    FILE *f = fopen("vuln_service.exe", "wb");
    if (f == NULL) {
        printf("[!] Could not create vuln_service.exe\n");
        return;
    }

    // This is a minimal PE that just exits - enough to satisfy the service manager
    // In reality you'd compile a proper service, but this works for demo purposes
    unsigned char dummyExe[] = {
        0x4D, 0x5A, 0x90, 0x00  // MZ header - minimum valid PE
    };

    fwrite(dummyExe, 1, sizeof(dummyExe), f);
    fclose(f);

    printf("[+] Dummy service executable created\n");
}

int main() {
    printf("=== Vulnerable Service Setup (Educational Demo) ===\n\n");
    printf("This tool creates a deliberately misconfigured Windows service\n");
    printf("that allows standard users to modify its configuration.\n\n");

    printf("WARNING: Only run this in a test/lab environment!\n");
    printf("Press ENTER to continue or CTRL+C to abort...");
    getchar();

    CreateDummyServiceExecutable();
    CreateVulnerableService();

    printf("\n=== Setup Complete ===\n");
    printf("You can now demonstrate privilege escalation by:\n");
    printf("1. Opening a standard (non-admin) command prompt\n");
    printf("2. Running: privesc_demo.exe\n");
    printf("3. Watch as it escalates from user to SYSTEM!\n\n");

    return 0;
}
