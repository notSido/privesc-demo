/*
 * Service Cleanup Utility
 * Removes the vulnerable demo service
 */

#include <windows.h>
#include <stdio.h>

int main() {
    printf("=== Service Cleanup Utility ===\n\n");

    SC_HANDLE hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (hSCManager == NULL) {
        printf("[!] Failed to open SCManager: %lu\n", GetLastError());
        printf("[!] Make sure you run this as Administrator\n");
        return 1;
    }

    SC_HANDLE hService = OpenService(hSCManager, "VulnDemoService", SERVICE_ALL_ACCESS | DELETE);
    if (hService == NULL) {
        printf("[*] Service not found or already deleted\n");
        CloseServiceHandle(hSCManager);
        return 0;
    }

    printf("[*] Stopping service...\n");
    SERVICE_STATUS status;
    ControlService(hService, SERVICE_CONTROL_STOP, &status);
    Sleep(1000);

    printf("[*] Deleting service...\n");
    if (DeleteService(hService)) {
        printf("[+] Service deleted successfully\n");
        printf("[*] The service will be fully removed after system restart or when all handles are closed\n");
    } else {
        printf("[!] Failed to delete service: %lu\n", GetLastError());
    }

    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);

    printf("\n[*] Cleanup complete. Now you can run setup_vulnerable_service.exe again\n");
    return 0;
}
