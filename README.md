# Control-DSE

## Project Overview
This project demonstrates kernel-level DSE (Driver Signature Enforcement) control using Ring 0 access through the RTCore64 driver.

## Setup Instructions

### 1. Build the Project
- Open the project in **Visual Studio**
- Build the solution
- Navigate to `x64\Release` directory
- Extract the following files:
  - `KernelOffsets.exe` (main executable)
  - `Hello.sys` (kernel driver to be loaded)
  - `RTCore64.sys` (Ring 0 driver)

### 2. File Placement on Target Machine
Place the driver files in the following locations:

- **RTCore64.sys** → `C:\Users\Public\`
- **Hello.sys** → `Desktop`

## Usage Instructions

### Step 1: Run the Kernel Offsets Tool
Open Command Prompt and execute:
```
.\KernelOffsets.exe TestService
```

This will:
1. Find the address of `g_CiOptions` in the kernel
2. Check the current DSE status (enabled or disabled)
3. Disable DSE temporarily
4. Load the Hello.sys driver
5. Re-enable DSE with the value `0x06` in `g_CiOptions`
6. Unload RTCore64.sys
7. Stop the driver service
8. Delete the service
9. Print the final status

### Step 2: Verify Driver Loading (Optional)
To verify that Hello.sys was successfully loaded:

1. Open **Process Hacker** as Administrator
2. Click on the **System** process
3. Click on the **Third Icon** (Show Lower Pane)
4. Click on the **DLLs** tab
5. You should see **Hello.sys** listed in the loaded DLL files

## How It Works

The project performs the following operations:

1. **Locate g_CiOptions**: Finds the kernel variable controlling DSE
2. **Disable DSE**: Temporarily disables Driver Signature Enforcement
3. **Load Unsigned Driver**: Loads the Hello.sys driver without signature validation
4. **Re-enable DSE**: Re-enables DSE with the kernel value set to `0x06`
5. **Cleanup**: Unloads RTCore64.sys, stops and deletes the service
6. **Report Status**: Displays the final operation status

## Requirements

- Windows 10/11 (x64)
- Administrator privileges
- Process Hacker (for verification)
- Visual Studio (for building)

## Warning

⚠️ This project involves kernel-level operations and DSE manipulation. Use responsibly and only in controlled environments for educational purposes.
