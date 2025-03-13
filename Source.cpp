#include "HandleGuard.hpp"
#include <iostream>

BOOL LoadLibraryOntoProcessW(HANDLE hProcess, LPCWSTR lpLibFileName)
{
    std::cout << "[DEBUG] Attempting to load library: " << lpLibFileName << std::endl;

    // Get the address of the LoadLibraryW function
    HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
    if (hKernel32 == NULL)
    {
        std::cout << "[ERROR] Failed to get handle to kernel32.dll" << std::endl;
        return FALSE;
    }
    std::cout << "[DEBUG] Successfully got kernel32.dll handle" << std::endl;

    FARPROC pLoadLibraryW = GetProcAddress(hKernel32, "LoadLibraryW");
    if (pLoadLibraryW == NULL)
    {
        std::cout << "[ERROR] Failed to get LoadLibraryW address" << std::endl;
        return FALSE;
    }
    std::cout << "[DEBUG] Successfully got LoadLibraryW address" << std::endl;

    // Allocate memory in the remote process for the DLL path
    LPVOID pDllPath = VirtualAllocEx(hProcess, NULL, (wcslen(lpLibFileName) + 1) * sizeof(WCHAR), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pDllPath == NULL)
    {
        std::cout << "[ERROR] Failed to allocate memory in remote process" << std::endl;
        return FALSE;
    }
    std::cout << "[DEBUG] Successfully allocated memory at " << pDllPath << std::endl;

    // Write the DLL path to the allocated memory
    if (!WriteProcessMemory(hProcess, pDllPath, lpLibFileName, (wcslen(lpLibFileName) + 1) * sizeof(WCHAR), NULL))
    {
        std::cout << "[ERROR] Failed to write DLL path to remote process" << std::endl;
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        return FALSE;
    }
    std::cout << "[DEBUG] Successfully wrote DLL path to remote process" << std::endl;

    // Create a remote thread in the target process
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryW, pDllPath, 0, NULL);
    if (hThread == NULL)
    {
        std::cout << "[ERROR] Failed to create remote thread" << std::endl;
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        return FALSE;
    }
    std::cout << "[DEBUG] Successfully created remote thread with handle " << hThread << std::endl;

    // Use HandleGuard to manage the remote thread handle
    HandleGuard threadGuard(hThread);

    // Wait for the remote thread to finish
    std::cout << "[DEBUG] Waiting for remote thread to complete" << std::endl;
    WaitForSingleObject(hThread, INFINITE);

    // Get the exit code of the remote thread
    DWORD dwExitCode;
    GetExitCodeThread(hThread, &dwExitCode);
    std::cout << "[DEBUG] Remote thread completed with exit code " << dwExitCode << std::endl;

    // Clean up
    VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
    std::cout << "[DEBUG] Cleaned up allocated memory" << std::endl;
    return TRUE;
}

HANDLE CreateSuspendedProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSTARTUPINFO lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{
    HANDLE hProcess = NULL;
    std::cout << "[DEBUG] Attempting to create suspended process: " << lpApplicationName << std::endl;

    // Create the process in suspended mode
    if (!CreateProcessW(lpApplicationName, lpCommandLine, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, lpStartupInfo, lpProcessInformation))
    {
        std::cout << "[ERROR] Failed to create suspended process" << std::endl;
        return NULL;
    }

    hProcess = lpProcessInformation->hProcess;
    std::cout << "[DEBUG] Successfully created process with handle " << hProcess << std::endl;
    return hProcess;
}

int main()
{
    std::cout << "[DEBUG] Program starting" << std::endl;

    // Path to the target process
    LPCWSTR lpApplicationName = L"C:\\Program Files (x86)\\Steam\\steamapps\\common\\Okami\\okami.exe.unpacked.exe";

    // Command line arguments for the target process
    WCHAR lpCommandLine[] = L"";

    // Startup information for the target process
    STARTUPINFO startupInfo;
    ZeroMemory(&startupInfo, sizeof(STARTUPINFO));
    startupInfo.cb = sizeof(STARTUPINFO);
    std::cout << "[DEBUG] Initialized startup info" << std::endl;

    // Process information for the target process
    PROCESS_INFORMATION processInfo;
    ZeroMemory(&processInfo, sizeof(PROCESS_INFORMATION));
    std::cout << "[DEBUG] Initialized process info" << std::endl;

    // Create the target process in suspended mode
    HANDLE hProcess = CreateSuspendedProcessW(lpApplicationName, lpCommandLine, &startupInfo, &processInfo);
    if (hProcess == NULL)
    {
        std::cout << "[ERROR] Process creation failed" << std::endl;
        MessageBoxW(NULL, L"Failed to create the target process", L"Error", MB_ICONERROR);
        return 1;
    }

    // Use HandleGuard to manage process and thread handles
    HandleGuard processGuard(processInfo.hProcess);
    HandleGuard threadGuard(processInfo.hThread);
    std::cout << "[DEBUG] Created HandleGuards for process and thread" << std::endl;

    // Path to the DLL to inject
    LPCWSTR lpLibFileName = L"C:\\WorkDir\\Okami\\perikiyoxd\\SuteiOpun\\x64\\Debug\\SuteiOpun.dll";

    // Inject the DLL into the target process
    if (!LoadLibraryOntoProcessW(hProcess, lpLibFileName))
    {
        std::cout << "[ERROR] DLL injection failed" << std::endl;
        MessageBoxW(NULL, L"Failed to inject the DLL into the target process", L"Error", MB_ICONERROR);
        return 1;
    }
    std::cout << "[DEBUG] DLL injection successful" << std::endl;

    // Resume the target process
    ResumeThread(processInfo.hThread);
    std::cout << "[DEBUG] Resumed target process thread" << std::endl;

    std::cout << "[DEBUG] Program completed successfully" << std::endl;
    // Handles will be automatically closed when HandleGuard goes out of scope
    return 0;
}