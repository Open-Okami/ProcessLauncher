#include "HandleGuard.hpp"
#include <iostream>
#include <vector>
#include <string>

// Process-related functions
namespace ProcessUtils {
    HANDLE CreateSuspendedProcessW(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, 
                                 LPSTARTUPINFO lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {
        std::cout << "[DEBUG] Attempting to create suspended process: " << lpApplicationName << std::endl;

        if (!CreateProcessW(lpApplicationName, lpCommandLine, NULL, NULL, FALSE, 
                          CREATE_SUSPENDED, NULL, NULL, lpStartupInfo, lpProcessInformation)) {
            std::cout << "[ERROR] Failed to create suspended process" << std::endl;
            return NULL;
        }

        std::cout << "[DEBUG] Successfully created process with handle " 
                  << lpProcessInformation->hProcess << std::endl;
        return lpProcessInformation->hProcess;
    }

    bool ResumeProcess(HANDLE hThread) {
        std::cout << "[DEBUG] Attempting to resume process thread" << std::endl;
        DWORD result = ResumeThread(hThread);
        if (result == -1) {
            std::cout << "[ERROR] Failed to resume process thread" << std::endl;
            return false;
        }
        std::cout << "[DEBUG] Successfully resumed process thread" << std::endl;
        return true;
    }
}

// DLL injection-related functions
namespace InjectionUtils {
    struct InjectionContext {
        LPVOID pDllPath = nullptr;
        HANDLE hThread = nullptr;
        
        ~InjectionContext() {
            if (pDllPath) {
                std::cout << "[DEBUG] InjectionContext destructor called" << std::endl;
            }
        }
    };

    FARPROC GetLoadLibraryAddress() {
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        if (!hKernel32) {
            std::cout << "[ERROR] Failed to get handle to kernel32.dll" << std::endl;
            return nullptr;
        }
        std::cout << "[DEBUG] Successfully got kernel32.dll handle" << std::endl;

        FARPROC pLoadLibraryW = GetProcAddress(hKernel32, "LoadLibraryW");
        if (!pLoadLibraryW) {
            std::cout << "[ERROR] Failed to get LoadLibraryW address" << std::endl;
            return nullptr;
        }
        std::cout << "[DEBUG] Successfully got LoadLibraryW address" << std::endl;
        
        return pLoadLibraryW;
    }

    BOOL InjectDLL(HANDLE hProcess, LPCWSTR lpLibFileName, FARPROC pLoadLibraryW) {
        std::cout << "[DEBUG] Attempting to inject DLL: " << lpLibFileName << std::endl;

        // Allocate memory for DLL path
        InjectionContext context;
        context.pDllPath = VirtualAllocEx(hProcess, NULL, 
                                        (wcslen(lpLibFileName) + 1) * sizeof(WCHAR), 
                                        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!context.pDllPath) {
            std::cout << "[ERROR] Failed to allocate memory in remote process" << std::endl;
            return FALSE;
        }
        std::cout << "[DEBUG] Successfully allocated memory at " << context.pDllPath << std::endl;

        // Write DLL path
        if (!WriteProcessMemory(hProcess, context.pDllPath, lpLibFileName, 
                              (wcslen(lpLibFileName) + 1) * sizeof(WCHAR), NULL)) {
            std::cout << "[ERROR] Failed to write DLL path to remote process" << std::endl;
            VirtualFreeEx(hProcess, context.pDllPath, 0, MEM_RELEASE);
            return FALSE;
        }
        std::cout << "[DEBUG] Successfully wrote DLL path to remote process" << std::endl;

        // Create remote thread
        context.hThread = CreateRemoteThread(hProcess, NULL, 0, 
                                           (LPTHREAD_START_ROUTINE)pLoadLibraryW, 
                                           context.pDllPath, 0, NULL);
        if (!context.hThread) {
            std::cout << "[ERROR] Failed to create remote thread" << std::endl;
            VirtualFreeEx(hProcess, context.pDllPath, 0, MEM_RELEASE);
            return FALSE;
        }
        std::cout << "[DEBUG] Successfully created remote thread with handle " 
                  << context.hThread << std::endl;

        // Manage thread and wait
        HandleGuard threadGuard(context.hThread);
        std::cout << "[DEBUG] Waiting for remote thread to complete" << std::endl;
        WaitForSingleObject(context.hThread, INFINITE);

        // Check exit code
        DWORD dwExitCode;
        GetExitCodeThread(context.hThread, &dwExitCode);
        std::cout << "[DEBUG] Remote thread completed with exit code " << dwExitCode << std::endl;

        // Clean up
        VirtualFreeEx(hProcess, context.pDllPath, 0, MEM_RELEASE);
        std::cout << "[DEBUG] Cleaned up allocated memory" << std::endl;
        
        return TRUE;
    }

    bool InjectMultipleDLLs(HANDLE hProcess, const std::vector<std::wstring>& dllPaths) {
        FARPROC pLoadLibraryW = GetLoadLibraryAddress();
        if (!pLoadLibraryW) {
            return false;
        }

        bool allSuccessful = true;
        for (const auto& dllPath : dllPaths) {
            if (!InjectDLL(hProcess, dllPath.c_str(), pLoadLibraryW)) {
                std::cout << "[ERROR] Failed to inject DLL: " << dllPath.c_str() << std::endl;
                allSuccessful = false;
            } else {
                std::cout << "[DEBUG] Successfully injected DLL: " << dllPath.c_str() << std::endl;
            }
        }
        return allSuccessful;
    }
}

int main() {
    std::cout << "[DEBUG] Program starting" << std::endl;

    // Process configuration
    const LPCWSTR lpApplicationName = L"C:\\Program Files (x86)\\Steam\\steamapps\\common\\Okami\\okami.exe.unpacked.exe";
    WCHAR lpCommandLine[] = L"";
    
    STARTUPINFO startupInfo{};
    startupInfo.cb = sizeof(STARTUPINFO);
    std::cout << "[DEBUG] Initialized startup info" << std::endl;

    PROCESS_INFORMATION processInfo{};
    std::cout << "[DEBUG] Initialized process info" << std::endl;

    // Create suspended process
    HANDLE hProcess = ProcessUtils::CreateSuspendedProcessW(lpApplicationName, lpCommandLine, 
                                                          &startupInfo, &processInfo);
    if (!hProcess) {
        std::cout << "[ERROR] Process creation failed" << std::endl;
        MessageBoxW(NULL, L"Failed to create the target process", L"Error", MB_ICONERROR);
        return 1;
    }

    // Manage handles
    HandleGuard processGuard(processInfo.hProcess);
    HandleGuard threadGuard(processInfo.hThread);
    std::cout << "[DEBUG] Created HandleGuards for process and thread" << std::endl;

    // DLLs to inject
    std::vector<std::wstring> dllPaths = {
        L"C:\\WorkDir\\Okami\\perikiyoxd\\SuteiOpun\\x64\\Debug\\SuteiOpun.dll"
        // Add more DLL paths as needed
    };

    // Inject multiple DLLs
    if (!InjectionUtils::InjectMultipleDLLs(hProcess, dllPaths)) {
        std::cout << "[ERROR] One or more DLL injections failed" << std::endl;
        MessageBoxW(NULL, L"Failed to inject one or more DLLs", L"Error", MB_ICONERROR);
        return 1;
    }
        
	// Attach debugger messagebox
	MessageBoxW(NULL, L"Attach debugger now", L"Debug", MB_ICONINFORMATION);


    // Resume process
    if (!ProcessUtils::ResumeProcess(processInfo.hThread)) {
        std::cout << "[ERROR] Failed to resume process" << std::endl;
        return 1;
    }

    std::cout << "[DEBUG] Program completed successfully" << std::endl;
    return 0;
}