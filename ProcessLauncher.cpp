#include "HandleGuard.hpp"
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <sstream>
#include <filesystem>
#include <windows.h>

// Process-related functions
namespace ProcessUtils {
    HANDLE CreateSuspendedProcessW(std::string_view lpApplicationName, std::string_view lpCommandLine, 
                                 LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation) {
        std::cout << "[DEBUG] Attempting to create suspended process: " << lpApplicationName << std::endl;

		std::string workingDirectory = std::filesystem::path(lpApplicationName).parent_path().string();
		std::cout << "[DEBUG] Working directory: " << workingDirectory << std::endl;

        BOOL result = CreateProcessA(
            lpApplicationName.data(),
            (LPSTR)lpCommandLine.data(),
            NULL,
            NULL,
            FALSE,
            CREATE_SUSPENDED,
            NULL,
            workingDirectory.c_str(),
            lpStartupInfo,
            lpProcessInformation
        );
        
        if (!result) {
          std::cout << "[ERROR] Failed to create suspended process"
                    << std::endl;
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

        FARPROC pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
        if (!pLoadLibraryA) {
            std::cout << "[ERROR] Failed to get LoadLibraryA address" << std::endl;
            return nullptr;
        }
        std::cout << "[DEBUG] Successfully got LoadLibraryA address" << std::endl;
        
        return pLoadLibraryA;
    }

    BOOL InjectDLL(HANDLE hProcess, std::string_view lpLibFileName, FARPROC pLoadLibraryA) {
        std::cout << "[DEBUG] Attempting to inject DLL: " << lpLibFileName << std::endl;

        SIZE_T memorySize = lpLibFileName.size() + 1;

        // Allocate memory for DLL path
        InjectionContext context;
        LPVOID allocatedMemoryPointer = VirtualAllocEx(hProcess,
                                                       NULL,
                                                       memorySize,
                                                       MEM_COMMIT | MEM_RESERVE,
                                                       PAGE_READWRITE);

        auto deallocateMemory = [&context, hProcess]() {
            if (context.pDllPath) {
                VirtualFreeEx(hProcess, context.pDllPath, 0, MEM_RELEASE);
                std::cout << "[DEBUG] Cleaned up allocated memory" << std::endl;
            }
        };

        if (!allocatedMemoryPointer) {
            std::cout << "[ERROR] Failed to allocate memory in remote process" << std::endl;
            return FALSE;
        }

        std::cout << "[DEBUG] Successfully allocated memory at " << context.pDllPath << std::endl;
        context.pDllPath = allocatedMemoryPointer;
                
        BOOL writeProcessMemoryResult = WriteProcessMemory(hProcess,
                                                            context.pDllPath,
                                                            lpLibFileName.data(),
                                                            lpLibFileName.size() + 1,
                                                            NULL);

        // Write DLL path
        if (!writeProcessMemoryResult) {
            std::cout << "[ERROR] Failed to write DLL path to remote process" << std::endl;
            deallocateMemory();
            return FALSE;
        }
        std::cout << "[DEBUG] Successfully wrote DLL path to remote process" << std::endl;

        // Create remote thread
        context.hThread = CreateRemoteThread(hProcess, NULL, 0, 
                                           (LPTHREAD_START_ROUTINE)pLoadLibraryA, 
                                           context.pDllPath, 0, NULL);
        if (!context.hThread) {
            std::cout << "[ERROR] Failed to create remote thread" << std::endl;
            deallocateMemory();
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
        deallocateMemory();
        
        return TRUE;
    }

    bool InjectMultipleDLLs(HANDLE hProcess, const std::vector<std::string>& dllPaths) {
        FARPROC pLoadLibraryA = GetLoadLibraryAddress();
        if (!pLoadLibraryA) {
            return false;
        }

        bool allSuccessful = true;
        for (const auto& dllPath : dllPaths) {
            if (!InjectDLL(hProcess, dllPath, pLoadLibraryA)) {
                std::cout << "[ERROR] Failed to inject DLL: " << dllPath.c_str() << std::endl;
                allSuccessful = false;
            } else {
                std::cout << "[DEBUG] Successfully injected DLL: " << dllPath.c_str() << std::endl;
            }
        }
        return allSuccessful;
    }
}

struct ConfigData {
    std::string applicationName;
    std::string commandLine;
    std::vector<std::string> dllPaths;
    bool attachDebugger = false;
};

void CreateDefaultConfig(const std::string& configPath) {
    std::cout << "[DEBUG] Creating default configuration file: " << configPath << std::endl;
    
    std::ofstream configFile(configPath);
    if (!configFile.is_open()) {
        std::cout << "[ERROR] Failed to create configuration file" << std::endl;
        return;
    }

    configFile << "; Configuration file for DLL injector" << std::endl;
    configFile << "; ------ Configuration Options ------" << std::endl;
    configFile << "; ApplicationName: Path to the target application" << std::endl;
    configFile << "; CommandLine: Command line arguments for the target application" << std::endl;
    configFile << "; AttachDebugger: Set to true to show a message box so you can attach a debugger" << std::endl;
    configFile << "; DLLPath: Path to the DLL to inject. Add more lines for multiple DLLs" << std::endl;
    configFile << "; -----------------------------------" << std::endl;
    configFile << std::endl;
    configFile << "ApplicationName: C:\\Program Files (x86)\\Steam\\steamapps\\common\\Okami\\okami.exe.unpacked.exe" << std::endl;
    configFile << "CommandLine: " << std::endl;
    configFile << "AttachDebugger: false" << std::endl;
    configFile << "; DLLPath: C:\\Example\\DLL.dll" << std::endl;
    configFile << "; DLLPath: C:\\Example\\DLL2.dll" << std::endl;
    
    configFile.close();
}

void LoadConfig(const std::string& configPath, ConfigData* configData) {
    std::cout << "[DEBUG] Loading configuration file: " << configPath << std::endl;

    std::ifstream configFile(configPath);
    if (!configFile.is_open()) {
        std::cout << "[ERROR] Failed to open configuration file" << std::endl;
        CreateDefaultConfig(configPath);
        return;
    }

    std::string line;
    while (std::getline(configFile, line)) {
        // Trim whitespace from the beginning and end of the line
        line.erase(0, line.find_first_not_of(" \t\n\r"));
        line.erase(line.find_last_not_of(" \t\n\r") + 1);

        if (line.empty() || line[0] == ';') {
            continue;
        }

        size_t delimiterPos = line.find(':');
        if (delimiterPos == std::string::npos) {
            continue;
        }

        std::string key = line.substr(0, delimiterPos);
        std::string value = line.substr(delimiterPos + 1);

        // Trim whitespace from the beginning and end of the key and value
        key.erase(0, key.find_first_not_of(" \t\n\r"));
        key.erase(key.find_last_not_of(" \t\n\r") + 1);
        value.erase(0, value.find_first_not_of(" \t\n\r"));
        value.erase(value.find_last_not_of(" \t\n\r") + 1);

        if (key == "ApplicationName") {
            configData->applicationName = std::string(value.begin(), value.end());
        } else if (key == "CommandLine") {
            configData->commandLine = std::string(value.begin(), value.end());
        } else if (key == "DLLPath") {
            std::filesystem::path dllPath(value);
            if (dllPath.is_absolute()) {
                std::cout << "[DEBUG] Adding DLL path: " << value << std::endl;
                configData->dllPaths.push_back(std::string(value.begin(), value.end()));
            } else {
                std::cout << "[ERROR] Invalid DLL path: " << value << std::endl;
            }
        } else if (key == "AttachDebugger") {
            configData->attachDebugger = value == "true";
        } else {
            std::cout << "[ERROR] Unknown key: " << key << std::endl;
        }
    }
    
    configFile.close();
}

void PrintConfig(const ConfigData& configData) {
    std::cout << "[DEBUG] Configuration data:" << std::endl;
    std::cout << "ApplicationName: " << configData.applicationName << std::endl;
    std::cout << "CommandLine: " << configData.commandLine << std::endl;
    std::cout << "AttachDebugger: " << (configData.attachDebugger ? "true" : "false") << std::endl;
    std::cout << "DLLPaths:" << std::endl;
    for (const auto& dllPath : configData.dllPaths) {
        std::cout << "  " << dllPath << std::endl;
    }
}

int main() {
    std::cout << "[DEBUG] Program starting" << std::endl;

    const std::string configPath = "config.txt";
    ConfigData configData;

    // Load configuration file
    LoadConfig(configPath, &configData);

    // Print configuration data
    PrintConfig(configData);

    STARTUPINFOA startupInfo{};
    startupInfo.cb = sizeof(STARTUPINFOA);
    std::cout << "[DEBUG] Initialized startup info" << std::endl;

    PROCESS_INFORMATION processInfo{};
    std::cout << "[DEBUG] Initialized process info" << std::endl;

    // Create suspended process
    HANDLE hProcess = ProcessUtils::CreateSuspendedProcessW(
        configData.applicationName, 
        configData.commandLine,
        &startupInfo,
        &processInfo);
    
    if (!hProcess) {
        std::cout << "[ERROR] Process creation failed" << std::endl;
        MessageBoxW(NULL, L"Failed to create the target process", L"Error", MB_ICONERROR);
        return 1;
    }

    // Manage handles
    HandleGuard processGuard(processInfo.hProcess);
    HandleGuard threadGuard(processInfo.hThread);
    std::cout << "[DEBUG] Created HandleGuards for process and thread" << std::endl;

    // Inject multiple DLLs
    if (!InjectionUtils::InjectMultipleDLLs(hProcess, configData.dllPaths)) {
        std::cout << "[ERROR] One or more DLL injections failed" << std::endl;
        MessageBoxW(NULL, L"Failed to inject one or more DLLs", L"Error", MB_ICONERROR);
        return 1;
    }
        
	// Attach debugger
    if (configData.attachDebugger) {
        MessageBoxW(NULL, L"Attach debugger now", L"Debugger", MB_ICONINFORMATION);
    }

    // Resume process
    if (!ProcessUtils::ResumeProcess(processInfo.hThread)) {
        std::cout << "[ERROR] Failed to resume process" << std::endl;
        return 1;
    }

    std::cout << "[DEBUG] Program completed successfully" << std::endl;
    return 0;
}