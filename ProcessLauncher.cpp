#include "HandleGuard.hpp"
#include <iostream>
#include <vector>
#include <string>
#include <fstream>
#include <filesystem>
#include <string_view>

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

// Function to print error messages
void PrintError(const std::string &message)
{
    std::cout << "[ERROR] " << message << std::endl;
}

// Process-related functions
namespace ProcessUtils
{
    HANDLE CreateSuspendedProcessW(std::string_view lpApplicationName,
                                   std::string_view lpCommandLine,
                                   LPSTARTUPINFOA lpStartupInfo,
                                   LPPROCESS_INFORMATION lpProcessInformation)
    {
        std::string workingDirectory = std::filesystem::path(lpApplicationName).parent_path().string();

        std::cout << "[DEBUG] Creating suspended process: " << lpApplicationName << "\n";
        std::cout << "[DEBUG] Command line: " << lpCommandLine << "\n";
        std::cout << "[DEBUG] Working directory: " << workingDirectory << "\n";

        system("pause");

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
            lpProcessInformation);

        if (!result)
        {
            DWORD err = GetLastError();
            PrintError("Failed to create suspended process: " + std::to_string(err));
            return NULL;
        }

        return lpProcessInformation->hProcess;
    }

    bool ResumeProcess(HANDLE hThread)
    {
        DWORD result = ResumeThread(hThread);
        if (result == -1)
        {
            DWORD err = GetLastError();
            PrintError("Failed to resume process thread: " + std::to_string(err));
            return false;
        }
        return true;
    }
}

// DLL injection-related functions
namespace InjectionUtils
{
    struct InjectionContext
    {
        LPVOID pDllPath = nullptr;
        HANDLE hThread = nullptr;
    };

    FARPROC GetLoadLibraryAddress()
    {
        HMODULE hKernel32 = GetModuleHandleW(L"kernel32.dll");
        if (!hKernel32)
        {
            DWORD err = GetLastError();
            PrintError("Failed to get handle to kernel32.dll: " + std::to_string(err));
            return nullptr;
        }

        FARPROC pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
        if (!pLoadLibraryA)
        {
            DWORD err = GetLastError();
            PrintError("Failed to get address of LoadLibraryA: " + std::to_string(err));
            return nullptr;
        }

        return pLoadLibraryA;
    }

    BOOL InjectDLL(HANDLE hProcess,
                   std::string_view lpLibFileName,
                   FARPROC pLoadLibraryA)
    {
        SIZE_T memorySize = lpLibFileName.size() + 1;

        // Allocate memory for DLL path
        InjectionContext context;
        LPVOID allocatedMemoryAddress = VirtualAllocEx(hProcess,
                                                       NULL,
                                                       memorySize,
                                                       MEM_COMMIT | MEM_RESERVE,
                                                       PAGE_READWRITE);

        if (!allocatedMemoryAddress)
        {
            DWORD err = GetLastError();
            PrintError("Failed to allocate memory in remote process: " + std::to_string(err));
            return FALSE;
        }

        auto deallocateMemory = [&context, hProcess]()
        {
            if (context.pDllPath)
            {
                VirtualFreeEx(hProcess, context.pDllPath, 0, MEM_RELEASE);
            }
        };

        context.pDllPath = allocatedMemoryAddress;

        BOOL writeProcessMemoryResult = WriteProcessMemory(hProcess,
                                                           context.pDllPath,
                                                           lpLibFileName.data(),
                                                           lpLibFileName.size() + 1,
                                                           NULL);

        // Write DLL path
        if (!writeProcessMemoryResult)
        {
            PrintError("Failed to write DLL path to remote process");
            deallocateMemory();
            return FALSE;
        }

        // Create remote thread
        context.hThread = CreateRemoteThread(hProcess, NULL, 0,
                                             (LPTHREAD_START_ROUTINE)pLoadLibraryA,
                                             context.pDllPath, 0, NULL);
        if (!context.hThread)
        {
            PrintError("Failed to create remote thread");
            deallocateMemory();
            return FALSE;
        }

        // Manage thread and wait
        HandleGuard threadGuard(context.hThread);
        WaitForSingleObject(context.hThread, INFINITE);

        // Check exit code
        DWORD dwExitCode;
        GetExitCodeThread(context.hThread, &dwExitCode);

        // Clean up
        deallocateMemory();

        return TRUE;
    }

    bool InjectMultipleDLLs(HANDLE hProcess,
                            const std::vector<std::string> &dllPaths)
    {
        FARPROC pLoadLibraryA = GetLoadLibraryAddress();
        if (!pLoadLibraryA)
        {
            return false;
        }

        bool allSuccessful = true;
        for (const auto &dllPath : dllPaths)
        {
            if (!InjectDLL(hProcess, dllPath, pLoadLibraryA))
            {
                PrintError("Failed to inject DLL: " + dllPath);
                allSuccessful = false;
            }
        }
        return allSuccessful;
    }
}

struct ConfigData
{
    std::string applicationName;
    std::string commandLine;
    std::vector<std::string> dllPaths;
    bool attachDebugger = false;
};

void CreateDefaultConfig(const std::string &configPath)
{
    std::cout << "[DEBUG] Creating default configuration file: " << configPath << std::endl;

    std::ofstream configFile(configPath);
    if (!configFile.is_open())
    {
        PrintError("Failed to create configuration file");
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

void LoadConfig(const std::string &configPath,
                ConfigData *configData)
{
    std::cout << "[DEBUG] Loading configuration file: " << configPath << std::endl;

    std::ifstream configFile(configPath);
    if (!configFile.is_open())
    {
        PrintError("Failed to open configuration file");
        CreateDefaultConfig(configPath);
        return;
    }

    std::string line;
    while (std::getline(configFile, line))
    {
        // Trim whitespace from the beginning and end of the line
        line.erase(0, line.find_first_not_of(" \t\n\r"));
        line.erase(line.find_last_not_of(" \t\n\r") + 1);

        if (line.empty() || line[0] == ';')
        {
            continue;
        }

        size_t delimiterPos = line.find(':');
        if (delimiterPos == std::string::npos)
        {
            continue;
        }

        std::string key = line.substr(0, delimiterPos);
        std::string value = line.substr(delimiterPos + 1);

        // Trim whitespace from the beginning and end of the key and value
        key.erase(0, key.find_first_not_of(" \t\n\r"));
        key.erase(key.find_last_not_of(" \t\n\r") + 1);
        value.erase(0, value.find_first_not_of(" \t\n\r"));
        value.erase(value.find_last_not_of(" \t\n\r") + 1);

        if (key == "ApplicationName")
        {
            configData->applicationName = std::string(value.begin(), value.end());
        }
        else if (key == "CommandLine")
        {
            configData->commandLine = std::string(value.begin(), value.end());
        }
        else if (key == "DLLPath")
        {
            std::filesystem::path dllPath(value);
            if (dllPath.is_absolute())
            {
                configData->dllPaths.push_back(std::string(value.begin(), value.end()));
            }
            else
            {
                PrintError("Invalid DLL path: " + value);
            }
        }
        else if (key == "AttachDebugger")
        {
            configData->attachDebugger = value == "true";
        }
        else
        {
            PrintError("Unknown key: " + key);
        }
    }

    configFile.close();

    // Validate paths, we don't want to inject invalid DLLs or create invalid processes
    if (configData->applicationName.empty() || !std::filesystem::exists(configData->applicationName))
    {
        PrintError("Invalid ApplicationName: " + configData->applicationName);
    }

    if (!configData->dllPaths.empty())
    {
        for (const auto &dllPath : configData->dllPaths)
        {
            if (!std::filesystem::exists(dllPath))
            {
                PrintError("Invalid DLLPath: " + dllPath);
            }
        }
    }
}

void PrintConfig(const ConfigData &configData)
{
    std::cout << "[DEBUG] Configuration data:" << std::endl;
    std::cout << "ApplicationName: " << configData.applicationName << std::endl;
    std::cout << "CommandLine: " << configData.commandLine << std::endl;
    std::cout << "AttachDebugger: " << (configData.attachDebugger ? "true" : "false") << std::endl;
    std::cout << "DLLPaths:" << std::endl;
    for (const auto &dllPath : configData.dllPaths)
    {
        std::cout << "  " << dllPath << std::endl;
    }
}

int main()
{
    std::cout << "[DEBUG] Program starting" << std::endl;

    const std::string configPath = "config.txt";
    ConfigData configData;

    // Load configuration file
    LoadConfig(configPath, &configData);

    // Print configuration data
    PrintConfig(configData);

    STARTUPINFOA startupInfo{};
    startupInfo.cb = sizeof(STARTUPINFOA);

    PROCESS_INFORMATION processInfo{};

    // Create suspended process
    HANDLE hProcess = ProcessUtils::CreateSuspendedProcessW(
        configData.applicationName,
        configData.commandLine,
        &startupInfo,
        &processInfo);

    if (!hProcess)
    {
        PrintError("Process creation failed");
        MessageBoxW(NULL, L"Failed to create the target process", L"Error", MB_ICONERROR);
        return 1;
    }

    // Manage handles
    HandleGuard processGuard(processInfo.hProcess);
    HandleGuard threadGuard(processInfo.hThread);

    // Inject multiple DLLs
    if (!InjectionUtils::InjectMultipleDLLs(hProcess, configData.dllPaths))
    {
        PrintError("One or more DLL injections failed");
        MessageBoxW(NULL, L"Failed to inject one or more DLLs", L"Error", MB_ICONERROR);
        return 1;
    }

    // Attach debugger
    if (configData.attachDebugger)
    {
        MessageBoxW(NULL, L"Attach debugger now", L"Debugger", MB_ICONINFORMATION);
    }

    // Resume process
    if (!ProcessUtils::ResumeProcess(processInfo.hThread))
    {
        PrintError("Failed to resume process");
        return 1;
    }

    std::cout << "[DEBUG] Program completed successfully" << std::endl;
    return 0;
}