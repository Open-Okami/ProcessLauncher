# ProcessLauncher

## Overview
ProcessLauncher is a Windows-only application that starts a process in suspended mode and injects one or more DLLs into it. The application is configured via a `config.txt` file, allowing users to specify the target process, command-line arguments, and DLL paths. An optional debugger attachment prompt can be enabled before execution resumes.

## Building

### 1. Visual Studio 2022

1. Open `ProcessLauncher.sln` in Visual Studio 2022.
2. Build the solution in the desired configuration (e.g., `Release` or `Debug`).

### 2. Command Line (MSBuild)

1. Open a Visual Studio Developer Command Prompt.
2. Navigate to the `ProcessLauncher` directory.
3. Run the following command:
```sh
msbuild ProcessLauncher.sln /p:Configuration=Release
```

## Usage
### Configure `config.txt`

The `config.txt` file will be created automatically in the same directory as `ProcessLauncher.exe` the first time the application is run.

Usually you want to modify the `config.txt` file to specify the target application and DLLs to inject.

Edit `config.txt` to specify the target application and DLLs:
```plaintext
ApplicationName: C:\Path\To\Application.exe
CommandLine: 
AttachDebugger: false
DLLPath: C:\Path\To\DLL1.dll
DLLPath: C:\Path\To\DLL2.dll
```

### Run `ProcessLauncher.exe`

### Done!

## Configuration Options
- `ApplicationName`: Path to the target executable.
- `CommandLine`: Optional command-line arguments.
- `AttachDebugger`: `true` to show a debugger attachment prompt, `false` to disable it.
- `DLLPath`: DLLs to inject (can be multiple entries).

## License
MIT License.