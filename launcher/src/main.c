
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"
#include "gui_launch.h"
#include "dll_include.h"
#include "../../common/shared.h"

int main(int argc, char *argv[]) {
    DPRINTF("Application starting.\n");
    if (argc == 2 && (strcmp(argv[1], "/?") == 0 || strcmp(argv[1], "--help") == 0)) {
        printf("A launcher that injects a helper DLL into a target executable to facilitate UTF-8 file access.\n\n");
        printf("Usage:\n");
        printf("  %s\n", argv[0]);
        printf("    (Opens a file dialog to select the target executable)\n\n");
        printf("  %s <path_to_exe> [args...]\n", argv[0]);
        printf("    (Launches the specified executable and injects the DLL)\n");
        return 0;
    }

    char targetPath[MAX_PATH] = {0};
    char *commandLine = NULL;

    if (argc < 2) {
        ShowWindow(GetConsoleWindow(), SW_HIDE);
        DPRINTF("No command line args, launching GUI.\n");
        if (!handleGuiLaunch(targetPath, MAX_PATH)) {
            DPRINTF("GUI launch cancelled by user.\n");
            return 0; // User cancelled
        }
        commandLine = targetPath;
    } else {
        // Use command line arguments
        commandLine = strstr(GetCommandLineA(), argv[1]);
    }
    DPRINTF("Final command line: \"%s\".\n", commandLine);

    if (commandLine == NULL) {
        fprintf(stderr, "Invalid command line.\n");
        return 1;
    }

    // 1. Create a temporary directory and extract DLLs
    char tempPath[MAX_PATH];
    char tempDir[MAX_PATH];
    char propagatorDllPath[MAX_PATH];

    DWORD pathLen = GetTempPath(MAX_PATH, tempPath);
    if (pathLen == 0 || pathLen > MAX_PATH) {
        fprintf(stderr, "Error getting temporary path.\n");
        return 1;
    }
    if (GetTempFileName(tempPath, "w32", 0, tempDir) == 0) {
        fprintf(stderr, "Error creating temporary file name.\n");
        return 1;
    }
    DeleteFile(tempDir); // GetTempFileName creates a file, we want a directory
    if (!CreateDirectory(tempDir, NULL)) {
        fprintf(stderr, "Error creating temporary directory.\n");
        return 1;
    }
    DPRINTF("Created temporary directory: %s\n", tempDir);

    sprintf(propagatorDllPath, "%s\\propagator.dll", tempDir);

    write_resource_to_file(propagatorDllPath, PROPAGATOR_START, PROPAGATOR_END);

    // 2. Create the target process in a suspended state
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessA(NULL, commandLine, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        fprintf(stderr, "CreateProcess failed (%d).\n", GetLastError());
        // Cleanup
        DeleteFile(propagatorDllPath);
        RemoveDirectory(tempDir);
        return 1;
    }
    DPRINTF("Created suspended process with PID: %lu.\n", pi.dwProcessId);

    // 3. Inject the propagator DLL
    LPVOID remoteMem = VirtualAllocEx(pi.hProcess, NULL, strlen(propagatorDllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (!remoteMem) {
        fprintf(stderr, "VirtualAllocEx failed (%d).\n", GetLastError());
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        // Cleanup files
        DeleteFile(propagatorDllPath);
        RemoveDirectory(tempDir);
        return 1;
    }
    DPRINTF("Allocated %zu bytes in remote process at address %p.\n", strlen(propagatorDllPath) + 1, remoteMem);

    if (!WriteProcessMemory(pi.hProcess, remoteMem, propagatorDllPath, strlen(propagatorDllPath) + 1, NULL)) {
        fprintf(stderr, "WriteProcessMemory failed (%d).\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        // Cleanup files
        DeleteFile(propagatorDllPath);
        RemoveDirectory(tempDir);
        return 1;
    }
    DPRINTF("Wrote propagator DLL path to remote memory.\n");

    HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, remoteMem, 0, NULL);
    if (!hThread) {
        fprintf(stderr, "CreateRemoteThread failed (%d).\n", GetLastError());
        VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        // Cleanup files
        DeleteFile(propagatorDllPath);
        RemoveDirectory(tempDir);
        return 1;
    }
    DPRINTF("Created remote thread (handle: %p) to load the DLL.\n", hThread);

    WaitForSingleObject(hThread, INFINITE);
    DPRINTF("Remote thread finished.\n");

    CloseHandle(hThread);
    VirtualFreeEx(pi.hProcess, remoteMem, 0, MEM_RELEASE);

    // 4. Resume the process
    ResumeThread(pi.hThread);
    DPRINTF("Process resumed.\n");

    // 5. Wait for the target process to exit and then clean up
    WaitForSingleObject(pi.hProcess, INFINITE);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    DeleteFile(propagatorDllPath);
    RemoveDirectory(tempDir);
    DPRINTF("Target process finished. Cleaning up and exiting.\n");

    return 0;
}
