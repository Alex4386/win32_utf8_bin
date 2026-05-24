#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include <wchar.h>
#include "../common/shared.h"

static BOOL full_path(const wchar_t *input, wchar_t *output, DWORD count) {
    DWORD len = GetFullPathNameW(input, count, output, NULL);
    return len > 0 && len < count;
}

static const wchar_t *base_name(const wchar_t *path) {
    const wchar_t *slash = wcsrchr(path, L'\\');
    const wchar_t *fslash = wcsrchr(path, L'/');
    const wchar_t *base = slash > fslash ? slash : fslash;
    return base ? base + 1 : path;
}

static void append_quoted(wchar_t *buffer, size_t count, const wchar_t *value) {
    size_t len = wcslen(buffer);
    if (len + wcslen(value) + 4 >= count) {
        return;
    }
    if (len > 0) {
        wcscat(buffer, L" ");
    }
    wcscat(buffer, L"\"");
    wcscat(buffer, value);
    wcscat(buffer, L"\"");
}

int main(void) {
    int argc = 0;
    wchar_t **argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    wchar_t propagator_path[MAX_PATH];
    wchar_t payload_path[MAX_PATH];
    wchar_t target_path[MAX_PATH];
    wchar_t command[2048] = {0};
    PROPAGATOR_CONFIG config;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    DWORD init_result;
    DWORD child_code = 1;
    int i;

    if (!argv || argc < 4) {
        fwprintf(stderr, L"usage: injection_driver <propagator.dll> <payload.dll> <target.exe> [target args...]\n");
        if (argv) {
            LocalFree(argv);
        }
        return 1;
    }

    if (!full_path(argv[1], propagator_path, MAX_PATH) ||
        !full_path(argv[2], payload_path, MAX_PATH) ||
        !full_path(argv[3], target_path, MAX_PATH)) {
        fwprintf(stderr, L"failed to resolve full paths\n");
        LocalFree(argv);
        return 1;
    }

    append_quoted(command, sizeof(command) / sizeof(command[0]), target_path);
    for (i = 4; i < argc; ++i) {
        append_quoted(command, sizeof(command) / sizeof(command[0]), argv[i]);
    }

    ZeroMemory(&config, sizeof(config));
    config.magic = PROPAGATOR_MAGIC;
    config.version = PROPAGATOR_VERSION;
    lstrcpynW(config.propagator_path, propagator_path, MAX_PATH);
    config.payload_count = 1;
    lstrcpynW(config.payloads[0].dll_path, payload_path, MAX_PATH);
    lstrcpynA(config.payloads[0].init_export, "PayloadMarkerInitialize", PROPAGATOR_INIT_EXPORT_LEN);

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessW(NULL, command, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        fwprintf(stderr, L"CreateProcessW failed: %lu\n", GetLastError());
        LocalFree(argv);
        return 1;
    }

    init_result = inject_and_initialize_propagator_w(pi.hProcess, propagator_path, &config);
    if (init_result != ERROR_SUCCESS) {
        fwprintf(stderr, L"inject_and_initialize_propagator_w failed: %lu\n", init_result);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        LocalFree(argv);
        return 1;
    }

    ResumeThread(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &child_code);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    wprintf(L"injection_driver payload=%ls exit=%lu\n", base_name(payload_path), child_code);

    LocalFree(argv);
    return (int)child_code;
}
