#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include <string.h>
#include <wchar.h>

static int wait_child(PROCESS_INFORMATION *pi, BOOL resume_child) {
    DWORD code = 1;

    if (resume_child) {
        ResumeThread(pi->hThread);
    }
    WaitForSingleObject(pi->hProcess, INFINITE);
    GetExitCodeProcess(pi->hProcess, &code);
    CloseHandle(pi->hThread);
    CloseHandle(pi->hProcess);
    return (int)code;
}

static void make_probe_command(wchar_t *buffer, size_t count, const wchar_t *probe, const wchar_t *label, const wchar_t *expected_payload) {
    if (expected_payload && expected_payload[0]) {
        swprintf(buffer, count, L"\"%ls\" %ls \"%ls\"", probe, label, expected_payload);
    } else {
        swprintf(buffer, count, L"\"%ls\" %ls", probe, label);
    }
    buffer[count - 1] = L'\0';
}

static int launch_create_process_w(const wchar_t *probe, const wchar_t *label, const wchar_t *expected_payload, DWORD flags, BOOL resume_child) {
    wchar_t command[1024];
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;

    make_probe_command(command, sizeof(command) / sizeof(command[0]), probe, label, expected_payload);
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessW(NULL, command, NULL, NULL, FALSE, flags, NULL, NULL, &si, &pi)) {
        wprintf(L"CreateProcessW failed: %lu\n", GetLastError());
        return 1;
    }
    return wait_child(&pi, resume_child);
}

static int launch_create_process_a(const wchar_t *probe, const wchar_t *expected_payload) {
    wchar_t command_w[1024];
    char command[2048];
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;

    make_probe_command(command_w, sizeof(command_w) / sizeof(command_w[0]), probe, L"create_process_a", expected_payload);
    WideCharToMultiByte(CP_ACP, 0, command_w, -1, command, sizeof(command), NULL, NULL);

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
        printf("CreateProcessA failed: %lu\n", GetLastError());
        return 1;
    }
    return wait_child(&pi, FALSE);
}

static int launch_shell_execute_w(const wchar_t *probe, const wchar_t *expected_payload) {
    SHELLEXECUTEINFOW info;
    wchar_t parameters[512];
    DWORD code = 1;

    if (expected_payload && expected_payload[0]) {
        swprintf(parameters, sizeof(parameters) / sizeof(parameters[0]), L"shell_execute_w \"%ls\"", expected_payload);
    } else {
        swprintf(parameters, sizeof(parameters) / sizeof(parameters[0]), L"shell_execute_w");
    }
    parameters[(sizeof(parameters) / sizeof(parameters[0])) - 1] = L'\0';

    ZeroMemory(&info, sizeof(info));
    info.cbSize = sizeof(info);
    info.fMask = SEE_MASK_NOCLOSEPROCESS;
    info.lpFile = probe;
    info.lpParameters = parameters;
    info.nShow = SW_SHOWNORMAL;

    if (!ShellExecuteExW(&info)) {
        wprintf(L"ShellExecuteExW failed: %lu\n", GetLastError());
        return 1;
    }
    WaitForSingleObject(info.hProcess, INFINITE);
    GetExitCodeProcess(info.hProcess, &code);
    CloseHandle(info.hProcess);
    return (int)code;
}

int main(void) {
    int argc = 0;
    wchar_t **argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    const wchar_t *mode;
    const wchar_t *probe;
    const wchar_t *expected_payload;

    if (!argv || argc < 3) {
        wprintf(L"usage: process_parent <mode> <probe.exe>\n");
        if (argv) {
            LocalFree(argv);
        }
        return 1;
    }

    mode = argv[1];
    probe = argv[2];
    expected_payload = argc > 3 ? argv[3] : NULL;

    if (lstrcmpW(mode, L"a") == 0) {
        int result = launch_create_process_a(probe, expected_payload);
        LocalFree(argv);
        return result;
    }
    if (lstrcmpW(mode, L"w") == 0) {
        int result = launch_create_process_w(probe, L"create_process_w", expected_payload, 0, FALSE);
        LocalFree(argv);
        return result;
    }
    if (lstrcmpW(mode, L"suspended") == 0) {
        int result = launch_create_process_w(probe, L"create_process_suspended", expected_payload, CREATE_SUSPENDED, TRUE);
        LocalFree(argv);
        return result;
    }
    if (lstrcmpW(mode, L"shell") == 0) {
        int result = launch_shell_execute_w(probe, expected_payload);
        LocalFree(argv);
        return result;
    }
    if (lstrcmpW(mode, L"nested") == 0) {
        wchar_t nested_command[1024];
        STARTUPINFOW si;
        PROCESS_INFORMATION pi;

        if (expected_payload && expected_payload[0]) {
            swprintf(nested_command, sizeof(nested_command) / sizeof(nested_command[0]),
                     L"\"%ls\" w \"%ls\" \"%ls\"", argv[0], probe, expected_payload);
        } else {
            swprintf(nested_command, sizeof(nested_command) / sizeof(nested_command[0]),
                     L"\"%ls\" w \"%ls\"", argv[0], probe);
        }
        nested_command[(sizeof(nested_command) / sizeof(nested_command[0])) - 1] = L'\0';

        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        ZeroMemory(&pi, sizeof(pi));
        if (!CreateProcessW(NULL, nested_command, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            wprintf(L"nested CreateProcessW failed: %lu\n", GetLastError());
            LocalFree(argv);
            return 1;
        }
        {
            int result = wait_child(&pi, FALSE);
            LocalFree(argv);
            return result;
        }
    }

    wprintf(L"unknown mode: %ls\n", mode);
    LocalFree(argv);
    return 1;
}
