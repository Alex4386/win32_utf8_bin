#include <windows.h>
#include <shellapi.h>
#include <shlwapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <wchar.h>
#include "config.h"
#include "gui_launch.h"
#include "dll_include.h"
#include "../../common/shared.h"

static int append_chars(wchar_t **buffer, size_t *len, size_t *cap, const wchar_t *text, size_t text_len) {
    wchar_t *grown;

    if (*len + text_len + 1 > *cap) {
        size_t next_cap = *cap ? *cap : 64;
        while (*len + text_len + 1 > next_cap) {
            next_cap *= 2;
        }
        grown = (wchar_t*)realloc(*buffer, next_cap * sizeof(wchar_t));
        if (!grown) {
            return 0;
        }
        *buffer = grown;
        *cap = next_cap;
    }

    memcpy(*buffer + *len, text, text_len * sizeof(wchar_t));
    *len += text_len;
    (*buffer)[*len] = L'\0';
    return 1;
}

static int append_repeated_char(wchar_t **buffer, size_t *len, size_t *cap, wchar_t ch, size_t count) {
    while (count--) {
        if (!append_chars(buffer, len, cap, &ch, 1)) {
            return 0;
        }
    }
    return 1;
}

static int append_quoted_arg(wchar_t **buffer, size_t *len, size_t *cap, const wchar_t *arg) {
    size_t i;
    size_t slash_count = 0;
    int needs_quote = (arg[0] == L'\0') || wcspbrk(arg, L" \t\"") != NULL;
    const wchar_t quote = L'"';
    const wchar_t backslash = L'\\';

    if (!needs_quote) {
        return append_chars(buffer, len, cap, arg, wcslen(arg));
    }

    if (!append_chars(buffer, len, cap, &quote, 1)) {
        return 0;
    }

    for (i = 0; arg[i]; ++i) {
        if (arg[i] == L'\\') {
            ++slash_count;
            continue;
        }
        if (arg[i] == L'"') {
            if (!append_repeated_char(buffer, len, cap, backslash, slash_count * 2 + 1) ||
                !append_chars(buffer, len, cap, &quote, 1)) {
                return 0;
            }
            slash_count = 0;
            continue;
        }
        if (slash_count) {
            if (!append_repeated_char(buffer, len, cap, backslash, slash_count)) {
                return 0;
            }
            slash_count = 0;
        }
        if (!append_chars(buffer, len, cap, arg + i, 1)) {
            return 0;
        }
    }

    if (!append_repeated_char(buffer, len, cap, backslash, slash_count * 2) ||
        !append_chars(buffer, len, cap, &quote, 1)) {
        return 0;
    }
    return 1;
}

static wchar_t* command_line_from_argv(LPWSTR *argv, int start, int argc) {
    wchar_t *command = NULL;
    size_t len = 0;
    size_t cap = 0;
    int i;

    for (i = start; i < argc; ++i) {
        const wchar_t space = L' ';
        if (i > start && !append_chars(&command, &len, &cap, &space, 1)) {
            free(command);
            return NULL;
        }
        if (!append_quoted_arg(&command, &len, &cap, argv[i])) {
            free(command);
            return NULL;
        }
    }
    return command;
}

static wchar_t* command_line_from_gui_options(const GUI_LAUNCH_OPTIONS *options) {
    wchar_t *command = NULL;
    size_t len = 0;
    size_t cap = 0;

    if (!append_quoted_arg(&command, &len, &cap, options->target_path)) {
        free(command);
        return NULL;
    }

    if (options->use_arguments && options->arguments[0]) {
        const wchar_t space = L' ';
        if (!append_chars(&command, &len, &cap, &space, 1) ||
            !append_chars(&command, &len, &cap, options->arguments, wcslen(options->arguments))) {
            free(command);
            return NULL;
        }
    }
    return command;
}

static int append_option_with_value(wchar_t **buffer, size_t *len, size_t *cap,
                                    const wchar_t *option, const wchar_t *value) {
    const wchar_t space = L' ';

    if (*len && !append_chars(buffer, len, cap, &space, 1)) {
        return 0;
    }
    if (!append_chars(buffer, len, cap, option, wcslen(option)) ||
        !append_chars(buffer, len, cap, &space, 1) ||
        !append_quoted_arg(buffer, len, cap, value)) {
        return 0;
    }
    return 1;
}

static wchar_t* elevated_parameters_from_gui_options(const GUI_LAUNCH_OPTIONS *options) {
    wchar_t *params = NULL;
    size_t len = 0;
    size_t cap = 0;
    wchar_t codepage[32];
    const wchar_t separator[] = L" -- ";

    wsprintfW(codepage, L"%lu", options->fallback_codepage);
    if (!append_option_with_value(&params, &len, &cap, L"--codepage", codepage)) {
        free(params);
        return NULL;
    }

    if (options->use_current_directory) {
        if (!append_option_with_value(&params, &len, &cap, L"--cwd", options->current_directory)) {
            free(params);
            return NULL;
        }
    }

    if (!append_chars(&params, &len, &cap, separator, wcslen(separator)) ||
        !append_quoted_arg(&params, &len, &cap, options->target_path)) {
        free(params);
        return NULL;
    }

    if (options->use_arguments && options->arguments[0]) {
        const wchar_t space = L' ';
        if (!append_chars(&params, &len, &cap, &space, 1) ||
            !append_chars(&params, &len, &cap, options->arguments, wcslen(options->arguments))) {
            free(params);
            return NULL;
        }
    }
    return params;
}

static BOOL relaunch_elevated_from_gui_options(const GUI_LAUNCH_OPTIONS *options) {
    wchar_t self_path[MAX_PATH];
    wchar_t inherited_directory[MAX_PATH];
    wchar_t *params;
    SHELLEXECUTEINFOW sei;
    BOOL ok;

    if (!GetModuleFileNameW(NULL, self_path, MAX_PATH)) {
        return FALSE;
    }
    params = elevated_parameters_from_gui_options(options);
    if (!params) {
        return FALSE;
    }

    ZeroMemory(&sei, sizeof(sei));
    sei.cbSize = sizeof(sei);
    sei.fMask = SEE_MASK_NOCLOSEPROCESS;
    sei.lpVerb = L"runas";
    sei.lpFile = self_path;
    sei.lpParameters = params;
    if (options->use_current_directory) {
        sei.lpDirectory = options->current_directory;
    } else if (GetCurrentDirectoryW(MAX_PATH, inherited_directory)) {
        sei.lpDirectory = inherited_directory;
    }
    sei.nShow = SW_SHOWNORMAL;

    ok = ShellExecuteExW(&sei);
    if (ok && sei.hProcess) {
        CloseHandle(sei.hProcess);
    }
    free(params);
    return ok;
}

static int parse_codepage_name(const wchar_t *value, DWORD *codepage) {
    wchar_t *end = NULL;
    unsigned long numeric;

    if (!value || !value[0] || !codepage) {
        return 0;
    }

    if (lstrcmpiW(value, L"acp") == 0 || lstrcmpiW(value, L"ansi") == 0) {
        *codepage = CP_ACP;
        return 1;
    }
    if (lstrcmpiW(value, L"oem") == 0 || lstrcmpiW(value, L"oemcp") == 0) {
        *codepage = CP_OEMCP;
        return 1;
    }
    if (lstrcmpiW(value, L"utf-8") == 0 || lstrcmpiW(value, L"utf8") == 0) {
        *codepage = CP_UTF8;
        return 1;
    }
    if (lstrcmpiW(value, L"shift-jis") == 0 || lstrcmpiW(value, L"shift_jis") == 0 ||
        lstrcmpiW(value, L"sjis") == 0 || lstrcmpiW(value, L"cp932") == 0) {
        *codepage = 932;
        return 1;
    }
    if (lstrcmpiW(value, L"korean") == 0 || lstrcmpiW(value, L"ks_c_5601") == 0 ||
        lstrcmpiW(value, L"cp949") == 0) {
        *codepage = 949;
        return 1;
    }

    if ((value[0] == L'c' || value[0] == L'C') && (value[1] == L'p' || value[1] == L'P')) {
        value += 2;
    }
    numeric = wcstoul(value, &end, 10);
    if (end && *end == L'\0' && numeric <= 0xffff) {
        *codepage = (DWORD)numeric;
        return 1;
    }
    return 0;
}

static void print_usage(const wchar_t *program) {
    wprintf(L"A launcher that applies win32_utf8 to a target executable.\n\n");
    wprintf(L"Usage:\n");
    wprintf(L"  %ls\n", program);
    wprintf(L"    Opens a file dialog to select the target executable.\n\n");
    wprintf(L"  %ls [--codepage=<name-or-number>] [--cwd <dir>] -- <target.exe> [args...]\n", program);
    wprintf(L"    Launches the target with win32_utf8 propagation.\n\n");
    wprintf(L"Codepage aliases: acp, oem, utf-8, shift-jis, korean, cp932, cp949, or a numeric codepage.\n");
}

int main(void) {
    int argc = 0;
    LPWSTR *argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    GUI_LAUNCH_OPTIONS gui_options;
    wchar_t *command_line = NULL;
    wchar_t current_directory[MAX_PATH] = {0};
    LPCWSTR launch_current_directory = NULL;
    wchar_t temp_path[MAX_PATH];
    wchar_t temp_dir[MAX_PATH];
    wchar_t propagator_dll_path[MAX_PATH];
    wchar_t payload_dll_path[MAX_PATH];
    PROPAGATOR_CONFIG config;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    DWORD path_len;
    DWORD init_result;
    DWORD child_exit_code;
    DWORD fallback_codepage = CP_ACP;
    int target_arg = -1;
    BOOL gui_mode = FALSE;
    GUI_LAUNCH_OPTIONS *gui_retry_options = NULL;
    int i;
    int exit_code = 1;

    DPRINTF("Application starting.\n");

    if (argv && argc == 2 && (lstrcmpW(argv[1], L"/?") == 0 || lstrcmpW(argv[1], L"--help") == 0)) {
        print_usage(argv[0]);
        LocalFree(argv);
        return 0;
    }

    if (!argv || argc < 1) {
        fwprintf(stderr, L"Invalid command line.\n");
        return 1;
    }

    if (argc == 1) {
        gui_mode = TRUE;
        gui_retry_options = &gui_options;
        ShowWindow(GetConsoleWindow(), SW_HIDE);
        DPRINTF("No command line args, launching GUI.\n");
        if (!handleGuiLaunch(&gui_options)) {
            DPRINTF("GUI launch cancelled by user.\n");
            LocalFree(argv);
            return 0;
        }
        command_line = command_line_from_gui_options(&gui_options);
        fallback_codepage = gui_options.fallback_codepage;
        if (gui_options.use_current_directory) {
            lstrcpynW(current_directory, gui_options.current_directory, MAX_PATH);
            launch_current_directory = current_directory;
        }
    } else {
        for (i = 1; i < argc; ++i) {
            const wchar_t codepage_prefix[] = L"--codepage=";
            if (lstrcmpW(argv[i], L"--") == 0) {
                target_arg = i + 1;
                break;
            } else if (_wcsnicmp(argv[i], codepage_prefix, wcslen(codepage_prefix)) == 0) {
                if (!parse_codepage_name(argv[i] + wcslen(codepage_prefix), &fallback_codepage)) {
                    fwprintf(stderr, L"Invalid codepage: %ls\n", argv[i] + wcslen(codepage_prefix));
                    print_usage(argv[0]);
                    LocalFree(argv);
                    return 1;
                }
            } else if (lstrcmpW(argv[i], L"--codepage") == 0) {
                if (++i >= argc || !parse_codepage_name(argv[i], &fallback_codepage)) {
                    fwprintf(stderr, L"Invalid or missing codepage.\n");
                    print_usage(argv[0]);
                    LocalFree(argv);
                    return 1;
                }
            } else if (lstrcmpW(argv[i], L"--cwd") == 0) {
                if (++i >= argc || !argv[i][0]) {
                    fwprintf(stderr, L"Invalid or missing CWD.\n");
                    print_usage(argv[0]);
                    LocalFree(argv);
                    return 1;
                }
                lstrcpynW(current_directory, argv[i], MAX_PATH);
                launch_current_directory = current_directory;
            } else if (_wcsnicmp(argv[i], L"--cwd=", 6) == 0) {
                if (!argv[i][6]) {
                    fwprintf(stderr, L"Invalid or missing CWD.\n");
                    print_usage(argv[0]);
                    LocalFree(argv);
                    return 1;
                }
                lstrcpynW(current_directory, argv[i] + 6, MAX_PATH);
                launch_current_directory = current_directory;
            } else {
                fwprintf(stderr, L"Unexpected option before --: %ls\n", argv[i]);
                print_usage(argv[0]);
                LocalFree(argv);
                return 1;
            }
        }

        if (target_arg < 0 || target_arg >= argc) {
            fwprintf(stderr, L"Missing target command after --.\n");
            print_usage(argv[0]);
            LocalFree(argv);
            return 1;
        }

        command_line = command_line_from_argv(argv, target_arg, argc);
    }

    if (!command_line) {
        fwprintf(stderr, L"Invalid command line.\n");
        LocalFree(argv);
        return 1;
    }

    path_len = GetTempPathW(MAX_PATH, temp_path);
    if (path_len == 0 || path_len > MAX_PATH) {
        fwprintf(stderr, L"Error getting temporary path (%lu).\n", GetLastError());
        goto cleanup_command;
    }
    if (GetTempFileNameW(temp_path, L"w32", 0, temp_dir) == 0) {
        fwprintf(stderr, L"Error creating temporary file name (%lu).\n", GetLastError());
        goto cleanup_command;
    }
    DeleteFileW(temp_dir);
    if (!CreateDirectoryW(temp_dir, NULL)) {
        fwprintf(stderr, L"Error creating temporary directory (%lu).\n", GetLastError());
        goto cleanup_command;
    }

    lstrcpynW(propagator_dll_path, temp_dir, MAX_PATH);
    if (!PathAppendW(propagator_dll_path, L"propagator.dll")) {
        fwprintf(stderr, L"Temporary path is too long.\n");
        RemoveDirectoryW(temp_dir);
        goto cleanup_command;
    }

    if (!write_resource_to_file_w(propagator_dll_path, (const unsigned char*)PROPAGATOR_START, (const unsigned char*)PROPAGATOR_END)) {
        fwprintf(stderr, L"Error writing propagator DLL (%lu).\n", GetLastError());
        RemoveDirectoryW(temp_dir);
        goto cleanup_command;
    }

    lstrcpynW(payload_dll_path, temp_dir, MAX_PATH);
    if (!PathAppendW(payload_dll_path, PAYLOAD_NAME)) {
        fwprintf(stderr, L"Temporary payload path is too long.\n");
        DeleteFileW(propagator_dll_path);
        RemoveDirectoryW(temp_dir);
        goto cleanup_command;
    }

    if (!write_resource_to_file_w(payload_dll_path, (const unsigned char*)PAYLOAD_START, (const unsigned char*)PAYLOAD_END)) {
        fwprintf(stderr, L"Error writing payload DLL (%lu).\n", GetLastError());
        DeleteFileW(propagator_dll_path);
        RemoveDirectoryW(temp_dir);
        goto cleanup_command;
    }

    ZeroMemory(&config, sizeof(config));
    config.magic = PROPAGATOR_MAGIC;
    config.version = PROPAGATOR_VERSION;
    lstrcpynW(config.propagator_path, propagator_dll_path, MAX_PATH);
    config.payload_count = 1;
    lstrcpynW(config.payloads[0].dll_path, payload_dll_path, MAX_PATH);
    lstrcpynA(config.payloads[0].init_export, "w32u8_initialize", PROPAGATOR_INIT_EXPORT_LEN);
    config.payloads[0].init_data_size = sizeof(fallback_codepage);
    memcpy(config.payloads[0].init_data, &fallback_codepage, sizeof(fallback_codepage));

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    ZeroMemory(&pi, sizeof(pi));

    if (!CreateProcessW(NULL, command_line, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, launch_current_directory, &si, &pi)) {
        DWORD create_error = GetLastError();
        if (gui_mode && gui_retry_options && create_error == ERROR_ELEVATION_REQUIRED) {
            DPRINTF("Target requires elevation; relaunching launcher elevated.\n");
            if (relaunch_elevated_from_gui_options(gui_retry_options)) {
                exit_code = 0;
            } else {
                MessageBoxW(NULL, L"Unable to restart the launcher as administrator.",
                            L"win32_utf8 launcher", MB_OK | MB_ICONERROR);
            }
        } else {
            fwprintf(stderr, L"CreateProcess failed (%lu).\n", create_error);
        }
        DeleteFileW(payload_dll_path);
        DeleteFileW(propagator_dll_path);
        RemoveDirectoryW(temp_dir);
        goto cleanup_command;
    }

    init_result = inject_and_initialize_propagator_w(pi.hProcess, propagator_dll_path, &config);
    if (init_result != ERROR_SUCCESS) {
        fwprintf(stderr, L"Propagator initialization failed (%lu).\n", init_result);
        TerminateProcess(pi.hProcess, 1);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        DeleteFileW(payload_dll_path);
        DeleteFileW(propagator_dll_path);
        RemoveDirectoryW(temp_dir);
        goto cleanup_command;
    }

    ResumeThread(pi.hThread);
    WaitForSingleObject(pi.hProcess, INFINITE);
    if (GetExitCodeProcess(pi.hProcess, &child_exit_code)) {
        exit_code = (int)child_exit_code;
    } else {
        exit_code = 1;
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    DeleteFileW(payload_dll_path);
    DeleteFileW(propagator_dll_path);
    RemoveDirectoryW(temp_dir);

cleanup_command:
    if (argv) {
        LocalFree(argv);
    }
    free(command_line);
    return exit_code;
}
