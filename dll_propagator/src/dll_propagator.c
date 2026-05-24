#include <windows.h>
#include <stdio.h>
#include "detour.h"
#include "../../common/shared.h"

#ifndef DEBUG
#define DEBUG 1
#endif

#if DEBUG
#define DLOG(fmt, ...) do { \
    char _buf[512]; \
    snprintf(_buf, sizeof(_buf) - 1, "win32_utf8 propagator: " fmt, ##__VA_ARGS__); \
    _buf[sizeof(_buf) - 1] = '\0'; \
    OutputDebugStringA(_buf); \
} while (0)
#else
#define DLOG(fmt, ...) do {} while (0)
#endif

typedef BOOL (WINAPI *PFN_CreateProcessA)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *PFN_CreateProcessW)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *PFN_CreateProcessAsUserA)(HANDLE, LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *PFN_CreateProcessAsUserW)(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *PFN_CreateProcessWithLogonW)(LPCWSTR, LPCWSTR, LPCWSTR, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
typedef BOOL (WINAPI *PFN_CreateProcessWithTokenW)(HANDLE, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

BOOL WINAPI DetourCreateProcessA(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
BOOL WINAPI DetourCreateProcessW(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
BOOL WINAPI DetourCreateProcessAsUserA(HANDLE, LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
BOOL WINAPI DetourCreateProcessAsUserW(HANDLE, LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
BOOL WINAPI DetourCreateProcessWithLogonW(LPCWSTR, LPCWSTR, LPCWSTR, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
BOOL WINAPI DetourCreateProcessWithTokenW(HANDLE, DWORD, LPCWSTR, LPWSTR, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);

static PROPAGATOR_CONFIG g_config;
static volatile LONG g_init_started = 0;
static volatile LONG g_init_done = 0;
static DWORD g_init_result = ERROR_SUCCESS;

static PFN_CreateProcessA RealCreateProcessA = NULL;
static PFN_CreateProcessW RealCreateProcessW = NULL;
static PFN_CreateProcessAsUserA RealCreateProcessAsUserA = NULL;
static PFN_CreateProcessAsUserW RealCreateProcessAsUserW = NULL;
static PFN_CreateProcessWithLogonW RealCreateProcessWithLogonW = NULL;
static PFN_CreateProcessWithTokenW RealCreateProcessWithTokenW = NULL;

static DWORD propagate_to_child(HANDLE process) {
    DWORD result;

    if (!process || !g_config.propagator_path[0]) {
        return ERROR_INVALID_PARAMETER;
    }

    result = inject_and_initialize_propagator_w(process, g_config.propagator_path, &g_config);
    if (result != ERROR_SUCCESS) {
        DLOG("child propagation failed: %lu\n", result);
    }
    return result;
}

static void resume_if_needed(HANDLE thread, BOOL caller_requested_suspended) {
    if (thread && !caller_requested_suspended) {
        ResumeThread(thread);
    }
}

static BOOL hook_proc(HMODULE module, const char *name, void *detour, void **real) {
    void *target;
    void *trampoline = NULL;

    if (!module) {
        return FALSE;
    }

    target = (void*)GetProcAddress(module, name);
    if (!target) {
        return FALSE;
    }

    if (!DetourAttach(target, detour, &trampoline)) {
        DLOG("failed to hook %s (%lu)\n", name, GetLastError());
        return FALSE;
    }

    if (*real == NULL) {
        *real = trampoline;
    }
    return TRUE;
}

static DWORD hook_process_apis(void) {
    HMODULE kernel32 = GetModuleHandleW(L"kernel32.dll");
    HMODULE kernelbase = GetModuleHandleW(L"kernelbase.dll");
    HMODULE advapi32 = LoadLibraryW(L"advapi32.dll");
    BOOL hooked_process_create = FALSE;

    hooked_process_create |= hook_proc(kernelbase, "CreateProcessA", DetourCreateProcessA, (void**)&RealCreateProcessA);
    hooked_process_create |= hook_proc(kernel32, "CreateProcessA", DetourCreateProcessA, (void**)&RealCreateProcessA);
    hooked_process_create |= hook_proc(kernelbase, "CreateProcessW", DetourCreateProcessW, (void**)&RealCreateProcessW);
    hooked_process_create |= hook_proc(kernel32, "CreateProcessW", DetourCreateProcessW, (void**)&RealCreateProcessW);

    hook_proc(advapi32, "CreateProcessAsUserA", DetourCreateProcessAsUserA, (void**)&RealCreateProcessAsUserA);
    hook_proc(advapi32, "CreateProcessAsUserW", DetourCreateProcessAsUserW, (void**)&RealCreateProcessAsUserW);
    hook_proc(advapi32, "CreateProcessWithLogonW", DetourCreateProcessWithLogonW, (void**)&RealCreateProcessWithLogonW);
    hook_proc(advapi32, "CreateProcessWithTokenW", DetourCreateProcessWithTokenW, (void**)&RealCreateProcessWithTokenW);

    return hooked_process_create ? ERROR_SUCCESS : ERROR_PROC_NOT_FOUND;
}

static DWORD validate_config(const PROPAGATOR_CONFIG *config) {
    DWORD i;

    if (!config) {
        return ERROR_INVALID_PARAMETER;
    }
    if (config->magic != PROPAGATOR_MAGIC || config->version != PROPAGATOR_VERSION) {
        return ERROR_BAD_FORMAT;
    }
    if (!config->propagator_path[0] || config->payload_count > PROPAGATOR_MAX_PAYLOADS) {
        return ERROR_INVALID_PARAMETER;
    }
    for (i = 0; i < config->payload_count; ++i) {
        if (!config->payloads[i].dll_path[0]) {
            return ERROR_INVALID_PARAMETER;
        }
    }
    return ERROR_SUCCESS;
}

static FARPROC find_payload_export(HMODULE module, const char *name) {
    FARPROC proc;
    char decorated[PROPAGATOR_INIT_EXPORT_LEN + 8];

    proc = GetProcAddress(module, name);
    if (proc) {
        return proc;
    }

    snprintf(decorated, sizeof(decorated), "%s@4", name);
    proc = GetProcAddress(module, decorated);
    if (proc) {
        return proc;
    }

    snprintf(decorated, sizeof(decorated), "_%s@4", name);
    return GetProcAddress(module, decorated);
}

static DWORD load_payloads(void) {
    DWORD i;

    for (i = 0; i < g_config.payload_count; ++i) {
        HMODULE module = LoadLibraryW(g_config.payloads[i].dll_path);
        if (!module) {
            return GetLastError();
        }

        if (g_config.payloads[i].init_export[0]) {
            typedef DWORD (WINAPI *PFN_PayloadInit)(void*);
            PFN_PayloadInit init = (PFN_PayloadInit)find_payload_export(module, g_config.payloads[i].init_export);
            if (!init) {
                return GetLastError();
            }
            {
                void *init_data = g_config.payloads[i].init_data_size
                    ? g_config.payloads[i].init_data
                    : NULL;
                DWORD result = init(init_data);
                if (result != ERROR_SUCCESS) {
                    return result;
                }
            }
        }

    }
    return ERROR_SUCCESS;
}

__declspec(dllexport) DWORD WINAPI PropagatorInitialize(void *reserved) {
    DWORD result;
    PROPAGATOR_CONFIG local_config;

    if (g_init_done) {
        return g_init_result;
    }

    if (InterlockedCompareExchange(&g_init_started, 1, 0) != 0) {
        while (!g_init_done) {
            Sleep(1);
        }
        return g_init_result;
    }

    if (!reserved) {
        result = ERROR_INVALID_PARAMETER;
        goto finish;
    }

    memcpy(&local_config, reserved, sizeof(local_config));
    result = validate_config(&local_config);
    if (result != ERROR_SUCCESS) {
        goto finish;
    }

    memcpy(&g_config, &local_config, sizeof(g_config));

    result = load_payloads();
    if (result == ERROR_SUCCESS) {
        result = hook_process_apis();
    }

finish:
    g_init_result = result;
    InterlockedExchange(&g_init_done, 1);
    DLOG("initializer finished: %lu\n", result);
    return result;
}

BOOL WINAPI DetourCreateProcessA(
    LPCSTR application_name,
    LPSTR command_line,
    LPSECURITY_ATTRIBUTES process_attributes,
    LPSECURITY_ATTRIBUTES thread_attributes,
    BOOL inherit_handles,
    DWORD creation_flags,
    LPVOID environment,
    LPCSTR current_directory,
    LPSTARTUPINFOA startup_info,
    LPPROCESS_INFORMATION process_information
) {
    BOOL caller_suspended = (creation_flags & CREATE_SUSPENDED) != 0;
    BOOL result;

    if (!RealCreateProcessA) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return FALSE;
    }

    result = RealCreateProcessA(application_name, command_line, process_attributes, thread_attributes,
                                inherit_handles, creation_flags | CREATE_SUSPENDED, environment,
                                current_directory, startup_info, process_information);
    if (result && process_information) {
        propagate_to_child(process_information->hProcess);
        resume_if_needed(process_information->hThread, caller_suspended);
    }
    return result;
}

BOOL WINAPI DetourCreateProcessW(
    LPCWSTR application_name,
    LPWSTR command_line,
    LPSECURITY_ATTRIBUTES process_attributes,
    LPSECURITY_ATTRIBUTES thread_attributes,
    BOOL inherit_handles,
    DWORD creation_flags,
    LPVOID environment,
    LPCWSTR current_directory,
    LPSTARTUPINFOW startup_info,
    LPPROCESS_INFORMATION process_information
) {
    BOOL caller_suspended = (creation_flags & CREATE_SUSPENDED) != 0;
    BOOL result;

    if (!RealCreateProcessW) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return FALSE;
    }

    result = RealCreateProcessW(application_name, command_line, process_attributes, thread_attributes,
                                inherit_handles, creation_flags | CREATE_SUSPENDED, environment,
                                current_directory, startup_info, process_information);
    if (result && process_information) {
        propagate_to_child(process_information->hProcess);
        resume_if_needed(process_information->hThread, caller_suspended);
    }
    return result;
}

BOOL WINAPI DetourCreateProcessAsUserA(
    HANDLE token,
    LPCSTR application_name,
    LPSTR command_line,
    LPSECURITY_ATTRIBUTES process_attributes,
    LPSECURITY_ATTRIBUTES thread_attributes,
    BOOL inherit_handles,
    DWORD creation_flags,
    LPVOID environment,
    LPCSTR current_directory,
    LPSTARTUPINFOA startup_info,
    LPPROCESS_INFORMATION process_information
) {
    BOOL caller_suspended = (creation_flags & CREATE_SUSPENDED) != 0;
    BOOL result;

    if (!RealCreateProcessAsUserA) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return FALSE;
    }

    result = RealCreateProcessAsUserA(token, application_name, command_line, process_attributes,
                                      thread_attributes, inherit_handles, creation_flags | CREATE_SUSPENDED,
                                      environment, current_directory, startup_info, process_information);
    if (result && process_information) {
        propagate_to_child(process_information->hProcess);
        resume_if_needed(process_information->hThread, caller_suspended);
    }
    return result;
}

BOOL WINAPI DetourCreateProcessAsUserW(
    HANDLE token,
    LPCWSTR application_name,
    LPWSTR command_line,
    LPSECURITY_ATTRIBUTES process_attributes,
    LPSECURITY_ATTRIBUTES thread_attributes,
    BOOL inherit_handles,
    DWORD creation_flags,
    LPVOID environment,
    LPCWSTR current_directory,
    LPSTARTUPINFOW startup_info,
    LPPROCESS_INFORMATION process_information
) {
    BOOL caller_suspended = (creation_flags & CREATE_SUSPENDED) != 0;
    BOOL result;

    if (!RealCreateProcessAsUserW) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return FALSE;
    }

    result = RealCreateProcessAsUserW(token, application_name, command_line, process_attributes,
                                      thread_attributes, inherit_handles, creation_flags | CREATE_SUSPENDED,
                                      environment, current_directory, startup_info, process_information);
    if (result && process_information) {
        propagate_to_child(process_information->hProcess);
        resume_if_needed(process_information->hThread, caller_suspended);
    }
    return result;
}

BOOL WINAPI DetourCreateProcessWithLogonW(
    LPCWSTR username,
    LPCWSTR domain,
    LPCWSTR password,
    DWORD logon_flags,
    LPCWSTR application_name,
    LPWSTR command_line,
    DWORD creation_flags,
    LPVOID environment,
    LPCWSTR current_directory,
    LPSTARTUPINFOW startup_info,
    LPPROCESS_INFORMATION process_information
) {
    BOOL caller_suspended = (creation_flags & CREATE_SUSPENDED) != 0;
    BOOL result;

    if (!RealCreateProcessWithLogonW) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return FALSE;
    }

    result = RealCreateProcessWithLogonW(username, domain, password, logon_flags, application_name,
                                         command_line, creation_flags | CREATE_SUSPENDED, environment,
                                         current_directory, startup_info, process_information);
    if (result && process_information) {
        propagate_to_child(process_information->hProcess);
        resume_if_needed(process_information->hThread, caller_suspended);
    }
    return result;
}

BOOL WINAPI DetourCreateProcessWithTokenW(
    HANDLE token,
    DWORD logon_flags,
    LPCWSTR application_name,
    LPWSTR command_line,
    DWORD creation_flags,
    LPVOID environment,
    LPCWSTR current_directory,
    LPSTARTUPINFOW startup_info,
    LPPROCESS_INFORMATION process_information
) {
    BOOL caller_suspended = (creation_flags & CREATE_SUSPENDED) != 0;
    BOOL result;

    if (!RealCreateProcessWithTokenW) {
        SetLastError(ERROR_PROC_NOT_FOUND);
        return FALSE;
    }

    result = RealCreateProcessWithTokenW(token, logon_flags, application_name, command_line,
                                         creation_flags | CREATE_SUSPENDED, environment,
                                         current_directory, startup_info, process_information);
    if (result && process_information) {
        propagate_to_child(process_information->hProcess);
        resume_if_needed(process_information->hThread, caller_suspended);
    }
    return result;
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)reserved;

    switch (reason) {
        case DLL_PROCESS_ATTACH:
            DisableThreadLibraryCalls(instance);
            break;
        case DLL_PROCESS_DETACH:
            /*
             * During process teardown, loader ordering can make hooked module
             * pages unsafe to patch back. The process is exiting anyway, so
             * leave hooks in place rather than risking a detach-time AV.
             */
            break;
    }
    return TRUE;
}
