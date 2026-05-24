#include <windows.h>
#include <shellapi.h>
#include <stdio.h>
#include <wchar.h>

static BOOL has_win32_utf8(void) {
    return GetModuleHandleW(L"win32_utf8.x64.dll") ||
           GetModuleHandleW(L"win32_utf8.x86.dll") ||
           GetModuleHandleW(L"win32_utf8.dll");
}

static BOOL has_propagator(void) {
    return GetModuleHandleW(L"propagator.dll") ||
           GetModuleHandleW(L"dll_propagator.x64.dll") ||
           GetModuleHandleW(L"dll_propagator.x86.dll");
}

int main(void) {
    int argc = 0;
    wchar_t **argv = CommandLineToArgvW(GetCommandLineW(), &argc);
    const wchar_t *expected_payload = (argv && argc > 2) ? argv[2] : NULL;
    BOOL has_prop = has_propagator();
    BOOL has_payload = expected_payload ? (GetModuleHandleW(expected_payload) != NULL) : has_win32_utf8();
    BOOL init_ok = TRUE;

    if (expected_payload) {
        wchar_t value[8];
        init_ok = GetEnvironmentVariableW(L"PAYLOAD_MARKER_INITIALIZED", value, sizeof(value) / sizeof(value[0])) > 0 &&
                  lstrcmpW(value, L"1") == 0;
    }

    wprintf(L"probe:%ls propagator=%d payload=%d init=%d\n",
            (argv && argc > 1) ? argv[1] : L"default",
            has_prop ? 1 : 0,
            has_payload ? 1 : 0,
            init_ok ? 1 : 0);

    if (argv) {
        LocalFree(argv);
    }
    return (has_prop && has_payload && init_ok) ? 0 : 2;
}
