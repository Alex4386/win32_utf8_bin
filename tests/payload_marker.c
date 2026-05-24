#include <windows.h>

__declspec(dllexport) DWORD WINAPI PayloadMarkerInitialize(void *reserved) {
    (void)reserved;
    return SetEnvironmentVariableW(L"PAYLOAD_MARKER_INITIALIZED", L"1") ? ERROR_SUCCESS : GetLastError();
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance;
    (void)reason;
    (void)reserved;
    return TRUE;
}
