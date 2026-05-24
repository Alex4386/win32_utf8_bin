#include <windows.h>
#include <stdio.h>

int wmain(void) {
    static const char utf8_name[] = "w32u8_\xE2\x98\x83.tmp";
    static const wchar_t wide_name[] = L"w32u8_\x2603.tmp";
    HANDLE file;
    DWORD written;
    DWORD attrs;

    DeleteFileW(wide_name);

    file = CreateFileA(utf8_name, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        wprintf(L"ansi:create_file failed %lu\n", GetLastError());
        return 2;
    }

    if (!WriteFile(file, "ok", 2, &written, NULL)) {
        DWORD error = GetLastError();
        CloseHandle(file);
        DeleteFileW(wide_name);
        wprintf(L"ansi:write failed %lu\n", error);
        return 3;
    }
    CloseHandle(file);

    attrs = GetFileAttributesW(wide_name);
    if (attrs == INVALID_FILE_ATTRIBUTES) {
        wprintf(L"ansi:utf8 path missing %lu\n", GetLastError());
        return 4;
    }

    DeleteFileW(wide_name);
    wprintf(L"ansi:utf8 createfile ok\n");
    return 0;
}
