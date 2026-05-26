#include <windows.h>
#include <stdio.h>
#include <wchar.h>

static int append_wide(wchar_t *dst, size_t cap, const wchar_t *src) {
    size_t used = wcslen(dst);
    size_t add = wcslen(src);
    if (used + add + 1 > cap) {
        return 0;
    }
    memcpy(dst + used, src, (add + 1) * sizeof(wchar_t));
    return 1;
}

static int append_ansi(char *dst, size_t cap, const char *src) {
    size_t used = strlen(dst);
    size_t add = strlen(src);
    if (used + add + 1 > cap) {
        return 0;
    }
    memcpy(dst + used, src, add + 1);
    return 1;
}

int main(void) {
    wchar_t temp[MAX_PATH];
    wchar_t dir[MAX_PATH];
    wchar_t expected[MAX_PATH];
    char mixed[MAX_PATH * 4];
    DWORD temp_len;
    int mixed_len;
    HANDLE file;

    static const char cp932_filename[] = "\x93\xFA\x96\x7B.txt";
    static const wchar_t wide_filename[] = L"\x65E5\x672C.txt";

    temp_len = GetTempPathW(MAX_PATH, temp);
    if (!temp_len || temp_len >= MAX_PATH) {
        printf("mixed_encoding_path:get_temp failed %lu\n", GetLastError());
        return 1;
    }

    wsprintfW(dir, L"%lsw32u8_mixed_%lu_\x2603", temp, GetTickCount());
    if (!CreateDirectoryW(dir, NULL)) {
        printf("mixed_encoding_path:create_dir failed %lu\n", GetLastError());
        return 1;
    }

    ZeroMemory(mixed, sizeof(mixed));
    mixed_len = WideCharToMultiByte(CP_UTF8, 0, dir, -1, mixed, sizeof(mixed), NULL, NULL);
    if (!mixed_len) {
        printf("mixed_encoding_path:utf8_dir failed %lu\n", GetLastError());
        RemoveDirectoryW(dir);
        return 1;
    }
    mixed[mixed_len - 1] = '\0';
    if (!append_ansi(mixed, sizeof(mixed), "\\") ||
        !append_ansi(mixed, sizeof(mixed), cp932_filename)) {
        printf("mixed_encoding_path:mixed_path too long\n");
        RemoveDirectoryW(dir);
        return 1;
    }

    lstrcpynW(expected, dir, MAX_PATH);
    if (!append_wide(expected, MAX_PATH, L"\\") ||
        !append_wide(expected, MAX_PATH, wide_filename)) {
        printf("mixed_encoding_path:expected_path too long\n");
        RemoveDirectoryW(dir);
        return 1;
    }

    file = CreateFileA(mixed, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        printf("mixed_encoding_path:create_file failed %lu\n", GetLastError());
        RemoveDirectoryW(dir);
        return 1;
    }
    CloseHandle(file);

    if (GetFileAttributesW(expected) == INVALID_FILE_ATTRIBUTES) {
        printf("mixed_encoding_path:expected file missing %lu\n", GetLastError());
        DeleteFileA(mixed);
        RemoveDirectoryW(dir);
        return 1;
    }

    DeleteFileW(expected);
    RemoveDirectoryW(dir);
    printf("mixed_encoding_path ok\n");
    return 0;
}
