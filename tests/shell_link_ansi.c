#define COBJMACROS
#include <windows.h>
#include <objbase.h>
#include <shlobj.h>
#include <stdio.h>

static const wchar_t generated_dir_name[] = {0x65e5, 0x672c, 0x8a9e, 0};
static const wchar_t generated_exe_name[] = {0x30c6, 0x30b9, 0x30c8, L'.', L'e', L'x', L'e', 0};

int main(void) {
    IShellLinkA *link_a = NULL;
    IShellLinkW *link_w = NULL;
    IPersistFile *persist = NULL;
    HRESULT hr;
    wchar_t path[MAX_PATH];
    wchar_t temp_dir[MAX_PATH];
    wchar_t base_dir[MAX_PATH];
    wchar_t nested_dir[MAX_PATH];
    wchar_t expected_target[MAX_PATH];
    wchar_t link_path[MAX_PATH];
    char sjis_target[MAX_PATH * 2];
    HANDLE file;
    int sjis_len;
    int exit_code = 2;
    DWORD attempt;

    if (!GetTempPathW(MAX_PATH, temp_dir)) {
        printf("temporary path setup failed: %lu\n", GetLastError());
        return 2;
    }

    for (attempt = 0; attempt < 32; ++attempt) {
        wsprintfW(base_dir, L"%lsw32u8_lnk_%lu_%lu",
                  temp_dir, GetCurrentProcessId(), GetTickCount() + attempt);
        if (CreateDirectoryW(base_dir, NULL)) {
            break;
        }
        if (GetLastError() != ERROR_ALREADY_EXISTS) {
            printf("CreateDirectoryW(base) failed: %lu\n", GetLastError());
            return 2;
        }
    }
    if (attempt == 32) {
        printf("CreateDirectoryW(base) failed: no unique directory\n");
        return 2;
    }

    wsprintfW(nested_dir, L"%ls\\%ls", base_dir, generated_dir_name);
    wsprintfW(expected_target, L"%ls\\%ls", nested_dir, generated_exe_name);
    wsprintfW(link_path, L"%ls\\generated.lnk", base_dir);

    if (!CreateDirectoryW(nested_dir, NULL)) {
        printf("CreateDirectoryW(nested) failed: %lu\n", GetLastError());
        RemoveDirectoryW(base_dir);
        return 2;
    }
    file = CreateFileW(expected_target, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        printf("CreateFileW(target) failed: %lu\n", GetLastError());
        RemoveDirectoryW(nested_dir);
        RemoveDirectoryW(base_dir);
        return 2;
    }
    CloseHandle(file);

    sjis_len = WideCharToMultiByte(932, 0, expected_target, -1,
                                   sjis_target, sizeof(sjis_target), NULL, NULL);
    if (!sjis_len) {
        printf("WideCharToMultiByte(CP932) failed: %lu\n", GetLastError());
        DeleteFileW(expected_target);
        RemoveDirectoryW(nested_dir);
        RemoveDirectoryW(base_dir);
        return 2;
    }

    hr = CoInitialize(NULL);
    if (FAILED(hr)) {
        printf("CoInitialize failed: 0x%08lx\n", (unsigned long)hr);
        goto cleanup_files;
    }

    hr = CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER,
                          &IID_IShellLinkA, (void**)&link_a);
    if (FAILED(hr)) {
        printf("CoCreateInstance failed: 0x%08lx\n", (unsigned long)hr);
        CoUninitialize();
        goto cleanup_files;
    }

    hr = IShellLinkA_SetPath(link_a, sjis_target);
    if (FAILED(hr)) {
        printf("IShellLinkA_SetPath failed: 0x%08lx\n", (unsigned long)hr);
        IShellLinkA_Release(link_a);
        CoUninitialize();
        goto cleanup_files;
    }

    hr = IShellLinkA_QueryInterface(link_a, &IID_IPersistFile, (void**)&persist);
    if (FAILED(hr)) {
        printf("QueryInterface(IPersistFile) failed: 0x%08lx\n", (unsigned long)hr);
        IShellLinkA_Release(link_a);
        CoUninitialize();
        goto cleanup_files;
    }

    hr = IPersistFile_Save(persist, link_path, TRUE);
    IPersistFile_Release(persist);
    IShellLinkA_Release(link_a);
    if (FAILED(hr)) {
        printf("IPersistFile_Save failed: 0x%08lx\n", (unsigned long)hr);
        CoUninitialize();
        goto cleanup_files;
    }

    hr = CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER,
                          &IID_IShellLinkW, (void**)&link_w);
    if (FAILED(hr)) {
        printf("CoCreateInstance(IShellLinkW) failed: 0x%08lx\n", (unsigned long)hr);
        CoUninitialize();
        goto cleanup_files;
    }
    hr = IShellLinkW_QueryInterface(link_w, &IID_IPersistFile, (void**)&persist);
    if (FAILED(hr)) {
        printf("QueryInterface(IPersistFile/W) failed: 0x%08lx\n", (unsigned long)hr);
        IShellLinkW_Release(link_w);
        CoUninitialize();
        goto cleanup_files;
    }
    hr = IPersistFile_Load(persist, link_path, STGM_READ);
    IPersistFile_Release(persist);
    if (FAILED(hr)) {
        printf("IPersistFile_Load failed: 0x%08lx\n", (unsigned long)hr);
        IShellLinkW_Release(link_w);
        CoUninitialize();
        goto cleanup_files;
    }

    ZeroMemory(path, sizeof(path));
    hr = IShellLinkW_GetPath(link_w, path, MAX_PATH, NULL, SLGP_RAWPATH);
    IShellLinkW_Release(link_w);
    CoUninitialize();

    if (FAILED(hr)) {
        printf("IShellLinkW_GetPath failed: 0x%08lx\n", (unsigned long)hr);
        goto cleanup_files;
    }

    if (lstrcmpW(path, expected_target) != 0) {
        wprintf(L"shell_link_ansi mismatch\nactual:   %ls\nexpected: %ls\n", path, expected_target);
        exit_code = 1;
        goto cleanup_files;
    }

    printf("shell_link_ansi ok\n");
    exit_code = 0;

cleanup_files:
    DeleteFileW(link_path);
    DeleteFileW(expected_target);
    RemoveDirectoryW(nested_dir);
    RemoveDirectoryW(base_dir);
    return exit_code;
}
