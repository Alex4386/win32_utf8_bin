#define COBJMACROS
#include <windows.h>
#include <objbase.h>
#include <shlobj.h>
#include <stdio.h>

static const char sjis_target[] =
    "C:\\Program Files\\\x93\x8c\x95\xfb\x8c\xb6\x91\x7a\x8b\xbd\\install.exe";
static const wchar_t expected_target[] =
    L"C:\\Program Files\\\x6771\x65b9\x5e7b\x60f3\x90f7\\install.exe";

int main(void) {
    IShellLinkA *link_a = NULL;
    IShellLinkW *link_w = NULL;
    IPersistFile *persist = NULL;
    HRESULT hr;
    wchar_t path[MAX_PATH];
    wchar_t temp_dir[MAX_PATH];
    wchar_t link_path[MAX_PATH];

    hr = CoInitialize(NULL);
    if (FAILED(hr)) {
        printf("CoInitialize failed: 0x%08lx\n", (unsigned long)hr);
        return 2;
    }

    hr = CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER,
                          &IID_IShellLinkA, (void**)&link_a);
    if (FAILED(hr)) {
        printf("CoCreateInstance failed: 0x%08lx\n", (unsigned long)hr);
        CoUninitialize();
        return 2;
    }

    hr = IShellLinkA_SetPath(link_a, sjis_target);
    if (FAILED(hr)) {
        printf("IShellLinkA_SetPath failed: 0x%08lx\n", (unsigned long)hr);
        IShellLinkA_Release(link_a);
        CoUninitialize();
        return 2;
    }

    GetTempPathW(MAX_PATH, temp_dir);
    GetTempFileNameW(temp_dir, L"lnk", 0, link_path);
    DeleteFileW(link_path);
    lstrcatW(link_path, L".lnk");

    hr = IShellLinkA_QueryInterface(link_a, &IID_IPersistFile, (void**)&persist);
    if (FAILED(hr)) {
        printf("QueryInterface(IPersistFile) failed: 0x%08lx\n", (unsigned long)hr);
        IShellLinkA_Release(link_a);
        CoUninitialize();
        return 2;
    }

    hr = IPersistFile_Save(persist, link_path, TRUE);
    IPersistFile_Release(persist);
    IShellLinkA_Release(link_a);
    if (FAILED(hr)) {
        printf("IPersistFile_Save failed: 0x%08lx\n", (unsigned long)hr);
        DeleteFileW(link_path);
        CoUninitialize();
        return 2;
    }

    hr = CoCreateInstance(&CLSID_ShellLink, NULL, CLSCTX_INPROC_SERVER,
                          &IID_IShellLinkW, (void**)&link_w);
    if (FAILED(hr)) {
        printf("CoCreateInstance(IShellLinkW) failed: 0x%08lx\n", (unsigned long)hr);
        DeleteFileW(link_path);
        CoUninitialize();
        return 2;
    }
    hr = IShellLinkW_QueryInterface(link_w, &IID_IPersistFile, (void**)&persist);
    if (FAILED(hr)) {
        printf("QueryInterface(IPersistFile/W) failed: 0x%08lx\n", (unsigned long)hr);
        IShellLinkW_Release(link_w);
        DeleteFileW(link_path);
        CoUninitialize();
        return 2;
    }
    hr = IPersistFile_Load(persist, link_path, STGM_READ);
    IPersistFile_Release(persist);
    if (FAILED(hr)) {
        printf("IPersistFile_Load failed: 0x%08lx\n", (unsigned long)hr);
        IShellLinkW_Release(link_w);
        DeleteFileW(link_path);
        CoUninitialize();
        return 2;
    }

    ZeroMemory(path, sizeof(path));
    hr = IShellLinkW_GetPath(link_w, path, MAX_PATH, NULL, SLGP_RAWPATH);
    IShellLinkW_Release(link_w);
    DeleteFileW(link_path);
    CoUninitialize();

    if (FAILED(hr)) {
        printf("IShellLinkW_GetPath failed: 0x%08lx\n", (unsigned long)hr);
        return 2;
    }

    if (lstrcmpW(path, expected_target) != 0) {
        wprintf(L"shell_link_ansi mismatch\nactual:   %ls\nexpected: %ls\n", path, expected_target);
        return 1;
    }

    wprintf(L"shell_link_ansi ok: %ls\n", path);
    return 0;
}
