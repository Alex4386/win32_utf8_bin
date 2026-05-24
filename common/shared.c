#include "shared.h"
#include <tlhelp32.h>
#include <stdio.h>
#include <wchar.h>

static DWORD rva_to_file_offset(IMAGE_SECTION_HEADER *sections, WORD section_count, DWORD rva);
static DWORD find_remote_module_base_w(DWORD process_id, const wchar_t* dll_path, ULONG_PTR* module_base);

#define REMOTE_INIT_TIMEOUT_MS 10000

// Helper function to write a resource to a file
BOOL write_resource_to_file(const char* path, const char* start, const char* end) {
    FILE *file = fopen(path, "wb");
    if (!file) {
        return FALSE;
    }
    size_t size = end - start;
    fwrite(start, 1, size, file);
    fclose(file);
    return TRUE;
}

BOOL write_resource_to_file_w(const wchar_t* path, const unsigned char* start, const unsigned char* end) {
    HANDLE file;
    DWORD remaining;
    const unsigned char *cursor;

    file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    remaining = (DWORD)(end - start);
    cursor = start;
    while (remaining > 0) {
        DWORD written = 0;
        DWORD chunk = remaining;
        if (!WriteFile(file, cursor, chunk, &written, NULL) || written == 0) {
            CloseHandle(file);
            DeleteFileW(path);
            return FALSE;
        }
        cursor += written;
        remaining -= written;
    }

    if (!CloseHandle(file)) {
        DeleteFileW(path);
        return FALSE;
    }
    return TRUE;
}

DWORD get_file_export_rva_w(const wchar_t* dll_path, const char* export_name, DWORD_PTR* export_rva) {
    HANDLE file = INVALID_HANDLE_VALUE;
    HANDLE mapping = NULL;
    BYTE *base = NULL;
    DWORD result = ERROR_PROC_NOT_FOUND;

    if (!dll_path || !export_name || !export_rva) {
        return ERROR_INVALID_PARAMETER;
    }
    *export_rva = 0;

    file = CreateFileW(dll_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return GetLastError();
    }

    mapping = CreateFileMappingW(file, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!mapping) {
        result = GetLastError();
        CloseHandle(file);
        return result;
    }

    base = (BYTE*)MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
    if (!base) {
        result = GetLastError();
        CloseHandle(mapping);
        CloseHandle(file);
        return result;
    }

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
        result = ERROR_BAD_EXE_FORMAT;
        goto cleanup;
    }

    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) {
        result = ERROR_BAD_EXE_FORMAT;
        goto cleanup;
    }

    DWORD export_va = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD export_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (!export_va || !export_size) {
        result = ERROR_PROC_NOT_FOUND;
        goto cleanup;
    }

    IMAGE_SECTION_HEADER *sections = IMAGE_FIRST_SECTION(nt);
    WORD section_count = nt->FileHeader.NumberOfSections;

    DWORD export_file_offset = 0;
    for (WORD i = 0; i < section_count; ++i) {
        DWORD va = sections[i].VirtualAddress;
        DWORD size = sections[i].Misc.VirtualSize;
        if (size < sections[i].SizeOfRawData) {
            size = sections[i].SizeOfRawData;
        }
        if (export_va >= va && export_va < va + size) {
            export_file_offset = sections[i].PointerToRawData + (export_va - va);
            break;
        }
    }

    if (!export_file_offset) {
        result = ERROR_BAD_EXE_FORMAT;
        goto cleanup;
    }

    IMAGE_EXPORT_DIRECTORY *exports = (IMAGE_EXPORT_DIRECTORY*)(base + export_file_offset);

#define RVA_TO_PTR(type, rva) (type)(base + rva_to_file_offset(sections, section_count, (DWORD)(rva)))
    DWORD *names = RVA_TO_PTR(DWORD*, exports->AddressOfNames);
    WORD *ordinals = RVA_TO_PTR(WORD*, exports->AddressOfNameOrdinals);
    DWORD *functions = RVA_TO_PTR(DWORD*, exports->AddressOfFunctions);

    if (!names || !ordinals || !functions) {
        result = ERROR_BAD_EXE_FORMAT;
        goto cleanup;
    }

    for (DWORD i = 0; i < exports->NumberOfNames; ++i) {
        char *name = RVA_TO_PTR(char*, names[i]);
        if (name && lstrcmpA(name, export_name) == 0) {
            WORD ordinal = ordinals[i];
            if (ordinal >= exports->NumberOfFunctions) {
                result = ERROR_BAD_EXE_FORMAT;
                goto cleanup;
            }
            *export_rva = functions[ordinal];
            result = ERROR_SUCCESS;
            goto cleanup;
        }
    }

#undef RVA_TO_PTR

cleanup:
    UnmapViewOfFile(base);
    CloseHandle(mapping);
    CloseHandle(file);
    return result;
}

static DWORD rva_to_file_offset(IMAGE_SECTION_HEADER *sections, WORD section_count, DWORD rva) {
    for (WORD i = 0; i < section_count; ++i) {
        DWORD va = sections[i].VirtualAddress;
        DWORD size = sections[i].Misc.VirtualSize;
        if (size < sections[i].SizeOfRawData) {
            size = sections[i].SizeOfRawData;
        }
        if (rva >= va && rva < va + size) {
            return sections[i].PointerToRawData + (rva - va);
        }
    }
    return rva;
}

static DWORD find_remote_module_base_w(DWORD process_id, const wchar_t* dll_path, ULONG_PTR* module_base) {
    HANDLE snapshot;
    MODULEENTRY32W module;
    DWORD result = ERROR_MOD_NOT_FOUND;

    if (!dll_path || !module_base) {
        return ERROR_INVALID_PARAMETER;
    }
    *module_base = 0;

    snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return GetLastError();
    }

    ZeroMemory(&module, sizeof(module));
    module.dwSize = sizeof(module);
    if (Module32FirstW(snapshot, &module)) {
        do {
            if (lstrcmpiW(module.szExePath, dll_path) == 0) {
                *module_base = (ULONG_PTR)module.modBaseAddr;
                result = ERROR_SUCCESS;
                break;
            }
        } while (Module32NextW(snapshot, &module));
    } else {
        result = GetLastError();
    }

    CloseHandle(snapshot);
    return result;
}

DWORD inject_and_initialize_propagator_w(HANDLE process, const wchar_t* dll_path, const PROPAGATOR_CONFIG* config) {
    DWORD result = ERROR_SUCCESS;
    SIZE_T path_bytes;
    LPVOID remote_path = NULL;
    LPVOID remote_config = NULL;
    HANDLE thread = NULL;
    DWORD process_id;
    ULONG_PTR remote_module = 0;
    DWORD_PTR init_rva = 0;
    LPTHREAD_START_ROUTINE remote_init = NULL;

    if (!process || !dll_path) {
        return ERROR_INVALID_PARAMETER;
    }

    path_bytes = (wcslen(dll_path) + 1) * sizeof(wchar_t);
    remote_path = VirtualAllocEx(process, NULL, path_bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remote_path) {
        return GetLastError();
    }

    if (!WriteProcessMemory(process, remote_path, dll_path, path_bytes, NULL)) {
        result = GetLastError();
        goto cleanup;
    }

    if (config) {
        remote_config = VirtualAllocEx(process, NULL, sizeof(*config), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!remote_config) {
            result = GetLastError();
            goto cleanup;
        }
        if (!WriteProcessMemory(process, remote_config, config, sizeof(*config), NULL)) {
            result = GetLastError();
            goto cleanup;
        }
    }

    thread = CreateRemoteThread(process, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryW, remote_path, 0, NULL);
    if (!thread) {
        result = GetLastError();
        goto cleanup;
    }

    result = WaitForSingleObject(thread, REMOTE_INIT_TIMEOUT_MS);
    if (result != WAIT_OBJECT_0) {
        result = (result == WAIT_TIMEOUT) ? WAIT_TIMEOUT : GetLastError();
        goto cleanup;
    }
    if (!GetExitCodeThread(thread, &result) || result == 0) {
        result = GetLastError();
        if (result == ERROR_SUCCESS) {
            result = ERROR_MOD_NOT_FOUND;
        }
        goto cleanup;
    }
    CloseHandle(thread);
    thread = NULL;

    process_id = GetProcessId(process);
    if (process_id == 0) {
        result = GetLastError();
        goto cleanup;
    }

    result = find_remote_module_base_w(process_id, dll_path, &remote_module);
    if (result != ERROR_SUCCESS) {
        goto cleanup;
    }

    result = get_file_export_rva_w(dll_path, "PropagatorInitialize", &init_rva);
    if (result != ERROR_SUCCESS) {
        result = get_file_export_rva_w(dll_path, "PropagatorInitialize@4", &init_rva);
    }
    if (result != ERROR_SUCCESS) {
        result = get_file_export_rva_w(dll_path, "_PropagatorInitialize@4", &init_rva);
    }
    if (result != ERROR_SUCCESS) {
        goto cleanup;
    }

    remote_init = (LPTHREAD_START_ROUTINE)(remote_module + init_rva);

    thread = CreateRemoteThread(process, NULL, 0, remote_init, remote_config, 0, NULL);
    if (!thread) {
        result = GetLastError();
        goto cleanup;
    }

    result = WaitForSingleObject(thread, REMOTE_INIT_TIMEOUT_MS);
    if (result != WAIT_OBJECT_0) {
        result = (result == WAIT_TIMEOUT) ? WAIT_TIMEOUT : GetLastError();
        goto cleanup;
    }
    if (!GetExitCodeThread(thread, &result)) {
        result = GetLastError();
    }

cleanup:
    if (thread) {
        CloseHandle(thread);
    }
    if (remote_path) {
        VirtualFreeEx(process, remote_path, 0, MEM_RELEASE);
    }
    if (remote_config) {
        VirtualFreeEx(process, remote_config, 0, MEM_RELEASE);
    }
    return result;
}
