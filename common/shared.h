#ifndef __COMMON_SHARED_H__
#define __COMMON_SHARED_H__

#include <windows.h>

#define PROPAGATOR_MAGIC 0x31504752u
#define PROPAGATOR_VERSION 1u
#define PROPAGATOR_MAX_PAYLOADS 8
#define PROPAGATOR_INIT_EXPORT_LEN 64
#define PROPAGATOR_INIT_DATA_LEN 64

typedef struct PROPAGATOR_PAYLOAD {
    wchar_t dll_path[MAX_PATH];
    char init_export[PROPAGATOR_INIT_EXPORT_LEN];
    DWORD flags;
    DWORD init_data_size;
    BYTE init_data[PROPAGATOR_INIT_DATA_LEN];
} PROPAGATOR_PAYLOAD;

typedef struct PROPAGATOR_CONFIG {
    DWORD magic;
    DWORD version;
    DWORD flags;
    wchar_t propagator_path[MAX_PATH];
    DWORD payload_count;
    PROPAGATOR_PAYLOAD payloads[PROPAGATOR_MAX_PAYLOADS];
} PROPAGATOR_CONFIG;

BOOL write_resource_to_file(const char* path, const char* start, const char* end);
BOOL write_resource_to_file_w(const wchar_t* path, const unsigned char* start, const unsigned char* end);
DWORD get_file_export_rva_w(const wchar_t* dll_path, const char* export_name, DWORD_PTR* export_rva);
DWORD inject_and_initialize_propagator_w(HANDLE process, const wchar_t* dll_path, const PROPAGATOR_CONFIG* config);

#endif // __COMMON_SHARED_H__
