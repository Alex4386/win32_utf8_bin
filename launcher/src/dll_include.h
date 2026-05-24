#ifndef __DLL_INCLUDE__
#define __DLL_INCLUDE__

#if defined(__x86_64__)
// Propagator DLL
extern const unsigned char _binary_dll_propagator_x64_dll_start[];
extern const unsigned char _binary_dll_propagator_x64_dll_end[];
extern const unsigned char _binary_win32_utf8_x64_dll_start[];
extern const unsigned char _binary_win32_utf8_x64_dll_end[];

#define PROPAGATOR_START _binary_dll_propagator_x64_dll_start
#define PROPAGATOR_END _binary_dll_propagator_x64_dll_end
#define PAYLOAD_START _binary_win32_utf8_x64_dll_start
#define PAYLOAD_END _binary_win32_utf8_x64_dll_end
#define PAYLOAD_NAME L"win32_utf8.x64.dll"

#elif defined(__i386__)
// Propagator DLL - x86 has no preceding underscore
extern const unsigned char binary_dll_propagator_x86_dll_start[];
extern const unsigned char binary_dll_propagator_x86_dll_end[];
extern const unsigned char binary_win32_utf8_x86_dll_start[];
extern const unsigned char binary_win32_utf8_x86_dll_end[];

#define PROPAGATOR_START binary_dll_propagator_x86_dll_start
#define PROPAGATOR_END binary_dll_propagator_x86_dll_end
#define PAYLOAD_START binary_win32_utf8_x86_dll_start
#define PAYLOAD_END binary_win32_utf8_x86_dll_end
#define PAYLOAD_NAME L"win32_utf8.x86.dll"

#else
#error "Unsupported architecture"
#endif

#endif
