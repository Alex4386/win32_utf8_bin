#ifndef __DLL_INCLUDE__
#define __DLL_INCLUDE__

#if defined(__x86_64__)
// Propagator DLL
extern const char _binary_dll_propagator_x64_dll_start[];
extern const char _binary_dll_propagator_x64_dll_end[];

#define PROPAGATOR_START _binary_dll_propagator_x64_dll_start
#define PROPAGATOR_END _binary_dll_propagator_x64_dll_end

#elif defined(__i386__)
// Propagator DLL - x86 has no preceding underscore
extern const char binary_dll_propagator_x86_dll_start[];
extern const char binary_dll_propagator_x86_dll_end[];

#define PROPAGATOR_START binary_dll_propagator_x86_dll_start
#define PROPAGATOR_END binary_dll_propagator_x86_dll_end

#else
#error "Unsupported architecture"
#endif

#endif
