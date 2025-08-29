#ifndef __DLL_INCLUDE__
#define __DLL_INCLUDE__

#if defined(__x86_64__)
extern const unsigned char _binary_child_dll_start[];
extern const unsigned char _binary_child_dll_end[];
extern const unsigned int _binary_child_dll_size;

#define CHILD_START _binary_child_dll_start
#define CHILD_END _binary_child_dll_end
#define CHILD_SIZE _binary_child_dll_size

#elif defined(__i386__)
extern const unsigned char binary_child_dll_start[];
extern const unsigned char binary_child_dll_end[];
extern const unsigned int binary_child_dll_size;

#define CHILD_START binary_child_dll_start
#define CHILD_END binary_child_dll_end
#define CHILD_SIZE binary_child_dll_size

#else
#error "Unsupported architecture"
#endif

#endif
