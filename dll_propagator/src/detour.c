#include <windows.h>
#include <stdint.h>
#include <string.h>
#include "detour.h"

#ifdef _WIN64
#define DETOUR_PATCH_SIZE 14
#define TRAMPOLINE_TAIL_SIZE 14
#else
#define DETOUR_PATCH_SIZE 6
#define TRAMPOLINE_TAIL_SIZE 6
#endif

#define MAX_PATCH_COPY 32
#define TRAMPOLINE_SIZE 128

struct INSN_INFO {
    SIZE_T length;
    int rel_offset;
    int rel_size;
    int rip_offset;
};

struct DETOUR_RECORD {
    void *target;
    void *trampoline;
    SIZE_T patch_size;
    BYTE original[MAX_PATCH_COPY];
    struct DETOUR_RECORD *next;
};

static CRITICAL_SECTION g_detour_lock;
static LONG g_detour_lock_ready = 0;
static struct DETOUR_RECORD *g_detours = NULL;

static void ensure_lock(void) {
    if (InterlockedCompareExchange(&g_detour_lock_ready, 1, 0) == 0) {
        InitializeCriticalSection(&g_detour_lock);
        InterlockedExchange(&g_detour_lock_ready, 2);
    }
    while (g_detour_lock_ready != 2) {
        Sleep(0);
    }
}

static BOOL is_int32(int64_t value) {
    return value >= INT32_MIN && value <= INT32_MAX;
}

static BOOL has_modrm(BYTE opcode, BOOL two_byte) {
    if (two_byte) {
        if ((opcode >= 0x80 && opcode <= 0x8F) || opcode == 0xAF || opcode == 0xB6 || opcode == 0xB7 ||
            opcode == 0xBE || opcode == 0xBF || opcode == 0x1F || opcode == 0x10 || opcode == 0x11 ||
            opcode == 0x28 || opcode == 0x29) {
            return TRUE;
        }
        return FALSE;
    }

    if (opcode < 0x40 && (opcode & 0x07) <= 3) return TRUE;
    if (opcode >= 0x80 && opcode <= 0x8F) return TRUE;
    if (opcode >= 0xC0 && opcode <= 0xC1) return TRUE;
    if (opcode >= 0xD0 && opcode <= 0xD3) return TRUE;
    if (opcode == 0x62 || opcode == 0x63 || opcode == 0x69 || opcode == 0x6B ||
        opcode == 0x84 || opcode == 0x85 || opcode == 0x86 || opcode == 0x87 ||
        opcode == 0x8D || opcode == 0x8F || opcode == 0xC6 || opcode == 0xC7 ||
        opcode == 0xF6 || opcode == 0xF7 || opcode == 0xFE || opcode == 0xFF) {
        return TRUE;
    }
    return FALSE;
}

static BOOL decode_instruction(const BYTE *code, struct INSN_INFO *info) {
    SIZE_T i = 0;
    BYTE opcode;
    BOOL two_byte = FALSE;
    BOOL operand_prefix = FALSE;
    BOOL address_prefix = FALSE;
    BOOL rex_w = FALSE;

    ZeroMemory(info, sizeof(*info));
    info->rel_offset = -1;
    info->rip_offset = -1;

    for (;;) {
        BYTE b = code[i];
        if (b == 0x66) {
            operand_prefix = TRUE;
            ++i;
        } else if (b == 0x67) {
            address_prefix = TRUE;
            ++i;
        } else if (b == 0xF0 || b == 0xF2 || b == 0xF3 ||
                   b == 0x2E || b == 0x36 || b == 0x3E || b == 0x26 || b == 0x64 || b == 0x65) {
            ++i;
#ifdef _WIN64
        } else if (b >= 0x40 && b <= 0x4F) {
            rex_w = (b & 0x08) != 0;
            ++i;
#endif
        } else {
            break;
        }
    }

    opcode = code[i++];
    if (opcode == 0x0F) {
        two_byte = TRUE;
        opcode = code[i++];
    }

    if (!two_byte) {
        if (opcode == 0xE8 || opcode == 0xE9) {
            info->rel_offset = (int)i;
            info->rel_size = 4;
            i += 4;
            info->length = i;
            return TRUE;
        }
        if (opcode == 0xEB || (opcode >= 0x70 && opcode <= 0x7F) || (opcode >= 0xE0 && opcode <= 0xE3)) {
            info->rel_offset = (int)i;
            info->rel_size = 1;
            i += 1;
            info->length = i;
            return TRUE;
        }
        if ((opcode >= 0xB8 && opcode <= 0xBF)) {
#ifdef _WIN64
            i += rex_w ? 8 : 4;
#else
            i += operand_prefix ? 2 : 4;
#endif
            info->length = i;
            return TRUE;
        }
        if (opcode == 0x68) {
            i += operand_prefix ? 2 : 4;
            info->length = i;
            return TRUE;
        }
        if (opcode == 0x6A) {
            i += 1;
            info->length = i;
            return TRUE;
        }
        if (opcode == 0xC2 || opcode == 0xCA) {
            i += 2;
            info->length = i;
            return TRUE;
        }
    } else if (opcode >= 0x80 && opcode <= 0x8F) {
        info->rel_offset = (int)i;
        info->rel_size = 4;
        i += 4;
        info->length = i;
        return TRUE;
    }

    if (has_modrm(opcode, two_byte)) {
        BYTE modrm = code[i++];
        BYTE mod = (modrm >> 6) & 0x03;
        BYTE reg = (modrm >> 3) & 0x07;
        BYTE rm = modrm & 0x07;

        if (!address_prefix && mod != 3 && rm == 4) {
            BYTE sib = code[i++];
            BYTE base = sib & 0x07;
            if (mod == 0 && base == 5) {
                i += 4;
            } else if (mod == 1) {
                i += 1;
            } else if (mod == 2) {
                i += 4;
            }
        } else if (mod == 0 && rm == 5) {
#ifdef _WIN64
            if (!address_prefix) {
                info->rip_offset = (int)i;
            }
#endif
            i += 4;
        } else if (mod == 1) {
            i += 1;
        } else if (mod == 2) {
            i += 4;
        }

        if (!two_byte) {
            if (opcode == 0x80 || opcode == 0x82 || opcode == 0x83 || opcode == 0xC0 ||
                opcode == 0xC1 || opcode == 0xC6) {
                i += 1;
            } else if (opcode == 0x81 || opcode == 0xC7 || opcode == 0x69) {
                i += operand_prefix ? 2 : 4;
            } else if (opcode == 0x6B) {
                i += 1;
            } else if (opcode == 0xF6 && (reg == 0 || reg == 1)) {
                i += 1;
            } else if (opcode == 0xF7 && (reg == 0 || reg == 1)) {
                i += operand_prefix ? 2 : 4;
            }
        }
    }

    if (i == 0 || i > 15) {
        return FALSE;
    }

    info->length = i;
    return TRUE;
}

static void write_abs_jump(BYTE *dst, void *target) {
#ifdef _WIN64
    dst[0] = 0xFF;
    dst[1] = 0x25;
    *(int32_t*)(dst + 2) = 0;
    *(uint64_t*)(dst + 6) = (uint64_t)(uintptr_t)target;
#else
    dst[0] = 0x68;
    *(uint32_t*)(dst + 1) = (uint32_t)(uintptr_t)target;
    dst[5] = 0xC3;
#endif
}

static void *alloc_near(void *target) {
#ifdef _WIN64
    SYSTEM_INFO si;
    BYTE *base = (BYTE*)target;
    BYTE *min_addr;
    BYTE *max_addr;
    SIZE_T step;
    MEMORY_BASIC_INFORMATION mbi;

    GetSystemInfo(&si);
    step = si.dwAllocationGranularity;
    min_addr = (base > (BYTE*)0x70000000) ? base - 0x70000000 : (BYTE*)si.lpMinimumApplicationAddress;
    max_addr = base + 0x70000000;
    if (max_addr > (BYTE*)si.lpMaximumApplicationAddress || max_addr < base) {
        max_addr = (BYTE*)si.lpMaximumApplicationAddress;
    }

    for (BYTE *p = base; p >= min_addr; p -= step) {
        if (VirtualQuery(p, &mbi, sizeof(mbi)) && mbi.State == MEM_FREE) {
            void *mem = VirtualAlloc(mbi.BaseAddress, TRAMPOLINE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (mem) return mem;
        }
        if (p < min_addr + step) break;
    }

    for (BYTE *p = base; p < max_addr; p += step) {
        if (VirtualQuery(p, &mbi, sizeof(mbi)) && mbi.State == MEM_FREE) {
            void *mem = VirtualAlloc(mbi.BaseAddress, TRAMPOLINE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (mem) return mem;
        }
    }
    return NULL;
#else
    (void)target;
    return VirtualAlloc(NULL, TRAMPOLINE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
#endif
}

static BOOL build_trampoline(BYTE *target, BYTE *trampoline, SIZE_T *patch_size) {
    SIZE_T copied = 0;
    SIZE_T out = 0;

    while (copied < DETOUR_PATCH_SIZE) {
        struct INSN_INFO insn;
        BYTE *src = target + copied;
        BYTE *dst = trampoline + out;

        if (!decode_instruction(src, &insn) || insn.length == 0 || copied + insn.length > MAX_PATCH_COPY) {
            return FALSE;
        }

        memcpy(dst, src, insn.length);

        if (insn.rel_offset >= 0) {
            int64_t old_disp = 0;
            int64_t abs_target;
            int64_t new_disp;

            if (insn.rel_size == 1) {
                old_disp = *(int8_t*)(src + insn.rel_offset);
            } else if (insn.rel_size == 4) {
                old_disp = *(int32_t*)(src + insn.rel_offset);
            }
            abs_target = (int64_t)(intptr_t)(src + insn.length) + old_disp;
            new_disp = abs_target - (int64_t)(intptr_t)(dst + insn.length);

            if (insn.rel_size == 1) {
                if (new_disp < INT8_MIN || new_disp > INT8_MAX) {
                    return FALSE;
                }
                *(int8_t*)(dst + insn.rel_offset) = (int8_t)new_disp;
            } else {
                if (!is_int32(new_disp)) {
                    return FALSE;
                }
                *(int32_t*)(dst + insn.rel_offset) = (int32_t)new_disp;
            }
        }

#ifdef _WIN64
        if (insn.rip_offset >= 0) {
            int64_t old_disp = *(int32_t*)(src + insn.rip_offset);
            int64_t abs_target = (int64_t)(intptr_t)(src + insn.length) + old_disp;
            int64_t new_disp = abs_target - (int64_t)(intptr_t)(dst + insn.length);
            if (!is_int32(new_disp)) {
                return FALSE;
            }
            *(int32_t*)(dst + insn.rip_offset) = (int32_t)new_disp;
        }
#endif

        copied += insn.length;
        out += insn.length;
    }

    write_abs_jump(trampoline + out, target + copied);
    *patch_size = copied;
    return TRUE;
}

BOOL DetourAttach(void *target, void *detour, void **original) {
    struct DETOUR_RECORD *record;
    BYTE patch[DETOUR_PATCH_SIZE];
    DWORD old_protect;

    if (!target || !detour || !original) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ensure_lock();
    EnterCriticalSection(&g_detour_lock);

    for (record = g_detours; record; record = record->next) {
        if (record->target == target) {
            *original = record->trampoline;
            LeaveCriticalSection(&g_detour_lock);
            return TRUE;
        }
    }

    record = (struct DETOUR_RECORD*)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sizeof(*record));
    if (!record) {
        LeaveCriticalSection(&g_detour_lock);
        SetLastError(ERROR_OUTOFMEMORY);
        return FALSE;
    }

    record->target = target;
    record->trampoline = alloc_near(target);
    if (!record->trampoline) {
        HeapFree(GetProcessHeap(), 0, record);
        LeaveCriticalSection(&g_detour_lock);
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        return FALSE;
    }

    if (!build_trampoline((BYTE*)target, (BYTE*)record->trampoline, &record->patch_size)) {
        VirtualFree(record->trampoline, 0, MEM_RELEASE);
        HeapFree(GetProcessHeap(), 0, record);
        LeaveCriticalSection(&g_detour_lock);
        SetLastError(ERROR_INVALID_FUNCTION);
        return FALSE;
    }

    memcpy(record->original, target, record->patch_size);
    write_abs_jump(patch, detour);

    if (!VirtualProtect(target, record->patch_size, PAGE_EXECUTE_READWRITE, &old_protect)) {
        VirtualFree(record->trampoline, 0, MEM_RELEASE);
        HeapFree(GetProcessHeap(), 0, record);
        LeaveCriticalSection(&g_detour_lock);
        return FALSE;
    }

    memcpy(target, patch, DETOUR_PATCH_SIZE);
    if (record->patch_size > DETOUR_PATCH_SIZE) {
        memset((BYTE*)target + DETOUR_PATCH_SIZE, 0x90, record->patch_size - DETOUR_PATCH_SIZE);
    }
    FlushInstructionCache(GetCurrentProcess(), target, record->patch_size);
    VirtualProtect(target, record->patch_size, old_protect, &old_protect);

    record->next = g_detours;
    g_detours = record;
    *original = record->trampoline;

    LeaveCriticalSection(&g_detour_lock);
    return TRUE;
}

BOOL DetourDetach(void *target) {
    struct DETOUR_RECORD **link;
    struct DETOUR_RECORD *record;
    DWORD old_protect;

    if (!target) {
        SetLastError(ERROR_INVALID_PARAMETER);
        return FALSE;
    }

    ensure_lock();
    EnterCriticalSection(&g_detour_lock);

    for (link = &g_detours; *link; link = &(*link)->next) {
        if ((*link)->target == target) {
            record = *link;
            if (!VirtualProtect(record->target, record->patch_size, PAGE_EXECUTE_READWRITE, &old_protect)) {
                LeaveCriticalSection(&g_detour_lock);
                return FALSE;
            }
            memcpy(record->target, record->original, record->patch_size);
            FlushInstructionCache(GetCurrentProcess(), record->target, record->patch_size);
            VirtualProtect(record->target, record->patch_size, old_protect, &old_protect);
            *link = record->next;
            VirtualFree(record->trampoline, 0, MEM_RELEASE);
            HeapFree(GetProcessHeap(), 0, record);
            LeaveCriticalSection(&g_detour_lock);
            return TRUE;
        }
    }

    LeaveCriticalSection(&g_detour_lock);
    SetLastError(ERROR_NOT_FOUND);
    return FALSE;
}

void DetourDetachAll(void) {
    struct DETOUR_RECORD *record;

    if (g_detour_lock_ready != 2) {
        return;
    }

    ensure_lock();
    EnterCriticalSection(&g_detour_lock);

    record = g_detours;
    while (record) {
        struct DETOUR_RECORD *next = record->next;
        DWORD old_protect;
        if (VirtualProtect(record->target, record->patch_size, PAGE_EXECUTE_READWRITE, &old_protect)) {
            memcpy(record->target, record->original, record->patch_size);
            FlushInstructionCache(GetCurrentProcess(), record->target, record->patch_size);
            VirtualProtect(record->target, record->patch_size, old_protect, &old_protect);
        }
        VirtualFree(record->trampoline, 0, MEM_RELEASE);
        HeapFree(GetProcessHeap(), 0, record);
        record = next;
    }
    g_detours = NULL;

    LeaveCriticalSection(&g_detour_lock);
}
