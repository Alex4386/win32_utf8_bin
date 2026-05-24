#ifndef DETOUR_H
#define DETOUR_H

#include <windows.h>

BOOL DetourAttach(void *target, void *detour, void **original);
BOOL DetourDetach(void *target);
void DetourDetachAll(void);

#endif
