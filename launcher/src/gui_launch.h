#ifndef GUI_LAUNCH_H
#define GUI_LAUNCH_H

#include <windows.h>

typedef struct GUI_LAUNCH_OPTIONS {
    wchar_t target_path[MAX_PATH];
    wchar_t arguments[2048];
    wchar_t current_directory[MAX_PATH];
    BOOL use_arguments;
    BOOL use_current_directory;
    DWORD fallback_codepage;
} GUI_LAUNCH_OPTIONS;

BOOL handleGuiLaunch(GUI_LAUNCH_OPTIONS *options);

#endif // GUI_LAUNCH_H
