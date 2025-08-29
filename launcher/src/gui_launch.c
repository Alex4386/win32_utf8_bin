#include <windows.h>
#include <commdlg.h> // For GetOpenFileName
#include "config.h"

BOOL handleGuiLaunch(char *targetPath, int maxPathLen) {
    OPENFILENAMEA ofn;
    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = NULL;
    ofn.lpstrFile = targetPath;
    ofn.nMaxFile = maxPathLen;
    ofn.lpstrFilter = "Executable files (*.exe)\0*.exe\0All files (*.*)\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.lpstrFileTitle = NULL;
    ofn.nMaxFileTitle = 0;
    ofn.lpstrInitialDir = NULL;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    return GetOpenFileNameA(&ofn);

}
