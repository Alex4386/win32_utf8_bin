#include <windows.h>
#include <windowsx.h>
#include <commdlg.h>
#include <shlobj.h>
#include <stdlib.h>
#include "gui_launch.h"

#define IDC_APP_EDIT       1001
#define IDC_APP_BROWSE     1002
#define IDC_ARGS_CHECK     1003
#define IDC_ARGS_EDIT      1004
#define IDC_CWD_CHECK      1005
#define IDC_CWD_EDIT       1006
#define IDC_CWD_BROWSE     1007
#define IDC_CODEPAGE_COMBO 1008
#define IDC_LAUNCH         1009
#define IDC_CANCEL         1010

typedef struct GUI_STATE {
    GUI_LAUNCH_OPTIONS *options;
    HWND app_edit;
    HWND args_check;
    HWND args_edit;
    HWND cwd_check;
    HWND cwd_edit;
    HWND cwd_browse;
    HWND codepage_combo;
    BOOL finished;
    BOOL accepted;
} GUI_STATE;

typedef struct CODEPAGE_ENUM_STATE {
    HWND combo;
    int default_index;
    BOOL has_utf8;
} CODEPAGE_ENUM_STATE;

static CODEPAGE_ENUM_STATE *g_codepage_enum_state = NULL;

static void set_control_font(HWND hwnd, HFONT font) {
    SendMessageW(hwnd, WM_SETFONT, (WPARAM)font, TRUE);
}

static HWND add_control(HWND parent, const wchar_t *class_name, const wchar_t *text,
                        DWORD style, int x, int y, int w, int h, int id, HFONT font) {
    HWND hwnd = CreateWindowExW(0, class_name, text, style, x, y, w, h, parent,
                               (HMENU)(INT_PTR)id, GetModuleHandleW(NULL), NULL);
    if (hwnd && font) {
        set_control_font(hwnd, font);
    }
    return hwnd;
}

static BOOL browse_application(HWND owner, wchar_t *path, DWORD path_count) {
    OPENFILENAMEW ofn;

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = owner;
    ofn.lpstrFile = path;
    ofn.nMaxFile = path_count;
    ofn.lpstrFilter = L"Executable files (*.exe)\0*.exe\0All files (*.*)\0*.*\0";
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;
    return GetOpenFileNameW(&ofn);
}

static BOOL browse_directory(HWND owner, wchar_t *path, DWORD path_count) {
    BROWSEINFOW bi;
    PIDLIST_ABSOLUTE pidl;
    BOOL ok = FALSE;

    ZeroMemory(&bi, sizeof(bi));
    bi.hwndOwner = owner;
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    bi.lpszTitle = L"Select working directory";

    pidl = SHBrowseForFolderW(&bi);
    if (pidl) {
        ok = SHGetPathFromIDListW(pidl, path);
        CoTaskMemFree(pidl);
        if (ok) {
            path[path_count - 1] = L'\0';
        }
    }
    return ok;
}

static void update_enabled_state(GUI_STATE *state) {
    BOOL use_args = Button_GetCheck(state->args_check) == BST_CHECKED;
    BOOL use_cwd = Button_GetCheck(state->cwd_check) == BST_CHECKED;

    EnableWindow(state->args_edit, use_args);
    EnableWindow(state->cwd_edit, use_cwd);
    EnableWindow(state->cwd_browse, use_cwd);
}

static BOOL combo_has_codepage(HWND combo, DWORD codepage) {
    int count = (int)SendMessageW(combo, CB_GETCOUNT, 0, 0);
    int i;

    for (i = 0; i < count; ++i) {
        if ((DWORD)SendMessageW(combo, CB_GETITEMDATA, i, 0) == codepage) {
            return TRUE;
        }
    }
    return FALSE;
}

static int add_codepage_choice(HWND combo, DWORD codepage) {
    CPINFOEXW info;
    wchar_t label[160];
    int index;

    if (combo_has_codepage(combo, codepage)) {
        return -1;
    }

    if (GetCPInfoExW(codepage, 0, &info) && info.CodePageName[0]) {
        wsprintfW(label, L"%lu - %ls", codepage, info.CodePageName);
    } else {
        wsprintfW(label, L"%lu", codepage);
    }

    index = (int)SendMessageW(combo, CB_ADDSTRING, 0, (LPARAM)label);
    if (index >= 0) {
        SendMessageW(combo, CB_SETITEMDATA, index, (LPARAM)codepage);
    }
    return index;
}

static BOOL CALLBACK enum_codepage_proc(LPWSTR codepage_string) {
    CODEPAGE_ENUM_STATE *state = g_codepage_enum_state;
    wchar_t *end = NULL;
    DWORD codepage;
    int index;

    if (!state || !codepage_string || !codepage_string[0]) {
        return TRUE;
    }

    codepage = wcstoul(codepage_string, &end, 10);
    if (!end || *end != L'\0') {
        return TRUE;
    }

    index = add_codepage_choice(state->combo, codepage);
    if (codepage == 932 && index >= 0) {
        state->default_index = index;
    }
    if (codepage == CP_UTF8) {
        state->has_utf8 = TRUE;
    }
    return TRUE;
}

static void add_codepage_choices(HWND combo) {
    CODEPAGE_ENUM_STATE enum_state;
    int default_index;

    ZeroMemory(&enum_state, sizeof(enum_state));
    enum_state.combo = combo;
    enum_state.default_index = -1;

    g_codepage_enum_state = &enum_state;
    EnumSystemCodePagesW(enum_codepage_proc, CP_INSTALLED);
    g_codepage_enum_state = NULL;

    if (!enum_state.has_utf8) {
        add_codepage_choice(combo, CP_UTF8);
    }

    default_index = enum_state.default_index;
    if (default_index < 0) {
        DWORD acp = GetACP();
        int count = (int)SendMessageW(combo, CB_GETCOUNT, 0, 0);
        int i;

        for (i = 0; i < count; ++i) {
            if ((DWORD)SendMessageW(combo, CB_GETITEMDATA, i, 0) == acp) {
                default_index = i;
                break;
            }
        }
    }
    SendMessageW(combo, CB_SETCURSEL, default_index >= 0 ? default_index : 0, 0);
}

static BOOL collect_options(HWND hwnd, GUI_STATE *state) {
    int codepage_index;

    GetWindowTextW(state->app_edit, state->options->target_path, MAX_PATH);
    GetWindowTextW(state->args_edit, state->options->arguments,
                   sizeof(state->options->arguments) / sizeof(state->options->arguments[0]));
    GetWindowTextW(state->cwd_edit, state->options->current_directory, MAX_PATH);

    state->options->use_arguments = Button_GetCheck(state->args_check) == BST_CHECKED;
    state->options->use_current_directory = Button_GetCheck(state->cwd_check) == BST_CHECKED;

    codepage_index = (int)SendMessageW(state->codepage_combo, CB_GETCURSEL, 0, 0);
    if (codepage_index >= 0) {
        state->options->fallback_codepage =
            (DWORD)SendMessageW(state->codepage_combo, CB_GETITEMDATA, codepage_index, 0);
    } else {
        state->options->fallback_codepage = 932;
    }

    if (!state->options->target_path[0]) {
        MessageBoxW(hwnd, L"Select an application to launch.", L"win32_utf8 launcher",
                    MB_OK | MB_ICONEXCLAMATION);
        return FALSE;
    }
    if (state->options->use_current_directory && !state->options->current_directory[0]) {
        MessageBoxW(hwnd, L"Select a working directory or disable the CWD option.",
                    L"win32_utf8 launcher", MB_OK | MB_ICONEXCLAMATION);
        return FALSE;
    }
    return TRUE;
}

static LRESULT CALLBACK launch_wnd_proc(HWND hwnd, UINT msg, WPARAM wparam, LPARAM lparam) {
    GUI_STATE *state = (GUI_STATE*)GetWindowLongPtrW(hwnd, GWLP_USERDATA);

    switch (msg) {
        case WM_CREATE: {
            CREATESTRUCTW *cs = (CREATESTRUCTW*)lparam;
            HFONT font = (HFONT)GetStockObject(DEFAULT_GUI_FONT);

            state = (GUI_STATE*)cs->lpCreateParams;
            SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)state);

            add_control(hwnd, L"STATIC", L"Application", WS_CHILD | WS_VISIBLE,
                        14, 18, 120, 20, -1, font);
            state->app_edit = add_control(hwnd, L"EDIT", L"",
                        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
                        14, 40, 420, 24, IDC_APP_EDIT, font);
            add_control(hwnd, L"BUTTON", L"Browse...",
                        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                        444, 39, 86, 26, IDC_APP_BROWSE, font);

            state->args_check = add_control(hwnd, L"BUTTON", L"Launch with arguments",
                        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                        14, 78, 180, 22, IDC_ARGS_CHECK, font);
            state->args_edit = add_control(hwnd, L"EDIT", L"",
                        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
                        14, 102, 516, 24, IDC_ARGS_EDIT, font);

            state->cwd_check = add_control(hwnd, L"BUTTON", L"Launch from specific CWD",
                        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
                        14, 138, 210, 22, IDC_CWD_CHECK, font);
            state->cwd_edit = add_control(hwnd, L"EDIT", L"",
                        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL,
                        14, 162, 420, 24, IDC_CWD_EDIT, font);
            state->cwd_browse = add_control(hwnd, L"BUTTON", L"Browse...",
                        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                        444, 161, 86, 26, IDC_CWD_BROWSE, font);

            add_control(hwnd, L"STATIC", L"Fallback encoding", WS_CHILD | WS_VISIBLE,
                        14, 200, 130, 20, -1, font);
            state->codepage_combo = add_control(hwnd, L"COMBOBOX", L"",
                        WS_CHILD | WS_VISIBLE | CBS_DROPDOWNLIST | WS_VSCROLL,
                        150, 196, 210, 180, IDC_CODEPAGE_COMBO, font);
            add_codepage_choices(state->codepage_combo);

            add_control(hwnd, L"BUTTON", L"Launch",
                        WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON,
                        340, 232, 90, 28, IDC_LAUNCH, font);
            add_control(hwnd, L"BUTTON", L"Cancel",
                        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
                        440, 232, 90, 28, IDC_CANCEL, font);

            update_enabled_state(state);
            return 0;
        }
        case WM_COMMAND:
            switch (LOWORD(wparam)) {
                case IDC_APP_BROWSE: {
                    wchar_t path[MAX_PATH] = {0};
                    GetWindowTextW(state->app_edit, path, MAX_PATH);
                    if (browse_application(hwnd, path, MAX_PATH)) {
                        SetWindowTextW(state->app_edit, path);
                    }
                    return 0;
                }
                case IDC_CWD_BROWSE: {
                    wchar_t path[MAX_PATH] = {0};
                    GetWindowTextW(state->cwd_edit, path, MAX_PATH);
                    if (browse_directory(hwnd, path, MAX_PATH)) {
                        SetWindowTextW(state->cwd_edit, path);
                    }
                    return 0;
                }
                case IDC_ARGS_CHECK:
                case IDC_CWD_CHECK:
                    update_enabled_state(state);
                    return 0;
                case IDC_LAUNCH:
                    if (collect_options(hwnd, state)) {
                        state->accepted = TRUE;
                        state->finished = TRUE;
                        DestroyWindow(hwnd);
                    }
                    return 0;
                case IDC_CANCEL:
                    state->accepted = FALSE;
                    state->finished = TRUE;
                    DestroyWindow(hwnd);
                    return 0;
            }
            break;
        case WM_CLOSE:
            state->accepted = FALSE;
            state->finished = TRUE;
            DestroyWindow(hwnd);
            return 0;
    }
    return DefWindowProcW(hwnd, msg, wparam, lparam);
}

BOOL handleGuiLaunch(GUI_LAUNCH_OPTIONS *options) {
    WNDCLASSW wc;
    GUI_STATE state;
    HWND hwnd;
    MSG msg;
    const wchar_t class_name[] = L"Win32Utf8LaunchDialog";

    if (!options) {
        return FALSE;
    }

    ZeroMemory(options, sizeof(*options));
    options->fallback_codepage = 932;

    ZeroMemory(&state, sizeof(state));
    state.options = options;

    CoInitialize(NULL);

    ZeroMemory(&wc, sizeof(wc));
    wc.lpfnWndProc = launch_wnd_proc;
    wc.hInstance = GetModuleHandleW(NULL);
    wc.hCursor = LoadCursorW(NULL, (LPCWSTR)IDC_ARROW);
    wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
    wc.lpszClassName = class_name;
    RegisterClassW(&wc);

    hwnd = CreateWindowExW(WS_EX_DLGMODALFRAME, class_name, L"win32_utf8 launcher",
                           WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
                           CW_USEDEFAULT, CW_USEDEFAULT, 560, 310,
                           NULL, NULL, GetModuleHandleW(NULL), &state);
    if (!hwnd) {
        CoUninitialize();
        return FALSE;
    }

    ShowWindow(hwnd, SW_SHOW);
    UpdateWindow(hwnd);

    while (!state.finished && GetMessageW(&msg, NULL, 0, 0) > 0) {
        if (!IsDialogMessageW(hwnd, &msg)) {
            TranslateMessage(&msg);
            DispatchMessageW(&msg);
        }
    }

    CoUninitialize();
    return state.accepted;
}
