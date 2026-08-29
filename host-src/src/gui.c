/* Win32 dialog front end.
 *
 * Same controls and the same dark palette the tkinter build had: an IP box
 * prefilled with the detected LAN address but still editable, Start/Stop, the
 * two independent update-block checkboxes, the guide-site picker, firewall
 * buttons and a live log. The checkboxes take effect immediately - the DNS
 * threads read the toggles per query, so there is nothing to restart.
 *
 * The log is a RichEdit rather than a plain EDIT so each line can keep the
 * colour of its subsystem; a plain edit control has a single text colour for
 * the whole buffer.
 */
#include "host.h"
#include "resource.h"
#include <commctrl.h>
#include <richedit.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TIMER_LOG 1

/* Palette, carried over from the Python build. */
#define COL_BG      RGB(0x12, 0x14, 0x1a)
#define COL_LOGBG   RGB(0x0b, 0x0d, 0x12)
#define COL_FG      RGB(0xd8, 0xde, 0xe9)
#define COL_ACCENT  RGB(0xff, 0x33, 0x66)
#define COL_RUN     RGB(0x48, 0xd1, 0x8a)
#define COL_STOP    RGB(0xe0, 0xb0, 0x50)

#define COL_DNS     RGB(0x6f, 0xb3, 0xff)
#define COL_HTTP    RGB(0x48, 0xd1, 0x8a)
#define COL_TLS     RGB(0xc7, 0x92, 0xea)
#define COL_FW      RGB(0xe0, 0xb0, 0x50)
#define COL_ERR     RGB(0xff, 0x5f, 0x6d)
#define COL_STAR    RGB(0x9a, 0xa4, 0xb2)

#define COL_HINT    RGB(0x6b, 0x72, 0x80)
#define IP_HINT     "enter pc ip here"

static HBRUSH g_bg_brush;
static HBRUSH g_logbg_brush;
static HFONT  g_title_font;
static HFONT  g_log_font;
static int    g_running;

/* The IP box shows its own greyed hint rather than a cue banner: cue banners
 * need comctl32 v6, which would mean shipping a manifest, and this way the
 * placeholder colour is ours to control. */
static int    g_ip_hint;

static void ip_show_hint(HWND dlg)
{
    g_ip_hint = 1;
    SetDlgItemTextA(dlg, IDC_IP, IP_HINT);
    InvalidateRect(GetDlgItem(dlg, IDC_IP), NULL, TRUE);
}

static void ip_clear_hint(HWND dlg)
{
    if (!g_ip_hint)
        return;
    g_ip_hint = 0;
    SetDlgItemTextA(dlg, IDC_IP, "");
    InvalidateRect(GetDlgItem(dlg, IDC_IP), NULL, TRUE);
}

/* Colour a log line by which subsystem emitted it. */
static COLORREF colour_for(const char *line)
{
    if (strncmp(line, "[DNS]", 5) == 0)   return COL_DNS;
    if (strncmp(line, "[HTTPS]", 7) == 0) return COL_HTTP;
    if (strncmp(line, "[HTTP]", 6) == 0)  return COL_HTTP;
    if (strncmp(line, "[TLS]", 5) == 0)   return COL_TLS;
    if (strncmp(line, "[FW]", 4) == 0)    return COL_FW;
    if (strncmp(line, "[PAK]", 5) == 0)   return COL_ERR;
    if (strncmp(line, "[*]", 3) == 0 || line[0] == '=') return COL_STAR;
    if (strstr(line, "FAIL") || strstr(line, "ERROR") ||
        strstr(line, "failed")) return COL_ERR;
    return COL_FG;
}

static void rich_append(HWND re, const char *text, COLORREF colour)
{
    CHARFORMAT2A cf;
    int len = GetWindowTextLengthA(re);

    SendMessageA(re, EM_SETSEL, len, len);

    memset(&cf, 0, sizeof(cf));
    cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_COLOR;
    cf.crTextColor = colour;
    SendMessageA(re, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);

    SendMessageA(re, EM_REPLACESEL, FALSE, (LPARAM)text);
}

static void log_append(HWND dlg)
{
    char buf[16384];
    HWND re = GetDlgItem(dlg, IDC_LOG);
    char *line, *next;
    int autoscroll;

    if (!log_drain(buf, sizeof(buf)))
        return;

    /* Keep the control from growing without bound over a long session. */
    if (GetWindowTextLengthA(re) > 400000) {
        SetWindowTextA(re, "");
        SendMessageA(re, EM_SETBKGNDCOLOR, 0, (LPARAM)COL_LOGBG);
    }

    for (line = buf; line && *line; line = next) {
        char keep;
        next = strstr(line, "\r\n");
        if (next) {
            next += 2;
            keep = *next;
            *next = 0;
        } else {
            keep = 0;
        }
        rich_append(re, line, colour_for(line));
        if (next)
            *next = keep;
        if (next && !*next)
            break;
    }

    autoscroll = IsDlgButtonChecked(dlg, IDC_AUTOSCROLL) == BST_CHECKED;
    if (autoscroll)
        SendMessageA(re, EM_SCROLLCARET, 0, 0);
}

static void set_running(HWND dlg, int on)
{
    g_running = on;
    SetDlgItemTextA(dlg, IDC_STATUS, on ? "running" : "stopped");
    InvalidateRect(GetDlgItem(dlg, IDC_STATUS), NULL, TRUE);
    EnableWindow(GetDlgItem(dlg, IDC_START), !on);
    EnableWindow(GetDlgItem(dlg, IDC_STOP), on);
    EnableWindow(GetDlgItem(dlg, IDC_IP), !on);
    EnableWindow(GetDlgItem(dlg, IDC_GUIDE), !on);
}

static void read_toggles(HWND dlg)
{
    InterlockedExchange(&g_cfg.block_fw,
        IsDlgButtonChecked(dlg, IDC_BLOCK_FW) == BST_CHECKED);
    InterlockedExchange(&g_cfg.block_game,
        IsDlgButtonChecked(dlg, IDC_BLOCK_GAME) == BST_CHECKED);

    log_line("[*]    firmware updates: %s   game updates: %s",
             g_cfg.block_fw ? "BLOCKED" : "allowed",
             g_cfg.block_game ? "BLOCKED" : "allowed");
}

static void fill_guide(HWND dlg)
{
    HWND cb = GetDlgItem(dlg, IDC_GUIDE);
    int i, n = pak_host_count(), sel = 0;

    SendMessageA(cb, CB_RESETCONTENT, 0, 0);
    SendMessageA(cb, CB_ADDSTRING, 0, (LPARAM)"builtin");
    for (i = 0; i < n; i++) {
        const char *h = pak_host_name(i);
        int idx;
        if (strcmp(h, "_builtin") == 0)
            continue;
        idx = (int)SendMessageA(cb, CB_ADDSTRING, 0, (LPARAM)h);
        if (g_cfg.guide_site[0] && str_ieq(h, g_cfg.guide_site))
            sel = idx;
    }
    SendMessageA(cb, CB_SETCURSEL, sel, 0);
}

static void apply_guide(HWND dlg)
{
    char pick[128] = "";
    HWND cb = GetDlgItem(dlg, IDC_GUIDE);
    int idx = (int)SendMessageA(cb, CB_GETCURSEL, 0, 0);

    if (idx >= 0)
        SendMessageA(cb, CB_GETLBTEXT, idx, (LPARAM)pick);
    if (pick[0] == 0 || strcmp(pick, "builtin") == 0)
        g_cfg.guide_site[0] = 0;
    else {
        strncpy(g_cfg.guide_site, pick, sizeof(g_cfg.guide_site) - 1);
        g_cfg.guide_site[sizeof(g_cfg.guide_site) - 1] = 0;
    }
}

/* ------------------------------------------------------------- donations */

/* Taken verbatim from the Arsenal UI's DONATE_ADDRS
 * (D:\latestarsenal\assets\app.js), so both front ends stay in step. */
static const struct { const char *label, *addr; } DONATE[DON_COUNT] = {
    { "Bitcoin",        "bc1q03qy0d85px8z7nn882xzq5r7ny9k9dpvkzwc55" },
    { "Bitcoin",        "bc1qyug6sn9d9u6lsdn9pqpl59euldrwntrgm6uxtg" },
    { "USDC (SPL/SOL)", "E3cSJRoWvNjQkvNHMLmyN1dba4t4j3cdLjiYY8RXs28e" },
    { "USDT (BNB)",     "0x4FD7C01DF66F307Eb4D95E3b4981a71ca1Efda75" },
    { "Ethereum",       "0x4FD7C01DF66F307Eb4D95E3b4981a71ca1Efda75" },
    { "XMR/MON",        "47dgHAixRSmTC4y1Daf5xH3svZjKRNEHSenAQUzsnJucCtVx"
                        "Nodc4Y78ECACYibFvMhfLREzUvu2FPnUqcoZ94GzLfCfZrJ" },
};

static void copy_to_clipboard(HWND owner, const char *text)
{
    size_t n = strlen(text) + 1;
    HGLOBAL mem;
    void *p;

    if (!OpenClipboard(owner))
        return;
    EmptyClipboard();

    mem = GlobalAlloc(GMEM_MOVEABLE, n);
    if (mem) {
        p = GlobalLock(mem);
        memcpy(p, text, n);
        GlobalUnlock(mem);
        /* ownership passes to the clipboard - do not free mem */
        SetClipboardData(CF_TEXT, mem);
    }
    CloseClipboard();
}

static INT_PTR CALLBACK donate_proc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
    int i;

    switch (msg) {
    case WM_INITDIALOG:
        SendMessageA(GetDlgItem(dlg, IDC_DON_TITLE), WM_SETFONT,
                     (WPARAM)g_title_font, TRUE);
        for (i = 0; i < DON_COUNT; i++) {
            SetDlgItemTextA(dlg, DON_LABEL_BASE + i, DONATE[i].label);
            SetDlgItemTextA(dlg, DON_ADDR_BASE + i, DONATE[i].addr);
        }
        return TRUE;

    case WM_CTLCOLORDLG:
        return (INT_PTR)g_bg_brush;

    /* A read-only EDIT sends WM_CTLCOLORSTATIC rather than WM_CTLCOLOREDIT,
     * so the address boxes are picked out by control ID here. */
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLOREDIT: {
        HDC dc = (HDC)wp;
        int id = GetDlgCtrlID((HWND)lp);

        if (id >= DON_ADDR_BASE && id < DON_ADDR_BASE + DON_COUNT) {
            SetTextColor(dc, COL_FG);
            SetBkColor(dc, COL_LOGBG);
            return (INT_PTR)g_logbg_brush;
        }
        SetBkMode(dc, TRANSPARENT);
        SetTextColor(dc, id == IDC_DON_TITLE ? COL_ACCENT : COL_FG);
        return (INT_PTR)g_bg_brush;
    }

    case WM_COMMAND: {
        int id = LOWORD(wp);

        if (id >= DON_COPY_BASE && id < DON_COPY_BASE + DON_COUNT) {
            i = id - DON_COPY_BASE;
            copy_to_clipboard(dlg, DONATE[i].addr);
            log_line("[*]    copied %s address to the clipboard",
                     DONATE[i].label);
            /* Only the row just copied reads "Copied", so the label always
             * points at whatever is actually on the clipboard now. */
            for (i = 0; i < DON_COUNT; i++)
                SetDlgItemTextA(dlg, DON_COPY_BASE + i, "Copy");
            SetDlgItemTextA(dlg, id, "Copied");
            return TRUE;
        }
        if (id == IDCANCEL) {
            EndDialog(dlg, 0);
            return TRUE;
        }
        return FALSE;
    }

    case WM_CLOSE:
        EndDialog(dlg, 0);
        return TRUE;
    }
    return FALSE;
}

static DWORD WINAPI fw_open_thread(LPVOID unused)
{
    (void)unused;
    fw_open_ports();
    return 0;
}

static DWORD WINAPI fw_off_thread(LPVOID unused)
{
    (void)unused;
    fw_set(0);
    return 0;
}

static void do_start(HWND dlg)
{
    char ip[64], custom[512];

    GetDlgItemTextA(dlg, IDC_IP, ip, sizeof(ip));
    /* Judged from the text actually in the box, not from the hint flag: text
     * can be set programmatically without the box ever taking focus, and that
     * must not be overridden. */
    if (ip[0] == 0 || strcmp(ip, IP_HINT) == 0) {
        detect_lan_ip(ip, sizeof(ip));
        log_line("[*]    no IP entered - falling back to the detected %s", ip);
    }
    g_ip_hint = 0;
    strncpy(g_cfg.ip, ip, sizeof(g_cfg.ip) - 1);
    g_cfg.ip[sizeof(g_cfg.ip) - 1] = 0;
    SetDlgItemTextA(dlg, IDC_IP, g_cfg.ip);

    GetDlgItemTextA(dlg, IDC_CUSTOM, custom, sizeof(custom));
    custom_set(custom);
    if (g_cfg.custom_url[0]) {
        log_line("[*]    User's Guide redirects to %s", g_cfg.custom_url);
        log_line("[*]    %s resolves to the REAL internet, not our mirror",
                 g_cfg.custom_host);
    }

    apply_guide(dlg);
    read_toggles(dlg);
    servers_start();
    set_running(dlg, 1);
}

static void init_theme(HWND dlg)
{
    HWND re = GetDlgItem(dlg, IDC_LOG);
    HDC dc = GetDC(dlg);
    int dpi = GetDeviceCaps(dc, LOGPIXELSY);
    ReleaseDC(dlg, dc);

    g_bg_brush = CreateSolidBrush(COL_BG);
    g_logbg_brush = CreateSolidBrush(COL_LOGBG);

    g_title_font = CreateFontA(-MulDiv(15, dpi, 72), 0, 0, 0, FW_BOLD, 0, 0, 0,
                               DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                               CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                               DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");
    g_log_font = CreateFontA(-MulDiv(10, dpi, 72), 0, 0, 0, FW_NORMAL, 0, 0, 0,
                             DEFAULT_CHARSET, OUT_DEFAULT_PRECIS,
                             CLIP_DEFAULT_PRECIS, CLEARTYPE_QUALITY,
                             FIXED_PITCH | FF_MODERN, "Consolas");

    SendMessageA(GetDlgItem(dlg, IDC_TITLE), WM_SETFONT, (WPARAM)g_title_font, TRUE);
    SendMessageA(re, WM_SETFONT, (WPARAM)g_log_font, TRUE);
    SendMessageA(re, EM_SETBKGNDCOLOR, 0, (LPARAM)COL_LOGBG);
    SendMessageA(re, EM_LIMITTEXT, (WPARAM)-1, 0);
    SendMessageA(re, EM_EXLIMITTEXT, 0, (LPARAM)0x7FFFFFFF);
}

/* The log and the IP box are laid out relative to the dialog edges so the
 * window stays useful when resized - the log takes all the leftover space. */
static void layout(HWND dlg)
{
    RECT rc, lg;
    HWND re = GetDlgItem(dlg, IDC_LOG);

    if (!re)
        return;
    GetClientRect(dlg, &rc);
    GetWindowRect(re, &lg);
    MapWindowPoints(NULL, dlg, (LPPOINT)&lg, 2);

    MoveWindow(re, lg.left, lg.top,
               rc.right - lg.left * 2,
               rc.bottom - lg.top - lg.left, TRUE);
}

static INT_PTR CALLBACK dlg_proc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp)
{
    switch (msg) {
    case WM_INITDIALOG: {
        char line[256], detected[64];

        init_theme(dlg);

        ip_show_hint(dlg);
        /* Seed the box from --url, otherwise pressing Start would read an
         * empty control and silently discard what was passed on the command
         * line. */
        SetDlgItemTextA(dlg, IDC_CUSTOM, g_cfg.custom_url);
        CheckDlgButton(dlg, IDC_BLOCK_FW,
                       g_cfg.block_fw ? BST_CHECKED : BST_UNCHECKED);
        CheckDlgButton(dlg, IDC_BLOCK_GAME,
                       g_cfg.block_game ? BST_CHECKED : BST_UNCHECKED);
        CheckDlgButton(dlg, IDC_AUTOSCROLL, BST_CHECKED);

        snprintf(line, sizeof(line),
                 "%d site(s) available (exe + sites\\ folder) + %s",
                 pak_host_count(), GUIDE_HOST);
        SetDlgItemTextA(dlg, IDC_SITES, line);

        fill_guide(dlg);
        SetTimer(dlg, TIMER_LOG, 120, NULL);

        /* No auto-start: the IP has to be typed in first. Report what we
         * detected so it can just be copied in if it looks right. */
        detect_lan_ip(detected, sizeof(detected));
        log_line("[*]    ready - enter this PC's IP, then press Start");
        log_line("[*]    detected LAN IP looks like %s", detected);

        /* Focus the Start button, not the IP box: if the edit had focus at
         * startup its EN_SETFOCUS would fire immediately and wipe the hint
         * before it was ever seen. Returning FALSE keeps this focus. */
        SetFocus(GetDlgItem(dlg, IDC_START));
        return FALSE;
    }

    /* Dark theme: the dialog face, every static/checkbox label and the IP box
     * all have to be repainted, otherwise Windows draws them system-grey on
     * top of the dark background. */
    case WM_CTLCOLORDLG:
        return (INT_PTR)g_bg_brush;

    case WM_CTLCOLORSTATIC: {
        HDC dc = (HDC)wp;
        int id = GetDlgCtrlID((HWND)lp);

        SetBkMode(dc, TRANSPARENT);
        if (id == IDC_TITLE)
            SetTextColor(dc, COL_ACCENT);
        else if (id == IDC_STATUS)
            SetTextColor(dc, g_running ? COL_RUN : COL_STOP);
        else
            SetTextColor(dc, COL_FG);
        return (INT_PTR)g_bg_brush;
    }

    case WM_CTLCOLOREDIT: {
        HDC dc = (HDC)wp;
        int id = GetDlgCtrlID((HWND)lp);

        SetTextColor(dc, (id == IDC_IP && g_ip_hint) ? COL_HINT : COL_FG);
        SetBkColor(dc, COL_LOGBG);
        return (INT_PTR)g_logbg_brush;
    }

    case WM_SIZE:
        layout(dlg);
        return TRUE;

    case WM_GETMINMAXINFO: {
        MINMAXINFO *mmi = (MINMAXINFO *)lp;
        mmi->ptMinTrackSize.x = 720;
        mmi->ptMinTrackSize.y = 420;
        return TRUE;
    }

    case WM_TIMER:
        if (wp == TIMER_LOG)
            log_append(dlg);
        return TRUE;

    case WM_COMMAND:
        /* Hint clears when the box is focused and comes back if it is left
         * empty, so Start always has something sensible to read. */
        if (LOWORD(wp) == IDC_IP) {
            if (HIWORD(wp) == EN_SETFOCUS) {
                ip_clear_hint(dlg);
                return TRUE;
            }
            if (HIWORD(wp) == EN_KILLFOCUS) {
                char cur[64];
                GetDlgItemTextA(dlg, IDC_IP, cur, sizeof(cur));
                if (cur[0] == 0)
                    ip_show_hint(dlg);
                return TRUE;
            }
            return FALSE;
        }

        /* The URL applies live: both the redirect and the DNS carve-out read
         * it per request, so it can be changed without stopping the server. */
        if (LOWORD(wp) == IDC_CUSTOM && HIWORD(wp) == EN_KILLFOCUS) {
            char cur[512], before[512];
            snprintf(before, sizeof(before), "%s", g_cfg.custom_url);
            GetDlgItemTextA(dlg, IDC_CUSTOM, cur, sizeof(cur));
            custom_set(cur);
            if (strcmp(before, g_cfg.custom_url) != 0) {
                if (g_cfg.custom_url[0])
                    log_line("[*]    online site set: %s (host %s -> upstream)",
                             g_cfg.custom_url, g_cfg.custom_host);
                else
                    log_line("[*]    online site cleared - serving bundled sites");
            }
            return TRUE;
        }

        switch (LOWORD(wp)) {
        case IDC_CUSTOM_CLEAR:
            SetDlgItemTextA(dlg, IDC_CUSTOM, "");
            custom_set("");
            log_line("[*]    online site cleared - serving bundled sites");
            return TRUE;
        case IDC_START:
            do_start(dlg);
            return TRUE;
        case IDC_STOP:
            servers_stop();
            set_running(dlg, 0);
            return TRUE;
        case IDC_BLOCK_FW:
        case IDC_BLOCK_GAME:
            read_toggles(dlg);
            return TRUE;
        case IDC_FW_OPEN:
            CloseHandle(CreateThread(NULL, 0, fw_open_thread, NULL, 0, NULL));
            return TRUE;
        case IDC_FW_OFF:
            CloseHandle(CreateThread(NULL, 0, fw_off_thread, NULL, 0, NULL));
            return TRUE;
        case IDC_DONATE: {
            INT_PTR rc = DialogBoxParamA(GetModuleHandleA(NULL),
                                         MAKEINTRESOURCEA(IDD_DONATE), dlg,
                                         donate_proc, 0);
            if (rc == -1)
                log_line("[*]    donate dialog failed to open (err %lu)",
                         GetLastError());
            return TRUE;
        }
        case IDCANCEL:
            servers_stop();
            EndDialog(dlg, 0);
            return TRUE;
        }
        return FALSE;

    case WM_CLOSE:
        servers_stop();
        EndDialog(dlg, 0);
        return TRUE;
    }
    return FALSE;
}

int gui_run(void)
{
    INITCOMMONCONTROLSEX icc;
    HMODULE rich;

    icc.dwSize = sizeof(icc);
    icc.dwICC = ICC_STANDARD_CLASSES;
    InitCommonControlsEx(&icc);

    /* RICHEDIT50W lives in Msftedit.dll and must be loaded before the dialog
     * template referencing it is instantiated, or the control silently fails
     * to create and the whole dialog comes back NULL. */
    rich = LoadLibraryA("Msftedit.dll");

    log_set_gui(1);
    DialogBoxParamA(GetModuleHandleA(NULL), MAKEINTRESOURCEA(IDD_MAIN), NULL,
                    dlg_proc, 0);

    if (g_bg_brush)    DeleteObject(g_bg_brush);
    if (g_logbg_brush) DeleteObject(g_logbg_brush);
    if (g_title_font)  DeleteObject(g_title_font);
    if (g_log_font)    DeleteObject(g_log_font);
    if (rich)          FreeLibrary(rich);
    return 0;
}
