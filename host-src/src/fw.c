/* Windows Firewall helpers.
 *
 * netsh is shelled out to rather than using the COM firewall API: it is the
 * same command a user would run by hand, so what the tool does stays
 * inspectable, and its output can be echoed straight into the log.
 */
#include "host.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define RULE_TCP "PS Exploit Host (TCP-In)"
#define RULE_UDP "PS Exploit Host (UDP-In)"

/* Runs a command with no console window and captures its output. */
static int run_capture(const char *cmd, char *out, int cap)
{
    SECURITY_ATTRIBUTES sa;
    HANDLE rd = NULL, wr = NULL;
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    char *line;
    DWORD code = 1, got;
    int used = 0;

    if (out && cap)
        out[0] = 0;

    memset(&sa, 0, sizeof(sa));
    sa.nLength = sizeof(sa);
    sa.bInheritHandle = TRUE;
    if (!CreatePipe(&rd, &wr, &sa, 65536))
        return 1;
    SetHandleInformation(rd, HANDLE_FLAG_INHERIT, 0);

    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    si.hStdOutput = wr;
    si.hStdError = wr;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);

    line = _strdup(cmd);
    if (!CreateProcessA(NULL, line, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL,
                        NULL, &si, &pi)) {
        free(line);
        CloseHandle(rd);
        CloseHandle(wr);
        return 1;
    }
    free(line);
    CloseHandle(wr);

    if (out) {
        while (used < cap - 1 &&
               ReadFile(rd, out + used, cap - 1 - used, &got, NULL) && got)
            used += got;
        out[used] = 0;
    } else {
        char sink[512];
        while (ReadFile(rd, sink, sizeof(sink), &got, NULL) && got)
            ;
    }
    CloseHandle(rd);

    WaitForSingleObject(pi.hProcess, 30000);
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return (int)code;
}

int fw_is_admin(void)
{
    HANDLE tok = NULL;
    TOKEN_ELEVATION el;
    DWORD len = sizeof(el);
    int admin = 0;

    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tok)) {
        if (GetTokenInformation(tok, TokenElevation, &el, sizeof(el), &len))
            admin = el.TokenIsElevated != 0;
        CloseHandle(tok);
    }
    return admin;
}

int fw_enabled(void)
{
    char out[8192];
    run_capture("netsh advfirewall show allprofiles state", out, sizeof(out));
    /* "State  ON" for any profile means inbound traffic can be filtered. */
    return strstr(out, "ON") != NULL;
}

int fw_rules_present(int *tcp, int *udp)
{
    char out[8192];

    run_capture("netsh advfirewall firewall show rule name=\"" RULE_TCP "\"",
                out, sizeof(out));
    *tcp = (strstr(out, "No rules match") == NULL);

    run_capture("netsh advfirewall firewall show rule name=\"" RULE_UDP "\"",
                out, sizeof(out));
    *udp = (strstr(out, "No rules match") == NULL);

    return *tcp && *udp;
}

int fw_open_ports(void)
{
    char cmd[512], out[4096];
    int rc1, rc2;

    if (!fw_is_admin()) {
        log_line("[FW]   need administrator rights to add firewall rules");
        log_line("[FW]   right-click the exe and Run as administrator, or run:");
        log_line("[FW]     netsh advfirewall firewall add rule name=\"" RULE_TCP
                 "\" dir=in action=allow protocol=TCP localport=%d,%d",
                 g_cfg.http_port, g_cfg.https_port);
        return 0;
    }

    snprintf(cmd, sizeof(cmd),
             "netsh advfirewall firewall add rule name=\"" RULE_TCP "\" "
             "dir=in action=allow protocol=TCP localport=%d,%d",
             g_cfg.http_port, g_cfg.https_port);
    rc1 = run_capture(cmd, out, sizeof(out));

    snprintf(cmd, sizeof(cmd),
             "netsh advfirewall firewall add rule name=\"" RULE_UDP "\" "
             "dir=in action=allow protocol=UDP localport=%d",
             g_cfg.dns_port);
    rc2 = run_capture(cmd, out, sizeof(out));

    if (rc1 == 0 && rc2 == 0) {
        log_line("[FW]   opened inbound TCP %d,%d and UDP %d",
                 g_cfg.http_port, g_cfg.https_port, g_cfg.dns_port);
        return 1;
    }
    log_line("[FW]   netsh returned %d/%d - rules may not be in place", rc1, rc2);
    return 0;
}

int fw_remove_rules(void)
{
    char out[4096];
    int rc1, rc2;

    if (!fw_is_admin()) {
        log_line("[FW]   need administrator rights to remove firewall rules");
        return 0;
    }
    rc1 = run_capture("netsh advfirewall firewall delete rule name=\"" RULE_TCP "\"",
                      out, sizeof(out));
    rc2 = run_capture("netsh advfirewall firewall delete rule name=\"" RULE_UDP "\"",
                      out, sizeof(out));
    log_line("[FW]   removed this tool's firewall rules (%d/%d)", rc1, rc2);
    return rc1 == 0 || rc2 == 0;
}

int fw_set(int on)
{
    char out[4096];
    int rc;

    if (!fw_is_admin()) {
        log_line("[FW]   need administrator rights to change the firewall");
        return 0;
    }
    rc = run_capture(on ? "netsh advfirewall set allprofiles state on"
                        : "netsh advfirewall set allprofiles state off",
                     out, sizeof(out));
    log_line("[FW]   firewall turned %s (%d)", on ? "ON" : "OFF", rc);
    return rc == 0;
}
