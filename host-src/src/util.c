/* Logging, path discovery, LAN IP detection and small string helpers. */
#include "host.h"
#include <iphlpapi.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>

cfg_t g_cfg;

/* ----------------------------------------------------------------- logging */

/* Lines are queued for the GUI and echoed to the console when one is attached.
 * A ring keeps a burst of DNS traffic from growing without bound. */
#define LOG_RING 512
#define LOG_LINE 512

static CRITICAL_SECTION log_cs;
static int  log_ready;
static int  log_gui;
static char log_buf[LOG_RING][LOG_LINE];
static int  log_head, log_tail;

static void log_init(void)
{
    if (!log_ready) {
        InitializeCriticalSection(&log_cs);
        log_ready = 1;
    }
}

void log_set_gui(int on)
{
    log_init();
    log_gui = on;
}

void log_line(const char *fmt, ...)
{
    char line[LOG_LINE];
    va_list ap;
    int next;

    va_start(ap, fmt);
    vsnprintf(line, sizeof(line) - 2, fmt, ap);
    va_end(ap);

    log_init();

    if (!log_gui) {
        printf("%s\n", line);
        fflush(stdout);
        return;
    }

    EnterCriticalSection(&log_cs);
    next = (log_head + 1) % LOG_RING;
    if (next == log_tail)                    /* full: drop the oldest */
        log_tail = (log_tail + 1) % LOG_RING;
    strcpy(log_buf[log_head], line);
    log_head = next;
    LeaveCriticalSection(&log_cs);
}

int log_drain(char *buf, int cap)
{
    int used = 0;

    log_init();
    EnterCriticalSection(&log_cs);
    while (log_tail != log_head) {
        int n = (int)strlen(log_buf[log_tail]);
        if (used + n + 3 >= cap)
            break;
        memcpy(buf + used, log_buf[log_tail], n);
        used += n;
        buf[used++] = '\r';
        buf[used++] = '\n';
        log_tail = (log_tail + 1) % LOG_RING;
    }
    LeaveCriticalSection(&log_cs);
    buf[used] = 0;
    return used;
}

/* ------------------------------------------------------------------- paths */

void exe_path(char *out, int cap)
{
    DWORD n = GetModuleFileNameA(NULL, out, (DWORD)cap);
    if (n == 0 || n >= (DWORD)cap)
        out[0] = 0;
}

void exe_dir(char *out, int cap)
{
    char *p;

    exe_path(out, cap);
    p = strrchr(out, '\\');
    if (p)
        *p = 0;
}

/* ------------------------------------------------------------------ string */

void str_lower(char *s)
{
    for (; *s; s++)
        if (*s >= 'A' && *s <= 'Z')
            *s += 32;
}

int str_ieq(const char *a, const char *b)
{
    return _stricmp(a, b) == 0;
}

/* True when host equals one of domains or is a subdomain of one. Matching the
 * dot explicitly is what stops notupdate.playstation.net.evil.com from being
 * treated as a match for update.playstation.net. */
int suffix_match(const char *host, char *const *domains, int n)
{
    size_t hl = strlen(host);
    int i;

    for (i = 0; i < n; i++) {
        size_t dl = strlen(domains[i]);
        if (hl == dl && _stricmp(host, domains[i]) == 0)
            return 1;
        if (hl > dl + 1 && host[hl - dl - 1] == '.' &&
            _stricmp(host + hl - dl, domains[i]) == 0)
            return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ LAN IP */

/* Best-guess LAN IP: the source address the OS would use to reach the default
 * route. connect() on a UDP socket sends nothing, it just picks the route. */
void detect_lan_ip(char *out, int cap)
{
    SOCKET s;
    struct sockaddr_in dst, me;
    int len = sizeof(me);
    PIP_ADAPTER_INFO info = NULL, p;
    ULONG sz = 0;

    out[0] = 0;

    s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s != INVALID_SOCKET) {
        memset(&dst, 0, sizeof(dst));
        dst.sin_family = AF_INET;
        dst.sin_port = htons(80);
        dst.sin_addr.s_addr = inet_addr("8.8.8.8");
        if (connect(s, (struct sockaddr *)&dst, sizeof(dst)) == 0 &&
            getsockname(s, (struct sockaddr *)&me, &len) == 0) {
            const char *ip = inet_ntoa(me.sin_addr);
            if (ip && strncmp(ip, "169.254.", 8) != 0) {
                strncpy(out, ip, cap - 1);
                out[cap - 1] = 0;
            }
        }
        closesocket(s);
    }
    if (out[0])
        return;

    /* Fall back to the first private, non-APIPA adapter address. */
    if (GetAdaptersInfo(NULL, &sz) == ERROR_BUFFER_OVERFLOW)
        info = (PIP_ADAPTER_INFO)malloc(sz);
    if (info && GetAdaptersInfo(info, &sz) == NO_ERROR) {
        for (p = info; p; p = p->Next) {
            const char *ip = p->IpAddressList.IpAddress.String;
            if (!ip[0] || strcmp(ip, "0.0.0.0") == 0)
                continue;
            if (strncmp(ip, "127.", 4) == 0 || strncmp(ip, "169.254.", 8) == 0)
                continue;
            strncpy(out, ip, cap - 1);
            out[cap - 1] = 0;
            break;
        }
    }
    free(info);

    if (!out[0])
        strncpy(out, "0.0.0.0", cap - 1);
}

int ip_is_local(const char *ip)
{
    char mine[64];
    detect_lan_ip(mine, sizeof(mine));
    return strcmp(mine, ip) == 0;
}
