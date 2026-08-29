/* Selective DNS spoofer.
 *
 * Queries for the mirrored hosts are answered with our own LAN IP, the update
 * hosts get NXDOMAIN, and everything else is forwarded upstream so the console
 * keeps working internet.
 *
 * Spoofs and blocks are answered on the receive thread - they need no I/O.
 * Only forwarding, which can block for the upstream timeout, is handed to a
 * small worker pool, so one slow upstream lookup can never stall the replies
 * the console actually cares about.
 */
#include "host.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define TYPE_A       1
#define UPSTREAM_MS  3000
#define NWORKERS     8
#define QDEPTH       64
#define MAXPKT       4096

extern volatile LONG g_stop;
static SOCKET dns_sock = INVALID_SOCKET;

/* Tears the socket down so the blocking recvfrom() in dns_thread returns and
 * the port is released immediately. Without this, Stop then Start fails with
 * WSAEADDRINUSE: the old socket is still bound and SO_EXCLUSIVEADDRUSE - which
 * we want, to avoid silently co-binding with ICS - forbids a second bind. */
void dns_shutdown(void)
{
    SOCKET s = dns_sock;

    dns_sock = INVALID_SOCKET;
    if (s != INVALID_SOCKET)
        closesocket(s);
}

typedef struct {
    unsigned char data[MAXPKT];
    int len;
    struct sockaddr_in from;
    char host[256];
} job;

static job          queue[QDEPTH];
static int          q_head, q_tail;
static CRITICAL_SECTION q_cs;
static HANDLE       q_sem;
static HANDLE       workers[NWORKERS];
static int          pool_up;

/* ------------------------------------------------------------ wire format */

/* Returns the offset just past the question, or -1. Compression pointers are
 * illegal in a question, so a packet using one is treated as malformed. */
static int parse_question(const unsigned char *d, int len, char *host,
                          int hostcap, int *qtype)
{
    int i = 12, used = 0;

    if (len < 12)
        return -1;
    host[0] = 0;

    while (i < len) {
        int n = d[i];
        if (n == 0) {
            i++;
            break;
        }
        if (n & 0xC0)
            return -1;
        i++;
        if (i + n > len || used + n + 2 >= hostcap)
            return -1;
        if (used)
            host[used++] = '.';
        memcpy(host + used, d + i, n);
        used += n;
        i += n;
    }
    host[used] = 0;
    if (!used || i + 4 > len)
        return -1;

    *qtype = (d[i] << 8) | d[i + 1];
    return i + 4;
}

static int build_answer(const unsigned char *q, int qend, int qtype,
                        const char *ip, unsigned char *out)
{
    int n = 0;

    memcpy(out, q, 2);                       /* transaction id */
    out[2] = 0x81; out[3] = 0x80;            /* QR=1 RD=1 RA=1 RCODE=0 */
    memcpy(out + 4, q + 4, 2);               /* qdcount, echoed */

    if (qtype != TYPE_A) {
        /* AAAA and friends: NOERROR with no answers, so the console falls
         * back to IPv4 cleanly instead of retrying. */
        memset(out + 6, 0, 6);
        memcpy(out + 12, q + 12, qend - 12);
        return qend;
    }

    out[6] = 0; out[7] = 1;                  /* ancount = 1 */
    memset(out + 8, 0, 4);
    memcpy(out + 12, q + 12, qend - 12);
    n = qend;

    out[n++] = 0xC0; out[n++] = 0x0C;        /* name -> offset 12 */
    out[n++] = 0x00; out[n++] = 0x01;        /* type A */
    out[n++] = 0x00; out[n++] = 0x01;        /* class IN */
    out[n++] = 0x00; out[n++] = 0x00;
    out[n++] = 0x00; out[n++] = 0x3C;        /* TTL 60 */
    out[n++] = 0x00; out[n++] = 0x04;        /* rdlength */
    *(uint32_t *)(out + n) = inet_addr(ip);
    n += 4;
    return n;
}

static int build_nxdomain(const unsigned char *q, int qend, unsigned char *out)
{
    memcpy(out, q, 2);
    out[2] = 0x81; out[3] = 0x83;            /* RCODE=3, NXDOMAIN */
    memcpy(out + 4, q + 4, 2);
    memset(out + 6, 0, 6);
    memcpy(out + 12, q + 12, qend - 12);
    return qend;
}

/* ---------------------------------------------------------------- workers */

static void forward(job *j)
{
    SOCKET up;
    struct sockaddr_in dst;
    unsigned char reply[MAXPKT];
    DWORD tmo = UPSTREAM_MS;
    int n;

    up = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (up == INVALID_SOCKET)
        return;
    setsockopt(up, SOL_SOCKET, SO_RCVTIMEO, (char *)&tmo, sizeof(tmo));

    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    dst.sin_port = htons(53);
    dst.sin_addr.s_addr = inet_addr(g_cfg.upstream);

    if (sendto(up, (char *)j->data, j->len, 0, (struct sockaddr *)&dst,
               sizeof(dst)) == j->len) {
        n = recv(up, (char *)reply, sizeof(reply), 0);
        if (n > 0)
            sendto(dns_sock, (char *)reply, n, 0,
                   (struct sockaddr *)&j->from, sizeof(j->from));
        else
            log_line("[DNS] fail  %s %s (upstream timeout)",
                     inet_ntoa(j->from.sin_addr), j->host);
    }
    closesocket(up);
}

static DWORD WINAPI worker(LPVOID unused)
{
    job local;

    (void)unused;
    /* The pool outlives a Stop/Start cycle: jobs are only ever queued while a
     * server is running, and exiting on g_stop would leave the pool empty
     * after a restart, silently killing upstream forwarding. */
    for (;;) {
        WaitForSingleObject(q_sem, INFINITE);

        EnterCriticalSection(&q_cs);
        if (q_head == q_tail) {
            LeaveCriticalSection(&q_cs);
            continue;
        }
        local = queue[q_tail];
        q_tail = (q_tail + 1) % QDEPTH;
        LeaveCriticalSection(&q_cs);

        forward(&local);
    }
    return 0;
}

static void enqueue(const unsigned char *d, int len, struct sockaddr_in *from,
                    const char *host)
{
    int next;

    EnterCriticalSection(&q_cs);
    next = (q_head + 1) % QDEPTH;
    if (next == q_tail) {                    /* saturated - drop, client retries */
        LeaveCriticalSection(&q_cs);
        return;
    }
    memcpy(queue[q_head].data, d, len);
    queue[q_head].len = len;
    queue[q_head].from = *from;
    strncpy(queue[q_head].host, host, sizeof(queue[q_head].host) - 1);
    queue[q_head].host[sizeof(queue[q_head].host) - 1] = 0;
    q_head = next;
    LeaveCriticalSection(&q_cs);

    ReleaseSemaphore(q_sem, 1, NULL);
}

/* ----------------------------------------------------------------- server */

DWORD WINAPI dns_thread(LPVOID arg)
{
    struct sockaddr_in addr, from;
    unsigned char pkt[MAXPKT], out[MAXPKT];
    BOOL excl = TRUE;
    int i;

    (void)arg;

    dns_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (dns_sock == INVALID_SOCKET) {
        log_line("[DNS] socket failed");
        return 1;
    }

    /* Not SO_REUSEADDR: on Windows that would let us silently co-bind with
     * whatever already owns :53 - usually Internet Connection Sharing - and
     * queries would then land on a random one of the two sockets. An
     * exclusive bind fails loudly instead. */
    setsockopt(dns_sock, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (char *)&excl,
               sizeof(excl));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((u_short)g_cfg.dns_port);
    addr.sin_addr.s_addr = inet_addr(g_cfg.ip);

    if (bind(dns_sock, (struct sockaddr *)&addr, sizeof(addr)) != 0) {
        log_line("[DNS] BIND FAILED on %s:%d - error %d",
                 g_cfg.ip, g_cfg.dns_port, WSAGetLastError());
        log_line("[DNS] Another DNS server already owns this address, or the");
        log_line("[DNS] IP is not one of this machine's. Internet Connection");
        log_line("[DNS] Sharing is the usual culprit:  net stop SharedAccess");
        closesocket(dns_sock);
        dns_sock = INVALID_SOCKET;
        return 1;
    }

    if (!pool_up) {
        InitializeCriticalSection(&q_cs);
        q_sem = CreateSemaphoreA(NULL, 0, QDEPTH, NULL);
        for (i = 0; i < NWORKERS; i++)
            workers[i] = CreateThread(NULL, 0, worker, NULL, 0, NULL);
        pool_up = 1;
    }

    log_line("[DNS] listening on %s:%d", g_cfg.ip, g_cfg.dns_port);

    while (!g_stop) {
        int fromlen = sizeof(from);
        int n = recvfrom(dns_sock, (char *)pkt, sizeof(pkt), 0,
                         (struct sockaddr *)&from, &fromlen);
        char host[256];
        int qtype, qend, len;
        const char *why;

        if (n < 12) {
            if (n < 0 && g_stop)
                break;
            continue;
        }

        qend = parse_question(pkt, n, host, sizeof(host), &qtype);
        if (qend < 0) {
            enqueue(pkt, n, &from, "<malformed>");
            continue;
        }
        str_lower(host);

        why = block_reason(host);
        if (why) {
            len = build_nxdomain(pkt, qend, out);
            sendto(dns_sock, (char *)out, len, 0, (struct sockaddr *)&from,
                   sizeof(from));
            log_line("[DNS] BLOCK %s %s (%s update host)",
                     inet_ntoa(from.sin_addr), host, why);
            continue;
        }

        /* The custom online site must resolve to the REAL server, even when
         * it is one of the hosts we also carry a mirror of - otherwise the
         * redirect would land straight back on our own offline copy. */
        if (g_cfg.custom_host[0]) {
            char *one = g_cfg.custom_host;
            if (suffix_match(host, &one, 1)) {
                enqueue(pkt, n, &from, host);
                log_line("[DNS] real  %s %s (custom site -> upstream)",
                         inet_ntoa(from.sin_addr), host);
                continue;
            }
        }

        if (suffix_match(host, g_cfg.spoof, g_cfg.nspoof)) {
            len = build_answer(pkt, qend, qtype, g_cfg.ip, out);
            sendto(dns_sock, (char *)out, len, 0, (struct sockaddr *)&from,
                   sizeof(from));
            if (qtype == TYPE_A)
                log_line("[DNS] SPOOF %s %s (A) -> %s",
                         inet_ntoa(from.sin_addr), host, g_cfg.ip);
            else
                log_line("[DNS] SPOOF %s %s (type%d) -> empty",
                         inet_ntoa(from.sin_addr), host, qtype);
            continue;
        }

        enqueue(pkt, n, &from, host);
    }

    dns_shutdown();
    log_line("[DNS] stopped, port released");
    return 0;
}
