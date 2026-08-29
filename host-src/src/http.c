/* Static file server for the mirrored sites.
 *
 * Content comes from the archive appended to the exe, with an optional
 * sites\ folder next to the exe taking priority so a single page can be
 * swapped without repacking. The same request handler backs both the plain
 * :80 listener and the TLS one, via the http_sink indirection.
 */
#include "host.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern volatile LONG g_stop;

#define MAXREQ   16384
#define MAXPATH  1024

/* ------------------------------------------------------------------- mime */

static const char *mime_for(const char *path)
{
    static const struct { const char *ext, *type; } tbl[] = {
        { ".html", "text/html; charset=utf-8" },
        { ".htm",  "text/html; charset=utf-8" },
        /* mirrored pages keep their original .php URLs; they are static now */
        { ".php",  "text/html; charset=utf-8" },
        { ".js",   "application/javascript; charset=utf-8" },
        { ".mjs",  "application/javascript; charset=utf-8" },
        { ".css",  "text/css; charset=utf-8" },
        { ".json", "application/json" },
        { ".xml",  "application/xml" },
        { ".txt",  "text/plain; charset=utf-8" },
        { ".wasm", "application/wasm" },
        { ".appcache", "text/cache-manifest" },
        { ".elf",  "application/octet-stream" },
        { ".bin",  "application/octet-stream" },
        { ".prx",  "application/octet-stream" },
        { ".sprx", "application/octet-stream" },
        { ".self", "application/octet-stream" },
        { ".png",  "image/png" },
        { ".jpg",  "image/jpeg" },
        { ".jpeg", "image/jpeg" },
        { ".gif",  "image/gif" },
        { ".svg",  "image/svg+xml" },
        { ".ico",  "image/x-icon" },
        { ".webp", "image/webp" },
        /* locally mirrored CDN assets (Font Awesome / Google Fonts) */
        { ".woff", "font/woff" },
        { ".woff2","font/woff2" },
        { ".ttf",  "font/ttf" },
        { ".eot",  "application/vnd.ms-fontobject" },
    };
    const char *dot = strrchr(path, '.');
    const char *slash = strrchr(path, '/');
    size_t i;

    if (dot && (!slash || dot > slash)) {
        for (i = 0; i < sizeof(tbl) / sizeof(tbl[0]); i++)
            if (_stricmp(dot, tbl[i].ext) == 0)
                return tbl[i].type;
    } else if (slash && _stricmp(slash + 1, "css2") == 0) {
        return "text/css; charset=utf-8";     /* Google Fonts, extensionless */
    }
    return "application/octet-stream";
}

static int is_page_ext(const char *last)
{
    const char *dot = strrchr(last, '.');
    if (!dot)
        return 1;                             /* extensionless: treat as a page */
    return _stricmp(dot, ".html") == 0 || _stricmp(dot, ".htm") == 0;
}

/* ------------------------------------------------------------ disk override */

static int disk_read(const char *rel, unsigned char **out, uint64_t *len)
{
    char full[MAXPATH];
    char dir[MAX_PATH];
    HANDLE f;
    LARGE_INTEGER sz;
    DWORD got;
    unsigned char *buf;

    exe_dir(dir, sizeof(dir));
    snprintf(full, sizeof(full), "%s\\sites\\%s", dir, rel);
    { char *p; for (p = full; *p; p++) if (*p == '/') *p = '\\'; }

    f = CreateFileA(full, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                    FILE_ATTRIBUTE_NORMAL, NULL);
    if (f == INVALID_HANDLE_VALUE)
        return 0;
    if (!GetFileSizeEx(f, &sz) || sz.QuadPart > 512LL * 1024 * 1024) {
        CloseHandle(f);
        return 0;
    }
    buf = (unsigned char *)malloc((size_t)sz.QuadPart + 1);
    if (!buf) {
        CloseHandle(f);
        return 0;
    }
    if (!ReadFile(f, buf, (DWORD)sz.QuadPart, &got, NULL) ||
        got != (DWORD)sz.QuadPart) {
        free(buf);
        CloseHandle(f);
        return 0;
    }
    CloseHandle(f);
    *out = buf;
    *len = (uint64_t)sz.QuadPart;
    return 1;
}

/* Look a pak-relative path up on disk first, then in the archive. */
static const unsigned char *fetch(const char *rel, uint64_t *len, int *freeit)
{
    unsigned char *disk = NULL;

    if (disk_read(rel, &disk, len)) {
        *freeit = 1;
        return disk;
    }
    return pak_get(rel, len, freeit);
}

/* ---------------------------------------------------------------- routing */

/* The document root for a request, as a pak host prefix. */
static void root_for_host(const char *host, char *out, int cap)
{
    char h[256];
    const char *colon;

    out[0] = 0;
    if (host && host[0]) {
        strncpy(h, host, sizeof(h) - 1);
        h[sizeof(h) - 1] = 0;
        colon = strchr(h, ':');
        if (colon)
            h[colon - h] = 0;
        str_lower(h);

        if (pak_have_host(h)) {
            snprintf(out, cap, "%s", h);
            return;
        }
        if (strncmp(h, "www.", 4) == 0 && pak_have_host(h + 4)) {
            snprintf(out, cap, "%s", h + 4);
            return;
        }
    }

    /* The guide host lands on the configured site so the console gets the host
     * picker rather than being dropped straight into one exploit page. */
    if (g_cfg.guide_site[0] && pak_have_host(g_cfg.guide_site)) {
        snprintf(out, cap, "%s", g_cfg.guide_site);
        return;
    }
    snprintf(out, cap, "_builtin");
}

/* Map a URL path to an archive path.
 *
 * The site files live flat under their host folder, but the console reaches
 * them under whatever prefix the original URL had:
 *
 *     manuals.playstation.net/document/<locale>/ps5/main.js
 *     zecoxao.github.io/luasauce/main.js
 *
 * Every asset in a mirrored page is a relative link, so that prefix repeats on
 * each one. Rather than hardcode a mount point, leading segments are stripped
 * one at a time until a real file turns up. A literal hit always wins, so a
 * genuine subdirectory (psfree/, offsets/, payloads/) is never shadowed.
 */
static const unsigned char *resolve_req(const char *urlpath, const char *host,
                                        uint64_t *len, int *freeit,
                                        char *chosen, int chosencap)
{
    char root[256], clean[MAXPATH], cand[MAXPATH];
    char *parts[64];
    int nparts = 0, i, j;
    const unsigned char *body;
    char *p, *tok;

    root_for_host(host, root, sizeof(root));

    strncpy(clean, urlpath, sizeof(clean) - 1);
    clean[sizeof(clean) - 1] = 0;
    if ((p = strchr(clean, '?')) != NULL) *p = 0;
    if ((p = strchr(clean, '#')) != NULL) *p = 0;
    str_lower(clean);

    for (tok = strtok(clean, "/"); tok && nparts < 64; tok = strtok(NULL, "/")) {
        if (strcmp(tok, ".") == 0 || strcmp(tok, "..") == 0)
            continue;                          /* no traversal out of the root */
        parts[nparts++] = tok;
    }

    /* The TLS key material sits next to the exe; never hand it out. */
    if (nparts && (_stricmp(parts[nparts - 1], "snakeoil.pfx") == 0 ||
                   _stricmp(parts[nparts - 1], "snakeoil.pem") == 0 ||
                   _stricmp(parts[nparts - 1], "snakeoil.key") == 0))
        nparts = 0;

    if (nparts == 0) {
        snprintf(cand, sizeof(cand), "%s/index.html", root);
        body = fetch(cand, len, freeit);
        if (body) {
            snprintf(chosen, chosencap, "%s", cand);
        }
        return body;
    }

    for (i = 0; i < nparts; i++) {
        int used = snprintf(cand, sizeof(cand), "%s", root);
        for (j = i; j < nparts; j++)
            used += snprintf(cand + used, sizeof(cand) - used, "/%s", parts[j]);

        body = fetch(cand, len, freeit);
        if (body) {
            snprintf(chosen, chosencap, "%s", cand);
            return body;
        }

        /* directory request -> its index.html */
        snprintf(cand + used, sizeof(cand) - used, "/index.html");
        body = fetch(cand, len, freeit);
        if (body) {
            snprintf(chosen, chosencap, "%s", cand);
            return body;
        }
    }

    /* Unknown path: fall back to index.html only when it looks like a page
     * request. A missing .js or .elf must 404 - answering with HTML would be
     * served as script and fail with a confusing parse error instead. */
    if (is_page_ext(parts[nparts - 1])) {
        snprintf(cand, sizeof(cand), "%s/index.html", root);
        body = fetch(cand, len, freeit);
        if (body) {
            snprintf(chosen, chosencap, "%s", cand);
            return body;
        }
    }
    return NULL;
}

/* --------------------------------------------------------------- response */

static int sink_all(http_sink *s, const void *buf, uint64_t len)
{
    const char *p = (const char *)buf;

    while (len) {
        int chunk = (int)(len > 262144 ? 262144 : len);
        int n = s->send(s->ctx, p, chunk);
        if (n <= 0)
            return 0;
        p += n;
        len -= n;
    }
    return 1;
}

int http_serve_request(const char *req, int reqlen, http_sink *sink,
                       const char *peer)
{
    char method[16] = "", url[MAXPATH] = "", host[256] = "";
    char chosen[MAXPATH] = "", head[1024];
    const char *line, *eol;
    const unsigned char *body;
    uint64_t len = 0;
    /* keep=0 always: connections are one-shot (see http_conn loop). Keep-alive
     * reuse let rapid slopkit beacons coalesce on a connection; the reader only
     * consumes the first request per recv and discarded the rest, desyncing the
     * next read -> garbage method -> spurious 405 (killed poops ps1_prepare). */
    int freeit = 0, headonly, n, keep = 0;

    (void)reqlen;

    if (sscanf(req, "%15s %1023s", method, url) != 2)
        return 0;
    headonly = (_stricmp(method, "HEAD") == 0);
    if (!headonly && _stricmp(method, "GET") != 0 && _stricmp(method, "POST") != 0) {
        n = snprintf(head, sizeof(head),
                     "HTTP/1.1 405 Method Not Allowed\r\n"
                     "Content-Length: 0\r\nConnection: close\r\n\r\n");
        sink_all(sink, head, n);
        return 0;
    }

    for (line = strchr(req, '\n'); line; line = eol) {
        line++;
        eol = strchr(line, '\n');
        if (line[0] == '\r' || line[0] == '\n')
            break;
        if (_strnicmp(line, "Host:", 5) == 0) {
            const char *v = line + 5;
            int i = 0;
            while (*v == ' ' || *v == '\t') v++;
            while (v[i] && v[i] != '\r' && v[i] != '\n' && i < (int)sizeof(host) - 1) {
                host[i] = v[i];
                i++;
            }
            host[i] = 0;
        } else if (_strnicmp(line, "Connection:", 11) == 0) {
            if (strstr(line, "close") || strstr(line, "Close"))
                keep = 0;
        }
        if (!eol)
            break;
    }

    /* Telemetry beacons: /REPORT/... from our harness, /log/... from slopkit.
     * These carry their payload in the URL and want nothing back, but the
     * normal unknown-path rule would answer each one with the whole index page.
     * During a heap spray that is a real perturbation - tens of KB re-fetched
     * per mark, on a console browser, while the exploit is timing-sensitive -
     * so they get an empty 204 instead. The URL is still logged, which is the
     * entire point of them. */
    /* Matched anywhere in the path, not just at the start: slopkit's mark()
     * uses a RELATIVE url, so its beacons arrive under whatever prefix the
     * console is browsing - /document/en/ps5/log/... - and a leading-anchor
     * test silently misses every one of them. */
    if (strstr(url, "/REPORT/") || strstr(url, "/log/")) {
        n = snprintf(head, sizeof(head),
                     "HTTP/1.1 204 No Content\r\n"
                     "Cache-Control: no-store\r\n"
                     "Access-Control-Allow-Origin: *\r\n"
                     "Connection: close\r\n\r\n");
        sink_all(sink, head, n);
        log_line("[%s] %s %s%s", sink->tag ? sink->tag : "HTTP", peer,
                 host[0] ? host : "-", url);
        return 1;
    }

    /* ELF payload relay: .../api/payload/<name> streams sites/<site>/payloads/
     * <name> to the console's elfldr, which listens on TCP 9021 after a
     * jailbreak. The console IP is the request peer. GET or POST both work; the
     * ELF lives on the host, so the request carries no body. */
    {
        const char *ap = strstr(url, "/api/payload/");
        if (ap) {
            const char *nm = ap + 13;             /* after "/api/payload/" */
            char nbuf[128], iurl[160], echosen[MAXPATH], bj[160];
            const unsigned char *elf = NULL;
            uint64_t elen = 0;
            int efree = 0, ni = 0, okbytes = -1, bl;

            while (nm[ni] && nm[ni] != '?' && nm[ni] != '\r' && nm[ni] != '\n'
                   && ni < (int)sizeof(nbuf) - 1) {
                if (nm[ni] == '/' || nm[ni] == '\\') { ni = 0; break; }
                nbuf[ni] = nm[ni];
                ni++;
            }
            nbuf[ni] = 0;

            if (ni > 0 && !strstr(nbuf, "..")) {
                snprintf(iurl, sizeof(iurl), "/payloads/%s", nbuf);
                elf = resolve_req(iurl, host, &elen, &efree, echosen, sizeof(echosen));
                if (elf && elen > 0) {
                    SOCKET cs = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
                    if (cs != INVALID_SOCKET) {
                        struct sockaddr_in ta;
                        DWORD tmo = 15000;
                        memset(&ta, 0, sizeof(ta));
                        ta.sin_family = AF_INET;
                        ta.sin_port = htons(9021);
                        ta.sin_addr.s_addr = inet_addr(peer);
                        setsockopt(cs, SOL_SOCKET, SO_SNDTIMEO,
                                   (const char *)&tmo, sizeof(tmo));
                        if (ta.sin_addr.s_addr != INADDR_NONE
                            && connect(cs, (struct sockaddr *)&ta, sizeof(ta)) == 0) {
                            uint64_t off = 0;
                            int sok = 1, chunk, w;
                            while (off < elen) {
                                chunk = (int)(elen - off > 262144 ? 262144 : elen - off);
                                w = send(cs, (const char *)elf + off, chunk, 0);
                                if (w <= 0) { sok = 0; break; }
                                off += (uint64_t)w;
                            }
                            shutdown(cs, SD_SEND);
                            if (sok) okbytes = (int)elen;
                        }
                        closesocket(cs);
                    }
                    if (efree) free((void *)elf);
                }
            }

            if (okbytes >= 0)
                bl = snprintf(bj, sizeof(bj),
                              "{\"ok\":true,\"name\":\"%s\",\"bytes\":%d,\"port\":9021}",
                              nbuf, okbytes);
            else
                bl = snprintf(bj, sizeof(bj), "{\"ok\":false,\"name\":\"%s\"}", nbuf);
            n = snprintf(head, sizeof(head),
                         "HTTP/1.1 200 OK\r\n"
                         "Content-Type: application/json\r\n"
                         "Content-Length: %d\r\n"
                         "Cache-Control: no-store\r\n"
                         "Access-Control-Allow-Origin: *\r\n"
                         "Connection: close\r\n\r\n%s",
                         bl, bj);
            sink_all(sink, head, n);
            log_line("[%s] %s %s%s -> payload %s bytes=%d",
                     sink->tag ? sink->tag : "HTTP", peer, host[0] ? host : "-",
                     url, nbuf, okbytes);
            return 1;
        }
    }

    /* elfldr liveness probe: GET .../api/elfldr connect-tests the console (request
     * peer) on TCP 9021 with a short timeout and reports {"up":true|false}, so the
     * exploit page can skip straight to the payload screen when already jailbroken. */
    if (strstr(url, "/api/elfldr")) {
        int up = 0, bl;
        char bj[32];
        SOCKET cs = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (cs != INVALID_SOCKET) {
            struct sockaddr_in ta;
            u_long nb = 1;
            memset(&ta, 0, sizeof(ta));
            ta.sin_family = AF_INET;
            ta.sin_port = htons(9021);
            ta.sin_addr.s_addr = inet_addr(peer);
            ioctlsocket(cs, FIONBIO, &nb);
            if (ta.sin_addr.s_addr != INADDR_NONE) {
                fd_set wf;
                struct timeval tv;
                connect(cs, (struct sockaddr *)&ta, sizeof(ta));
                FD_ZERO(&wf);
                FD_SET(cs, &wf);
                tv.tv_sec = 1;
                tv.tv_usec = 500000;   /* 1.5s */
                if (select(0, NULL, &wf, NULL, &tv) == 1) {
                    int err = 0, el = sizeof(err);
                    getsockopt(cs, SOL_SOCKET, SO_ERROR, (char *)&err, &el);
                    if (err == 0) up = 1;
                }
            }
            closesocket(cs);
        }
        bl = snprintf(bj, sizeof(bj), "{\"up\":%s}", up ? "true" : "false");
        n = snprintf(head, sizeof(head),
                     "HTTP/1.1 200 OK\r\n"
                     "Content-Type: application/json\r\n"
                     "Content-Length: %d\r\n"
                     "Cache-Control: no-store\r\n"
                     "Access-Control-Allow-Origin: *\r\n"
                     "Connection: close\r\n\r\n%s",
                     bl, bj);
        sink_all(sink, head, n);
        log_line("[%s] %s %s -> elfldr up=%d",
                 sink->tag ? sink->tag : "HTTP", peer, url, up);
        return 1;
    }

    /* One-shot arming latch for poops-style slopkit pages. The exploit page
     * claims a host-visible latch before it does anything irreversible
     * (setuid(1), kernel corruption) so a reload cannot silently re-run it.
     *   GET .../latch             -> {"set":0} | {"set":1,...}
     *   GET .../latch/set-<text>  -> arm  -> {"set":1,...}
     *   GET .../latch/escalate-.. -> arm  -> {"set":1,...}
     *   GET .../latch/clear       -> disarm -> {"set":0}
     * In-memory + Interlocked so it is thread-safe across the :80/:443 conn
     * threads; a console reboot is a fresh boot anyway, and ?auto=1 clears it. */
    {
        const char *lp = strstr(url, "/latch");
        if (lp) {
            const char *sub = lp + 6;      /* the char right after "/latch" */
            static volatile LONG g_latch_set = 0;
            int handled = 1, ls;
            char body_json[96];
            int bl;

            if (*sub == 0 || *sub == '?') {
                /* read: leave state as-is */
            } else if (strncmp(sub, "/set-", 5) == 0
                       || strncmp(sub, "/escalate-", 10) == 0) {
                InterlockedExchange(&g_latch_set, 1);
            } else if (strncmp(sub, "/clear", 6) == 0) {
                InterlockedExchange(&g_latch_set, 0);
            } else {
                handled = 0;               /* e.g. /latchfoo — not ours */
            }

            if (handled) {
                ls = (int)g_latch_set;
                bl = snprintf(body_json, sizeof(body_json),
                              ls ? "{\"set\":1,\"detail\":\"armed\",\"ts\":1}"
                                 : "{\"set\":0}");
                n = snprintf(head, sizeof(head),
                             "HTTP/1.1 200 OK\r\n"
                             "Content-Type: application/json\r\n"
                             "Content-Length: %d\r\n"
                             "Cache-Control: no-store\r\n"
                             "Access-Control-Allow-Origin: *\r\n"
                             /* MUST be close: this handler is the only one that
                              * used keep-alive, and a reused connection made the
                              * host mis-parse the NEXT request line -> spurious
                              * 405 -> latch.set() saw !ok -> ps1 "latch did not
                              * take". Close matches every other response. */
                             "Connection: close\r\n\r\n%s",
                             bl, body_json);
                sink_all(sink, head, n);
                log_line("[%s] %s %s%s -> latch set=%d",
                         sink->tag ? sink->tag : "HTTP", peer,
                         host[0] ? host : "-", url, ls);
                return 1;
            }
        }
    }

    /* Custom online site: bounce anything that would have been served from the
     * default root - the guide host and any unknown host - straight at it. A
     * request that names a bundled mirror by host is left alone, so those
     * still work while a custom site is configured. */
    if (g_cfg.custom_url[0]) {
        char h[256];
        char *colon;

        snprintf(h, sizeof(h), "%s", host);
        colon = strchr(h, ':');
        if (colon)
            *colon = 0;
        str_lower(h);

        if (!h[0] || !pak_have_host(h)) {
            n = snprintf(head, sizeof(head),
                         "HTTP/1.1 302 Found\r\n"
                         "Location: %s\r\n"
                         "Content-Length: 0\r\n"
                         "Cache-Control: no-store\r\n"
                         "Connection: close\r\n\r\n",
                         g_cfg.custom_url);
            sink_all(sink, head, n);
            log_line("[%s] %s %s%s -> 302 %s", sink->tag ? sink->tag : "HTTP",
                     peer, host[0] ? host : "-", url, g_cfg.custom_url);
            return 0;
        }
    }

    body = resolve_req(url, host, &len, &freeit, chosen, sizeof(chosen));
    if (!body) {
        n = snprintf(head, sizeof(head),
                     "HTTP/1.1 404 Not Found\r\n"
                     "Content-Type: text/plain\r\n"
                     "Content-Length: 9\r\n"
                     "Connection: %s\r\n\r\nnot found",
                     keep ? "keep-alive" : "close");
        sink_all(sink, head, n);
        log_line("[%s] %s %s%s -> 404", sink->tag ? sink->tag : "HTTP", peer,
                 host[0] ? host : "-", url);
        return keep;
    }

    n = snprintf(head, sizeof(head),
                 "HTTP/1.1 200 OK\r\n"
                 "Content-Type: %s\r\n"
                 "Content-Length: %llu\r\n"
                 "Cache-Control: no-store\r\n"
                 "Access-Control-Allow-Origin: *\r\n"
                 "Connection: %s\r\n\r\n",
                 mime_for(chosen), (unsigned long long)len,
                 keep ? "keep-alive" : "close");

    if (!sink_all(sink, head, n))
        keep = 0;
    else if (!headonly && !sink_all(sink, body, len))
        keep = 0;

    log_line("[%s] %s %s%s -> 200 (%llu bytes)", sink->tag ? sink->tag : "HTTP",
             peer, host[0] ? host : "-", url, (unsigned long long)len);

    if (freeit)
        free((void *)body);
    return keep;
}

/* ------------------------------------------------------- plain :80 server */

static int sock_send(void *ctx, const void *buf, int len)
{
    return send((SOCKET)(UINT_PTR)ctx, (const char *)buf, len, 0);
}

static DWORD WINAPI conn_thread(LPVOID arg)
{
    SOCKET s = (SOCKET)(UINT_PTR)arg;
    char req[MAXREQ], peer[64] = "?";
    struct sockaddr_in sa;
    int salen = sizeof(sa);
    http_sink sink;
    DWORD tmo = 15000;

    if (getpeername(s, (struct sockaddr *)&sa, &salen) == 0)
        strncpy(peer, inet_ntoa(sa.sin_addr), sizeof(peer) - 1);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char *)&tmo, sizeof(tmo));

    sink.send = sock_send;
    sink.ctx = (void *)(UINT_PTR)s;
    sink.tag = "HTTP";

    for (;;) {
        int used = 0, n;

        /* Read until the end of the headers; these requests have no body. */
        for (;;) {
            n = recv(s, req + used, MAXREQ - 1 - used, 0);
            if (n <= 0)
                goto done;
            used += n;
            req[used] = 0;
            if (strstr(req, "\r\n\r\n") || strstr(req, "\n\n"))
                break;
            if (used >= MAXREQ - 1)
                goto done;
        }

        http_serve_request(req, used, &sink, peer);
        break;   /* one request per connection: no keep-alive reuse -> no desync */
    }

done:
    shutdown(s, SD_BOTH);
    closesocket(s);
    return 0;
}

/* [0] = plain listener, [1] = TLS listener. */
static SOCKET listen_sock[2] = { INVALID_SOCKET, INVALID_SOCKET };

void http_shutdown(void)
{
    int i;

    for (i = 0; i < 2; i++) {
        SOCKET s = listen_sock[i];
        listen_sock[i] = INVALID_SOCKET;
        if (s != INVALID_SOCKET)
            closesocket(s);          /* unblocks accept() */
    }
}

DWORD WINAPI http_thread(LPVOID arg)
{
    int tls = (int)(INT_PTR)arg;
    SOCKET srv;
    struct sockaddr_in addr;
    BOOL yes = TRUE;
    int port = tls ? g_cfg.https_port : g_cfg.http_port;
    const char *tag = tls ? "HTTPS" : "HTTP";

    if (tls && !tls_init()) {
        log_line("[HTTPS] disabled: certificate unavailable");
        return 1;
    }

    srv = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (srv == INVALID_SOCKET)
        return 1;
    setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, (char *)&yes, sizeof(yes));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons((u_short)port);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(srv, (struct sockaddr *)&addr, sizeof(addr)) != 0 ||
        listen(srv, 32) != 0) {
        log_line("[%s] BIND FAILED on :%d - error %d", tag, port,
                 WSAGetLastError());
        closesocket(srv);
        return 1;
    }
    listen_sock[tls ? 1 : 0] = srv;
    log_line("[%s] listening on 0.0.0.0:%d", tag, port);

    while (!g_stop) {
        SOCKET c = accept(srv, NULL, NULL);
        HANDLE t;

        if (c == INVALID_SOCKET) {
            if (g_stop)
                break;
            continue;
        }
        t = CreateThread(NULL, 0, tls ? tls_conn_thread : conn_thread,
                         (LPVOID)(UINT_PTR)c, 0, NULL);
        if (t)
            CloseHandle(t);
        else
            closesocket(c);
    }

    if (listen_sock[tls ? 1 : 0] != INVALID_SOCKET) {
        listen_sock[tls ? 1 : 0] = INVALID_SOCKET;
        closesocket(srv);
    }
    log_line("[%s] stopped, port released", tag);
    return 0;
}
