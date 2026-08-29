/* Portable PS4/PS5 exploit host - shared declarations.
 *
 * C99 + Win32 only. No third-party dependencies: TLS is Schannel, certificate
 * generation is CNG, and the bundled sites are decompressed with the Windows
 * Compression API. Everything links against DLLs that ship with the OS.
 */
#ifndef HOST_H
#define HOST_H

#define WIN32_LEAN_AND_MEAN
#define SECURITY_WIN32
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <wincrypt.h>
#include <stdint.h>

#define HOST_VERSION "2.0"

/* ------------------------------------------------------------------ config */

/* Only the guide host is hijacked by default. Everything else - including
 * exploit sites browsed to by hand - passes through to the real internet. */
#define GUIDE_HOST "manuals.playstation.net"

typedef struct {
    char ip[64];             /* LAN IP handed to the console */
    char upstream[64];       /* real resolver for everything not spoofed */
    int  dns_port, http_port, https_port;

    /* Live toggles. The DNS threads read these per query, so flipping a GUI
     * checkbox takes effect immediately with no restart. */
    volatile LONG block_fw;
    volatile LONG block_game;

    char **spoof;            /* hostnames answered with our own IP */
    int    nspoof;
    char **extra_block;      /* --block additions, always in effect */
    int    nextra;

    char guide_site[128];    /* mirrored site the User's Guide opens */

    /* Optional online site to bounce the User's Guide to instead of serving a
     * bundled mirror. When set, custom_host is excluded from DNS spoofing so
     * the console can actually reach the real server; the update blocklists
     * are untouched either way. */
    char custom_url[512];
    char custom_host[256];

    int  no_firewall;
    int  console_mode;
} cfg_t;

extern cfg_t g_cfg;

/* -------------------------------------------------------------------- util */

void  log_line(const char *fmt, ...);
int   log_drain(char *buf, int cap);      /* GUI pulls pending lines */
void  log_set_gui(int on);

void  detect_lan_ip(char *out, int cap);
int   ip_is_local(const char *ip);
void  exe_path(char *out, int cap);       /* full path of our own .exe */
void  exe_dir(char *out, int cap);        /* directory containing it */

int   str_ieq(const char *a, const char *b);
int   suffix_match(const char *host, char *const *domains, int n);
void  str_lower(char *s);

/* --------------------------------------------------------------- blocklist */

const char *block_reason(const char *host);   /* "firmware" / "game" / NULL */
void        blocklist_describe(char *fw, int fwcap, char *game, int gamecap);

/* Normalises a typed URL into cfg.custom_url + cfg.custom_host. An empty or
 * blank string clears both, restoring the bundled-site behaviour. */
void custom_set(const char *url);

/* --------------------------------------------------------------------- pak */

/* The site mirror is appended to the .exe after linking and memory-mapped at
 * runtime, so nothing is ever extracted to %TEMP%. */
typedef struct {
    const char *path;        /* "host/dir/file.ext", lowercase, '/' separated */
    uint64_t    off;         /* absolute offset into the exe */
    uint64_t    raw;         /* size once decompressed */
    uint64_t    stored;      /* size on disk */
    uint32_t    flags;
} pak_entry;

#define PAK_FLAG_LZMS   1u
#define PAK_FLAG_XPRESS 2u

int  pak_open(void);         /* maps our own exe; 0 if no archive appended */
int  pak_host_count(void);
const char *pak_host_name(int i);
int  pak_have_host(const char *host);

/* Returns a buffer holding the file, or NULL. *needs_free tells the caller
 * whether to free it: raw entries are served straight out of the mapping. */
const unsigned char *pak_get(const char *path, uint64_t *len, int *needs_free);

/* ------------------------------------------------------------------ crypto */

int  cert_ensure(const char *dir, const char *ip, char *const *domains, int n,
                 PCCERT_CONTEXT *out);

/* --------------------------------------------------------------------- net */

DWORD WINAPI dns_thread(LPVOID arg);
DWORD WINAPI http_thread(LPVOID arg);     /* arg = 0 plain, 1 TLS */

/* Closing the listening sockets is what actually stops the servers: the
 * threads sit blocked in recvfrom()/accept() and only return once their socket
 * is torn down underneath them. Setting a flag alone leaves them parked
 * forever, holding the port. */
void dns_shutdown(void);
void http_shutdown(void);
void  servers_start(void);
void  servers_stop(void);
int   servers_running(void);

/* HTTP request handling, shared by the plain and TLS listeners. */
typedef struct {
    int  (*send)(void *ctx, const void *buf, int len);
    void  *ctx;
    const char *tag;          /* "HTTP" or "HTTPS", for the log only */
} http_sink;

int  http_serve_request(const char *req, int reqlen, http_sink *sink,
                        const char *peer);

/* TLS listener (Schannel). */
int  tls_init(void);
void tls_free(void);
DWORD WINAPI tls_conn_thread(LPVOID sock);

/* ---------------------------------------------------------------- firewall */

int  fw_is_admin(void);
int  fw_enabled(void);
int  fw_rules_present(int *tcp, int *udp);
int  fw_open_ports(void);
int  fw_remove_rules(void);
int  fw_set(int on);

/* --------------------------------------------------------------------- gui */

int  gui_run(void);

#endif /* HOST_H */
