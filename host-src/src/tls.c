/* HTTPS listener built on Schannel.
 *
 * The PS5 browser reaches the guide host over TLS, so plain HTTP alone is not
 * enough - a probe of the console's traffic showed it opening :443 with a real
 * ClientHello. Schannel is used directly rather than a bundled TLS library so
 * the executable keeps depending only on DLLs that ship with Windows.
 */
#include "host.h"
#include <schannel.h>
#include <sspi.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define IO_BUF   32768
#define MAXREQ   16384

static CredHandle g_cred;
static int        g_cred_ok;
static PCCERT_CONTEXT g_cert;
static char       g_cred_ip[64];   /* IP the cached credentials were built for */

typedef struct {
    SOCKET sock;
    CtxtHandle ctxt;
    SecPkgContext_StreamSizes sizes;
    int have_ctxt;
} tls_conn;

int tls_init(void)
{
    SCHANNEL_CRED sc;
    TimeStamp ts;
    SECURITY_STATUS st;
    char dir[MAX_PATH];

    /* Cached credentials are only good for the IP they were issued against.
     * After a Stop/Start with a different IP typed in, they have to be rebuilt
     * or the console is offered a certificate for the wrong address. */
    if (g_cred_ok && strcmp(g_cred_ip, g_cfg.ip) == 0)
        return 1;
    if (g_cred_ok) {
        log_line("[TLS]  IP changed to %s - rebuilding credentials", g_cfg.ip);
        tls_free();
    }

    exe_dir(dir, sizeof(dir));
    if (!cert_ensure(dir, g_cfg.ip, g_cfg.spoof, g_cfg.nspoof, &g_cert))
        return 0;

    memset(&sc, 0, sizeof(sc));
    sc.dwVersion = SCHANNEL_CRED_VERSION;
    sc.cCreds = 1;
    sc.paCred = &g_cert;
    /* Consoles are old clients; offering only modern suites would lock the
     * PS4 browser out entirely. */
    sc.grbitEnabledProtocols = SP_PROT_TLS1_0_SERVER | SP_PROT_TLS1_1_SERVER |
                               SP_PROT_TLS1_2_SERVER;
    sc.dwFlags = SCH_CRED_NO_SYSTEM_MAPPER;

    st = AcquireCredentialsHandleA(NULL, (SEC_CHAR *)UNISP_NAME_A,
                                   SECPKG_CRED_INBOUND, NULL, &sc, NULL, NULL,
                                   &g_cred, &ts);
    if (st != SEC_E_OK) {
        log_line("[TLS]  AcquireCredentialsHandle failed (0x%08lx)", (long)st);
        return 0;
    }
    g_cred_ok = 1;
    snprintf(g_cred_ip, sizeof(g_cred_ip), "%s", g_cfg.ip);
    return 1;
}

void tls_free(void)
{
    if (g_cred_ok) {
        FreeCredentialsHandle(&g_cred);
        g_cred_ok = 0;
    }
    if (g_cert) {
        CertFreeCertificateContext(g_cert);
        g_cert = NULL;
    }
}

/* ------------------------------------------------------------- handshake */

static int handshake(tls_conn *c, unsigned char *buf, int cap, int *carry)
{
    SecBuffer in[2], out[2];
    SecBufferDesc indesc, outdesc;
    DWORD attr;
    TimeStamp ts;
    SECURITY_STATUS st;
    int used = 0, need_more = 1;

    for (;;) {
        int n;

        if (need_more) {
            if (used >= cap)
                return 0;
            n = recv(c->sock, (char *)buf + used, cap - used, 0);
            if (n <= 0)
                return 0;
            used += n;
            need_more = 0;
        }

        in[0].BufferType = SECBUFFER_TOKEN;
        in[0].pvBuffer = buf;
        in[0].cbBuffer = used;
        in[1].BufferType = SECBUFFER_EMPTY;
        in[1].pvBuffer = NULL;
        in[1].cbBuffer = 0;
        indesc.ulVersion = SECBUFFER_VERSION;
        indesc.cBuffers = 2;
        indesc.pBuffers = in;

        out[0].BufferType = SECBUFFER_TOKEN;
        out[0].pvBuffer = NULL;
        out[0].cbBuffer = 0;
        out[1].BufferType = SECBUFFER_ALERT;
        out[1].pvBuffer = NULL;
        out[1].cbBuffer = 0;
        outdesc.ulVersion = SECBUFFER_VERSION;
        outdesc.cBuffers = 2;
        outdesc.pBuffers = out;

        st = AcceptSecurityContext(&g_cred,
                                   c->have_ctxt ? &c->ctxt : NULL,
                                   &indesc,
                                   ASC_REQ_SEQUENCE_DETECT | ASC_REQ_REPLAY_DETECT |
                                   ASC_REQ_CONFIDENTIALITY | ASC_REQ_EXTENDED_ERROR |
                                   ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_STREAM,
                                   0, &c->ctxt, &outdesc, &attr, &ts);

        if (st == SEC_E_INCOMPLETE_MESSAGE) {
            need_more = 1;                /* partial record, keep what we have */
            continue;
        }
        /* Once AcceptSecurityContext has produced a context it must be passed
         * back in on every later call, and deleted when we are done. */
        c->have_ctxt = 1;

        if (out[0].cbBuffer && out[0].pvBuffer) {
            const char *p = (const char *)out[0].pvBuffer;
            int left = (int)out[0].cbBuffer;
            while (left > 0) {
                int w = send(c->sock, p, left, 0);
                if (w <= 0)
                    break;
                p += w;
                left -= w;
            }
            FreeContextBuffer(out[0].pvBuffer);
            if (left > 0)
                return 0;
        }
        if (out[1].pvBuffer)
            FreeContextBuffer(out[1].pvBuffer);

        if (st == SEC_E_OK) {
            /* Application data may already be sitting behind the last
             * handshake record; keep it for the read loop. */
            if (in[1].BufferType == SECBUFFER_EXTRA && in[1].cbBuffer) {
                memmove(buf, buf + used - in[1].cbBuffer, in[1].cbBuffer);
                *carry = (int)in[1].cbBuffer;
            } else {
                *carry = 0;
            }
            return 1;
        }

        if (st == SEC_I_CONTINUE_NEEDED) {
            if (in[1].BufferType == SECBUFFER_EXTRA && in[1].cbBuffer) {
                memmove(buf, buf + used - in[1].cbBuffer, in[1].cbBuffer);
                used = (int)in[1].cbBuffer;
            } else {
                used = 0;
            }
            need_more = (used == 0);      /* leftovers may already be a record */
            continue;
        }

        if (st == SEC_E_UNTRUSTED_ROOT || st == SEC_E_CERT_EXPIRED)
            log_line("[TLS]  client rejected our certificate (0x%08lx)", (long)st);
        else if (FAILED(st))
            log_line("[TLS]  handshake failed (0x%08lx)", (long)st);
        return 0;
    }
}

/* ------------------------------------------------------------ record I/O */

static int tls_send(void *ctx, const void *data, int len)
{
    tls_conn *c = (tls_conn *)ctx;
    SecBuffer bufs[4];
    SecBufferDesc desc;
    unsigned char *msg;
    int chunk, total;
    const char *p;

    chunk = (int)c->sizes.cbMaximumMessage;
    if (len < chunk)
        chunk = len;

    msg = (unsigned char *)malloc(c->sizes.cbHeader + chunk + c->sizes.cbTrailer);
    if (!msg)
        return -1;
    memcpy(msg + c->sizes.cbHeader, data, chunk);

    bufs[0].BufferType = SECBUFFER_STREAM_HEADER;
    bufs[0].pvBuffer = msg;
    bufs[0].cbBuffer = c->sizes.cbHeader;
    bufs[1].BufferType = SECBUFFER_DATA;
    bufs[1].pvBuffer = msg + c->sizes.cbHeader;
    bufs[1].cbBuffer = chunk;
    bufs[2].BufferType = SECBUFFER_STREAM_TRAILER;
    bufs[2].pvBuffer = msg + c->sizes.cbHeader + chunk;
    bufs[2].cbBuffer = c->sizes.cbTrailer;
    bufs[3].BufferType = SECBUFFER_EMPTY;
    bufs[3].pvBuffer = NULL;
    bufs[3].cbBuffer = 0;
    desc.ulVersion = SECBUFFER_VERSION;
    desc.cBuffers = 4;
    desc.pBuffers = bufs;

    if (EncryptMessage(&c->ctxt, 0, &desc, 0) != SEC_E_OK) {
        free(msg);
        return -1;
    }

    total = (int)(bufs[0].cbBuffer + bufs[1].cbBuffer + bufs[2].cbBuffer);
    p = (const char *)msg;
    while (total > 0) {
        int w = send(c->sock, p, total, 0);
        if (w <= 0) {
            free(msg);
            return -1;
        }
        p += w;
        total -= w;
    }
    free(msg);
    return chunk;
}

DWORD WINAPI tls_conn_thread(LPVOID arg)
{
    tls_conn c;
    unsigned char io[IO_BUF];
    char req[MAXREQ], peer[64] = "?";
    struct sockaddr_in sa;
    int salen = sizeof(sa);
    int used = 0, reqlen = 0;
    http_sink sink;
    DWORD tmo = 15000;

    memset(&c, 0, sizeof(c));
    c.sock = (SOCKET)(UINT_PTR)arg;

    if (getpeername(c.sock, (struct sockaddr *)&sa, &salen) == 0)
        strncpy(peer, inet_ntoa(sa.sin_addr), sizeof(peer) - 1);
    setsockopt(c.sock, SOL_SOCKET, SO_RCVTIMEO, (char *)&tmo, sizeof(tmo));

    if (!handshake(&c, io, sizeof(io), &used))
        goto done;

    if (QueryContextAttributes(&c.ctxt, SECPKG_ATTR_STREAM_SIZES,
                               &c.sizes) != SEC_E_OK)
        goto done;

    sink.send = tls_send;
    sink.ctx = &c;
    sink.tag = "HTTPS";

    for (;;) {
        SecBuffer bufs[4];
        SecBufferDesc desc;
        SECURITY_STATUS st;
        int i, extra_off = -1, extra_len = 0;

        if (used == 0) {
            int n = recv(c.sock, (char *)io, sizeof(io), 0);
            if (n <= 0)
                break;
            used = n;
        }

        bufs[0].BufferType = SECBUFFER_DATA;
        bufs[0].pvBuffer = io;
        bufs[0].cbBuffer = used;
        for (i = 1; i < 4; i++) {
            bufs[i].BufferType = SECBUFFER_EMPTY;
            bufs[i].pvBuffer = NULL;
            bufs[i].cbBuffer = 0;
        }
        desc.ulVersion = SECBUFFER_VERSION;
        desc.cBuffers = 4;
        desc.pBuffers = bufs;

        st = DecryptMessage(&c.ctxt, &desc, 0, NULL);
        if (st == SEC_E_INCOMPLETE_MESSAGE) {
            int n;
            if (used >= (int)sizeof(io))
                break;
            n = recv(c.sock, (char *)io + used, sizeof(io) - used, 0);
            if (n <= 0)
                break;
            used += n;
            continue;
        }
        if (st == SEC_I_CONTEXT_EXPIRED)
            break;
        if (st != SEC_E_OK && st != SEC_I_RENEGOTIATE)
            break;

        for (i = 0; i < 4; i++) {
            if (bufs[i].BufferType == SECBUFFER_DATA && bufs[i].cbBuffer) {
                int n = (int)bufs[i].cbBuffer;
                if (reqlen + n < MAXREQ - 1) {
                    memcpy(req + reqlen, bufs[i].pvBuffer, n);
                    reqlen += n;
                    req[reqlen] = 0;
                }
            } else if (bufs[i].BufferType == SECBUFFER_EXTRA && bufs[i].cbBuffer) {
                extra_off = (int)((unsigned char *)bufs[i].pvBuffer - io);
                extra_len = (int)bufs[i].cbBuffer;
            }
        }

        if (extra_len > 0) {
            memmove(io, io + extra_off, extra_len);
            used = extra_len;
        } else {
            used = 0;
        }

        if (reqlen && (strstr(req, "\r\n\r\n") || strstr(req, "\n\n"))) {
            int keep = http_serve_request(req, reqlen, &sink, peer);
            reqlen = 0;
            req[0] = 0;
            if (!keep)
                break;
        }
    }

done:
    if (c.have_ctxt)
        DeleteSecurityContext(&c.ctxt);
    shutdown(c.sock, SD_BOTH);
    closesocket(c.sock);
    return 0;
}
