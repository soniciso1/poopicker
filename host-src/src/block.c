/* The two update blocklists, answered NXDOMAIN.
 *
 * Everything not listed here resolves normally, so PSN sign-in, the store and
 * online play keep working while updates are dead.
 */
#include "host.h"
#include <string.h>
#include <stdio.h>

/* Firmware (system software). Suffix matched, so this single entry covers
 * every regional host the public hosts-file lists enumerate by hand - the
 * whole [dfh]<region>01.ps[45].update.playstation.net set, both consoles. */
static char *const FW_BLOCK[] = {
    "update.playstation.net",
};

/* Game (title) patches. Two stages per console: the version check, then the
 * payload. Killing the check alone is enough - the console never learns a
 * patch exists - but the payload hosts are listed too so an already-queued
 * download cannot resume.
 *
 *   sgst.prod.dl.playstation.net        PS5 title-update XML  (the check)
 *   gst.prod.dl.playstation.net         PS5 patch PKG         (the payload)
 *   gs-sec.ww.prod.dl.playstation.net   PS4 update XML        (the check)
 *   gs2.ww.prod.dl.playstation.net      PS4 patch manifest + PKG
 *
 * Deliberately absent: tmdb.np.dl.playstation.net and the other
 * *.np.dl.playstation.net hosts are title metadata and icons - blocking them
 * breaks the library and store UI without stopping a single patch. The wider
 * prod.dl.playstation.net suffix is avoided for the same reason: it would kill
 * every store download, not just updates.
 */
static char *const GAME_BLOCK[] = {
    "sgst.prod.dl.playstation.net",
    "gst.prod.dl.playstation.net",
    "gs-sec.ww.prod.dl.playstation.net",
    "gs2.ww.prod.dl.playstation.net",
};

#define NFW   (int)(sizeof(FW_BLOCK) / sizeof(FW_BLOCK[0]))
#define NGAME (int)(sizeof(GAME_BLOCK) / sizeof(GAME_BLOCK[0]))

const char *block_reason(const char *host)
{
    /* --block additions are the user's own and apply whatever the two update
     * toggles are set to. */
    if (g_cfg.nextra && suffix_match(host, g_cfg.extra_block, g_cfg.nextra))
        return "user";
    if (g_cfg.block_fw && suffix_match(host, FW_BLOCK, NFW))
        return "firmware";
    if (g_cfg.block_game && suffix_match(host, GAME_BLOCK, NGAME))
        return "game";
    return NULL;
}

/* Accepts what a person would actually type - "es7in1.site",
 * "https://es7in1.site/", "http://karo218.ir/1100/" - and pulls the hostname
 * out of it. Without a scheme https is assumed, because every current exploit
 * host serves TLS and the console follows the redirect either way. */
void custom_set(const char *url)
{
    const char *p, *end;
    size_t n;

    g_cfg.custom_url[0] = 0;
    g_cfg.custom_host[0] = 0;

    if (!url)
        return;
    while (*url == ' ' || *url == '\t')
        url++;
    if (!*url)
        return;

    if (strstr(url, "://") == NULL)
        snprintf(g_cfg.custom_url, sizeof(g_cfg.custom_url), "https://%s", url);
    else
        snprintf(g_cfg.custom_url, sizeof(g_cfg.custom_url), "%s", url);

    /* trim a trailing newline or space a paste can leave behind */
    n = strlen(g_cfg.custom_url);
    while (n && (g_cfg.custom_url[n - 1] == ' ' || g_cfg.custom_url[n - 1] == '\r' ||
                 g_cfg.custom_url[n - 1] == '\n'))
        g_cfg.custom_url[--n] = 0;

    p = strstr(g_cfg.custom_url, "://");
    p += 3;
    for (end = p; *end && *end != '/' && *end != ':' && *end != '?'; end++)
        ;
    n = (size_t)(end - p);
    if (n == 0 || n >= sizeof(g_cfg.custom_host)) {
        g_cfg.custom_url[0] = 0;
        return;
    }
    memcpy(g_cfg.custom_host, p, n);
    g_cfg.custom_host[n] = 0;
    str_lower(g_cfg.custom_host);
}

static void join(char *out, int cap, char *const *list, int n)
{
    int i, used = 0;

    out[0] = 0;
    for (i = 0; i < n; i++) {
        int need = (int)strlen(list[i]) + (i ? 2 : 0);
        if (used + need + 1 >= cap)
            break;
        if (i)
            used += sprintf(out + used, ", ");
        used += sprintf(out + used, "%s", list[i]);
    }
    if (!out[0])
        strncpy(out, "nothing", cap - 1);
}

void blocklist_describe(char *fw, int fwcap, char *game, int gamecap)
{
    if (g_cfg.block_fw)
        join(fw, fwcap, FW_BLOCK, NFW);
    else
        strncpy(fw, "allowed", fwcap - 1);

    if (g_cfg.block_game)
        join(game, gamecap, GAME_BLOCK, NGAME);
    else
        strncpy(game, "allowed", gamecap - 1);
}
