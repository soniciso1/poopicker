/* Start/stop the three listeners as a unit. */
#include "host.h"
#include <stdio.h>

volatile LONG g_stop = 0;

static HANDLE th_dns, th_http, th_https;
static int running;

void servers_start(void)
{
    char fw[256], game[256];

    if (running)
        return;

    InterlockedExchange(&g_stop, 0);
    blocklist_describe(fw, sizeof(fw), game, sizeof(game));

    log_line("==========================================================");
    log_line("[*]    this PC : %s  <- set as the console's DNS", g_cfg.ip);
    log_line("[*]    upstream: %s", g_cfg.upstream);
    if (g_cfg.custom_url[0])
        log_line("[*]    guide   : %s  (online; %s resolved upstream)",
                 g_cfg.custom_url, g_cfg.custom_host);
    else
        log_line("[*]    guide   : %s", g_cfg.guide_site[0] ? g_cfg.guide_site
                                                            : "built-in page");
    log_line("[*]    sites   : %d mirrored", pak_host_count());
    log_line("[*]    fw upd  : %s", fw);
    log_line("[*]    game upd: %s", game);
    log_line("==========================================================");

    th_dns   = CreateThread(NULL, 0, dns_thread, NULL, 0, NULL);
    th_http  = CreateThread(NULL, 0, http_thread, (LPVOID)(INT_PTR)0, 0, NULL);
    th_https = CreateThread(NULL, 0, http_thread, (LPVOID)(INT_PTR)1, 0, NULL);
    running = 1;
}

void servers_stop(void)
{
    if (!running)
        return;

    InterlockedExchange(&g_stop, 1);

    /* The flag alone is not enough - every listener is parked in a blocking
     * call and would never look at it. Closing the sockets is what makes
     * those calls return, which is what actually frees the ports. */
    dns_shutdown();
    http_shutdown();

    if (th_dns)   { WaitForSingleObject(th_dns, 3000);   CloseHandle(th_dns); }
    if (th_http)  { WaitForSingleObject(th_http, 3000);  CloseHandle(th_http); }
    if (th_https) { WaitForSingleObject(th_https, 3000); CloseHandle(th_https); }
    th_dns = th_http = th_https = NULL;

    running = 0;
    log_line("[*]    stopped");
}

int servers_running(void)
{
    return running;
}
