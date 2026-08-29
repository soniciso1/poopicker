/* Portable PS4/PS5 exploit host - entry point, configuration and CLI.
 *
 * Built for the GUI subsystem so double-clicking the exe opens the dialog with
 * no console flashing behind it; --console attaches to the parent console
 * instead and runs headless.
 */
#include "host.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern volatile LONG g_stop;

/* This is a GUI-subsystem binary, so there is no console unless we ask for
 * one. When stdout has already been redirected to a file or a pipe we must
 * leave it alone - reopening CONOUT$ would send the output to the terminal and
 * the caller's redirection would capture nothing at all. */
static void attach_console(void)
{
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);

    if (h && h != INVALID_HANDLE_VALUE) {
        DWORD type = GetFileType(h);
        if (type == FILE_TYPE_DISK || type == FILE_TYPE_PIPE)
            return;
    }
    if (!AttachConsole(ATTACH_PARENT_PROCESS))
        AllocConsole();
    freopen("CONOUT$", "w", stdout);
    freopen("CONOUT$", "w", stderr);
}

static void usage(void)
{
    printf(
"Portable PS4/PS5 exploit host " HOST_VERSION "\n"
"\n"
"  Answers DNS for the mirrored hosts with this machine's LAN IP and forwards\n"
"  everything else upstream, so the console keeps working internet. Serves the\n"
"  bundled sites over HTTP :80 (PS4) and HTTPS :443 (PS5).\n"
"\n"
"  Firmware updates and game patches are blocked by default and toggled\n"
"  independently, from the GUI or with the two --allow flags.\n"
"\n"
"options:\n"
"  --ip ADDR             LAN IP to advertise (default: auto-detect)\n"
"  --upstream ADDR       upstream DNS resolver (default 8.8.8.8)\n"
"  --domain NAME         extra domain to spoof (repeatable)\n"
"  --block NAME          extra domain to answer NXDOMAIN (repeatable; always\n"
"                        applies, independent of the two update toggles)\n"
"  --allow-updates       do NOT block the firmware-update hosts\n"
"  --allow-game-updates  do NOT block the game/title patch hosts\n"
"  --guide-site NAME     mirrored site the User's Guide opens\n"
"                        (default es7in1.site; 'builtin' for the bundled page)\n"
"  --url ADDR            send the User's Guide to a live online site instead of\n"
"                        a bundled mirror, e.g. --url https://es7in1.site/ .\n"
"                        That host is then resolved upstream for real, so the\n"
"                        console reaches it; updates stay blocked regardless\n"
"  --dns-port N  --http-port N  --https-port N\n"
"  --console             run headless in the terminal instead of the GUI\n"
"  --no-firewall         skip the firewall check entirely\n"
"  --open-ports          add the inbound rules and exit\n"
"  --remove-firewall     delete this tool's rules and exit\n"
"  --enable-firewall     turn Windows Firewall back on and exit\n"
"  --disable-firewall    turn Windows Firewall off and exit\n"
"  --list-sites          print the bundled site list and exit\n");
}

static void add_str(char ***arr, int *n, const char *s)
{
    char *copy = _strdup(s);
    str_lower(copy);
    *arr = (char **)realloc(*arr, (*n + 1) * sizeof(char *));
    (*arr)[(*n)++] = copy;
}

/* Every mirrored site must resolve to us as well, otherwise the console would
 * go out to the real internet for it. */
static void build_spoof_list(void)
{
    int i, n = pak_host_count();

    add_str(&g_cfg.spoof, &g_cfg.nspoof, GUIDE_HOST);
    for (i = 0; i < n; i++) {
        const char *h = pak_host_name(i);
        if (strcmp(h, "_builtin") == 0)
            continue;
        add_str(&g_cfg.spoof, &g_cfg.nspoof, h);
    }
}

int WINAPI WinMain(HINSTANCE inst, HINSTANCE prev, LPSTR cmd, int show)
{
    WSADATA wsa;
    int i, console = 0, want_help = 0, list_sites = 0;
    int do_open = 0, do_remove = 0, do_enable = 0, do_disable = 0;
    char **extra_domains = NULL;
    int nextra_domains = 0;

    (void)inst; (void)prev; (void)cmd; (void)show;

    /* defaults */
    strcpy(g_cfg.upstream, "8.8.8.8");
    strcpy(g_cfg.guide_site, "es7in1.site");
    g_cfg.dns_port = 53;
    g_cfg.http_port = 80;
    g_cfg.https_port = 443;
    g_cfg.block_fw = 1;
    g_cfg.block_game = 1;

    for (i = 1; i < __argc; i++) {
        const char *a = __argv[i];
        const char *v = (i + 1 < __argc) ? __argv[i + 1] : NULL;

        if (!strcmp(a, "--ip") && v)                    { strncpy(g_cfg.ip, v, sizeof(g_cfg.ip) - 1); i++; }
        else if (!strcmp(a, "--upstream") && v)         { strncpy(g_cfg.upstream, v, sizeof(g_cfg.upstream) - 1); i++; }
        else if (!strcmp(a, "--guide-site") && v)       { strncpy(g_cfg.guide_site, v, sizeof(g_cfg.guide_site) - 1); str_lower(g_cfg.guide_site); i++; }
        else if (!strcmp(a, "--url") && v)              { custom_set(v); i++; }
        else if (!strcmp(a, "--domain") && v)           { add_str(&extra_domains, &nextra_domains, v); i++; }
        else if (!strcmp(a, "--block") && v)            { add_str(&g_cfg.extra_block, &g_cfg.nextra, v); i++; }
        else if (!strcmp(a, "--dns-port") && v)         { g_cfg.dns_port = atoi(v); i++; }
        else if (!strcmp(a, "--http-port") && v)        { g_cfg.http_port = atoi(v); i++; }
        else if (!strcmp(a, "--https-port") && v)       { g_cfg.https_port = atoi(v); i++; }
        else if (!strcmp(a, "--allow-updates"))         { g_cfg.block_fw = 0; }
        else if (!strcmp(a, "--allow-game-updates"))    { g_cfg.block_game = 0; }
        else if (!strcmp(a, "--console"))               { console = 1; }
        else if (!strcmp(a, "--no-firewall"))           { g_cfg.no_firewall = 1; }
        else if (!strcmp(a, "--open-ports"))            { do_open = 1; }
        else if (!strcmp(a, "--remove-firewall"))       { do_remove = 1; }
        else if (!strcmp(a, "--enable-firewall"))       { do_enable = 1; }
        else if (!strcmp(a, "--disable-firewall"))      { do_disable = 1; }
        else if (!strcmp(a, "--list-sites"))            { list_sites = 1; }
        else                                            { want_help = 1; }
    }

    if (strcmp(g_cfg.guide_site, "builtin") == 0)
        g_cfg.guide_site[0] = 0;

    if (want_help || console || list_sites || do_open || do_remove ||
        do_enable || do_disable)
        attach_console();

    if (want_help) {
        usage();
        return 2;
    }

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        printf("winsock init failed\n");
        return 1;
    }

    pak_open();
    build_spoof_list();
    for (i = 0; i < nextra_domains; i++)
        add_str(&g_cfg.spoof, &g_cfg.nspoof, extra_domains[i]);

    if (list_sites) {
        int n = pak_host_count();
        /* "available", not "bundled": the list now merges hosts baked into the
         * archive with any directory dropped into sites\ next to the exe. */
        printf("%d site(s) available:\n", n);
        for (i = 0; i < n; i++)
            printf("  %s\n", pak_host_name(i));
        return 0;
    }

    if (!g_cfg.ip[0])
        detect_lan_ip(g_cfg.ip, sizeof(g_cfg.ip));

    if (do_remove)  { fw_remove_rules(); return 0; }
    if (do_enable)  { fw_set(1); return 0; }
    if (do_disable) { fw_set(0); return 0; }
    if (do_open)    { fw_open_ports(); return 0; }

    if (!console)
        return gui_run();

    /* ------------------------------------------------------ console mode */
    if (!g_cfg.no_firewall) {
        int tcp = 0, udp = 0;
        if (fw_enabled() && !fw_rules_present(&tcp, &udp)) {
            log_line("[FW]   firewall is ON and ports %d/%d/%d are not open.",
                     g_cfg.http_port, g_cfg.https_port, g_cfg.dns_port);
            if (fw_is_admin())
                fw_open_ports();
            else
                log_line("[FW]   run as administrator, or pass --open-ports once.");
        }
    }

    servers_start();

    printf("\nRunning. Ctrl-C to stop.\n");
    for (;;)
        Sleep(1000);
}
