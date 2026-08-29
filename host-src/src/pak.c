/* Memory-mapped reader for the site archive appended to our own .exe.
 *
 * The whole file is mapped once. Uncompressed entries are handed to the HTTP
 * code as pointers into that mapping, so serving a mirrored site costs no
 * allocation and no copy - the pages are faulted in by the kernel on demand
 * and dropped again under memory pressure. Nothing is ever written to %TEMP%.
 */
#include "host.h"
#include "pakfmt.h"
#include <compressapi.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

static HANDLE          map_file = INVALID_HANDLE_VALUE;
static HANDLE          map_obj;
static const unsigned char *base;
static uint64_t        base_len;

static pak_entry *entries;
static uint32_t   nentries;

/* Open-addressed hash table over the entry array; 4k files want more than a
 * linear scan per request. */
static uint32_t *table;
static uint32_t  tmask;

static char **hosts;
static int    nhosts;

static uint32_t hash_str(const char *s)
{
    uint32_t h = 2166136261u;
    for (; *s; s++) {
        h ^= (unsigned char)*s;
        h *= 16777619u;
    }
    return h;
}

/* Register a hostname if it is not already known. */
static void add_host(const char *name, size_t len)
{
    int j;

    for (j = 0; j < nhosts; j++)
        if (strlen(hosts[j]) == len && memcmp(hosts[j], name, len) == 0)
            return;

    hosts = (char **)realloc(hosts, (nhosts + 1) * sizeof(char *));
    hosts[nhosts] = (char *)malloc(len + 1);
    memcpy(hosts[nhosts], name, len);
    hosts[nhosts][len] = 0;
    str_lower(hosts[nhosts]);
    nhosts++;
}

/* Any directory dropped into sites\ next to the exe counts as a host, exactly
 * like one baked into the archive. That is what makes a test page usable
 * without repacking 416 MB: create sites\<name>\index.html, restart, pick it
 * from the guide dropdown. Disk entries are registered here so they also get
 * DNS-spoofed and show up in the picker, not just served if asked for by name.
 */
static void collect_disk_hosts(void)
{
    char pat[MAX_PATH];
    char dir[MAX_PATH];
    WIN32_FIND_DATAA fd;
    HANDLE h;

    exe_dir(dir, sizeof(dir));
    snprintf(pat, sizeof(pat), "%s\\sites\\*", dir);

    h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE)
        return;
    do {
        if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
            continue;
        if (fd.cFileName[0] == '.')
            continue;
        add_host(fd.cFileName, strlen(fd.cFileName));
    } while (FindNextFileA(h, &fd));
    FindClose(h);
}

static void collect_hosts(void)
{
    uint32_t i;
    int j;

    for (i = 0; i < nentries; i++) {
        const char *slash = strchr(entries[i].path, '/');
        size_t len = slash ? (size_t)(slash - entries[i].path)
                           : strlen(entries[i].path);
        (void)j;
        add_host(entries[i].path, len);
    }
}

int pak_open(void)
{
    char path[MAX_PATH];
    LARGE_INTEGER sz;
    pak_footer ft;
    const unsigned char *p, *end;
    uint32_t i, cap;

    /* Done first so drop-in test sites still register even when the exe has no
     * archive appended at all (the bare build). */
    collect_disk_hosts();

    exe_path(path, sizeof(path));
    map_file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (map_file == INVALID_HANDLE_VALUE)
        return 0;

    if (!GetFileSizeEx(map_file, &sz) || sz.QuadPart < (LONGLONG)sizeof(ft))
        goto fail;
    base_len = (uint64_t)sz.QuadPart;

    map_obj = CreateFileMappingA(map_file, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!map_obj)
        goto fail;
    base = (const unsigned char *)MapViewOfFile(map_obj, FILE_MAP_READ, 0, 0, 0);
    if (!base)
        goto fail;

    memcpy(&ft, base + base_len - sizeof(ft), sizeof(ft));
    if (memcmp(ft.magic, PAK_MAGIC, PAK_MAGIC_LEN) != 0)
        goto fail;                     /* plain exe, no sites bundled */
    if (ft.index_off + ft.index_len > base_len || ft.count == 0)
        goto fail;

    entries = (pak_entry *)calloc(ft.count, sizeof(pak_entry));
    if (!entries)
        goto fail;

    p = base + ft.index_off;
    end = p + ft.index_len;
    for (i = 0; i < ft.count; i++) {
        uint32_t plen;
        char *s;

        if ((size_t)(end - p) < sizeof(uint32_t))
            goto fail;
        memcpy(&plen, p, 4);
        p += 4;
        if (plen == 0 || (size_t)(end - p) < plen + 28u)
            goto fail;

        s = (char *)malloc(plen + 1);
        memcpy(s, p, plen);
        s[plen] = 0;
        p += plen;

        entries[i].path = s;
        memcpy(&entries[i].off, p, 8);      p += 8;
        memcpy(&entries[i].raw, p, 8);      p += 8;
        memcpy(&entries[i].stored, p, 8);   p += 8;
        memcpy(&entries[i].flags, p, 4);    p += 4;

        if (entries[i].off + entries[i].stored > base_len)
            goto fail;
    }
    nentries = ft.count;

    for (cap = 16; cap < nentries * 2; cap <<= 1)
        ;
    tmask = cap - 1;
    table = (uint32_t *)malloc(cap * sizeof(uint32_t));
    for (i = 0; i < cap; i++)
        table[i] = 0xFFFFFFFFu;
    for (i = 0; i < nentries; i++) {
        uint32_t h = hash_str(entries[i].path) & tmask;
        while (table[h] != 0xFFFFFFFFu)
            h = (h + 1) & tmask;
        table[h] = i;
    }

    collect_hosts();
    return 1;

fail:
    if (base)
        UnmapViewOfFile(base);
    if (map_obj)
        CloseHandle(map_obj);
    if (map_file != INVALID_HANDLE_VALUE)
        CloseHandle(map_file);
    base = NULL;
    map_obj = NULL;
    map_file = INVALID_HANDLE_VALUE;
    return 0;
}

int pak_host_count(void) { return nhosts; }

const char *pak_host_name(int i)
{
    return (i >= 0 && i < nhosts) ? hosts[i] : NULL;
}

int pak_have_host(const char *host)
{
    int i;
    for (i = 0; i < nhosts; i++)
        if (str_ieq(hosts[i], host))
            return 1;
    return 0;
}

static const pak_entry *lookup(const char *path)
{
    uint32_t h;

    if (!table)
        return NULL;
    h = hash_str(path) & tmask;
    while (table[h] != 0xFFFFFFFFu) {
        const pak_entry *e = &entries[table[h]];
        if (strcmp(e->path, path) == 0)
            return e;
        h = (h + 1) & tmask;
    }
    return NULL;
}

const unsigned char *pak_get(const char *path, uint64_t *len, int *needs_free)
{
    const pak_entry *e = lookup(path);
    DECOMPRESSOR_HANDLE dec = NULL;
    unsigned char *out;
    SIZE_T got = 0;
    DWORD alg;

    *needs_free = 0;
    if (!e)
        return NULL;

    if (e->flags == 0) {                    /* stored raw - zero copy */
        *len = e->raw;
        return base + e->off;
    }

    alg = (e->flags & PAK_FLAG_LZMS) ? COMPRESS_ALGORITHM_LZMS
                                     : COMPRESS_ALGORITHM_XPRESS_HUFF;
    if (!CreateDecompressor(alg, NULL, &dec))
        return NULL;

    out = (unsigned char *)malloc((size_t)e->raw + 1);
    if (!out) {
        CloseDecompressor(dec);
        return NULL;
    }
    if (!Decompress(dec, (PVOID)(base + e->off), (SIZE_T)e->stored,
                    out, (SIZE_T)e->raw, &got) || got != (SIZE_T)e->raw) {
        log_line("[PAK]  decompress failed for %s", path);
        free(out);
        CloseDecompressor(dec);
        return NULL;
    }
    CloseDecompressor(dec);

    *len = e->raw;
    *needs_free = 1;
    return out;
}
