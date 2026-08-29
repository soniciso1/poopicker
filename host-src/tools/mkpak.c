/* mkpak - append a site tree to the host executable.
 *
 *   mkpak <base.exe> <sites-dir> <out.exe> [--fast] [--store]
 *
 * Each file is compressed with the Windows Compression API and kept compressed
 * only when that actually saves space; already-compressed content (png, pkg,
 * zip) stays raw so the server can hand it out straight from the memory
 * mapping with no copy. Large files stay raw too - decompressing 100 MB into
 * the heap to answer one request is worse than the bytes it would save.
 */
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <compressapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../src/pakfmt.h"

#define MAX_COMPRESS (64ULL * 1024 * 1024)
#define COPY_CHUNK   (4 * 1024 * 1024)

static DWORD g_alg = COMPRESS_ALGORITHM_LZMS;
static uint32_t g_flag = 1;              /* PAK_FLAG_LZMS */
static int g_store_only;

typedef struct {
    char    *path;
    uint64_t off, raw, stored;
    uint32_t flags;
} ent;

static ent *ents;
static uint32_t nents, cap_ents;
static uint64_t total_raw, total_stored;
static uint32_t g_failed;

static void die(const char *msg)
{
    fprintf(stderr, "mkpak: %s (err %lu)\n", msg, GetLastError());
    exit(1);
}

static void add_entry(const char *rel, uint64_t off, uint64_t raw,
                      uint64_t stored, uint32_t flags)
{
    if (nents == cap_ents) {
        cap_ents = cap_ents ? cap_ents * 2 : 1024;
        ents = (ent *)realloc(ents, cap_ents * sizeof(ent));
    }
    ents[nents].path = _strdup(rel);
    ents[nents].off = off;
    ents[nents].raw = raw;
    ents[nents].stored = stored;
    ents[nents].flags = flags;
    nents++;
}

/* Returns a malloc'd compressed buffer, or NULL to store raw. */
static unsigned char *try_compress(const unsigned char *in, size_t len,
                                   size_t *out_len)
{
    COMPRESSOR_HANDLE h = NULL;
    unsigned char *buf;
    SIZE_T need = 0, got = 0;

    if (g_store_only || len == 0 || len > MAX_COMPRESS)
        return NULL;
    if (!CreateCompressor(g_alg, NULL, &h))
        return NULL;

    /* A NULL destination reports the WORST-CASE buffer size, which is always
     * at least as large as the input - it says nothing about how well the data
     * actually compresses. Only the byte count from the real call does. */
    Compress(h, (PVOID)in, len, NULL, 0, &need);
    if (need < len)
        need = len + len / 16 + 4096;
    buf = (unsigned char *)malloc(need);
    if (!buf) {
        CloseCompressor(h);
        return NULL;
    }
    if (!Compress(h, (PVOID)in, len, buf, need, &got) || got == 0 ||
        got >= (SIZE_T)(len - len / 20)) {   /* must beat raw by 5% to be worth it */
        free(buf);
        CloseCompressor(h);
        return NULL;
    }
    CloseCompressor(h);
    *out_len = got;
    return buf;
}

static void pack_file(HANDLE out, const char *full, const char *rel)
{
    HANDLE f = INVALID_HANDLE_VALUE;
    LARGE_INTEGER sz;
    unsigned char *raw = NULL, *comp = NULL;
    size_t comp_len = 0;
    DWORD wrote, got, err = 0;
    LARGE_INTEGER pos;
    uint64_t off;
    int attempt;

    /* Real-time antivirus intercepts exploit payloads (kexploit.js, jb.js and
     * friends) while it scans them, so a long sequential read of the whole
     * mirror hits transient sharing violations on exactly the files that
     * matter most. Retry rather than silently shipping an archive with holes
     * in it. */
    for (attempt = 0; attempt < 6; attempt++) {
        f = CreateFileA(full, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (f != INVALID_HANDLE_VALUE)
            break;
        err = GetLastError();
        Sleep(150 * (attempt + 1));
    }
    if (f == INVALID_HANDLE_VALUE) {
        fprintf(stderr, "  UNREADABLE (err %lu): %s\n", err, rel);
        g_failed++;
        return;
    }
    if (!GetFileSizeEx(f, &sz)) {
        CloseHandle(f);
        return;
    }

    pos.QuadPart = 0;
    SetFilePointerEx(out, pos, &pos, FILE_CURRENT);
    off = (uint64_t)pos.QuadPart;

    if ((uint64_t)sz.QuadPart <= MAX_COMPRESS && sz.QuadPart > 0) {
        raw = (unsigned char *)malloc((size_t)sz.QuadPart);
        if (raw && ReadFile(f, raw, (DWORD)sz.QuadPart, &got, NULL) &&
            got == (DWORD)sz.QuadPart)
            comp = try_compress(raw, (size_t)sz.QuadPart, &comp_len);
    }

    if (comp) {
        if (!WriteFile(out, comp, (DWORD)comp_len, &wrote, NULL))
            die("write");
        add_entry(rel, off, (uint64_t)sz.QuadPart, comp_len, g_flag);
        total_stored += comp_len;
        free(comp);
    } else if (raw) {
        if (sz.QuadPart && !WriteFile(out, raw, (DWORD)sz.QuadPart, &wrote, NULL))
            die("write");
        add_entry(rel, off, (uint64_t)sz.QuadPart, (uint64_t)sz.QuadPart, 0);
        total_stored += (uint64_t)sz.QuadPart;
    } else {
        /* Too big to buffer: stream it through in chunks, stored raw. */
        unsigned char *chunk = (unsigned char *)malloc(COPY_CHUNK);
        uint64_t left = (uint64_t)sz.QuadPart;

        SetFilePointer(f, 0, NULL, FILE_BEGIN);
        while (left) {
            DWORD want = (DWORD)(left < COPY_CHUNK ? left : COPY_CHUNK);
            if (!ReadFile(f, chunk, want, &got, NULL) || got == 0)
                break;
            if (!WriteFile(out, chunk, got, &wrote, NULL))
                die("write");
            left -= got;
        }
        free(chunk);
        add_entry(rel, off, (uint64_t)sz.QuadPart, (uint64_t)sz.QuadPart, 0);
        total_stored += (uint64_t)sz.QuadPart;
    }

    total_raw += (uint64_t)sz.QuadPart;
    free(raw);
    CloseHandle(f);

    if ((nents % 200) == 0)
        printf("  %u files, %.1f MB in -> %.1f MB out\n", nents,
               total_raw / 1048576.0, total_stored / 1048576.0);
}

static void walk(HANDLE out, const char *dir, const char *prefix)
{
    char pat[MAX_PATH * 2], full[MAX_PATH * 2], rel[MAX_PATH * 2];
    WIN32_FIND_DATAA fd;
    HANDLE h;

    snprintf(pat, sizeof(pat), "%s\\*", dir);
    h = FindFirstFileA(pat, &fd);
    if (h == INVALID_HANDLE_VALUE)
        return;

    do {
        if (strcmp(fd.cFileName, ".") == 0 || strcmp(fd.cFileName, "..") == 0)
            continue;
        snprintf(full, sizeof(full), "%s\\%s", dir, fd.cFileName);
        if (prefix[0])
            snprintf(rel, sizeof(rel), "%s/%s", prefix, fd.cFileName);
        else
            snprintf(rel, sizeof(rel), "%s", fd.cFileName);

        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)
            walk(out, full, rel);
        else {
            char *p;
            for (p = rel; *p; p++)
                if (*p >= 'A' && *p <= 'Z')
                    *p += 32;
            pack_file(out, full, rel);
        }
    } while (FindNextFileA(h, &fd));

    FindClose(h);
}

static void copy_base(HANDLE out, const char *base)
{
    HANDLE f = CreateFileA(base, GENERIC_READ, FILE_SHARE_READ, NULL,
                           OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    unsigned char *buf;
    DWORD got, wrote;

    if (f == INVALID_HANDLE_VALUE)
        die("cannot open base exe");
    buf = (unsigned char *)malloc(COPY_CHUNK);
    while (ReadFile(f, buf, COPY_CHUNK, &got, NULL) && got)
        if (!WriteFile(out, buf, got, &wrote, NULL))
            die("write base");
    free(buf);
    CloseHandle(f);
}

int main(int argc, char **argv)
{
    HANDLE out;
    pak_footer ft;
    LARGE_INTEGER pos;
    DWORD wrote;
    uint32_t i;
    int argi;

    if (argc < 4) {
        fprintf(stderr,
                "usage: mkpak <base.exe> <sites-dir> <out.exe> [--fast] [--store]\n"
                "  --fast   XPRESS_HUFF instead of LZMS (much quicker to pack,\n"
                "           bigger result, faster to serve)\n"
                "  --store  no compression at all\n");
        return 2;
    }
    for (argi = 4; argi < argc; argi++) {
        if (strcmp(argv[argi], "--fast") == 0) {
            g_alg = COMPRESS_ALGORITHM_XPRESS_HUFF;
            g_flag = 2;                  /* PAK_FLAG_XPRESS */
        } else if (strcmp(argv[argi], "--store") == 0) {
            g_store_only = 1;
        }
    }

    out = CreateFileA(argv[3], GENERIC_READ | GENERIC_WRITE, 0, NULL,
                      CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (out == INVALID_HANDLE_VALUE)
        die("cannot create output");

    printf("mkpak: base=%s sites=%s out=%s alg=%s\n", argv[1], argv[2], argv[3],
           g_store_only ? "store" :
           (g_alg == COMPRESS_ALGORITHM_LZMS ? "LZMS" : "XPRESS_HUFF"));

    copy_base(out, argv[1]);
    walk(out, argv[2], "");

    if (nents == 0) {
        fprintf(stderr, "mkpak: no files found under %s\n", argv[2]);
        return 1;
    }

    pos.QuadPart = 0;
    SetFilePointerEx(out, pos, &pos, FILE_CURRENT);
    ft.index_off = (uint64_t)pos.QuadPart;

    for (i = 0; i < nents; i++) {
        uint32_t plen = (uint32_t)strlen(ents[i].path);
        WriteFile(out, &plen, 4, &wrote, NULL);
        WriteFile(out, ents[i].path, plen, &wrote, NULL);
        WriteFile(out, &ents[i].off, 8, &wrote, NULL);
        WriteFile(out, &ents[i].raw, 8, &wrote, NULL);
        WriteFile(out, &ents[i].stored, 8, &wrote, NULL);
        WriteFile(out, &ents[i].flags, 4, &wrote, NULL);
    }

    pos.QuadPart = 0;
    SetFilePointerEx(out, pos, &pos, FILE_CURRENT);
    ft.index_len = (uint64_t)pos.QuadPart - ft.index_off;
    ft.count = nents;
    ft.reserved = 0;
    memcpy(ft.magic, PAK_MAGIC, PAK_MAGIC_LEN);
    if (!WriteFile(out, &ft, sizeof(ft), &wrote, NULL))
        die("write footer");

    pos.QuadPart = 0;
    SetFilePointerEx(out, pos, &pos, FILE_CURRENT);
    printf("mkpak: %u files, %.1f MB raw -> %.1f MB stored, exe %.1f MB\n",
           nents, total_raw / 1048576.0, total_stored / 1048576.0,
           pos.QuadPart / 1048576.0);

    CloseHandle(out);

    if (g_failed) {
        fprintf(stderr,
                "\nmkpak: FAILED - %u file(s) could not be read, so the archive\n"
                "is incomplete. This is almost always real-time antivirus holding\n"
                "the exploit payloads open. Add an exclusion for the sites folder\n"
                "and pack again; do not ship this build.\n", g_failed);
        return 1;
    }
    return 0;
}
