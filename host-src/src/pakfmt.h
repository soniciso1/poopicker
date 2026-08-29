/* On-disk layout of the site archive appended to the .exe.
 *
 *   [ PE image ][ file data ][ index ][ footer ]
 *
 * The footer sits at the very end of the file, so the loader seeks backwards
 * from EOF and never has to care how big the PE image in front of it is. A
 * plain .exe with nothing appended simply fails the magic check and runs with
 * no bundled sites.
 *
 * Index entry, repeated `count` times:
 *   u32 path_len
 *   u8  path[path_len]      "host/dir/file.ext", lowercase, '/' separated
 *   u64 off                 absolute offset in the file
 *   u64 raw                 size once decompressed
 *   u64 stored              bytes actually present at off
 *   u32 flags               0 = stored raw, see PAK_FLAG_*
 *
 * Entries with flags 0 are served straight out of the memory mapping with no
 * copy at all; only compressed ones are expanded into a heap buffer.
 */
#ifndef PAKFMT_H
#define PAKFMT_H

#include <stdint.h>

#define PAK_MAGIC "PEHPAK01"
#define PAK_MAGIC_LEN 8

#pragma pack(push, 1)
typedef struct {
    char     magic[PAK_MAGIC_LEN];
    uint64_t index_off;
    uint64_t index_len;
    uint32_t count;
    uint32_t reserved;
} pak_footer;
#pragma pack(pop)

#endif /* PAKFMT_H */
