#!/usr/bin/env python3
"""unpak - read the site archive mkpak appends to the host exe.

READ-ONLY on the exe. Format is src/pakfmt.h:
    [ PE image ][ file data ][ index ][ footer ]
Footer is the last 32 bytes: magic PEHPAK01, index_off, index_len, count, rsv.
Index entry: u32 path_len, path bytes, u64 off, u64 raw, u64 stored, u32 flags.
flags 0 = raw, 1 = PAK_FLAG_LZMS. LZMS is decompressed through Cabinet.dll,
the same Windows Compression API mkpak compressed it with - there is no pure
Python LZMS, so this must run on Windows.

  python3 tools/unpak.py <exe>                       # list
  python3 tools/unpak.py <exe> --out DIR [site ...]  # extract (all, or named sites)
"""
import ctypes, os, struct, sys
from ctypes import wintypes

COMPRESS_ALGORITHM_LZMS = 5
cab = ctypes.WinDLL("Cabinet.dll")
cab.CreateDecompressor.argtypes = [wintypes.DWORD, ctypes.c_void_p, ctypes.POINTER(ctypes.c_void_p)]
cab.Decompress.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t,
                           ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]

_h = ctypes.c_void_p()
if not cab.CreateDecompressor(COMPRESS_ALGORITHM_LZMS, None, ctypes.byref(_h)):
    raise OSError("CreateDecompressor failed %d" % ctypes.get_last_error())


def lzms(buf, raw_len):
    out = ctypes.create_string_buffer(raw_len)
    got = ctypes.c_size_t(0)
    if not cab.Decompress(_h, buf, len(buf), out, raw_len, ctypes.byref(got)):
        raise OSError("Decompress failed %d" % ctypes.GetLastError())
    if got.value != raw_len:
        raise ValueError("short decompress %d != %d" % (got.value, raw_len))
    return out.raw[:raw_len]


def read_index(path):
    data = open(path, "rb")
    data.seek(-32, os.SEEK_END)
    ft = data.read(32)
    magic, index_off, index_len, count, _ = struct.unpack("<8sQQII", ft)
    if magic != b"PEHPAK01":
        raise SystemExit("no pak footer in %s (magic %r)" % (path, magic))
    data.seek(index_off)
    idx = data.read(index_len)
    ents, p = [], 0
    for _ in range(count):
        (n,) = struct.unpack_from("<I", idx, p); p += 4
        rel = idx[p:p + n].decode("utf-8", "replace"); p += n
        off, raw, stored, flags = struct.unpack_from("<QQQI", idx, p); p += 28
        ents.append((rel, off, raw, stored, flags))
    return data, ents


def main():
    if len(sys.argv) < 2:
        print(__doc__); return 2
    exe = sys.argv[1]
    outdir = None
    if "--out" in sys.argv:
        outdir = sys.argv[sys.argv.index("--out") + 1]
    want = [a for a in sys.argv[2:] if not a.startswith("--")]
    if outdir in want:
        want.remove(outdir)

    fh, ents = read_index(exe)
    if not outdir:
        sites = {}
        for rel, off, raw, stored, flags in ents:
            s = rel.split("/", 1)[0]
            n, r, st = sites.get(s, (0, 0, 0))
            sites[s] = (n + 1, r + raw, st + stored)
        print("%d files in %s" % (len(ents), exe))
        for s in sorted(sites):
            n, r, st = sites[s]
            print("  %-16s %4d files  %8.2f MB raw  %8.2f MB stored" %
                  (s, n, r / 1048576.0, st / 1048576.0))
        return 0

    n_out = 0
    for rel, off, raw, stored, flags in ents:
        site = rel.split("/", 1)[0]
        if want and site not in want:
            continue
        fh.seek(off)
        blob = fh.read(stored)
        if flags & 1:
            blob = lzms(blob, raw)
        if len(blob) != raw:
            raise SystemExit("size mismatch on %s" % rel)
        dst = os.path.join(outdir, rel.replace("/", os.sep))
        os.makedirs(os.path.dirname(dst), exist_ok=True)
        with open(dst, "wb") as f:
            f.write(blob)
        n_out += 1
    print("extracted %d files to %s" % (n_out, outdir))
    return 0


if __name__ == "__main__":
    sys.exit(main())
