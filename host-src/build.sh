#!/bin/bash
# Cross-build the host and the packer with MinGW-w64.
#
#   ./build.sh              build ps-exploit-host.exe (no sites)
#   ./build.sh pack DIR     build, then append DIR as the site archive
#
# Run from WSL; the resulting binaries are native Windows executables that
# depend only on DLLs shipping with the OS.
set -e

CC=${CC:-x86_64-w64-mingw32-gcc}
WINDRES=${WINDRES:-x86_64-w64-mingw32-windres}
OUT=${OUT:-build}

CFLAGS="-std=c99 -O2 -Wall -Wextra -Wno-unused-parameter"
LIBS="-lws2_32 -liphlpapi -lsecur32 -lcrypt32 -lncrypt -lcabinet -lcomctl32 -ladvapi32 -lole32"

mkdir -p "$OUT"

echo "[*] resources"
$WINDRES src/host.rc -O coff -o "$OUT/host.res"

echo "[*] host"
$CC $CFLAGS -mwindows -o "$OUT/ps-exploit-host.exe" \
    src/main.c src/util.c src/block.c src/pak.c src/dns.c src/http.c \
    src/tls.c src/cert.c src/fw.c src/servers.c src/gui.c \
    "$OUT/host.res" $LIBS

echo "[*] mkpak"
$CC $CFLAGS -o "$OUT/mkpak.exe" tools/mkpak.c -lcabinet

ls -la "$OUT"/*.exe

if [ "$1" = "pack" ]; then
    SITES=${2:?usage: ./build.sh pack <sites-dir>}
    echo "[*] packing $SITES"
    echo "    run this from Windows - mkpak needs the Compression API:"
    echo "      $OUT\\mkpak.exe $OUT\\ps-exploit-host.exe $SITES ps-exploit-host-full.exe"
fi
