# ps-exploit-host

Portable PS4/PS5 exploit host: selective DNS spoofer + HTTP/HTTPS server with
the exploit-host site mirror bundled into the executable.

C99 and Win32 only. No Python, no runtime, no third-party libraries — TLS is
Schannel, certificate generation is CNG, decompression is the Windows
Compression API. The binary depends solely on DLLs that ship with the OS.

## Why it was rewritten

The previous PyInstaller build was a 458 MB one-file exe that **extracted all
458 MB to `%TEMP%\_MEIxxxxx` on every single launch** and left the directories
behind. This version memory-maps the archive in place: nothing is written to
`%TEMP%`, startup is immediate, and the code itself is 487 KB instead of the
12.8 MB Python runtime.

## Build

Needs MinGW-w64 (`x86_64-w64-mingw32-gcc`). From WSL:

    ./build.sh

produces `build/ps-exploit-host.exe` (the bare server) and `build/mkpak.exe`.

Then append the sites — run this on Windows, because mkpak uses the Compression
API:

    build\mkpak.exe build\ps-exploit-host.exe <sites-dir> ps-exploit-host-full.exe

`<sites-dir>` holds one directory per hostname, plus an optional `_builtin`
directory used as the fallback page when the configured guide site is missing.

    --fast    XPRESS_HUFF instead of LZMS: much quicker to pack and to serve,
              somewhat larger result
    --store   no compression at all

Files that do not compress usefully, and anything over 64 MB, are stored raw and
served straight out of the memory mapping with no copy.

Reference figures for the full mirror: 4,186 files, 931.9 MB on disk, packed to
a **416.5 MB** executable with LZMS in about five minutes (the old PyInstaller
build was 458 MB). `--fast` is quicker still but lands near 930 MB, because
most of the bulk is already-compressed payloads and only the HTML and JS
actually shrink — LZMS is worth the wait here.

If mkpak reports unreadable files it exits non-zero and the build must not be
shipped. Real-time antivirus holding the exploit payloads open is the usual
cause — 59 files went missing that way on the first pack here. Add a Defender
exclusion for the sites folder and pack again.

## Running

Double-click for the GUI, or pass arguments for the CLI. Drop an optional
`sites\` folder next to the exe to override bundled content without repacking —
the on-disk copy wins, so a single page can be swapped in place.

    --ip ADDR             LAN IP to advertise (default: auto-detected)
    --upstream ADDR       upstream DNS resolver (default 8.8.8.8)
    --domain NAME         extra domain to spoof (repeatable)
    --block NAME          extra domain to NXDOMAIN (repeatable; always applies)
    --allow-updates       do NOT block the firmware-update hosts
    --allow-game-updates  do NOT block the game/title patch hosts
    --url ADDR            send the User's Guide to a live online site
    --guide-site NAME     mirrored site the User's Guide opens
    --dns-port N  --http-port N  --https-port N
    --console             headless in the terminal instead of the GUI
    --list-sites          print the bundled site list and exit
    --open-ports / --remove-firewall / --enable-firewall / --disable-firewall

Set the console's DNS to this machine's IP, then open the User's Guide.

## Drop-in test sites

Any directory placed in `sites\` next to the exe is treated as a host in its own
right: it is DNS-spoofed, it appears in the **User's Guide opens** dropdown, and
it is served like a bundled mirror. Nothing is repacked, so testing a page costs
a restart rather than a 416 MB rebuild.

    build\sites\my-test\index.html      ->  host "my-test"

Point the guide at it with `--guide-site my-test` (or the dropdown) and the
console's User's Guide lands there. A directory of the same name as a bundled
site shadows it, which is the easy way to swap one page of a mirror.

Shipped example: `sites\netctrl-test\` is a staged harness for the PS5
`sys_netcontrol` port in `port\poops-slopkit\` — it reports the console's UA,
firmware, BigInt support and which slopkit runtime globals exist, then loads and
preflights the exploit, with the kernel race behind a separate confirm.

## Using a live online site instead of a bundled one

The **Online site** box in the GUI (or `--url`) points the User's Guide at a
real site on the internet rather than a mirror baked into the exe. Leave it
blank for the bundled behaviour. It applies live — no restart needed.

Two things have to happen together for this to work, and both are handled:

* The guide host is answered with a `302` to the URL, so the console's browser
  goes there instead of getting local content.
* That URL's hostname is **removed from DNS spoofing** and resolved upstream
  for real. Without this the redirect would bounce straight back into our own
  offline copy for any site we also mirror — `es7in1.site` and friends are all
  in the bundle, so this is the common case, not an edge case.

Hosts that are still bundled keep serving locally if the console asks for them
by name, so both modes coexist. `https://` is assumed when no scheme is typed.

**Update blocking is completely unaffected** — the blocklists are evaluated
before any of this, so firmware and game patches stay dead while browsing a
live site.

## Update blocking

Two independent toggles, both answering NXDOMAIN, both live — the DNS threads
read them per query, so flipping a checkbox needs no restart.

**Firmware** is the single suffix `update.playstation.net`. Suffix matching
means that one entry covers every regional host the public hosts-file lists
enumerate by hand, the whole `[dfh]<region>01.ps[45].update.playstation.net`
set, for both consoles.

**Game patches** are two stages per console — the version check and then the
payload. Killing the check alone stops updates; the payload hosts are listed so
a queued download cannot resume either.

| host | console | stage |
| --- | --- | --- |
| `sgst.prod.dl.playstation.net` | PS5 | title-update XML (the check) |
| `gst.prod.dl.playstation.net` | PS5 | patch PKG |
| `gs-sec.ww.prod.dl.playstation.net` | PS4 | update XML |
| `gs2.ww.prod.dl.playstation.net` | PS4 | patch manifest + PKG |

Deliberately **not** blocked, though public blocklists include them:
`tmdb.np.dl.playstation.net` and the other `*.np.dl.playstation.net` hosts are
title metadata and icons — blocking them breaks the library and store UI and
stops zero patches. The `ribob01.net`, `*.np.community.playstation.net` and
akadns entries kill PSN sign-in. The bare `prod.dl.playstation.net` suffix is
avoided too: it would block every store download, not just updates.

## Layout

    src/host.h      shared declarations
    src/main.c      entry point, CLI, configuration
    src/util.c      logging, paths, LAN IP detection
    src/block.c     the two blocklists
    src/pak.c       memory-mapped archive reader
    src/pakfmt.h    on-disk archive layout
    src/dns.c       DNS server (spoof / block / forward)
    src/http.c      request handling, routing, MIME, plain listener
    src/tls.c       Schannel HTTPS listener
    src/cert.c      CNG self-signed certificate, cached as snakeoil.pfx
    src/fw.c        Windows Firewall helpers via netsh
    src/servers.c   start/stop the listeners as a unit
    src/gui.c       Win32 dialog
    src/host.rc     dialog template
    tools/mkpak.c   the packer
    test/e2e.ps1    end-to-end tests

## Notes

* The certificate is cached as `snakeoil.pfx` next to the exe and regenerated
  automatically whenever it stops matching the current IP or domain list, so
  moving the folder between machines just works.
* The DNS socket uses `SO_EXCLUSIVEADDRUSE` and binds the specific LAN IP.
  Sharing port 53 with the Internet Connection Sharing service would send
  queries to a random one of the two sockets, so an exclusive bind is used to
  fail loudly instead. If the bind fails: `net stop SharedAccess`.
* Schannel is configured for TLS 1.0–1.2. Offering only modern suites would
  lock the PS4 browser out entirely.

## Reading a packed exe back

`tools/unpak.py` lists or extracts the archive appended to a built host, which
is how a shipped binary is audited without trusting the notes that came with it:

    python tools/unpak.py poopicker-host.exe                       # list sites
    python tools/unpak.py poopicker-host.exe --out DIR             # extract all
    python tools/unpak.py poopicker-host.exe --out DIR p2jb        # one site

Windows only — LZMS decompression goes through the same `Cabinet.dll`
Compression API that `mkpak` compressed with, and there is no pure-Python LZMS.
Note that `mkpak` lowercases stored paths and the server lowercases request
paths, so `payloads/etaHEN.elf` is stored as `payloads/etahen.elf` and still
serves.
