# poopicker

Index page for the PS5 exploit sites, plus the offline host that serves them.

**Live index:** https://soniciso1.github.io/poopicker/

## poopicker-host.exe — the offline DNS + HTTP/HTTPS host

One executable. No install, no Python, nothing extracted to `%TEMP%` — the site
archive is memory-mapped in place. Run it elevated, point the console's DNS at
the PC, and open any address in the console browser: **any unknown hostname
serves the poopicker page**, so a stale bookmark lands on the index rather than
an error.

Download it from [Releases](../../releases). What is packed inside:

| site | chain | firmware | console |
|---|---|---|---|
| `poopicker` | — | — | the index |
| `p2jb` | kqueueex `cr_ref` leak | 12.00 – 12.70 | retail / testkit |
| `p2jb-dev` | same | 12.00 – 12.70 | devkit |
| `poopsploit` | netcontrol IPv6 `rthdr` UAF | 7.00 – 12.00 | retail / testkit |
| `poopsploit-dev` | same | 7.00 – 12.00 | devkit |
| `luasauce` | UMTX | | retail / testkit |
| `luasaucedev` | UMTX | | devkit |

Use **poopsploit on 12.00 and below** — it jailbreaks in seconds and tears down
cleanly. **p2jb** is only needed above 12.00: its leak runs for roughly 55
minutes before the race even starts.

`luasauce` / `luasaucedev` are a verbatim copy of
[zecoxao](https://github.com/zecoxao/zecoxao.github.io)'s sites (commit
`1a107fe`). Not our work; the credits on those pages are theirs and unmodified.

### Running it

    poopicker-host.exe                       GUI; DNS :53, HTTP :80, HTTPS :443
    poopicker-host.exe --console             headless in a terminal
    poopicker-host.exe --list-sites          print the packed hostnames and exit
    poopicker-host.exe --dns-port 5354       if something already owns :53

`--allow-updates` / `--allow-game-updates` turn the update blocking back off.

## host-src/

Full C source for that host — DNS spoofer, HTTP/HTTPS server, Schannel TLS, CNG
certificate generation, and `mkpak`, which appends a site tree to the bare exe.
C99 and Win32 only: no Python, no runtime, no third-party libraries. See
[host-src/README.md](host-src/README.md) to build it, and
`host-src/tools/unpak.py` to read a packed binary back and check what is
actually in it.
