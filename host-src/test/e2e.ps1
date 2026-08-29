# End-to-end check of the packed host binary: DNS spoof, both blocklists,
# upstream forwarding, HTTP routing by Host header, and the TLS listener.
# Uses only .NET sockets so the test rig needs nothing installed.
param(
    [string]$Exe = "E:\ps-exploit-host\build\host-test.exe",
    [string]$Ip = "127.0.0.1",
    [int]$DnsPort = 15353,
    [int]$HttpPort = 8081,
    [int]$HttpsPort = 8443
)

$fails = 0
function Check($label, $got, $want) {
    $ok = ($got -eq $want)
    if (-not $ok) { $script:fails++ }
    "{0} {1,-46} got={2} want={3}" -f $(if ($ok) { "ok  " } else { "FAIL" }), $label, $got, $want
}

function New-DnsQuery([string]$name, [int]$qtype = 1) {
    $b = New-Object System.Collections.Generic.List[byte]
    $b.AddRange([byte[]](0x12, 0x34))       # id
    $b.AddRange([byte[]](0x01, 0x00))       # RD
    $b.AddRange([byte[]](0x00, 0x01))       # qdcount
    $b.AddRange([byte[]](0, 0, 0, 0, 0, 0)) # an/ns/ar
    foreach ($label in $name.Split('.')) {
        $b.Add([byte]$label.Length)
        $b.AddRange([System.Text.Encoding]::ASCII.GetBytes($label))
    }
    $b.Add(0)
    $b.AddRange([byte[]](0, $qtype))
    $b.AddRange([byte[]](0, 1))             # class IN
    return , $b.ToArray()
}

function Invoke-Dns([string]$name, [int]$qtype = 1) {
    $c = New-Object System.Net.Sockets.UdpClient
    $c.Client.ReceiveTimeout = 5000
    try {
        $q = New-DnsQuery $name $qtype
        [void]$c.Send($q, $q.Length, $Ip, $DnsPort)
        $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        $r = $c.Receive([ref]$ep)
        $rcode = $r[3] -band 0x0F
        $ancount = ($r[6] -shl 8) -bor $r[7]
        $a = $null
        if ($ancount -gt 0 -and $r.Length -ge 4) {
            $a = "{0}.{1}.{2}.{3}" -f $r[$r.Length - 4], $r[$r.Length - 3],
                                     $r[$r.Length - 2], $r[$r.Length - 1]
        }
        return [pscustomobject]@{ rcode = $rcode; ancount = $ancount; addr = $a }
    } catch {
        return [pscustomobject]@{ rcode = -1; ancount = -1; addr = $null }
    } finally { $c.Close() }
}

function Invoke-Http([string]$hostHeader, [string]$path) {
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        $c.Connect($Ip, $HttpPort)
        $s = $c.GetStream()
        $req = "GET $path HTTP/1.1`r`nHost: $hostHeader`r`nConnection: close`r`n`r`n"
        $bytes = [System.Text.Encoding]::ASCII.GetBytes($req)
        $s.Write($bytes, 0, $bytes.Length)
        $sr = New-Object System.IO.StreamReader($s)
        return $sr.ReadToEnd()
    } catch { return "ERROR: $_" } finally { $c.Close() }
}

Write-Host "=== starting $Exe ==="
$p = Start-Process -FilePath $Exe -PassThru -WindowStyle Hidden -ArgumentList @(
    "--console", "--ip", $Ip, "--dns-port", $DnsPort, "--http-port", $HttpPort,
    "--https-port", $HttpsPort, "--no-firewall", "--upstream", "8.8.8.8")
Start-Sleep -Seconds 3

try {
    Write-Host "`n--- DNS ---"
    $r = Invoke-Dns "test.site"
    Check "spoof test.site -> our IP" $r.addr $Ip
    $r = Invoke-Dns "sub.test.site"
    Check "spoof subdomain of a mirrored host" $r.addr $Ip
    $r = Invoke-Dns "manuals.playstation.net"
    Check "spoof guide host" $r.addr $Ip

    $r = Invoke-Dns "update.playstation.net"
    Check "firmware block -> NXDOMAIN" $r.rcode 3
    $r = Invoke-Dns "fus01.ps5.update.playstation.net"
    Check "firmware block covers regional host" $r.rcode 3
    $r = Invoke-Dns "sgst.prod.dl.playstation.net"
    Check "game block (PS5 update XML)" $r.rcode 3
    $r = Invoke-Dns "gs2.ww.prod.dl.playstation.net"
    Check "game block (PS4 patch manifest)" $r.rcode 3

    $r = Invoke-Dns "tmdb.np.dl.playstation.net"
    Check "title metadata NOT blocked" $r.rcode 0

    $r = Invoke-Dns "example.com"
    Check "unrelated host forwarded upstream" ($r.ancount -ge 1) $true

    $r = Invoke-Dns "test.site" 28
    Check "AAAA answered empty, not spoofed" $r.ancount 0

    Write-Host "`n--- HTTP ---"
    $h = Invoke-Http "test.site" "/"
    Check "test.site / -> 200" ($h -match "^HTTP/1.1 200") $true
    Check "test.site / body" ($h -match "site index") $true

    $h = Invoke-Http "test.site" "/sub/app.js"
    Check "nested path served" ($h -match "console\.log") $true
    Check "js content-type" ($h -match "Content-Type: application/javascript") $true

    $h = Invoke-Http "test.site" "/some/deep/prefix/sub/app.js"
    Check "prefix stripping finds the file" ($h -match "console\.log") $true

    $h = Invoke-Http "test.site" "/payload.bin"
    Check "binary served with octet-stream" ($h -match "application/octet-stream") $true

    $h = Invoke-Http "manuals.playstation.net" "/document/en/ps5/index.html"
    Check "guide host falls through to es7in1" ($h -match "es7 menu") $true

    $h = Invoke-Http "test.site" "/nope.js"
    Check "missing script -> 404, not HTML" ($h -match "^HTTP/1.1 404") $true

    $h = Invoke-Http "test.site" "/nope.html"
    Check "missing page -> index.html" ($h -match "site index") $true

    $h = Invoke-Http "test.site" "/../../snakeoil.pfx"
    Check "key material never served" ($h -notmatch "PFX") $true

    # Round-trip the archive: big.html is stored compressed and must come back
    # byte-identical, random.bin does not compress so it is served straight out
    # of the memory mapping with no copy.
    Write-Host "`n--- archive round-trip ---"
    $sitesDir = "E:\ps-exploit-host\testsites\test.site"
    foreach ($name in @("big.html", "random.bin", "payload.bin")) {
        $tmp = Join-Path $env:TEMP "peh_$name"
        & curl.exe -sS -o $tmp -H "Host: test.site" "http://$Ip`:$HttpPort/$name" 2>&1 | Out-Null
        $want = (Get-FileHash -LiteralPath (Join-Path $sitesDir $name) -Algorithm SHA256).Hash
        $got = if (Test-Path $tmp) { (Get-FileHash -LiteralPath $tmp -Algorithm SHA256).Hash } else { "MISSING" }
        Check "$name sha256 matches source" $got $want
        Remove-Item $tmp -ErrorAction SilentlyContinue
    }

    # curl.exe, not .NET: PowerShell 5.1's HttpClientHandler silently ignores
    # ServerCertificateCustomValidationCallback, so a self-signed cert can
    # never be accepted there no matter what the callback returns.
    Write-Host "`n--- HTTPS ---"
    $code = (& curl.exe -k -sS -o NUL -w "%{http_code}" -H "Host: test.site" `
             "https://$Ip`:$HttpsPort/" 2>&1) -join ""
    Check "TLS handshake + 200" $code "200"

    $body = (& curl.exe -k -sS -H "Host: test.site" "https://$Ip`:$HttpsPort/" 2>&1) -join ""
    Check "TLS body correct" ($body -match "site index") $true

    $body = (& curl.exe -k -sS -H "Host: test.site" `
             "https://$Ip`:$HttpsPort/sub/app.js" 2>&1) -join ""
    Check "TLS serves nested asset" ($body -match "console\.log") $true
} finally {
    Write-Host "`n=== stopping ==="
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
}

# Phase 2. With the upstream pointed at a black hole, a forwarded query times
# out while a blocked one still answers NXDOMAIN instantly. That is the only
# way to tell "we blocked it" apart from "the real resolver said NXDOMAIN",
# which is what made the suffix-precision check ambiguous before.
function Phase2([string]$label, [string[]]$extraArgs, [hashtable]$expect) {
    Write-Host "`n--- $label ---"
    $args = @("--console", "--ip", $Ip, "--dns-port", $DnsPort,
              "--http-port", $HttpPort, "--https-port", $HttpsPort,
              "--no-firewall", "--upstream", "192.0.2.1") + $extraArgs
    $proc = Start-Process -FilePath $Exe -PassThru -WindowStyle Hidden -ArgumentList $args
    Start-Sleep -Seconds 2
    try {
        foreach ($name in $expect.Keys) {
            $r = Invoke-Dns $name
            $blocked = ($r.rcode -eq 3)
            Check $name $blocked $expect[$name]
        }
    } finally {
        Stop-Process -Id $proc.Id -Force -ErrorAction SilentlyContinue
        Start-Sleep -Milliseconds 500
    }
}

Phase2 "both toggles on (default)" @() @{
    "update.playstation.net"             = $true
    "hjp01.ps5.update.playstation.net"   = $true
    "sgst.prod.dl.playstation.net"       = $true
    "gs2.ww.prod.dl.playstation.net"     = $true
    "notupdate.playstation.net.evil.com" = $false   # suffix spoof, must forward
    "prod.dl.playstation.net"            = $false   # never blanket-blocked
    "tmdb.np.dl.playstation.net"         = $false   # metadata stays reachable
}

Phase2 "--allow-game-updates" @("--allow-game-updates") @{
    "update.playstation.net"         = $true
    "sgst.prod.dl.playstation.net"   = $false
    "gs2.ww.prod.dl.playstation.net" = $false
}

Phase2 "--allow-updates" @("--allow-updates") @{
    "update.playstation.net"       = $false
    "sgst.prod.dl.playstation.net" = $true
}

Phase2 "both allowed + custom --block" @("--allow-updates", "--allow-game-updates",
                                         "--block", "evil.example.com") @{
    "update.playstation.net"       = $false
    "sgst.prod.dl.playstation.net" = $false
    "evil.example.com"             = $true
    "a.evil.example.com"           = $true
}

Write-Host "`nFAILURES: $fails"
exit $(if ($fails) { 1 } else { 0 })
