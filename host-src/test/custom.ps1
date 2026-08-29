# Checks the online-site redirect: the guide host must 302 to the configured
# URL, bundled mirrors must still serve locally, the custom host must be
# excluded from DNS spoofing, and the update blocklists must be unaffected.
param(
    [string]$Exe = "E:\ps-exploit-host\build\host-test.exe",
    [string]$Ip = "127.0.0.1",
    [int]$DnsPort = 15353,
    [int]$HttpPort = 8081
)

$fails = 0
function Check($label, $got, $want) {
    $ok = ($got -eq $want)
    if (-not $ok) { $script:fails++ }
    "{0} {1,-44} got={2} want={3}" -f $(if($ok){"ok  "}else{"FAIL"}), $label, $got, $want
}

function Invoke-Dns([string]$name) {
    $c = New-Object System.Net.Sockets.UdpClient; $c.Client.ReceiveTimeout = 4000
    try {
        $b = New-Object System.Collections.Generic.List[byte]
        $b.AddRange([byte[]](0x12,0x34,0x01,0x00,0x00,0x01,0,0,0,0,0,0))
        foreach ($l in $name.Split('.')) {
            $b.Add([byte]$l.Length)
            $b.AddRange([System.Text.Encoding]::ASCII.GetBytes($l))
        }
        $b.Add(0); $b.AddRange([byte[]](0,1,0,1))
        $q = $b.ToArray(); [void]$c.Send($q,$q.Length,$Ip,$DnsPort)
        $ep = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any,0)
        $r = $c.Receive([ref]$ep)
        $addr = $null
        $an = ($r[6] -shl 8) -bor $r[7]
        if ($an -gt 0) { $addr = "{0}.{1}.{2}.{3}" -f $r[$r.Length-4],$r[$r.Length-3],$r[$r.Length-2],$r[$r.Length-1] }
        return [pscustomobject]@{ rcode = ($r[3] -band 0x0F); addr = $addr }
    } catch { return [pscustomobject]@{ rcode = -1; addr = $null } }
    finally { $c.Close() }
}

# Upstream is a black hole, so "forwarded" shows up as a timeout (rcode -1)
# and can be told apart from anything we answered ourselves.
$p = Start-Process -FilePath $Exe -PassThru -WindowStyle Hidden -ArgumentList @(
     "--console","--ip",$Ip,"--dns-port",$DnsPort,"--http-port",$HttpPort,
     "--https-port","8443","--no-firewall","--upstream","192.0.2.1",
     "--url","es7in1.site")
Start-Sleep -Seconds 4
try {
    Write-Host "--- redirect ---"
    $r = (& curl.exe -sS -i -H "Host: manuals.playstation.net" `
          "http://$Ip`:$HttpPort/document/en/ps5/index.html" 2>&1) -join "`n"
    Check "guide host -> 302" ($r -match "302 Found") $true
    Check "Location is the online site" ($r -match "Location: https://es7in1\.site") $true

    $r = (& curl.exe -sS -i -H "Host: some.unknown.host" "http://$Ip`:$HttpPort/" 2>&1) -join "`n"
    Check "unknown host also redirected" ($r -match "302 Found") $true

    $r = (& curl.exe -sS -i -H "Host: test.site" "http://$Ip`:$HttpPort/" 2>&1) -join "`n"
    Check "bundled mirror still served locally" ($r -match "200 OK") $true
    Check "bundled mirror body intact" ($r -match "site index") $true

    Write-Host "`n--- DNS ---"
    $d = Invoke-Dns "manuals.playstation.net"
    Check "guide host still spoofed to us" $d.addr $Ip
    $d = Invoke-Dns "es7in1.site"
    Check "custom host NOT spoofed (forwarded)" ($d.addr -eq $null) $true
    $d = Invoke-Dns "test.site"
    Check "other mirrors still spoofed" $d.addr $Ip

    Write-Host "`n--- blocking is unaffected ---"
    $d = Invoke-Dns "update.playstation.net"
    Check "firmware still blocked" $d.rcode 3
    $d = Invoke-Dns "sgst.prod.dl.playstation.net"
    Check "game patches still blocked" $d.rcode 3
} finally {
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
}

Write-Host "`nFAILURES: $fails"
exit $(if ($fails) { 1 } else { 0 })
