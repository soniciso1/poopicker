# Stop/Start must fully release the ports. This regression exists because the
# listeners block in recvfrom()/accept(); a stop flag alone never woke them, so
# the DNS socket stayed bound and the next Start failed with WSAEADDRINUSE
# (10048) - fatal for DNS specifically, because SO_EXCLUSIVEADDRUSE forbids a
# second bind where the TCP listeners could simply reuse theirs.
param(
    [string]$Exe = "E:\ps-exploit-host\build\host-test.exe",
    [string]$Ip = "127.0.0.1",
    [int]$Cycles = 4
)

Add-Type @"
using System;using System.Runtime.InteropServices;
public class UR{
 [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr h,int id);
 [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h,uint m,IntPtr w,IntPtr l);
 [DllImport("user32.dll",CharSet=CharSet.Ansi)] public static extern IntPtr SendMessageA(IntPtr h,uint m,IntPtr w,string l);
}
"@

$IDC_IP = 1001; $IDC_START = 1002; $IDC_STOP = 1003
$DNS = 15353; $HTTP = 8081; $HTTPS = 8443
$fails = 0

function Bound() {
    $u = Get-NetUDPEndpoint -LocalPort $DNS -ErrorAction SilentlyContinue
    $t = Get-NetTCPConnection -LocalPort $HTTP -State Listen -ErrorAction SilentlyContinue
    return [pscustomobject]@{ dns = [bool]$u; http = [bool]$t }
}

$p = Start-Process -FilePath $Exe -PassThru -ArgumentList @(
     "--dns-port",$DNS,"--http-port",$HTTP,"--https-port",$HTTPS)
Start-Sleep -Seconds 5
try {
    $p.Refresh(); $h = $p.MainWindowHandle
    [void][UR]::SendMessageA([UR]::GetDlgItem($h,$IDC_IP), 0x000C, [IntPtr]::Zero, $Ip)

    for ($i = 1; $i -le $Cycles; $i++) {
        [void][UR]::PostMessageW($h, 0x0111, [IntPtr]$IDC_START, [UR]::GetDlgItem($h,$IDC_START))
        Start-Sleep -Seconds 3
        $b = Bound
        if (-not ($b.dns -and $b.http)) { $fails++ }
        "{0} cycle {1} start -> dns={2} http={3}" -f `
            $(if($b.dns -and $b.http){"ok  "}else{"FAIL"}), $i, $b.dns, $b.http

        [void][UR]::PostMessageW($h, 0x0111, [IntPtr]$IDC_STOP, [UR]::GetDlgItem($h,$IDC_STOP))
        Start-Sleep -Seconds 3
        $b = Bound
        if ($b.dns -or $b.http) { $fails++ }
        "{0} cycle {1} stop  -> dns={2} http={3} (both must be False)" -f `
            $(if(-not $b.dns -and -not $b.http){"ok  "}else{"FAIL"}), $i, $b.dns, $b.http
    }
} finally {
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
}

Write-Host "`nFAILURES: $fails"
exit $(if ($fails) { 1 } else { 0 })
