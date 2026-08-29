# Opens the donation dialog, screenshots it, and checks every Copy button puts
# the right address on the clipboard.
#
# Two traps this test exists to avoid re-learning:
#   * Post, never Send, the button click - the dialog is MODAL, so SendMessage
#     would not return until it closed and the test would hang forever.
#   * Locate the dialog with EnumWindows, not FindWindowW; the latter did not
#     match the caption reliably even with the window open and visible.
# Must run STA: clipboard access hangs in the default MTA runspace.
param([string]$Exe = "E:\ps-exploit-host\build\host-test.exe")

Add-Type -AssemblyName System.Drawing
Add-Type -AssemblyName System.Windows.Forms
Add-Type @"
using System;using System.Text;using System.Collections.Generic;using System.Runtime.InteropServices;
public struct RECTD{public int L,T,R,B;}
public class UD{
 public delegate bool EnumProc(IntPtr h,IntPtr l);
 [DllImport("user32.dll")] public static extern bool EnumWindows(EnumProc cb,IntPtr l);
 [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h,out uint pid);
 [DllImport("user32.dll",CharSet=CharSet.Unicode)] public static extern int GetWindowTextW(IntPtr h,StringBuilder s,int c);
 [DllImport("user32.dll")] public static extern IntPtr GetDlgItem(IntPtr h,int id);
 [DllImport("user32.dll")] public static extern bool PostMessageW(IntPtr h,uint m,IntPtr w,IntPtr l);
 [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h,out RECTD r);
 [DllImport("user32.dll")] public static extern bool PrintWindow(IntPtr h,IntPtr dc,uint f);
 public static uint Target; public static string Want; public static IntPtr Hit;
 public static bool Cb(IntPtr h,IntPtr l){
   uint pid; GetWindowThreadProcessId(h,out pid);
   if(pid==Target){ var t=new StringBuilder(200); GetWindowTextW(h,t,200);
     if(t.ToString()==Want) Hit=h; }
   return true; }
}
"@

$WANT = @(
 "bc1q03qy0d85px8z7nn882xzq5r7ny9k9dpvkzwc55",
 "bc1qyug6sn9d9u6lsdn9pqpl59euldrwntrgm6uxtg",
 "E3cSJRoWvNjQkvNHMLmyN1dba4t4j3cdLjiYY8RXs28e",
 "0x4FD7C01DF66F307Eb4D95E3b4981a71ca1Efda75",
 "0x4FD7C01DF66F307Eb4D95E3b4981a71ca1Efda75",
 "47dgHAixRSmTC4y1Daf5xH3svZjKRNEHSenAQUzsnJucCtVxNodc4Y78ECACYibFvMhfLREzUvu2FPnUqcoZ94GzLfCfZrJ"
)

function Find-Win([int]$procId, [string]$title) {
    [UD]::Target = $procId; [UD]::Want = $title; [UD]::Hit = [IntPtr]::Zero
    $cb = [UD+EnumProc]{ param($a,$b) [UD]::Cb($a,$b) }
    [void][UD]::EnumWindows($cb, [IntPtr]::Zero)
    return [UD]::Hit
}

$fails = 0
$p = Start-Process -FilePath $Exe -PassThru -ArgumentList @(
     "--dns-port","15353","--http-port","8081","--https-port","8443")
Start-Sleep -Seconds 5
try {
    $p.Refresh(); $h = $p.MainWindowHandle
    [void][UD]::PostMessageW($h, 0x0111, [IntPtr]1016, [UD]::GetDlgItem($h,1016))
    Start-Sleep -Seconds 2

    $d = Find-Win $p.Id "Support the dev"
    if ($d -eq [IntPtr]::Zero) { Write-Host "FAIL dialog never opened"; exit 1 }
    Write-Host "ok   donation dialog opened"

    $r = New-Object RECTD; [void][UD]::GetWindowRect($d,[ref]$r)
    $w = $r.R-$r.L; $ht = $r.B-$r.T
    $bmp = New-Object System.Drawing.Bitmap $w,$ht
    $g = [System.Drawing.Graphics]::FromImage($bmp); $hdc = $g.GetHdc()
    [void][UD]::PrintWindow($d,$hdc,2); $g.ReleaseHdc($hdc)
    $bmp.Save("E:\ps-exploit-host\build\gui_donate.png",
              [System.Drawing.Imaging.ImageFormat]::Png)
    $g.Dispose(); $bmp.Dispose()
    Write-Host "ok   screenshot captured"

    for ($i = 0; $i -lt 6; $i++) {
        [System.Windows.Forms.Clipboard]::Clear()
        [void][UD]::PostMessageW($d, 0x0111, [IntPtr](1130+$i), [UD]::GetDlgItem($d,1130+$i))
        Start-Sleep -Milliseconds 500
        $got = [System.Windows.Forms.Clipboard]::GetText()
        $ok = ($got -eq $WANT[$i])
        if (-not $ok) { $fails++ }
        "{0} row {1} -> {2}" -f $(if($ok){"ok  "}else{"FAIL"}), $i,
            $(if($ok){$WANT[$i].Substring(0,[Math]::Min(26,$WANT[$i].Length)) + "..."}
              else {"got '$got'"})
    }
} finally {
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
}
Write-Host "`nFAILURES: $fails"
exit $(if ($fails) { 1 } else { 0 })
