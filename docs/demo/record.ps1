# 녹화기 — 데스크톱에 이미 떠 있는 터미널 창의 '영역'만 찍는다.
#
# 왜 창을 새로 안 만드나: 에이전트 셸에서 띄운 창은 대화형 데스크톱에 안 붙는다
# (6회 실측 — plain console·wt -w new·notepad 전부 EnumWindows에서 안 보임).
# 반면 이미 떠 있는 창의 좌표를 재서 그 사각형만 캡처하는 건 된다.
#
# ★전체 화면은 절대 찍지 않는다 — 다른 창(메신저·브라우저)이 그대로 녹화된다.
#   창을 못 찾으면 바탕화면으로 대체하지 않고 **중단**한다.
param(
    [int]$Seconds = 190,
    [string]$Out  = "",
    [int]$Fps     = 12
)
$ErrorActionPreference = "Stop"

Add-Type @"
using System; using System.Runtime.InteropServices;
public class W32 {
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L,T,R,B; }
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern bool SetForegroundWindow(IntPtr h);
  [DllImport("user32.dll")] public static extern bool ShowWindow(IntPtr h, int c);
}
"@
Add-Type -AssemblyName System.Windows.Forms

# ffmpeg 위치 — 후보 순서: ① PATH  ② 이 PC 실제 위치 ~\.local\ffmpeg  ③ WinGet.
# 새 터미널 -NoProfile에선 .local\ffmpeg가 PATH에 없어 ①이 비므로 ②가 필요.
$ff = @(
    (Get-Command ffmpeg -ErrorAction SilentlyContinue).Source,
    (Join-Path $env:USERPROFILE ".local\ffmpeg\ffmpeg.exe"),
    (Get-ChildItem "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\Gyan.FFmpeg*\*\bin\ffmpeg.exe" -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName)
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
if (-not $ff -or -not (Test-Path $ff)) { throw "ffmpeg 없음 — PATH나 WinGet에 설치 필요 (winget install Gyan.FFmpeg)" }
if (-not $Out) { $Out = Join-Path $PSScriptRoot "..\..\..\demo-recording.mp4" }

$term = Get-Process -Name WindowsTerminal -ErrorAction SilentlyContinue |
        Where-Object { $_.MainWindowHandle -ne 0 } | Select-Object -First 1
if (-not $term) { throw "터미널 창을 못 찾음 — 전체 화면으로 대체하지 않고 중단한다" }

[void][W32]::ShowWindow($term.MainWindowHandle, 9)      # SW_RESTORE
[void][W32]::SetForegroundWindow($term.MainWindowHandle)
Start-Sleep -Milliseconds 800

$r = New-Object W32+RECT
[void][W32]::GetWindowRect($term.MainWindowHandle, [ref]$r)
$vs = [System.Windows.Forms.SystemInformation]::VirtualScreen
$x = [Math]::Max($r.L, $vs.X); $y = [Math]::Max($r.T, $vs.Y)
$w = [Math]::Min($r.R, $vs.X + $vs.Width)  - $x
$h = [Math]::Min($r.B, $vs.Y + $vs.Height) - $y
if ($w % 2) { $w-- }; if ($h % 2) { $h-- }
if ($w -lt 400 -or $h -lt 300) { throw "창이 너무 작다 (${w}x${h}) — 최대화 후 재시도" }
Write-Host "녹화 영역: x=$x y=$y ${w}x${h} · ${Seconds}초 · ${Fps}fps"
Write-Host "출력: $Out"

$args = @("-y","-hide_banner","-loglevel","error","-f","gdigrab","-framerate","$Fps",
          "-offset_x","$x","-offset_y","$y","-video_size","${w}x${h}","-i","desktop",
          "-t","$Seconds","-pix_fmt","yuv420p","-c:v","libx264","-preset","veryfast",
          "-crf","23",$Out)
$proc = Start-Process -FilePath $ff -ArgumentList $args -PassThru -WindowStyle Hidden
Write-Host "ffmpeg PID=$($proc.Id) — 녹화 시작"
$proc.Id
