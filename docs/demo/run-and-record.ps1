# 3분 원테이크 녹화 — **전용 터미널 창에서만** 실행한다.
#
# ⚠️왜 이렇게까지 하나 (실제 사고 직전까지 감):
#   "이미 떠 있는 터미널 창의 영역"을 캡처했더니, 리허설 영상에 다른 프로젝트의
#   작업 세션 전문과 메신저 창이 그대로 찍혔다. 라이브 데스크톱의 한 사각형을
#   찍는다는 건 그 자리에 무엇이 있든 찍는다는 뜻이다. 그대로 제출했으면 공개
#   제출물에 무관한 정보가 들어갔다. 그래서:
#     1) 이 스크립트를 실행한 **자기 창**만 찍는다 (제목 마커로 식별)
#     2) 마커 창을 못 찾거나 여러 개면 **중단**한다 (바탕화면 대체 없음)
#     3) 녹화 중 다른 창을 이 창 위에 올리면 그게 찍힌다 — 3분간 건드리지 말 것
#
# 사용법: 새 터미널 창을 하나 열고(작업 중인 창 말고) 아래 한 줄
#   powershell -NoProfile -ExecutionPolicy Bypass -File docs\demo\run-and-record.ps1
param([int]$Seconds = 190, [int]$Fps = 12)
$ErrorActionPreference = "Stop"

Add-Type @"
using System; using System.Text; using System.Collections.Generic; using System.Runtime.InteropServices;
public class W32 {
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L,T,R,B; }
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  public static string Title(IntPtr h) { var sb = new StringBuilder(512); GetWindowTextW(h, sb, sb.Capacity); return sb.ToString(); }
}
"@
Add-Type -AssemblyName System.Windows.Forms

$MARKER = "SORTECH-ONETAKE"
$repo   = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
$ff     = "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\Gyan.FFmpeg_Microsoft.Winget.Source_8wekyb3d8bbwe\ffmpeg-8.1.2-full_build\bin\ffmpeg.exe"
# 제출 폴더에 바로 떨어뜨린다 — 촬영 후 파일을 옮기는 단계를 없앤다(옮기다 빠뜨린다).
# 레포 밖이라 대용량 바이너리가 커밋될 일도 없다.
$outDir = Join-Path $env:USERPROFILE "Downloads\sortech-제출"
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Force -Path $outDir | Out-Null }
$out    = Join-Path $outDir "실행화면-녹화.mp4"
if (-not (Test-Path $ff)) { throw "ffmpeg 없음: $ff" }

$Host.UI.RawUI.WindowTitle = $MARKER
Start-Sleep -Milliseconds 900

# --- 안전 검증: 지금 최상위 창이 '내 창'인가 -------------------------------
$fg = [W32]::GetForegroundWindow()
$fgTitle = [W32]::Title($fg)
if ($fgTitle -notlike "*$MARKER*") {
    throw "최상위 창이 이 데모 창이 아니다 (현재: '$fgTitle'). " +
          "이 창을 클릭해 맨 앞으로 놓고 다시 실행할 것 — 다른 창이 녹화되면 안 된다."
}
$candidates = Get-Process -Name WindowsTerminal, powershell, pwsh -ErrorAction SilentlyContinue |
              Where-Object { $_.MainWindowHandle -ne 0 -and $_.MainWindowTitle -like "*$MARKER*" }
if (@($candidates).Count -gt 1) { throw "마커 창이 여러 개다 — 하나만 남기고 다시 실행할 것" }

$r = New-Object W32+RECT
[void][W32]::GetWindowRect($fg, [ref]$r)
$vs = [System.Windows.Forms.SystemInformation]::VirtualScreen
$x = [Math]::Max($r.L, $vs.X); $y = [Math]::Max($r.T, $vs.Y)
$w = [Math]::Min($r.R, $vs.X + $vs.Width)  - $x
$h = [Math]::Min($r.B, $vs.Y + $vs.Height) - $y
if ($w % 2) { $w-- }; if ($h % 2) { $h-- }
if ($w -lt 700 -or $h -lt 500) { throw "창이 작다 (${w}x${h}) — 최대화 후 다시 실행할 것" }

Write-Host ""
Write-Host "  녹화 준비: ${w}x${h} @ ${Fps}fps · ${Seconds}초" -ForegroundColor Yellow
Write-Host "  ⚠️ 지금부터 3분간 이 창을 건드리지 말 것 (다른 창을 올리면 그게 찍힌다)" -ForegroundColor Red
Write-Host "  출력: $out" -ForegroundColor DarkGray
Write-Host ""
Start-Sleep -Seconds 4

$ffArgs = @("-y","-hide_banner","-loglevel","error","-f","gdigrab","-framerate","$Fps",
            "-offset_x","$x","-offset_y","$y","-video_size","${w}x${h}","-i","desktop",
            "-t","$Seconds","-pix_fmt","yuv420p","-c:v","libx264","-preset","veryfast",
            "-crf","23",$out)
$rec = Start-Process -FilePath $ff -ArgumentList $ffArgs -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 2

try {
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "demo.ps1")
} finally {
    Start-Sleep -Seconds 3
    if (-not $rec.HasExited) { $rec | Stop-Process -Force -ErrorAction SilentlyContinue }
    Start-Sleep -Seconds 2
    if (Test-Path $out) {
        Write-Host ""
        Write-Host ("  녹화 완료: $out  ({0:N1} MB)" -f ((Get-Item $out).Length / 1MB)) -ForegroundColor Green
    } else {
        Write-Host "  녹화 실패 — 파일이 없다" -ForegroundColor Red
    }
}
