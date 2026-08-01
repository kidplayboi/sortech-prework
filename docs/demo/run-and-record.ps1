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
param([int]$Seconds = 190, [int]$Fps = 12, [switch]$Force)
$ErrorActionPreference = "Stop"

Add-Type @"
using System; using System.Text; using System.Collections.Generic; using System.Runtime.InteropServices;
public class W32 {
  [StructLayout(LayoutKind.Sequential)] public struct RECT { public int L,T,R,B; }
  [DllImport("user32.dll")] public static extern bool GetWindowRect(IntPtr h, out RECT r);
  [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
  [DllImport("user32.dll")] public static extern uint GetWindowThreadProcessId(IntPtr h, out uint pid);
  [DllImport("user32.dll")] static extern int GetWindowTextW(IntPtr h, StringBuilder s, int n);
  public static string Title(IntPtr h) { var sb = new StringBuilder(512); GetWindowTextW(h, sb, sb.Capacity); return sb.ToString(); }
}
"@
Add-Type -AssemblyName System.Windows.Forms

$MARKER = "SORTECH-ONETAKE"
$repo   = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
# ffmpeg 위치 — 후보를 순서대로 시도한다(PC마다 위치가 달라 단일 경로는 깨진다):
#  ① PATH  ② 이 PC 실제 위치 ~\.local\ffmpeg  ③ WinGet(Gyan.FFmpeg) 설치.
# ★새 터미널 -NoProfile에선 .local\ffmpeg가 PATH에 없어 ①이 비므로 ②가 반드시 필요.
$ff = @(
    (Get-Command ffmpeg -ErrorAction SilentlyContinue).Source,
    (Join-Path $env:USERPROFILE ".local\ffmpeg\ffmpeg.exe"),
    (Get-ChildItem "$env:LOCALAPPDATA\Microsoft\WinGet\Packages\Gyan.FFmpeg*\*\bin\ffmpeg.exe" -ErrorAction SilentlyContinue |
        Select-Object -First 1 -ExpandProperty FullName)
) | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1
# 제출 폴더에 바로 떨어뜨린다 — 촬영 후 파일을 옮기는 단계를 없앤다(옮기다 빠뜨린다).
# 레포 밖이라 대용량 바이너리가 커밋될 일도 없다.
$outDir = Join-Path $env:USERPROFILE "Downloads\sortech-제출"
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Force -Path $outDir | Out-Null }
$out    = Join-Path $outDir "실행화면-녹화.mp4"
if (-not $ff -or -not (Test-Path $ff)) { throw "ffmpeg 없음 — PATH나 WinGet에 설치 필요 (winget install Gyan.FFmpeg)" }

$Host.UI.RawUI.WindowTitle = $MARKER
[Console]::Title = $MARKER
Start-Sleep -Milliseconds 900

# --- 안전 검증: 지금 최상위 창이 '내 창'인가 -------------------------------
# 제목만 보면 Windows Terminal이 제목 변경을 창(HWND)에 반영 안 해 자기 창을
# 못 알아본다(현재='S' 등). 제목이 안 맞으면 **최상위 창의 소유 프로세스가 이
# 스크립트의 조상(=나를 띄운 터미널)인지**로 확인한다. 둘 중 하나면 내 창이다.
function Get-AncestorPidSet([int]$seed) {
    $set = New-Object 'System.Collections.Generic.HashSet[int]'
    $cur = $seed
    for ($i = 0; $i -lt 8 -and $cur -gt 0; $i++) {
        [void]$set.Add($cur)
        $p = Get-CimInstance Win32_Process -Filter "ProcessId=$cur" -ErrorAction SilentlyContinue
        if (-not $p) { break }
        $cur = [int]$p.ParentProcessId
    }
    return $set
}
$fg = [W32]::GetForegroundWindow()
$fgTitle = [W32]::Title($fg)
$fgPid = [uint32]0
[void][W32]::GetWindowThreadProcessId($fg, [ref]$fgPid)
$mineIsFg = (Get-AncestorPidSet $PID).Contains([int]$fgPid)
if ((-not $Force) -and ($fgTitle -notlike "*$MARKER*") -and (-not $mineIsFg)) {
    throw "최상위 창이 이 데모 창이 아니다 (현재 제목='$fgTitle', pid=$fgPid). " +
          "이 터미널 창을 맨 앞에 두고 다시 실행하거나, 화면 정리를 확인했으면 뒤에 -Force 를 붙일 것."
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

# ffmpeg를 stdin 열고 띄운다 — 종료를 강제 kill이 아니라 'q'(정상 종료)로 해야
# mp4 마무리(moov atom)를 써서 재생 가능한 파일이 된다. 강제 kill = moov 없음 = 재생불가.
$argLine = "-y -hide_banner -loglevel error -f gdigrab -framerate $Fps -offset_x $x -offset_y $y -video_size ${w}x${h} -i desktop -t $Seconds -pix_fmt yuv420p -c:v libx264 -preset veryfast -crf 23 `"$out`""
$psi = New-Object System.Diagnostics.ProcessStartInfo
$psi.FileName = $ff
$psi.Arguments = $argLine
$psi.UseShellExecute = $false
$psi.RedirectStandardInput = $true
$psi.CreateNoWindow = $true
$rec = [System.Diagnostics.Process]::Start($psi)
Start-Sleep -Seconds 2

try {
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $PSScriptRoot "demo.ps1")
} finally {
    Start-Sleep -Seconds 3
    if ($rec -and -not $rec.HasExited) {
        # 강제 kill 금지 — 'q'로 정상 종료시켜 moov를 쓰게 한다(재생 가능 보장).
        try { $rec.StandardInput.Write("q"); $rec.StandardInput.Flush() } catch {}
        if (-not $rec.WaitForExit(8000)) { try { $rec.Kill() } catch {} }
    }
    Start-Sleep -Seconds 2
    if (Test-Path $out) {
        Write-Host ""
        Write-Host ("  녹화 완료: $out  ({0:N1} MB)" -f ((Get-Item $out).Length / 1MB)) -ForegroundColor Green
    } else {
        Write-Host "  녹화 실패 — 파일이 없다" -ForegroundColor Red
    }
}
