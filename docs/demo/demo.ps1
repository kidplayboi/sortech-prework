# 무편집 3분 원테이크용 데모 대본. 이 스크립트가 터미널 탭 안에서 통째로 돈다.
# 편집 없이 한 번에 찍기 위해 "읽을 시간"까지 스크립트가 갖고 있다.
# ⚠️sites.json·state.json을 건드리지 않는 시나리오만 쓴다 — 녹화가 중간에 끊겨도
#   레포가 더럽혀지지 않아야 한다.
$ErrorActionPreference = "Continue"
$repo = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Set-Location $repo
$Host.UI.RawUI.WindowTitle = "SORTECH-DEMO"

function Card($lines, $pause = 6) {
    Write-Host ""
    Write-Host ("  " + ("=" * 74)) -ForegroundColor DarkGray
    foreach ($l in $lines) { Write-Host ("  " + $l) -ForegroundColor Cyan }
    Write-Host ("  " + ("=" * 74)) -ForegroundColor DarkGray
    Write-Host ""
    Start-Sleep -Seconds $pause
}

function Step($n, $title, $why) {
    Write-Host ""
    Write-Host ("  [$n] $title") -ForegroundColor Yellow
    Write-Host ("      $why") -ForegroundColor DarkGray
    Write-Host ""
    Start-Sleep -Seconds 2
}

Clear-Host
Card @(
    "배포 검증 워처 — 배포한 게 진짜 반영됐는지 스스로 확인하는 도구",
    "",
    "감지 5층: L1 생존 / L2 내용 / L3 배포반영 / L4 렌더링 / L5 보안",
    "상태가 바뀔 때만 텔레그램으로 알린다",
    "소르테크 사전 과제 · github.com/kidplayboi/sortech-prework"
) 9

Step 1 "평시 순찰 — 지금 라이브 사이트 상태" "5개 층을 한 줄로. 200 OK만 보고 안심하지 않는다"
python -m watcher status
Start-Sleep -Seconds 7

Step 2 "배포 검증 집중 모드 — 기대 버전이 실제로 반영됐나" "원본(캐시 우회)과 사용자 화면 둘 다 그 버전이어야 통과"
python -m watcher deploy demo-shop --expect-version 1.0.1 --interval 5 --stable 2
Write-Host ("      종료코드 = " + $LASTEXITCODE + "  (0=안정, 1=실패, 3=핵심층 미검증)") -ForegroundColor Green
Start-Sleep -Seconds 6

Step 3 "반영 안 된 배포는 실패로 보고 — 무소식으로 끝나지 않는다" "기대 버전을 일부러 틀리게 준다. 시간 초과 시 반드시 1회 통보"
python -m watcher deploy demo-shop --expect-version 9.9.9 --interval 5 --max-wait 12
Write-Host ("      종료코드 = " + $LASTEXITCODE) -ForegroundColor Red
Start-Sleep -Seconds 6

Step 4 "L5 보안 — 해킹당했는데 주인만 모르는 상태" "검색봇에게만 도박 스팸을 보여주는 클로킹. 재현 서버로 실연"
python docs\demo\l5_demo.py
Start-Sleep -Seconds 7

Step 5 "회귀 테스트 — 외부 AI 교차 게이트 20라운드가 남긴 고정핀" "클로킹 판정만 발췌. 전체는 101개"
python -m unittest tests.test_cloaking -v 2>&1 | Select-Object -Last 14
Start-Sleep -Seconds 6

Card @(
    "알려진 한계도 README에 그대로 적었다",
    "",
    "- 검색봇에게 13~14번에 1번 미만 노출하는 클로커는 확정까지 못 간다",
    "- 회전 오탐은 0이 아니라 표본에서 관측 0 — 시드 흔들면 재현된다",
    "- CDN이 쿼리스트링을 무시하면 캐시 우회가 무효",
    "",
    "만든 과정 전부 = docs/ai-log (AI 오답 32건 실시간 박제)"
) 10
