"""제출물 빌드 — 마크다운 → docx → pdf → 제출 폴더로 모음.

한 번에 돌려서 사람이 그 폴더만 첨부하면 되게 한다.
중간 산출물(docx)과 원본(md)은 레포에 남기고, **제출 폴더에는 실제로 보낼 것만** 넣는다.

사용법: python tools/build_submission.py [출력폴더]
        기본 출력 = `~/Downloads/sortech-제출/`
        — 레포에 대용량 바이너리를 쌓지 않고, 메일에 첨부할 때 바로 찾는 자리에 둔다.
"""
import pathlib
import shutil
import subprocess
import sys

REPO = pathlib.Path(__file__).resolve().parent.parent
SRC = REPO / "docs" / "제출물"
DOCS = ["S1-AI활용기록", "S2-회고"]


def build_docx():
    for stem in DOCS:
        subprocess.run([sys.executable, str(REPO / "tools" / "make_docx.py"),
                        str(SRC / (stem + ".md"))], check=True, cwd=REPO)


def build_pdf():
    """Word COM으로 변환. 창 없는 잔여 인스턴스는 먼저 정리한다."""
    ps = r"""
Get-Process WINWORD -ErrorAction SilentlyContinue |
    Where-Object { -not $_.MainWindowTitle } | Stop-Process -Force
$word = New-Object -ComObject Word.Application
$word.Visible = $false; $word.DisplayAlerts = 0
try {
  foreach ($n in @(%s)) {
    $src = [string]("%s\" + $n + ".docx")
    $out = [string]("%s\" + $n + ".pdf")
    $doc = $word.Documents.Open($src, $false, $true)
    $doc.SaveAs2($out, 17)
    Write-Host ("  {0}  {1}쪽" -f $n, $doc.ComputeStatistics(2))
    $doc.Close(0)
  }
} finally { $word.Quit() }
""" % (",".join("'%s'" % d for d in DOCS), SRC, SRC)
    script = REPO / "tools" / "_topdf.ps1"
    script.write_text(ps, encoding="utf-8")
    try:
        subprocess.run(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass",
                        "-File", str(script)], check=True)
    finally:
        script.unlink(missing_ok=True)


def collect(out_dir):
    out_dir.mkdir(parents=True, exist_ok=True)
    copied = []
    for stem in DOCS:
        for ext in (".pdf", ".docx"):
            src = SRC / (stem + ext)
            if src.exists():
                shutil.copy2(src, out_dir / src.name)
                copied.append(src.name)
    mail = SRC / "메일-초안.md"
    if mail.exists():
        shutil.copy2(mail, out_dir / mail.name)
        copied.append(mail.name)

    readme = out_dir / "0-읽어주세요.txt"
    readme.write_text(
        "소르테크 사전 과제 제출물\n"
        "=========================\n\n"
        "첨부할 것\n"
        "  1. S1-AI활용기록.pdf   (AI 활용 기록 — 도구·모델, 날것 대화, 오답과 대응)\n"
        "  2. S2-회고.pdf         (회고 — 도구 순서, 막힌 지점, 대응, 다시 한다면)\n"
        "  3. 실행화면-녹화.mp4    ← 아직 없음. docs/demo/run-and-record.ps1 로 촬영\n\n"
        "메일 본문은 메일-초안.md 참고 (이름·연락처 채울 것)\n"
        "코드: https://github.com/kidplayboi/sortech-prework\n\n"
        "docx는 원본 형식이 필요할 때만 쓰고, 기본 첨부는 pdf.\n",
        encoding="utf-8")
    copied.append(readme.name)
    return copied


def main():
    out = (pathlib.Path(sys.argv[1]) if len(sys.argv) > 1
           else pathlib.Path.home() / "Downloads" / "sortech-제출")
    print("[1/3] docx 생성")
    build_docx()
    print("[2/3] pdf 변환")
    build_pdf()
    print("[3/3] 제출 폴더로 수집 → %s" % out)
    for name in collect(out):
        size = (out / name).stat().st_size / 1024
        print("  %-28s %8.1f KB" % (name, size))
    video = out / "실행화면-녹화.mp4"
    print()
    print("영상: %s" % ("있음" if video.exists() else "🔴 없음 — 녹화 후 이 폴더에 넣을 것"))


if __name__ == "__main__":
    main()
