"""정적 HTML 상태보드 — `watch`/`once` 매 패스마다 board.html 한 장 재생성.

회의 확정(2026-07-30): 서버 없음 — 브라우저로 열기만 하면 되는 파일 한 장
(설치 장벽 0 · 검증 표면 최소). 자동 새로고침은 meta refresh.
최근 알림 이력은 자체 JSON(board_history.json)에 최대 20건 유지.
모든 동적 텍스트는 html.escape — 사이트 응답에서 유래한 에러 문구가
보드 안에서 마크업으로 실행되면 안 된다.
"""
import html
import json
import os
import time

from .config import BOARD_HISTORY_PATH, BOARD_PATH

HISTORY_MAX = 20
SHOW_ALERTS = 8
DOT_CHAR = {"OK": "🟢", "WARN": "🟠", "FAIL": "🔴"}

_CSS = """
:root { color-scheme: light; }
* { box-sizing: border-box; margin: 0; }
body { font-family: system-ui, 'Apple SD Gothic Neo', 'Malgun Gothic', sans-serif;
       background: #fafafa; color: #1a1a1a; padding: 48px 24px; }
main { max-width: 720px; margin: 0 auto; }
h1 { font-size: 20px; font-weight: 700; letter-spacing: -0.01em; }
.sub { color: #6b7280; font-size: 13px; margin-top: 6px; }
.site { background: #fff; border: 1px solid #e5e7eb; border-radius: 10px;
        padding: 20px 24px; margin-top: 20px; }
.head { display: flex; align-items: baseline; gap: 10px; }
.name { font-size: 16px; font-weight: 600; }
.status { font-size: 13px; color: #374151; }
.layers { margin-top: 12px; border-top: 1px solid #f3f4f6; padding-top: 12px; }
.layer { font-size: 13px; color: #4b5563; padding: 3px 0; font-variant-numeric: tabular-nums; }
.layer b { color: #111827; font-weight: 600; margin-right: 8px; }
h2 { font-size: 14px; font-weight: 600; margin-top: 36px; color: #374151; }
.alert { font-size: 13px; color: #4b5563; padding: 6px 0; border-bottom: 1px solid #f3f4f6; }
.alert time { color: #9ca3af; margin-right: 10px; font-variant-numeric: tabular-nums; }
.empty { color: #9ca3af; font-size: 13px; padding: 8px 0; }
"""


def update_board(pass_rows, sent_texts, now=None):
    """매 패스 호출 — 이력 갱신 + board.html 재생성. 실패는 호출자가 격리한다."""
    now = now if now is not None else time.time()
    history = _append_history(sent_texts, now)
    _write_atomic(BOARD_PATH, _render(pass_rows, history, now))


def _append_history(sent_texts, now):
    history = []
    if BOARD_HISTORY_PATH.exists():
        try:
            loaded = json.loads(BOARD_HISTORY_PATH.read_text(encoding="utf-8"))
            if isinstance(loaded, list):
                # ts 타입까지 검사 — 문자열 ts 하나가 time.localtime에서 TypeError를
                # 내고 그 엔트리가 다시 저장돼 이후 보드 갱신이 영구 실패했다 (13차 P3-3)
                history = [e for e in loaded
                           if isinstance(e, dict) and isinstance(e.get("text"), str)
                           and isinstance(e.get("ts"), int)
                           and not isinstance(e.get("ts"), bool)]
        except (json.JSONDecodeError, OSError):
            history = []  # 손상 이력은 버리고 진행 — 보드가 감시를 막으면 안 된다
    for text in sent_texts:
        history.append({"ts": int(now), "text": text})
    history = history[-HISTORY_MAX:]
    _write_atomic(BOARD_HISTORY_PATH,
                  json.dumps(history, ensure_ascii=False, indent=1) + "\n")
    return history


def _write_atomic(path, content):
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(content, encoding="utf-8")
    os.replace(tmp, path)


def _render(rows, history, now):
    stamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(now))
    parts = [
        "<!doctype html><html lang='ko'><head><meta charset='utf-8'>",
        "<meta http-equiv='refresh' content='15'>",
        "<meta name='viewport' content='width=device-width, initial-scale=1'>",
        "<title>배포 검증 워처 — 상태보드</title>",
        "<style>%s</style></head><body><main>" % _CSS,
        "<h1>배포 검증 워처 — 상태보드</h1>",
        "<p class='sub'>마지막 갱신 %s · 15초마다 자동 새로고침</p>" % stamp,
    ]
    for row in rows:
        status = row.get("status", "FAIL")
        dot = DOT_CHAR.get(status, "🔴")
        layers = row.get("layers") or []
        # OK면 헤더 요약(전 층 상세 연결)이 아래 층 목록과 중복 — 상태 단어만.
        # WARN/FAIL·층 없음(체크 자체 실패)은 사유가 핵심 정보라 그대로 노출
        if status == "OK" and layers:
            head_text = "정상"
        else:
            head_text = str(row.get("reason", ""))
        parts.append("<section class='site'><div class='head'>")
        parts.append("<span>%s</span><span class='name'>%s</span>"
                     % (dot, html.escape(str(row.get("name", "")))))
        parts.append("<span class='status'>%s</span></div>" % html.escape(head_text))
        if layers:
            parts.append("<div class='layers'>")
            for layer in layers:
                mark = "✓" if layer.get("ok") else ("⚠" if layer.get("warn") else "✗")
                parts.append("<div class='layer'><b>%s %s</b>%s</div>" % (
                    html.escape(str(layer.get("layer", ""))), mark,
                    html.escape(str(layer.get("detail", ""))),
                ))
            parts.append("</div>")
        parts.append("</section>")
    parts.append("<h2>최근 알림</h2>")
    recent = list(reversed(history[-SHOW_ALERTS:]))
    if not recent:
        parts.append("<p class='empty'>아직 발송된 알림이 없습니다</p>")
    for entry in recent:
        when = time.strftime("%m-%d %H:%M", time.localtime(entry.get("ts", 0)))
        parts.append("<div class='alert'><time>%s</time>%s</div>"
                     % (when, html.escape(entry["text"])))
    parts.append("</main></body></html>\n")
    return "".join(parts)
