"""사이트별 상태 저장 + 전이 판정.

핵심 설계 (Codex 게이트 P1-2/3/4 교정): '관측된 상태'와 '통보된 상태'를 분리한다.
- observed/confirmed : 이번 체크에서 본 것 (읽기 명령도 이 값은 건드리지 않음)
- notified           : 텔레그램 발송이 '성공한' 마지막 상태
알림 조건 = confirmed != notified. 발송 성공 후에만 notified를 갱신하므로
① 첫 관측이 FAIL이어도 울리고 ② 전송 실패는 다음 패스에서 자연 재시도된다.
플랩(순단 한 번에 2연타) 방지: confirm_checks회 연속 같은 관측일 때만 확정.
"""
import json
import os
import time

from .config import STATE_PATH


def summarize(results):
    """계층 결과 목록 → (상태, 대표 사유)"""
    for r in results:
        if not r["ok"] and not r.get("warn"):
            return "FAIL", "%s %s" % (r["layer"], r["detail"])
    for r in results:
        if not r["ok"] and r.get("warn"):
            return "WARN", "%s %s" % (r["layer"], r["detail"])
    return "OK", " · ".join("%s %s" % (r["layer"], r["detail"]) for r in results)


def load_state():
    if not STATE_PATH.exists():
        return {}
    try:
        return json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        print("[경고] state.json 손상(%s) — 초기화 후 진행" % type(exc).__name__)
        return {}


def save_state(state):
    """임시 파일에 쓴 뒤 교체 — 기록 중 크래시로 파일이 잘리는 것 방지"""
    tmp = STATE_PATH.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, STATE_PATH)


def observe(state, site_key, status, reason, confirm=1):
    """관측 1회를 반영하고 알림 필요 여부를 반환한다.

    반환 dict: alert(발송 필요), status(확정 상태), prev_notified, duration_sec, reason
    """
    entry = state.setdefault(site_key, {})
    if "observed" not in entry:  # 신규 또는 구버전 스키마 → 안전 초기화
        entry.update({"observed": None, "streak": 0, "confirmed": None,
                      "confirmed_since": None, "notified": "OK", "reason": ""})
    now = int(time.time())

    if status == entry["observed"]:
        entry["streak"] += 1
    else:
        entry["observed"] = status
        entry["streak"] = 1
    entry["reason"] = reason

    if entry["streak"] >= max(1, confirm) and entry["confirmed"] != status:
        prev_since = entry["confirmed_since"]
        entry["confirmed"] = status
        entry["confirmed_since"] = now
        entry["last_change_duration"] = now - prev_since if prev_since else 0

    needs_alert = (
        entry["confirmed"] is not None and entry["confirmed"] != entry["notified"]
    )
    return {
        "alert": needs_alert,
        "status": entry["confirmed"],
        "prev_notified": entry["notified"],
        "duration_sec": entry.get("last_change_duration", 0),
        "reason": entry["reason"],
    }


def mark_notified(state, site_key):
    """발송이 실제로 성공했을 때만 호출한다."""
    entry = state[site_key]
    entry["notified"] = entry["confirmed"]
