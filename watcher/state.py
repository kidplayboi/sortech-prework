"""사이트별 상태 저장 + 전이 판정.

알림은 상태가 '변할 때만' 보낸다 — 매 체크마다 울리면 알림 피로로 결국 무시당한다.
상태: OK(전층 통과) / WARN(L3 캐시 불일치) / FAIL(L1·L2 등 실패)
"""
import json
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
    return json.loads(STATE_PATH.read_text(encoding="utf-8"))


def transition(state, site_key, new_status, reason):
    """상태 전이 여부를 판정하고 state를 갱신한다. 반환: (알림 필요 여부, 직전 상태, 지속 초)"""
    prev = state.get(site_key, {})
    prev_status = prev.get("status")
    now = int(time.time())
    changed = prev_status is not None and prev_status != new_status
    first = prev_status is None

    if first or changed:
        state[site_key] = {"status": new_status, "since": now, "reason": reason}
    else:
        state[site_key]["reason"] = reason

    STATE_PATH.write_text(
        json.dumps(state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    duration = now - prev.get("since", now)
    return changed, prev_status, duration
