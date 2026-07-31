"""사이트별 상태 저장 + 전이 판정.

핵심 설계 (Codex 게이트 P1-2/3/4 교정): '관측된 상태'와 '통보된 상태'를 분리한다.
- observed/confirmed : 이번 체크에서 본 것 (읽기 명령도 이 값은 건드리지 않음)
- notified           : 텔레그램 발송이 '성공한' 마지막 상태
알림 조건 = confirmed != notified. 발송 성공 후에만 notified를 갱신하므로
① 첫 관측이 FAIL이어도 울리고 ② 전송 실패는 상태가 유지되는 한 다음 패스에서
자연 재시도된다. 단, 통보 전에 스스로 원상 복구된 순단은 재시도 대신
"순단 후 자가 복구" 1회 통보로 전달한다 (3차 게이트 G1 — 조용히 버리지 않음).
플랩(순단 한 번에 2연타) 방지: confirm_checks회 연속 같은 관측일 때만 확정.
"""
import json
import os
import time

from .config import STATE_PATH

_REQUIRED_KEYS = {"observed", "streak", "confirmed", "confirmed_since",
                  "notified", "reason", "confirmed_reason"}


def summarize(results):
    """계층 결과 목록 → (상태, 대표 사유)

    대표 사유 선정 순위: 장애(FAIL) → 사이트 관련 주의(WARN) → **검증 불가(unknown)**.
    unknown은 사이트 상태가 아니라 우리 쪽 확인 실패이므로 사이트에 실제로 일어난
    일을 가리지 않게 맨 뒤로 둔다 (13차 P2-2·P2-3의 등급 분리와 같은 취지).
    """
    for r in results:
        if not r["ok"] and not r.get("warn"):
            return "FAIL", "%s %s" % (r["layer"], r["detail"])
    for r in results:
        if not r["ok"] and r.get("warn") and not r.get("unknown"):
            return "WARN", "%s %s" % (r["layer"], r["detail"])
    for r in results:
        if not r["ok"] and r.get("unknown"):
            return "WARN", "%s %s" % (r["layer"], r["detail"])
    return "OK", " · ".join("%s %s" % (r["layer"], r["detail"]) for r in results)


def load_state():
    if not STATE_PATH.exists():
        return {}
    try:
        data = json.loads(STATE_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        print("[경고] state.json 손상(%s) — 초기화 후 진행" % type(exc).__name__)
        return {}
    if not isinstance(data, dict):  # 유효한 JSON이어도 형태가 다르면 초기화 (G4)
        print("[경고] state.json 형태 이상 — 초기화 후 진행")
        return {}
    dropped = [k for k, v in data.items() if not isinstance(v, dict)]
    for key in dropped:
        print("[경고] state.json 항목 '%s' 형태 이상 — 해당 항목 초기화" % key)
        del data[key]
    return data


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
    if _entry_broken(entry):  # 신규·구버전·부분 스키마·값 타입 손상 → 완전 재초기화 (N6·G4·H-D)
        entry.clear()
        entry.update({"observed": None, "streak": 0, "confirmed": None,
                      "confirmed_since": None, "notified": "OK", "reason": "",
                      "confirmed_reason": ""})
    now = int(time.time())

    if status == entry["observed"]:
        entry["streak"] += 1
    else:
        entry["observed"] = status
        entry["streak"] = 1
    entry["reason"] = reason

    if entry["streak"] >= max(1, confirm) and entry["confirmed"] != status:
        prev_since = entry["confirmed_since"]
        # 미통보 '장애'(OK에서 이탈했다 복귀)만 사후 보고 대상이다 (G1·H-C·K-D).
        # 복귀 순간의 confirmed_reason만 쓰면 중간에 낀 WARN이 미통보 FAIL의 사유를
        # 지운다(7차 N-C — 1차 가드는 이 시퀀스를 못 막았음) → 이탈 구간 동안
        # '최악' 사유를 별도 누적했다가 복귀 시 이관한다.
        if entry["notified"] == "OK" and status != "OK":
            if "unnotified_worst" not in entry or status == "FAIL":
                entry["unnotified_worst"] = reason
                entry["unnotified_worst_fail"] = status == "FAIL"
            entry.setdefault("deviation_since", now)
        elif entry["notified"] == "OK" and status == "OK" and "unnotified_worst" in entry:
            # 이미 대기 중인 사후 보고는 최악(FAIL) 사유일 때만 덮어쓴다 (M-C).
            # 지속시간은 이 시점에 스냅샷 (M-H)
            if "pending_missed" not in entry or entry.get("unnotified_worst_fail"):
                entry["pending_missed"] = entry["unnotified_worst"]
                entry["pending_missed_duration"] = now - entry.get("deviation_since", now)
            _clear_deviation(entry)
        entry["confirmed"] = status
        entry["confirmed_since"] = now
        # 확정 시점의 사유를 따로 보관 — 발송 재시도 중 다른 관측의 사유가
        # 섞여 "🔴 이상 감지 — HTTP 200 정상" 같은 자기모순 알림 방지 (N2)
        entry["confirmed_reason"] = reason
        entry["last_change_duration"] = now - prev_since if prev_since else 0

    needs_alert = (
        entry["confirmed"] is not None and entry["confirmed"] != entry["notified"]
    )
    missed_reason = entry.get("pending_missed")
    return {
        "alert": needs_alert or missed_reason is not None,
        "missed_reason": missed_reason,
        "missed_duration": entry.get("pending_missed_duration", 0),
        "status": entry["confirmed"],
        "prev_notified": entry["notified"],
        "duration_sec": entry.get("last_change_duration", 0),
        "reason": entry.get("confirmed_reason") or entry["reason"],
    }


def mark_notified(state, site_key):
    """발송이 실제로 성공했을 때만 호출한다."""
    entry = state[site_key]
    entry["notified"] = entry["confirmed"]
    # 이탈이 통보됐으면 '미통보 최악' 추적은 종료 — 이후 복귀는 정상 회복 알림으로 나간다
    _clear_deviation(entry)


def _clear_deviation(entry):
    entry.pop("unnotified_worst", None)
    entry.pop("unnotified_worst_fail", None)
    entry.pop("deviation_since", None)


def clear_missed(state, site_key):
    """순단 사후 보고가 실제로 전달됐을 때만 호출한다 (H-C)."""
    state[site_key].pop("pending_missed", None)
    state[site_key].pop("pending_missed_duration", None)


def read_cloak(state, site_key):
    """L5 클로킹 누적 기억을 꺼낸다 — 없거나 형태가 이상하면 빈 기억."""
    entry = state.get(site_key)
    memory = entry.get("cloak") if isinstance(entry, dict) else None
    return dict(memory) if isinstance(memory, dict) else {}


def write_cloak(state, site_key, memory):
    """누적 기억을 보존한다. **observe() 뒤에 호출해야 한다** — 스키마가 깨진
    엔트리는 observe가 통째로 재초기화하므로 그 전에 쓰면 지워진다.
    빈 기억은 저장하지 않는다(state.json에 죽은 키를 남기지 않음)."""
    entry = state.setdefault(site_key, {})
    live = {kind: dict(bucket) for kind, bucket in (memory or {}).items() if bucket}
    if live:
        entry["cloak"] = live
    else:
        entry.pop("cloak", None)


def _entry_broken(entry):
    """키 존재 + 값 타입까지 검사 — 타입 손상 엔트리가 매 패스 예외로 한 사이트를
    영구 무력화하는 것 방지 (H-D)."""
    if not _REQUIRED_KEYS <= set(entry):
        return True
    if not isinstance(entry["streak"], int) or isinstance(entry["streak"], bool):
        return True
    if not isinstance(entry["notified"], str):
        return True
    for field in ("observed", "confirmed"):
        if entry[field] is not None and not isinstance(entry[field], str):
            return True
    if entry["streak"] < 0:  # 음수 streak은 확정을 여러 패스 억제한다 (K-E)
        return True
    if entry["confirmed_since"] is not None and not isinstance(entry["confirmed_since"], int):
        return True
    for optional_field, expected in (("last_change_duration", int), ("pending_missed", str),
                                     ("pending_missed_duration", int),
                                     ("unnotified_worst", str), ("unnotified_worst_fail", bool),
                                     ("deviation_since", int), ("cloak", dict)):
        if optional_field in entry and not isinstance(entry[optional_field], expected):
            return True
    return not (isinstance(entry["reason"], str) and isinstance(entry["confirmed_reason"], str))
