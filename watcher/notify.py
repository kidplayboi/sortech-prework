"""텔레그램 알림. 토큰/챗ID가 없으면 콘솔로 대체 출력한다(개발·데모 편의)."""
import os

import requests


def send(text):
    token = os.environ.get("TELEGRAM_BOT_TOKEN")
    chat_id = os.environ.get("TELEGRAM_CHAT_ID")
    if not token or not chat_id:
        print("[알림-콘솔] %s" % text)
        return False
    try:
        resp = requests.post(
            "https://api.telegram.org/bot%s/sendMessage" % token,
            json={"chat_id": chat_id, "text": text},
            timeout=10,
        )
        if resp.status_code != 200:
            print("[알림 실패] HTTP %d %s" % (resp.status_code, resp.text[:200]))
            return False
        return True
    except requests.RequestException as exc:
        print("[알림 실패] %s" % type(exc).__name__)
        return False


def fmt_transition(site_name, new_status, reason, prev_status, duration_sec):
    """알림 문구 3요소 — 어느 층 + 기대 vs 실측 + 조치 힌트 (reason에 층·실측 포함)"""
    if new_status == "FAIL":
        return "🔴 [%s] 이상 감지 — %s" % (site_name, reason)
    if new_status == "WARN":
        return "🟠 [%s] %s · 계속 감시" % (site_name, reason)
    minutes = max(1, duration_sec // 60)
    if prev_status in ("FAIL", "WARN"):
        return "🟢 [%s] 회복 — %d분 만에 정상 복귀" % (site_name, minutes)
    return "🟢 [%s] 정상" % site_name
