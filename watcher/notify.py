"""텔레그램 알림. 토큰/챗ID가 없으면 콘솔로 대체 출력한다(개발·데모 편의)."""
import os

import requests

TELEGRAM_TEXT_LIMIT = 3500  # 텔레그램 한도 4096보다 여유 있게 자름 (P2-6)


def send(text):
    text = text[:TELEGRAM_TEXT_LIMIT]
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
        # str(exc)는 요청 URL(=봇 토큰 포함)을 담을 수 있으므로 클래스명만 출력한다
        print("[알림 실패] %s" % type(exc).__name__)
        return False


def fmt_transition(site_name, new_status, reason, prev_status, duration_sec):
    """알림 문구 3요소 — 어느 층 + 기대 vs 실측 + 조치 힌트 (reason에 층·실측 포함)"""
    if new_status == "FAIL":
        return "🔴 [%s] 이상 감지 — %s" % (site_name, reason)
    if new_status == "WARN":
        return "🟠 [%s] %s · 계속 감시" % (site_name, reason)
    if prev_status in ("FAIL", "WARN"):
        return "🟢 [%s] 회복 — %s 만에 정상 복귀" % (site_name, _fmt_duration(duration_sec))
    return "🟢 [%s] 정상" % site_name


def _fmt_duration(seconds):
    """10초 장애를 '1분'으로 부풀리지 않는다 (P3-5)"""
    if seconds < 60:
        return "%d초" % max(1, seconds)
    return "%d분" % (seconds // 60)
