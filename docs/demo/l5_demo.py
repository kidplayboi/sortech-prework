"""녹화용 L5 실연 — 진짜 클로킹은 잡고, 회전 콘텐츠는 안 잡는다.

라이브 데모 사이트는 정상이라 화면에 🟢만 나온다. L5가 실제로 무엇을 가르는지
보이려면 침해된 사이트가 필요한데, 남의 사이트를 침해할 수는 없으니 회귀 테스트가
쓰는 **재현 서버**를 그대로 띄워 판정을 실행한다.

- `/cloak`      = 검색봇 UA에만 도박 문구를 내는 진짜 클로킹
- `/rotate16`   = 정상 사이트인데 배너가 16회차로 회전, 그중 한 회차에 그 문구가 실림
                  (13~20차 게이트에서 오탐이 반복 재현된 조건)

제출물의 서사가 여기 있다: 둘은 **같은 관측**(봇 시점에 문구가 보이고 일반 시점 표본엔
없음)이고, 이걸 가르는 게 판정 축 3개다.
"""
import pathlib
import socketserver
import sys
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "tests"))

from helpers import _RotatingHandler          # noqa: E402
from watcher import security                  # noqa: E402


def line(text=""):
    print(text, flush=True)


def beat(seconds):
    time.sleep(seconds)


def verdict_mark(result):
    if result.get("unknown"):
        return "\U0001f7e0 검증불가"
    if not result["ok"]:
        return "\U0001f7e0 의심" if result.get("warn") else "\U0001f534 확정"
    return "\U0001f7e2 이상없음"


def run(port, path, passes, label, note):
    _RotatingHandler.ROTATION.clear()
    site = {"url": "http://127.0.0.1:%d%s" % (port, path),
            "markers": ["데모샵"], "timeout_sec": 10}
    memory = {}
    line("  %s" % label)
    line("  %s" % note)
    for index in range(passes):
        result = security.check_cloaking(site, memory)
        line("    패스%d  %s  %s" % (index + 1, verdict_mark(result), result["detail"][:88]))
        beat(0.7)
    line()


def main():
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _RotatingHandler)
    server.daemon_threads = True
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        run(port, "/cloak", 2, "[1] 진짜 클로킹 — 검색봇에게만 도박 문구",
            "    (해킹된 사이트에 스팸을 심고 검색봇에만 노출하는 국내 실측 수법)")
        beat(1.2)
        run(port, "/rotate16", 4, "[2] 정상 사이트인데 배너가 회전 — 16회차 중 한 번에 같은 문구",
            "    (같은 관측인데 클로킹이 아니다. 13~20차 게이트가 반복해서 뚫은 조건)")
        line("  같은 관측을 가르는 것 = 회전 감지 · 패스 간 누적 · 위상 무작위화")
    finally:
        server.shutdown()


if __name__ == "__main__":
    main()
