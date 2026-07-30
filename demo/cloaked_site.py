"""클로킹(L5) 데모용 재현 서버 — 해킹당한 사이트를 흉내낸다.

일반 방문자에게는 정상 쇼핑몰을, 검색봇 UA에게는 도박 스팸을 섞어 보여준다.
국내에서 실제로 관측된 수법(해킹 후 검색봇에만 스팸 노출 → 주인은 몇 달을 모름)의
최소 재현 — 근거·출처 = docs/03-보안축-리서치.md

왜 로컬 서버인가: 감시 대상 데모(GitHub Pages)는 정적이라 UA 분기가 불가능하고,
클로킹은 서버가 요청자를 보고 응답을 가르는 현상이라 동적 엔드포인트가 필요하다.
외부 계정 없이 평가자가 그대로 재현할 수 있게 로컬로 둔다.

실행:
    python demo/cloaked_site.py            # http://127.0.0.1:8899
    python -m watcher status               # sites.json에 이 주소를 등록한 뒤
사람이 직접 확인 (워처가 하는 것과 같은 비교):
    curl -s http://127.0.0.1:8899 | findstr 바카라                      # 안 나옴
    curl -s -A "Googlebot/2.1" http://127.0.0.1:8899 | findstr 바카라   # 나옴
"""
import http.server
import sys

PORT = 8899
NORMAL = """<!doctype html><html lang="ko"><head><meta charset="utf-8">
<title>데모샵(재현)</title></head><body>
<h1>데모샵</h1><p>장바구니</p><p>여름 신상 입고</p>
</body></html>
"""
CLOAKED = """<!doctype html><html lang="ko"><head><meta charset="utf-8">
<title>데모샵(재현)</title></head><body>
<h1>데모샵</h1><p>장바구니</p><p>여름 신상 입고</p>
<div>바카라 카지노 먹튀검증 안전놀이터 사설토토 무료스핀</div>
</body></html>
"""
BOT_HINTS = ("googlebot", "bingbot", "yeti", "daumoa")


class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        ua = (self.headers.get("User-Agent") or "").lower()
        cloaked = any(hint in ua for hint in BOT_HINTS)
        body = (CLOAKED if cloaked else NORMAL).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        print("%s → %s" % (ua[:60] or "(UA 없음)", "스팸 노출" if cloaked else "정상"))

    def log_message(self, *_args):
        pass


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else PORT
    server = http.server.ThreadingHTTPServer(("127.0.0.1", port), Handler)
    server.daemon_threads = True
    print("클로킹 재현 서버 — http://127.0.0.1:%d (Ctrl+C 종료)" % port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n종료")


if __name__ == "__main__":
    main()
