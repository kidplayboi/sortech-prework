"""테스트용 재현 서버 픽스처 — 여러 테스트 모듈이 공유한다.

500라인 규칙(13차 P3-4)에 따라 test_watcher.py에서 분리. 각 경로가 어떤 결함을
재현하는지는 클래스 docstring·인라인 주석 참조.
"""
import gzip
import http.server
import time


class _DemoHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith("/big"):
            data = b"y" * 5000
            self.send_response(200)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if self.path.startswith("/gzip"):
            data = gzip.compress("압축응답 마커".encode("utf-8"))
            self.send_response(200)
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if self.path.startswith("/jsok"):
            # 마커가 원본 HTML엔 없고 JS 렌더로만 생긴다 — L2는 놓치고 L4만 잡는 SPA
            # 케이스. ⚠️마커를 소스에 통짜 문자열로 두면 L2 텍스트 검색에도 걸려
            # 전제가 깨진다(첫 픽스처의 함정) — JS에서 조각을 합쳐 만든다
            html = ("<html><body><div id='r'></div><script>"
                    "document.getElementById('r').textContent='렌더'+'마커';"
                    "</script></body></html>").encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)
            return
        if self.path.startswith("/jserr"):
            html = ("<html><body>렌더마커<script>"
                    "throw new TypeError('cart is undefined');"
                    "</script></body></html>").encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(html)))
            self.end_headers()
            self.wfile.write(html)
            return
        if self.path.startswith("/badgzip"):
            # gzip 선언 후 깨진 바이트 — urllib3 DecodeError 경로 (9차 P2-1)
            data = b"\x1f\x8b\x08\x00 broken not gzip"
            self.send_response(200)
            self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return
        if self.path.startswith("/cut"):
            # Content-Length 선언 후 조기 절단 — ProtocolError(IncompleteRead) 경로 (9차 P2-1)
            self.send_response(200)
            self.send_header("Content-Length", "10000")
            self.end_headers()
            self.wfile.write(b"partial")
            return
        if self.path.startswith("/drip"):
            # 바이트 단위 병적 트리클 (9차 N-A). 400회×0.05초=20초 안전 상한 —
            # 단언 상한(3초)보다 훨씬 길어 옛 코드의 누수를 가리지 못한다
            self.send_response(200)
            self.send_header("Content-Length", "100000")
            self.end_headers()
            try:
                for _ in range(400):
                    self.wfile.write(b"z")
                    self.wfile.flush()
                    time.sleep(0.05)
            except OSError:
                pass
            return
        self.send_response(200)
        self.send_header("Content-Length", "80000")
        self.end_headers()
        try:
            for _ in range(12):  # 찔끔찔끔 — 청크 버퍼가 안 차게 (총 6초, 시한 2초보다 김)
                self.wfile.write(b"x" * 800)
                self.wfile.flush()
                time.sleep(0.5)
        except OSError:
            pass

    def log_message(self, *_args):
        pass


class _ChunkDripHandler(http.server.BaseHTTPRequestHandler):
    """chunk-size 줄을 바이트 단위로 드리블 — readline()이 버퍼 락을 쥔 채 여러
    recv에 걸쳐 블록하는 9차 P1-1 재현. chunked는 HTTP/1.1에서만 해석되므로
    기존 1.0 핸들러와 분리한다. 400회×0.05초 ≈ 안전 상한 20초 (10차 P3-1 정정).

    /chunkdrip = keep-alive · /chunkdrip-close = Connection: close — 후자는 소켓
    소유권이 응답으로 넘어가 _connection.sock이 None이 되는 변종 (10차 P1-1:
    내부 속성 경유 shutdown은 이 변종을 못 깨웠다. 두 변종 모두 고정해야 한다)."""

    protocol_version = "HTTP/1.1"

    def do_GET(self):
        self.send_response(200)
        self.send_header("Transfer-Encoding", "chunked")
        if self.path.startswith("/chunkdrip-close"):
            self.send_header("Connection", "close")
        self.end_headers()
        try:
            # chunk-size 줄을 끝내지 않고 chunk-extension 바이트를 계속 드리블 —
            # readline()이 한 줄을 완성하지 못한 채 버퍼 락을 계속 쥔다 (진짜 P1-1
            # 조건). ⚠️줄이 짧게 끝나는 드리블은 readline이 줄 사이마다 락을 놓아
            # close-only도 회수돼 vacuous 테스트가 된다 — 음성대조로 적발된 함정
            self.wfile.write(b"1;")
            self.wfile.flush()
            for _ in range(400):  # 안전 상한 ~20초
                self.wfile.write(b"a")
                self.wfile.flush()
                time.sleep(0.05)
        except OSError:
            pass

    def log_message(self, *_args):
        pass
