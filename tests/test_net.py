"""네트워크 경로 회귀 테스트 — _bounded_get 총시한·워커 회수·인코딩·캐시 우회.

트리클 사가(9~12차)의 회귀 고정이 여기 모여 있다. 픽스처 = helpers.py
"""
import socketserver
import threading
import time
import unittest
from unittest import mock

import requests

try:  # discover -s tests (경로 삽입) 와 python -m unittest tests.test_net 양쪽 지원
    from helpers import _ChunkDripHandler, _DemoHandler
except ImportError:  # pragma: no cover - 실행 방식에 따른 분기 (14차 P3-3)
    from .helpers import _ChunkDripHandler, _DemoHandler
from watcher import checks


class BoundedGetIntegrationTest(unittest.TestCase):
    """G8: truncated 분기를 직접 호출로만 검증하지 않고 실제 HTTP 경로로 검증"""

    @classmethod
    def setUpClass(cls):
        cls.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _DemoHandler)
        cls.server.daemon_threads = True  # 진행 중 핸들러가 shutdown을 붙잡지 않게
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()
        cls.chunk_server = socketserver.ThreadingTCPServer(
            ("127.0.0.1", 0), _ChunkDripHandler
        )
        cls.chunk_server.daemon_threads = True
        cls.chunk_port = cls.chunk_server.server_address[1]
        threading.Thread(target=cls.chunk_server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.chunk_server.shutdown()

    @staticmethod
    def _watcher_threads():
        return [t for t in threading.enumerate() if t.name.startswith("watcher-")]

    def test_trickle_server_hits_total_deadline(self):
        """G3: 개별 read가 타임아웃을 안 넘는 찔끔 응답도 총 시한에 끊긴다"""
        started = time.monotonic()
        with self.assertRaises(requests.RequestException):
            checks._bounded_get("http://127.0.0.1:%d/slow" % self.port, 2)
        self.assertLess(time.monotonic() - started, 6)
        # H-A/H-F: 반환 시각만 재면 안 된다 — 워커·소켓이 실제로 회수되는지 검증.
        # 전역 active_count 비교는 무관 스레드에 오염돼 flaky했다(6차 M-A) —
        # 워커에 이름표(watcher-*)를 붙여 그 스레드만 추적한다.
        deadline = time.monotonic() + 8
        while self._watcher_threads() and time.monotonic() < deadline:
            time.sleep(0.1)
        self.assertEqual(self._watcher_threads(), [])

    def test_byte_trickle_worker_self_terminates(self):
        """9차 N-A 수리: 바이트 단위 트리클에서도 워커가 시한 직후 자가 종료한다.

        수리 전(iter_content 1024)은 read(1024)가 1024바이트를 다 모을 때까지
        블록해 워커가 수십 초 생존했다 — 3초 상한 폴링이 그 회귀를 고정한다
        (옛 코드는 서버 안전 상한 20초까지 살아남아 여기서 RED).
        """
        started = time.monotonic()
        with self.assertRaises(requests.RequestException):
            checks._bounded_get("http://127.0.0.1:%d/drip" % self.port, 1)
        self.assertLess(time.monotonic() - started, 4)
        deadline = time.monotonic() + 3
        while self._watcher_threads() and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertEqual(self._watcher_threads(), [])

    def test_chunked_framing_dribble_worker_reclaimed(self):
        """9차 P1-1: chunk-size 줄 드리블은 readline이 버퍼 락을 쥔 채 블록해
        read1 데드라인 검사가 돌지 않는다 — shutdown 위임이 소켓을 깨서 회수한다
        (close-only였던 옛 정리 경로는 같은 락에 막혀 워커·정리 스레드가 함께
        10초+ 잔존 — 이 폴링 상한에서 RED)."""
        started = time.monotonic()
        with self.assertRaises(requests.RequestException):
            checks._bounded_get("http://127.0.0.1:%d/chunkdrip" % self.chunk_port, 1)
        self.assertLess(time.monotonic() - started, 4)
        deadline = time.monotonic() + 4
        while self._watcher_threads() and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertEqual(self._watcher_threads(), [])

    def test_chunked_dribble_connection_close_variant_reclaimed(self):
        """10차 P1-1: Connection: close 변종 — _connection.sock이 None이라
        내부 속성 경유 shutdown이 무효였다. raw.shutdown()은 소유권 이전 전에
        저장된 참조를 써서 이 변종도 깨운다 (sock 경유였던 9차 수리는 여기서 RED)."""
        started = time.monotonic()
        with self.assertRaises(requests.RequestException):
            checks._bounded_get(
                "http://127.0.0.1:%d/chunkdrip-close" % self.chunk_port, 1
            )
        self.assertLess(time.monotonic() - started, 4)
        deadline = time.monotonic() + 4
        while self._watcher_threads() and time.monotonic() < deadline:
            time.sleep(0.05)
        self.assertEqual(self._watcher_threads(), [])

    def test_broken_gzip_translates_to_requests_exception(self):
        """9차 P2-1: urllib3 DecodeError가 requests 계열로 번역돼 L1 '요청 실패'로
        잡혀야 한다 — 누출되면 사이트 장애가 '체크 자체 실패'(워처 고장)로 오귀속"""
        l1, _body, _headers, _tr = checks._l1_alive(
            {"url": "http://127.0.0.1:%d/badgzip" % self.port, "timeout_sec": 5}
        )
        self.assertFalse(l1["ok"])
        self.assertIn("요청 실패", l1["detail"])

    def test_truncated_content_length_translates_to_requests_exception(self):
        """9차 P2-1: CL 선언 후 절단(ProtocolError)도 같은 번역 경로"""
        l1, _body, _headers, _tr = checks._l1_alive(
            {"url": "http://127.0.0.1:%d/cut" % self.port, "timeout_sec": 5}
        )
        self.assertFalse(l1["ok"])
        self.assertIn("요청 실패", l1["detail"])

    def test_gzip_body_is_decoded(self):
        """9차 read1 전환이 압축 해제(decode_content)를 잃지 않는지 고정"""
        status, body, headers, truncated = checks._bounded_get(
            "http://127.0.0.1:%d/gzip" % self.port, 5
        )
        self.assertEqual(status, 200)
        self.assertFalse(truncated)
        self.assertIn("압축응답 마커", checks._decode(body, headers))

    def test_size_cap_marks_truncated(self):
        with mock.patch.object(checks, "MAX_BODY_BYTES", 1000):
            status, body, _headers, truncated = checks._bounded_get(
                "http://127.0.0.1:%d/big" % self.port, 5
            )
        self.assertEqual(status, 200)
        self.assertTrue(truncated)
        self.assertGreaterEqual(len(body), 1000)


class BustUrlTest(unittest.TestCase):
    def test_fragment_does_not_eat_query(self):
        """P3-4: #fragment 붙은 URL에서도 nc= 쿼리가 서버에 전달돼야 한다"""
        url = checks._bust_url("https://a.b/version.txt#frag")
        self.assertNotIn("#", url)
        self.assertIn("nc=", url)

    def test_existing_query_preserved(self):
        url = checks._bust_url("https://a.b/v.txt?a=1")
        self.assertIn("a=1&nc=", url)


if __name__ == "__main__":
    unittest.main()
