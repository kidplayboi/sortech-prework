"""Codex 게이트(2026-07-29) 지적 사항 회귀 테스트.

P1 구조 결함 3종(첫관측 무알림·status의 전이 소비·전송실패 소멸)과
P1-1 인코딩 오탐, P3 파싱류가 되돌아오지 않는지 고정한다.
"""
import contextlib
import gzip
import http.server
import io
import socketserver
import threading
import time
import unittest
from unittest import mock

import requests

from watcher import checks, deploy, notify, state as state_mod
from watcher.cli import run_pass
from watcher.config import validate_sites as checks_validate


class StateTransitionTest(unittest.TestCase):
    def test_first_observation_fail_alerts(self):
        """P1-3: 처음부터 죽어 있던 사이트도 첫 관측에서 울려야 한다"""
        st = {}
        obs = state_mod.observe(st, "s", "FAIL", "L1 요청 실패", confirm=1)
        self.assertTrue(obs["alert"])
        self.assertEqual(obs["prev_notified"], "OK")

    def test_send_failure_retries_next_pass(self):
        """P1-4: 전송 실패(mark_notified 미호출) 시 다음 패스에서 재시도"""
        st = {}
        state_mod.observe(st, "s", "FAIL", "r", confirm=1)
        obs = state_mod.observe(st, "s", "FAIL", "r", confirm=1)
        self.assertTrue(obs["alert"])

    def test_send_success_stops_alerting(self):
        st = {}
        state_mod.observe(st, "s", "FAIL", "r", confirm=1)
        state_mod.mark_notified(st, "s")
        obs = state_mod.observe(st, "s", "FAIL", "r", confirm=1)
        self.assertFalse(obs["alert"])

    def test_recovery_alert_after_notified_fail(self):
        st = {}
        state_mod.observe(st, "s", "FAIL", "r", confirm=1)
        state_mod.mark_notified(st, "s")
        obs = state_mod.observe(st, "s", "OK", "ok", confirm=1)
        self.assertTrue(obs["alert"])
        self.assertEqual(obs["prev_notified"], "FAIL")

    def test_flap_damping_confirm2(self):
        """P2-8: confirm_checks=2면 순단 1회로는 상태가 확정되지 않는다"""
        st = {}
        obs = state_mod.observe(st, "s", "FAIL", "r", confirm=2)
        self.assertFalse(obs["alert"])
        obs = state_mod.observe(st, "s", "FAIL", "r", confirm=2)
        self.assertTrue(obs["alert"])

    def test_status_command_is_readonly(self):
        """P1-2: status(alert=False)는 state를 관측·기록하지 않는다"""
        sites = {"s": {"name": "테스트", "url": "http://example.invalid"}}
        st = {}
        fixed = [{"layer": "L1", "ok": True, "detail": "HTTP 200 · 1ms"}]
        with mock.patch.object(checks, "check_site", return_value=fixed), \
             mock.patch.object(state_mod, "save_state") as save, \
             mock.patch.object(state_mod, "observe") as observe, \
             contextlib.redirect_stdout(io.StringIO()):
            run_pass(sites, st, alert=False)
        save.assert_not_called()
        observe.assert_not_called()
        self.assertEqual(st, {})


class DecodeTest(unittest.TestCase):
    def test_charset_missing_korean_utf8(self):
        """P1-1: charset 없는 text/html의 한글이 깨지지 않아야 한다"""
        body = "<h1>데모샵</h1>".encode("utf-8")
        text = checks._decode(body, {"Content-Type": "text/html"})
        self.assertIn("데모샵", text)

    def test_charset_missing_korean_cp949(self):
        body = "<h1>데모샵</h1>".encode("cp949")
        text = checks._decode(body, {"Content-Type": "text/html"})
        self.assertIn("데모샵", text)

    def test_charset_header_respected(self):
        body = "<h1>데모샵</h1>".encode("euc-kr")
        text = checks._decode(body, {"Content-Type": "text/html; charset=euc-kr"})
        self.assertIn("데모샵", text)


class L2MarkerTest(unittest.TestCase):
    def test_no_markers_is_explicit_inactive(self):
        """P2-5: markers 미설정은 '마커 0/0 통과'가 아니라 명시적 비활성"""
        result = checks._l2_content({}, b"", {})
        self.assertTrue(result["ok"])
        self.assertIn("비활성", result["detail"])


class CachePolicyTest(unittest.TestCase):
    def test_no_cache_means_no_residue(self):
        self.assertEqual(checks._cache_policy({"Cache-Control": "no-cache, max-age=3600"}), "")

    def test_uppercase_directive(self):
        self.assertIn("1시간", checks._cache_policy({"Cache-Control": "MAX-AGE=3600"}))

    def test_seconds_not_rounded_to_minutes(self):
        self.assertIn("30초", checks._cache_policy({"Cache-Control": "max-age=30"}))

    def test_minutes(self):
        self.assertIn("10분", checks._cache_policy({"Cache-Control": "max-age=600"}))


class TruncatedBodyTest(unittest.TestCase):
    def test_truncated_body_is_not_content_missing(self):
        """N1: 부분 수신 본문에서 마커 부재를 '핵심 내용 없음'으로 단정하면 안 된다"""
        site = {"markers": ["데모샵"]}
        result = checks._l2_content(site, b"<html>partial", {}, truncated=True)
        self.assertFalse(result["ok"])
        self.assertIn("부분 수신", result["detail"])
        self.assertNotIn("핵심 내용 없음", result["detail"])

    def test_complete_body_missing_marker_is_content_missing(self):
        site = {"markers": ["데모샵"]}
        result = checks._l2_content(site, b"<html>other", {}, truncated=False)
        self.assertIn("핵심 내용 없음", result["detail"])


class ConfirmedReasonTest(unittest.TestCase):
    def test_alert_uses_confirmed_reason_not_latest_observation(self):
        """N2: 발송 대기 중 다른 관측의 사유가 섞여 자기모순 알림이 되면 안 된다"""
        st = {}
        state_mod.observe(st, "s", "FAIL", "L1 HTTP 503", confirm=2)
        state_mod.observe(st, "s", "FAIL", "L1 HTTP 503", confirm=2)  # 확정
        obs = state_mod.observe(st, "s", "OK", "L1 HTTP 200 · 정상", confirm=2)  # 미확정 관측
        self.assertTrue(obs["alert"])
        self.assertEqual(obs["status"], "FAIL")
        self.assertEqual(obs["reason"], "L1 HTTP 503")


class IsolationTest(unittest.TestCase):
    def test_one_site_failure_does_not_stop_pass(self):
        """N3: 한 사이트의 처리 예외가 다음 사이트 순찰을 막으면 안 된다"""
        sites = {
            "a": {"name": "A", "url": "http://a.invalid"},
            "b": {"name": "B", "url": "http://b.invalid"},
        }
        fixed = [{"layer": "L1", "ok": True, "detail": "HTTP 200 · 1ms"}]
        with mock.patch.object(checks, "check_site", return_value=fixed), \
             mock.patch.object(state_mod, "observe", side_effect=[TypeError("boom"), {
                 "alert": False, "missed_reason": None, "status": "OK",
                 "prev_notified": "OK", "duration_sec": 0, "reason": "r"}]) as observe, \
             mock.patch.object(state_mod, "save_state"), \
             contextlib.redirect_stdout(io.StringIO()):
            run_pass(sites, {}, alert=True, persist=False)
        self.assertEqual(observe.call_count, 2)

    def test_validate_sites_rejects_explicit_null(self):
        """11차 P3-1 + 12차 P3-1: null 등급은 런타임 영향 기준 —
        크래시 필드(confirm_checks/timeout_sec)만 error로 제외하고,
        무해 필드(markers/version_url)는 경고 후 감시 계속 (가용성 우선 H-G:
        단일 사이트 설정에서 감시 전면 중단을 만들지 않는다)"""
        for field in ("confirm_checks", "timeout_sec"):
            errors, _warnings, bad = checks_validate(
                {"s": {"name": "S", "url": "http://a.b", field: None}}
            )
            self.assertTrue(errors, field)
            self.assertIn("s", bad)
        for field in ("markers", "version_url"):
            errors, warnings, bad = checks_validate(
                {"s": {"name": "S", "url": "http://a.b", field: None}}
            )
            self.assertEqual(errors, [], field)
            self.assertNotIn("s", bad)
            self.assertTrue(any("null" in w for w in warnings), field)
        # markers null에 경고 두 개(자기모순 출력)를 내지 않는다
        _errors, warnings, _bad = checks_validate(
            {"s": {"name": "S", "url": "http://a.b", "markers": None}}
        )
        self.assertEqual(len([w for w in warnings if "markers" in w]), 1)

    def test_validate_sites_rejects_wrong_types(self):
        errors, _warnings, bad = checks_validate(
            {"s": {"name": "n", "url": "http://x", "markers": "데모샵", "confirm_checks": "2"}}
        )
        self.assertEqual(bad, {"s"})
        self.assertEqual(len(errors), 2)

    def test_validate_sites_rejects_empty_marker(self):
        """H-B: 빈 문자열 마커는 모든 페이지를 통과시켜 L2를 무음 무력화한다"""
        _errors, _warnings, bad = checks_validate(
            {"s": {"name": "n", "url": "http://x", "markers": [""]}}
        )
        self.assertEqual(bad, {"s"})


class ConsoleFallbackTest(unittest.TestCase):
    def test_console_fallback_counts_as_delivered(self):
        """N4: 토큰 없는 콘솔 폴백이 False면 같은 알림이 영구 반복된다"""
        with mock.patch.dict("os.environ", {}, clear=True), \
             contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(notify.send("테스트"))


class MissedTransientTest(unittest.TestCase):
    def test_unsent_outage_reported_on_self_recovery(self):
        """G1: 통보 전에 스스로 복구된 순단은 조용히 사라지지 않고 사후 보고된다"""
        st = {}
        state_mod.observe(st, "s", "FAIL", "L1 HTTP 503", confirm=1)  # 발송 실패 가정
        obs = state_mod.observe(st, "s", "OK", "정상", confirm=1)
        self.assertTrue(obs["alert"])
        self.assertEqual(obs["missed_reason"], "L1 HTTP 503")

    def test_notified_outage_recovery_is_normal_transition(self):
        st = {}
        state_mod.observe(st, "s", "FAIL", "r", confirm=1)
        state_mod.mark_notified(st, "s")
        obs = state_mod.observe(st, "s", "OK", "정상", confirm=1)
        self.assertIsNone(obs["missed_reason"])
        self.assertTrue(obs["alert"])

    def test_missed_recovery_is_not_reported_as_outage(self):
        """K-D: notified=FAIL 중 놓친 것은 '복구'다 — '미통보 장애'로 오보하면 안 된다"""
        st = {}
        state_mod.observe(st, "s", "FAIL", "r", confirm=1)
        state_mod.mark_notified(st, "s")
        state_mod.observe(st, "s", "OK", "정상", confirm=1)  # 회복 알림 전송 실패 가정
        obs = state_mod.observe(st, "s", "FAIL", "r2", confirm=1)  # 다시 장애
        self.assertIsNone(obs["missed_reason"])

    def test_worst_unnotified_reason_preserved_through_warn(self):
        """N-C: OK→FAIL(미발송)→WARN(미발송)→OK — 사후 보고는 최악(FAIL) 사유를 인용해야 한다"""
        st = {}
        state_mod.observe(st, "s", "FAIL", "L1 HTTP 503", confirm=1)
        state_mod.observe(st, "s", "WARN", "L3 버전 불일치", confirm=1)
        obs = state_mod.observe(st, "s", "OK", "정상", confirm=1)
        self.assertEqual(obs["missed_reason"], "L1 HTTP 503")

    def test_missed_report_retries_until_delivered(self):
        """H-C: 사후 보고도 전달 성공까지 유지 — clear_missed 후에만 소거"""
        st = {}
        state_mod.observe(st, "s", "FAIL", "L1 HTTP 503", confirm=1)
        state_mod.observe(st, "s", "OK", "정상", confirm=1)
        obs = state_mod.observe(st, "s", "OK", "정상", confirm=1)  # 발송 실패 후 재관측
        self.assertEqual(obs["missed_reason"], "L1 HTTP 503")
        state_mod.clear_missed(st, "s")
        obs = state_mod.observe(st, "s", "OK", "정상", confirm=1)
        self.assertIsNone(obs["missed_reason"])


class AlertOrderTest(unittest.TestCase):
    def test_current_outage_not_preempted_by_missed_report(self):
        """K-C: 과거 순단 사후 보고가 현재 진행 중인 🔴을 선점하면 안 된다"""
        sites = {"a": {"name": "A", "url": "u"}}
        obs_result = {"alert": True, "missed_reason": "L1 순단", "status": "FAIL",
                      "prev_notified": "OK", "duration_sec": 0, "reason": "지금 장애"}
        sent = []
        fixed = [{"layer": "L1", "ok": False, "detail": "지금 장애"}]
        with mock.patch.object(checks, "check_site", return_value=fixed), \
             mock.patch.object(state_mod, "observe", return_value=obs_result), \
             mock.patch.object(state_mod, "mark_notified"), \
             mock.patch.object(state_mod, "clear_missed"), \
             mock.patch.object(state_mod, "save_state"), \
             mock.patch.object(notify, "send", side_effect=lambda t: bool(sent.append(t)) or True), \
             contextlib.redirect_stdout(io.StringIO()):
            run_pass(sites, {}, alert=True, persist=False)
        self.assertEqual(len(sent), 2)
        self.assertIn("이상 감지", sent[0])   # 현재 장애 먼저
        self.assertIn("사후 보고", sent[1])


class CheckExceptionTest(unittest.TestCase):
    def test_check_exception_feeds_alert_path(self):
        """G2: 체크 예외가 콘솔 한 줄로 끝나지 않고 FAIL 상태로 알림 경로를 탄다"""
        sites = {"a": {"name": "A", "url": "u"}}
        obs_result = {"alert": False, "missed_reason": None, "status": "FAIL",
                      "prev_notified": "OK", "duration_sec": 0, "reason": "r"}
        with mock.patch.object(checks, "check_site", side_effect=RuntimeError("boom")), \
             mock.patch.object(state_mod, "observe", return_value=obs_result) as observe, \
             mock.patch.object(state_mod, "save_state"), \
             contextlib.redirect_stdout(io.StringIO()):
            run_pass(sites, {}, alert=True, persist=False)
        self.assertEqual(observe.call_args[0][2], "FAIL")
        self.assertIn("체크 자체 실패", observe.call_args[0][3])


class BadStateFileTest(unittest.TestCase):
    def test_partial_schema_entry_is_reinitialized(self):
        """G4: 부분 스키마 엔트리가 재초기화 가드를 우회하면 안 된다"""
        st = {"s": {"observed": "FAIL"}}
        obs = state_mod.observe(st, "s", "FAIL", "r", confirm=1)
        self.assertTrue(obs["alert"])


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


class DeployModeTest(unittest.TestCase):
    """배포 집중 모드 (D2 슬라이스 ②) — 판정 루프·앵커 계약·무소식 없음"""

    def _run(self, verdicts, **kw):
        sent, seq = [], iter(verdicts)
        with mock.patch.object(deploy, "_one_check", side_effect=lambda *a: next(seq)), \
             mock.patch.object(notify, "send",
                               side_effect=lambda t: bool(sent.append(t)) or True), \
             contextlib.redirect_stdout(io.StringIO()):
            rc = deploy.run_deploy_watch("s", {"name": "S"}, sleep=lambda _s: None, **kw)
        return rc, sent

    def test_stable_after_n_clean_passes(self):
        rc, sent = self._run([(deploy.VERDICT_OK, "d")] * 3)
        self.assertEqual(rc, 0)
        self.assertIn("🚀", sent[0])   # 시작 통보 필수
        self.assertIn("배포 안정", sent[-1])  # 결과 통보 필수 (무소식 없음)

    def test_pending_notified_once_then_stable(self):
        rc, sent = self._run(
            [(deploy.VERDICT_PENDING, "아직 1.0.1")] * 3 + [(deploy.VERDICT_OK, "d")] * 3
        )
        self.assertEqual(rc, 0)
        # 같은 미반영 사유 3회 관측 → 통보는 1회 (15초 스팸 금지)
        self.assertEqual(len([m for m in sent if "미반영" in m]), 1)

    def test_hard_fail_streak_reports_rollback(self):
        rc, sent = self._run([(deploy.VERDICT_FAIL, "L4 렌더링 에러: TypeError")] * 3)
        self.assertEqual(rc, 1)
        self.assertIn("롤백 검토", sent[-1])

    def test_timeout_reports_last_state(self):
        rc, sent = self._run([(deploy.VERDICT_PENDING, "사용자 화면은 아직 1.0.1")],
                             max_wait=0)
        self.assertEqual(rc, 1)
        self.assertIn("시간 초과", sent[-1])
        self.assertIn("1.0.1", sent[-1])

    def test_version_anchor_rejects_stale_origin(self):
        """앵커 계약(기각-2 승계): 원본·사용자가 서로 일치해도 기대 버전이 아니면
        안정이 아니다 — 배포가 서버에 아예 닿지 않은 상태를 오판하지 않는다"""
        with mock.patch.object(
            checks, "_fetch_version",
            side_effect=lambda site, bust: ("1.0.1", "", "")
        ):
            verdict, detail = deploy._version_goal({"version_url": "http://v"}, "1.0.2")
        self.assertEqual(verdict, deploy.VERDICT_PENDING)
        self.assertIn("서버에 반영되지 않음", detail)

    def test_version_anchor_ok_when_both_match(self):
        with mock.patch.object(
            checks, "_fetch_version",
            side_effect=lambda site, bust: ("1.0.2", "", "")
        ):
            verdict, _detail = deploy._version_goal({"version_url": "http://v"}, "1.0.2")
        self.assertEqual(verdict, deploy.VERDICT_OK)


class RenderLayerTest(unittest.TestCase):
    """L4 — 실제 헤드리스 렌더 경로 검증 (D2 슬라이스 ①). SETTLE_MS는 테스트에서
    단축 — 로컬 정적 페이지는 load 직후 렌더가 끝난다."""

    @classmethod
    def setUpClass(cls):
        cls.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _DemoHandler)
        cls.server.daemon_threads = True
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def _site(self, path, markers):
        return {"name": "R", "url": "http://127.0.0.1:%d%s" % (self.port, path),
                "markers": markers, "timeout_sec": 10}

    def test_js_rendered_marker_passes_l4(self):
        """마커가 원본 HTML엔 없고 JS 렌더로만 생기는 SPA — L2는 놓치고 L4가 잡는다"""
        from watcher import render
        site = self._site("/jsok", ["렌더마커"])
        with mock.patch.object(render, "SETTLE_MS", 100):
            result = render.check_render(site)
        self.assertTrue(result["ok"], result["detail"])
        # 교차 확인: 같은 페이지가 L2(원본 HTML)에서는 실제로 마커 부재다
        _status, body, headers, _tr = checks._bounded_get(site["url"], 5)
        self.assertNotIn("렌더마커", checks._decode(body, headers))

    def test_uncaught_js_error_fails_l4(self):
        from watcher import render
        with mock.patch.object(render, "SETTLE_MS", 100):
            result = render.check_render(self._site("/jserr", ["렌더마커"]))
        self.assertFalse(result["ok"])
        self.assertIn("TypeError", result["detail"])

    def test_rendered_missing_marker_fails_l4(self):
        from watcher import render
        with mock.patch.object(render, "SETTLE_MS", 100):
            result = render.check_render(self._site("/jsok", ["존재하지않는문구"]))
        self.assertFalse(result["ok"])
        self.assertIn("핵심 내용 없음", result["detail"])


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
