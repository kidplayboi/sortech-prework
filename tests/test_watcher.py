"""Codex 게이트(2026-07-29) 지적 사항 회귀 테스트.

P1 구조 결함 3종(첫관측 무알림·status의 전이 소비·전송실패 소멸)과
P1-1 인코딩 오탐, P3 파싱류가 되돌아오지 않는지 고정한다.
"""
import contextlib
import http.server
import io
import socketserver
import threading
import time
import unittest
from unittest import mock

import requests

from watcher import checks, notify, state as state_mod
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


class BoundedGetIntegrationTest(unittest.TestCase):
    """G8: truncated 분기를 직접 호출로만 검증하지 않고 실제 HTTP 경로로 검증"""

    @classmethod
    def setUpClass(cls):
        cls.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _DemoHandler)
        cls.server.daemon_threads = True  # 진행 중 핸들러가 shutdown을 붙잡지 않게
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

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
