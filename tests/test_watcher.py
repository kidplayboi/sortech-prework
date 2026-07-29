"""Codex 게이트(2026-07-29) 지적 사항 회귀 테스트.

P1 구조 결함 3종(첫관측 무알림·status의 전이 소비·전송실패 소멸)과
P1-1 인코딩 오탐, P3 파싱류가 되돌아오지 않는지 고정한다.
"""
import unittest
from unittest import mock

from watcher import checks, state as state_mod
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
             mock.patch.object(state_mod, "observe") as observe:
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
                 "alert": False, "status": "OK", "prev_notified": "OK",
                 "duration_sec": 0, "reason": "r"}]) as observe, \
             mock.patch.object(state_mod, "save_state"):
            run_pass(sites, {}, alert=True, persist=False)
        self.assertEqual(observe.call_count, 2)

    def test_validate_sites_rejects_wrong_types(self):
        errors, _warnings, bad = checks_validate(
            {"s": {"name": "n", "url": "u", "markers": "데모샵", "confirm_checks": "2"}}
        )
        self.assertEqual(bad, {"s"})
        self.assertEqual(len(errors), 2)


class ConsoleFallbackTest(unittest.TestCase):
    def test_console_fallback_counts_as_delivered(self):
        """N4: 토큰 없는 콘솔 폴백이 False면 같은 알림이 영구 반복된다"""
        from watcher import notify
        with mock.patch.dict("os.environ", {}, clear=True):
            self.assertTrue(notify.send("테스트"))


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
