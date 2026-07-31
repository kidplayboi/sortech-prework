"""상태 전이·알림·설정 검증 회귀 테스트 (게이트 1~13차).

네트워크 경로 = test_net.py · 층 모듈(L4/L5)·보드·deploy = test_layers.py
"""
import contextlib
import io
import unittest
from unittest import mock

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

    def test_corrupt_cloak_bucket_does_not_block_alerts(self):
        """18차 P2-1: cloak 중첩 버킷이 dict가 아니면 write_cloak가 TypeError를 내고,
        그게 알림 디스패치보다 앞이라 그 사이트가 **영구 무알림**이 된다 —
        다운된 사이트인데 알림 0건. `_entry_broken`은 바깥 dict만 보므로 통과한다.
        예외 없이 넘어가고, 손상 키는 다시 쓰지 않아 자가 치유돼야 한다."""
        st = {"s": {"cloak": {"spam": 5}}}
        state_mod.write_cloak(st, "s", state_mod.read_cloak(st, "s"))
        self.assertNotIn("cloak", st["s"])

    def test_healthy_cloak_bucket_survives_a_round_trip(self):
        """치유가 멀쩡한 누적까지 지우면 축 2가 매 패스 초기화된다 (음성 대조)"""
        st = {"s": {"cloak": {"spam": {"바카라": 2}}}}
        state_mod.write_cloak(st, "s", state_mod.read_cloak(st, "s"))
        self.assertEqual(st["s"]["cloak"], {"spam": {"바카라": 2}})
