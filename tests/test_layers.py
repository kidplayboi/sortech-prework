"""층 모듈 회귀 테스트 — L4 렌더링·L5 평판·상태보드·deploy 집중 모드 (D2).

L5 **클로킹 판정**은 분량이 커져 `test_cloaking.py`로 분리했다 (500라인 규칙).
"""
import contextlib
import io
import json
import pathlib
import shutil
import socketserver
import tempfile
import threading
import unittest
from unittest import mock

try:  # discover -s tests (경로 삽입) 와 python -m unittest tests.test_layers 양쪽 지원
    from helpers import _DemoHandler
except ImportError:  # pragma: no cover - 실행 방식에 따른 분기 (14차 P3-3)
    from .helpers import _DemoHandler
from watcher import board, checks, deploy, notify, security
from watcher.cli import run_pass


class ReputationLayerTest(unittest.TestCase):
    """L5 평판 축 (D2 슬라이스 ④) — Google Safe Browsing 조회"""

    def test_missing_gsb_key_warns_not_silent_pass(self):
        """noop이 실패를 성공처럼 보고하는 클래스 차단 + 13차 P2-3: '검증 불가'는
        사이트 상태가 아니라 우리 확인 실패이므로 unknown으로 구분돼야 한다"""
        with mock.patch.object(security, "_gsb_key", return_value=""):
            result = security.check_reputation({"url": "http://a.b"})
        self.assertFalse(result["ok"])
        self.assertTrue(result["warn"])
        self.assertTrue(result["unknown"])
        self.assertIn("GSB_API_KEY", result["detail"])

    def test_gsb_match_is_hard_fail(self):
        resp = mock.Mock(status_code=200)
        resp.json.return_value = {"matches": [{"threatType": "MALWARE"}]}
        with mock.patch.object(security, "_gsb_key", return_value="k"), \
             mock.patch.object(security.requests, "post", return_value=resp):
            result = security.check_reputation({"url": "http://a.b"})
        self.assertFalse(result["ok"])
        self.assertNotIn("warn", result)
        self.assertIn("MALWARE", result["detail"])

    def test_gsb_http_error_does_not_leak_body(self):
        """응답 본문에 키가 반사될 수 있어 상태코드만 노출"""
        resp = mock.Mock(status_code=403, text="key=SECRET123 invalid")
        with mock.patch.object(security, "_gsb_key", return_value="SECRET123"), \
             mock.patch.object(security.requests, "post", return_value=resp):
            result = security.check_reputation({"url": "http://a.b"})
        self.assertTrue(result["warn"])
        self.assertNotIn("SECRET123", result["detail"])

    def test_security_layer_skipped_unless_opted_in(self):
        with mock.patch.object(checks, "_l1_alive",
                               return_value=({"layer": "L1", "ok": True, "detail": "d"},
                                             b"body", {}, False)):
            results = checks.check_site({"url": "http://a.b"}, do_render=False)
        self.assertFalse(any("L5" in r["layer"] for r in results))


class IntermittentLayerTest(unittest.TestCase):
    """13차 P1-1 — 간헐 층(L4/L5)을 건너뛴 패스가 '정상'으로 오인되면
    🔴→🟢"회복"→🔴 거짓 복구·플랩·미보고가 난다. 직전 결과를 승계해 막는다."""

    L1_OK = {"layer": "L1", "ok": True, "detail": "HTTP 200"}
    L4_FAIL = {"layer": "L4", "ok": False, "detail": "렌더링 에러: TypeError"}

    def _pass(self, carry, results):
        sites = {"s": {"name": "S", "url": "http://a.b"}}
        with mock.patch.object(checks, "check_site", return_value=list(results)), \
             contextlib.redirect_stdout(io.StringIO()):
            rows, _sent = run_pass(sites, {}, alert=False, carry=carry)
        return rows[0]

    def test_skipped_layer_result_is_carried_not_assumed_ok(self):
        carry = {}
        first = self._pass(carry, [self.L1_OK, self.L4_FAIL])
        self.assertEqual(first["status"], "FAIL")
        # L4가 빠진 다음 패스 — 거짓 복구(OK)가 되면 안 된다
        second = self._pass(carry, [self.L1_OK])
        self.assertEqual(second["status"], "FAIL")
        self.assertIn("이전 관측", second["reason"])

    def test_carried_result_is_replaced_when_layer_runs_again(self):
        carry = {}
        self._pass(carry, [self.L1_OK, self.L4_FAIL])
        recovered = self._pass(
            carry, [self.L1_OK, {"layer": "L4", "ok": True, "detail": "렌더 정상"}])
        self.assertEqual(recovered["status"], "OK")
        self.assertNotIn("이전 관측", recovered["reason"])


class LayerGateTest(unittest.TestCase):
    """층 순서·게이트 계약 (13차 P2-1·P2-2·P2-5)"""

    def _l1(self, body=b"<html>plain</html>"):
        return mock.patch.object(
            checks, "_l1_alive",
            return_value=({"layer": "L1", "ok": True, "detail": "HTTP 200"},
                          body, {"Content-Type": "text/html; charset=utf-8"}, False))

    def test_spa_marker_judgment_is_deferred_to_l4(self):
        """P2-1: 원문에 마커가 없는 정상 SPA를 L2가 선점해 영구 🔴으로 만들면 안 된다"""
        rendered_ok = {"layer": "L4", "ok": True, "detail": "렌더 정상 · 마커 1/1"}
        with self._l1(), mock.patch("watcher.render.check_render", return_value=rendered_ok):
            results = checks.check_site(
                {"url": "http://a.b", "markers": ["앱마커"], "render": True},
                do_render=False)  # 스킵 패스여도 위임했으면 강제 실행
        layers = {r["layer"]: r for r in results}
        self.assertTrue(layers["L2"]["ok"])
        self.assertIn("위임", layers["L2"]["detail"])
        self.assertIn("L4", layers)

    def test_deferred_marker_with_unverifiable_l4_is_honest_fail(self):
        """위임했는데 심판이 없으면(Playwright 미설치 등) 조용한 공백을 만들지 않는다"""
        unknown = {"layer": "L4", "ok": False, "warn": True, "unknown": True,
                   "detail": "검증 불가 — Playwright 미설치"}
        with self._l1(), mock.patch("watcher.render.check_render", return_value=unknown):
            results = checks.check_site(
                {"url": "http://a.b", "markers": ["앱마커"], "render": True})
        l2 = [r for r in results if r["layer"] == "L2"][0]
        self.assertFalse(l2["ok"])
        self.assertIn("렌더 검증 불가", l2["detail"])

    def test_security_skipped_after_hard_fail(self):
        """P2-5: 확정 장애 뒤에 외부 API·추가 fetch를 쌓아 알림을 지연시키지 않는다"""
        with self._l1(b"<html>nothing</html>"), \
             mock.patch("watcher.security.check_security") as sec:
            results = checks.check_site(
                {"url": "http://a.b", "markers": ["없는마커"], "security": True})
        sec.assert_not_called()
        self.assertTrue(any(not r["ok"] and not r.get("warn") for r in results))


class BoardTest(unittest.TestCase):
    """정적 상태보드 (D2 슬라이스 ③) — 파일 생성·escape·이력 상한"""

    def setUp(self):
        self.dir = pathlib.Path(tempfile.mkdtemp())
        self.board = self.dir / "board.html"
        self.history = self.dir / "board_history.json"
        self.patches = [
            mock.patch.object(board, "BOARD_PATH", self.board),
            mock.patch.object(board, "BOARD_HISTORY_PATH", self.history),
        ]
        for p in self.patches:
            p.start()

    def tearDown(self):
        for p in self.patches:
            p.stop()
        shutil.rmtree(self.dir, ignore_errors=True)

    def _row(self, **kw):
        row = {"key": "s", "name": "데모샵", "status": "OK", "reason": "정상",
               "layers": [{"layer": "L1", "ok": True, "detail": "HTTP 200 · 10ms"}]}
        row.update(kw)
        return row

    def test_board_written_with_status_and_layers(self):
        board.update_board([self._row()], ["🟢 [데모샵] 회복"])
        html_text = self.board.read_text(encoding="utf-8")
        self.assertIn("데모샵", html_text)
        self.assertIn("HTTP 200", html_text)
        self.assertIn("회복", html_text)

    def test_dynamic_text_is_escaped(self):
        """사이트 응답에서 유래한 문구가 보드 안에서 마크업으로 살면 안 된다"""
        row = self._row(reason="<script>alert(1)</script>",
                        layers=[{"layer": "L2", "ok": False,
                                 "detail": "없음: <img src=x onerror=alert(1)>"}])
        board.update_board([row], ["🔴 <script>x</script>"])
        html_text = self.board.read_text(encoding="utf-8")
        self.assertNotIn("<script>alert(1)</script>", html_text)
        self.assertNotIn("<img src=x", html_text)
        self.assertIn("&lt;script&gt;", html_text)

    def test_history_capped(self):
        for i in range(30):
            board.update_board([self._row()], ["알림 %d" % i])
        history = json.loads(self.history.read_text(encoding="utf-8"))
        self.assertEqual(len(history), board.HISTORY_MAX)
        self.assertEqual(history[-1]["text"], "알림 29")  # 최신이 남고 옛것이 밀린다

    def test_corrupt_timestamp_entry_is_dropped(self):
        """13차 P3-3: 문자열 ts 하나가 TypeError를 내고 그 엔트리가 다시 저장돼
        이후 보드 갱신이 영구 실패했다 — 로드 단계에서 버린다"""
        self.history.write_text(
            json.dumps([{"ts": "2026-07-30", "text": "손상"}]), encoding="utf-8")
        board.update_board([self._row()], ["정상 알림"])  # 예외 없이 통과해야 한다
        history = json.loads(self.history.read_text(encoding="utf-8"))
        self.assertEqual([e["text"] for e in history], ["정상 알림"])
        self.assertIn("정상 알림", self.board.read_text(encoding="utf-8"))


class DeployModeTest(unittest.TestCase):
    """배포 집중 모드 (D2 슬라이스 ②) — 판정 루프·앵커 계약·무소식 없음"""

    def _run(self, verdicts, send_ok=True, **kw):
        """verdicts = (verdict, detail) 또는 (verdict, detail, unknowns) 시퀀스"""
        sent, seq = [], iter(verdicts)

        def next_check(*_a):
            item = next(seq)
            return item if len(item) == 3 else (item[0], item[1], [])

        def fake_send(text):
            if send_ok:
                sent.append(text)
            return send_ok

        with mock.patch.object(deploy, "_one_check", side_effect=next_check), \
             mock.patch.object(notify, "send", side_effect=fake_send), \
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

    def test_unknown_does_not_block_stable_but_is_noted(self):
        """13차 P2-3: '검증 불가'(키 미설정 등)를 미반영으로 묶으면 건강한 배포가
        10분 뒤 '시간 초과 실패'로 오보된다 — 안정은 내주되 미확인은 부기한다"""
        rc, sent = self._run(
            [(deploy.VERDICT_OK, "d", ["L5 평판 검증 불가 — GSB_API_KEY 미설정"])] * 3
        )
        self.assertEqual(rc, 0)
        self.assertIn("배포 안정", sent[-1])
        self.assertIn("미확인 항목", sent[-1])
        self.assertIn("GSB_API_KEY", sent[-1])

    def test_unknown_layer_is_not_pending_in_one_check(self):
        """같은 계약을 _one_check 수준에서도 고정 (검증 불가 ≠ 미반영)"""
        layers = [
            {"layer": "L1", "ok": True, "detail": "HTTP 200"},
            {"layer": "L5 평판", "ok": False, "warn": True, "unknown": True,
             "detail": "검증 불가 — GSB_API_KEY 미설정"},
        ]
        with mock.patch.object(checks, "check_site", return_value=layers):
            verdict, _detail, unknowns = deploy._one_check({"url": "http://a.b"}, None, None)
        self.assertEqual(verdict, deploy.VERDICT_OK)
        self.assertEqual(len(unknowns), 1)

    def test_terminal_notify_retries_until_sent(self):
        """13차 P2-4: 종말 통보가 한 번 실패했다고 무통보 종료하면 모듈 계약 위반"""
        attempts = []

        def flaky(_text):
            attempts.append(1)
            return len(attempts) >= 3  # 3번째에 성공

        with mock.patch.object(notify, "send", side_effect=flaky), \
             contextlib.redirect_stdout(io.StringIO()):
            sent = deploy._notify_final("🟢 결과", sleep=lambda _s: None)
        self.assertTrue(sent)
        self.assertEqual(len(attempts), 3)

    def test_pending_reason_not_consumed_when_send_fails(self):
        """전송 실패 시 last_pending을 갱신하면 그 사유는 영구 재시도되지 않는다 (H-C)"""
        rc, sent = self._run([(deploy.VERDICT_PENDING, "아직 1.0.1")] * 2,
                             send_ok=False, max_wait=0)
        self.assertEqual(rc, 1)
        self.assertEqual(sent, [])  # 전송 전부 실패 — 콘솔로만 보고


def _playwright_ready():
    """Playwright 패키지 + Chromium 브라우저가 **둘 다** 있는가.

    L4는 선택 기능이라 기본 설치(`requirements.txt`)에 브라우저가 없다.
    그 환경에서 이 테스트들이 **실패**하면 "이 도구가 고장났다"로 읽힌다 —
    실제로는 선택 의존성이 없을 뿐이다. 검증 불가를 성공으로 위장하지도 않고
    실패로 오귀속하지도 않는다: **정직하게 skip**하고 이유를 남긴다.
    (이 도구가 unknown을 사이트 장애와 구분하는 것과 같은 원칙이다)
    """
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return False, "playwright 미설치 — `pip install -r requirements-dev.txt`"
    try:
        with sync_playwright() as p:
            p.chromium.launch(headless=True).close()
    except Exception as exc:                      # 브라우저 바이너리 없음 등
        return False, "Chromium 실행 불가(%s) — `playwright install chromium`" % type(exc).__name__
    return True, ""


class RenderLayerTest(unittest.TestCase):
    """L4 — 실제 헤드리스 렌더 경로 검증 (D2 슬라이스 ①). SETTLE_MS는 테스트에서
    단축 — 로컬 정적 페이지는 load 직후 렌더가 끝난다.

    ⚠️선택 의존성(Playwright + Chromium)이 없으면 **skip**한다. 기본 설치만 한
    사람이 빨간 실패를 보고 도구가 고장난 줄 알면 안 된다."""

    @classmethod
    def setUpClass(cls):
        ready, why = _playwright_ready()
        if not ready:
            raise unittest.SkipTest("L4 선택 의존성 없음 — %s" % why)
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
