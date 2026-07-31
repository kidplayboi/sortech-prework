"""L5 클로킹 판정 회귀 테스트 — 재설계(축 1·2·3)와 그 음성 대조.

13~17차 게이트에서 같은 오탐이 다섯 번 반복된 자리라, 판정 계약은 500라인 규칙에
따라 test_layers.py에서 떼어내 여기 모았다. 설계 = docs/06-L5-판정-재설계안.md

이 파일의 규율 두 가지:
- 오탐 단언은 **실서버 픽스처**로 한다. 스텁은 "재확인에서 스팸이 사라진다"는
  가정을 고정할 뿐이라 수리를 검증하지 못한다 (14차 오답 14호 vacuous 클래스).
- 각 축을 뜯었을 때 오탐이 되살아나는지도 함께 단언한다. 되살아나지 않으면 그
  축은 장식이고, 테스트는 커버리지 0이다 (17차 오답 24호).
"""
import contextlib
import random
import socketserver
import threading
import unittest
from unittest import mock

try:  # discover -s tests (경로 삽입) 와 python -m unittest tests.test_cloaking 양쪽 지원
    from helpers import _RotatingHandler
except ImportError:  # pragma: no cover - 실행 방식에 따른 분기 (14차 P3-3)
    from .helpers import _RotatingHandler
from watcher import checks, cloak_decision, security

FIXED_SAMPLES = 8  # 문구 단언이 걸린 테스트는 표본 수를 고정한다 (축 3 무작위 제거)


def _fixed_samples(count=FIXED_SAMPLES):
    return mock.patch.object(cloak_decision, "user_sample_count", return_value=count)


def _is_hard_fail(result):
    return not result["ok"] and not result.get("warn")


class CloakingJudgmentTest(unittest.TestCase):
    """고정 응답 스텁 — '회전이 전혀 없는 안정 페이지'의 판정 계약"""

    def _cloak(self, user_text, bot_text, markers=("데모샵",), memory=None):
        """매 회차 같은 내용 = 회전 미관측. 안정 + 봇 시점 과반 재현이면
        축 1에 따라 그 패스에서 확정된다."""
        def fake(url, timeout, ua=checks.UA, referer=None):
            return (bot_text if ua == security.BOT_UA else user_text), ""

        site = {"url": "http://a.b", "markers": list(markers), "timeout_sec": 5}
        with mock.patch.object(security, "_fetch_view", side_effect=fake), \
             _fixed_samples():
            return security.check_cloaking(site, memory)

    def test_bot_only_spam_is_fail(self):
        """검색봇에만 도박 문구 = 클로킹 의심 (한국 실측 수법)"""
        result = self._cloak("데모샵 정상 페이지", "데모샵 바카라 카지노 먹튀검증")
        self.assertTrue(_is_hard_fail(result))
        self.assertIn("바카라", result["detail"])

    def test_spam_on_both_sides_is_not_cloaking(self):
        """양쪽에 다 있으면 사이트 성격 — 클로킹 아님(오탐 방지)"""
        result = self._cloak("카지노 리뷰 사이트 데모샵", "카지노 리뷰 사이트 데모샵")
        self.assertTrue(result["ok"], result["detail"])

    def test_marker_vanishing_for_bot_is_warn_not_fail(self):
        """봇 차단 WAF일 수도 있어 단정하지 않는다"""
        result = self._cloak("데모샵 정상", "Access Denied")
        self.assertFalse(result["ok"])
        self.assertTrue(result["warn"])
        self.assertIn("사라짐", result["detail"])

    def test_custom_spam_keyword_from_site_config(self):
        def fake(url, timeout, ua=checks.UA, referer=None):
            return ("정상" if ua != security.BOT_UA else "정상 특정광고문구"), ""

        site = {"url": "http://a.b", "markers": [], "spam_keywords": ["특정광고문구"]}
        with mock.patch.object(security, "_fetch_view", side_effect=fake), \
             _fixed_samples():
            result = security.check_cloaking(site)
        self.assertTrue(_is_hard_fail(result))
        self.assertIn("특정광고문구", result["detail"])

    def test_rotating_spam_is_rejected_early(self):
        """13차 P2-6 + 15차 P3-5: 일반 시점 재표본에서 그 문구가 관측되는 순간
        즉시 기각한다 — 남은 표본까지 다 뜨면 남의 사이트에 매 패스 부담이 된다"""
        seq = iter([
            ("정상 데모샵", ""),                  # 일반 1차
            ("정상 데모샵 바카라 배너", ""),      # 봇 1차 — 히트
            ("정상 데모샵 바카라 배너", ""),      # 일반 재표본 — 여기서 즉시 기각
        ])
        calls = []

        def fake(url, timeout, ua=checks.UA, referer=None):
            calls.append(ua)
            return next(seq)

        with mock.patch.object(security, "_fetch_view", side_effect=fake), \
             _fixed_samples():
            result = security.check_cloaking(
                {"url": "http://a.b", "markers": ["데모샵"], "timeout_sec": 5})
        self.assertTrue(result["ok"], result["detail"])
        self.assertIn("일반 시점에도 보이는 문구", result["detail"])
        self.assertEqual(len(calls), 3)  # 조기 종료 — 확인 블록을 다 뜨지 않는다

    def test_repeated_spam_is_confirmed_fail(self):
        """반대 방향 음성 대조 — 안정 페이지에서 재현되면 확정 FAIL이어야 한다"""
        result = self._cloak("정상 데모샵", "정상 데모샵 바카라")
        self.assertTrue(_is_hard_fail(result))
        self.assertIn("일반 시점 %d회 전부 부재" % (FIXED_SAMPLES + 1), result["detail"])

    def test_memory_is_persisted_for_the_caller(self):
        """축 2의 전제 — 판정 누적이 호출자 dict에 남아야 다음 패스로 이어진다"""
        memory = {}
        self._cloak("정상 데모샵", "정상 데모샵 바카라", memory=memory)
        self.assertEqual(memory["spam"]["바카라"], cloak_decision.CONFIRM_PASSES)

    def test_unobserved_pass_decays_instead_of_declaring_recovery(self):
        """봇이 이번 표본에서 못 봤다 ≠ 해소됐다.

        0으로 리셋하면 간헐 클로커가 🔴→🟢'회복'→🔴로 튄다 — 13차 P1-1이 간헐 층에
        대해 막은 거짓 복구와 같은 클래스다. 감쇠라서 확정 해제도 여러 깨끗한 패스를
        요구한다(비대칭 복구 금지).
        """
        memory = {}
        confirmed = self._cloak("정상 데모샵", "정상 데모샵 바카라", memory=memory)
        self.assertTrue(_is_hard_fail(confirmed))
        clean = [self._cloak("정상 데모샵", "정상 데모샵", memory=memory)
                 for _ in range(cloak_decision.CONFIRM_PASSES)]
        self.assertTrue(clean[0].get("warn"), clean[0]["detail"])  # 곧장 초록 금지
        self.assertIn("미관측", clean[0]["detail"])
        self.assertTrue(clean[-1]["ok"], clean[-1]["detail"])      # 다 지나면 해소
        self.assertEqual(memory.get("spam"), {})

    def test_non_200_view_is_unknown_not_match(self):
        """13차 P3-2: 비200·부분 수신을 '일치'로 통과시키면 거짓 음성"""
        with mock.patch.object(security, "_fetch_view",
                               side_effect=lambda *a, **k: ("", "검색봇 시점 응답 HTTP 403")):
            result = security.check_cloaking({"url": "http://a.b", "markers": []})
        self.assertFalse(result["ok"])
        self.assertTrue(result["unknown"])
        self.assertIn("비교 불가", result["detail"])

    def test_unknown_pass_does_not_touch_memory(self):
        """비교 불가는 반증이 아니다 — 못 본 패스가 누적을 지우면 안 된다"""
        memory = {"spam": {"바카라": 2}}
        with mock.patch.object(security, "_fetch_view",
                               side_effect=lambda *a, **k: ("", "일반 시점 응답 HTTP 503")):
            security.check_cloaking({"url": "http://a.b", "markers": []}, memory)
        self.assertEqual(memory, {"spam": {"바카라": 2}})


class _RealServerCase(unittest.TestCase):
    """회전 픽스처 실서버 — 하위 클래스가 공유한다"""

    @classmethod
    def setUpClass(cls):
        cls.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _RotatingHandler)
        cls.server.daemon_threads = True
        cls.port = cls.server.server_address[1]
        threading.Thread(target=cls.server.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()

    def setUp(self):
        _RotatingHandler.ROTATION.clear()  # 위상을 매 테스트 초기화

    def _site(self, path, markers=("데모샵",)):
        return {"url": "http://127.0.0.1:%d%s" % (self.port, path),
                "markers": list(markers), "timeout_sec": 10}


class CloakingRealServerTest(_RealServerCase):
    """14차 P2-1 — 스텁이 아닌 실서버로 오탐/탐지를 동시에 고정한다."""

    # 주기 2~16 전수. 9 이상은 **수리 전 코드에서 하드 FAIL이 실측된** 구간이다
    # (음성 대조 실측 = 시작 위상 전수 × 6패스: 수리 전 74/882 → 수리 후 0/882.
    #  /rotate12single은 21/72, /rotate14는 12/84였다)
    # /rotate17·/rotate24({1,18})는 18차 P3-3 — escalation 확률의 최대점은 스팸
    # 잔여류 간격이 `USER_SAMPLE_MAX+1`(=17)일 때다. 16에서 끊으면 회귀가 최악
    # 지점 **직전**까지만 덮는다
    ALL_PERIODS = ("/rotate2", "/rotate3", "/rotate4", "/rotate5", "/rotate6",
                   "/rotate7", "/rotate8", "/rotate9", "/rotate10", "/rotate11",
                   "/rotate12", "/rotate12single", "/rotate13", "/rotate14",
                   "/rotate15", "/rotate16", "/rotate17", "/rotate24",
                   "/rotate13dense")

    def _sweep(self, path, passes=12, seed=20260731):
        """한 사이트를 여러 패스 순찰하고 (하드 FAIL 수, 마지막 결과)를 돌려준다.
        축 3(무작위 표본 수)은 시드를 박아 재현 가능하게 만든다 — 무작위성을
        테스트에서 풀어두면 실패가 재현되지 않아 진단이 불가능하다.
        ⚠️단, 시드 하나의 0은 상한이 아니다 — 아래 다중 시드 단언과 짝으로 본다."""
        rng = random.Random(seed)
        memory, site, fails, result = {}, self._site(path), 0, None
        with mock.patch.object(
                cloak_decision, "user_sample_count",
                side_effect=lambda: rng.randint(cloak_decision.USER_SAMPLE_MIN,
                                                cloak_decision.USER_SAMPLE_MAX)), \
             mock.patch.object(
                cloak_decision, "bot_sample_count",
                side_effect=lambda: rng.randint(cloak_decision.BOT_SAMPLE_MIN,
                                                cloak_decision.BOT_SAMPLE_MAX)):
            for _ in range(passes):
                result = security.check_cloaking(site, memory)
                fails += 1 if _is_hard_fail(result) else 0
        return fails, result

    def test_sequential_rotation_is_never_hard_failed_any_period(self):
        """순차 회전 주기 2~24 전수 — 어떤 위상에서도 **하드 FAIL(🔴)은 없다.**

        13~16차는 "일반 블록이 mod P의 전 잔여류를 덮는다"를 근거로 삼았고, 그
        근거는 P>N에서 반드시 무너졌다(17차: P>=9 전부 오탐). 이제 근거가 다르다 —
        회전이 관측되면(축 1) 유한 표본의 부재를 결론으로 쓰지 않고, 확정은
        패스 간 누적(축 2)에만 맡기며, 양쪽 블록 길이를 흔들어(축 3) 위상 락을 없앤다.
        """
        for path in self.ALL_PERIODS:
            _RotatingHandler.ROTATION.clear()
            fails, _last = self._sweep(path)
            self.assertEqual(fails, 0, "%s 하드 FAIL %d회" % (path, fails))

    # 취약 주기 × 시드 스윕에서 **실측된 잔존 오탐 상한**. 0이 아니다 —
    # 20차 P1-1: "0/1206"이라고 쓴 근거는 시작 위상 0·시드 하나의 관측치였고,
    # 시드를 흔들면 주기 16에서 재현된다(시드 12개 × 경로 5 × 12패스 = 720패스에서
    # 5회, 0.69%). 회귀는 그 사실을 **숨기지 말고 상한으로** 지킨다 —
    # 여유 3배(2%)를 두되, 이 값을 넘으면 뭔가 나빠진 것이다
    RESIDUAL_MAX_RATE = 0.02

    def test_rotation_false_positive_stays_under_measured_bound(self):
        """19차 P2-2 · 20차 P1-1 — 위 단언은 시드 하나의 관측치다.

        시드를 바꾸면 무너지는 '구조적 보장'을 주장하지 않는다. 대신 여러 시드에서
        **잔존율이 실측 상한 아래인지**를 지킨다. 확률적 장치의 정직한 회귀 형태다.
        (수리 전 코드에서는 같은 스윕이 훨씬 높았다 — 감사 문서 §20차 참조)
        """
        paths = ("/rotate14", "/rotate15", "/rotate16", "/rotate17", "/rotate24")
        seeds, passes = range(12), 12
        fails = 0
        for seed in seeds:
            for path in paths:
                _RotatingHandler.ROTATION.clear()
                hits, _last = self._sweep(path, passes=passes, seed=seed)
                fails += hits
        total = len(list(seeds)) * len(paths) * passes
        self.assertLessEqual(fails / total, self.RESIDUAL_MAX_RATE,
                             "잔존 오탐 %d/%d — 실측 상한 초과" % (fails, total))

    def test_short_period_rotation_is_resolved_within_one_pass(self):
        """주기가 확인 블록 하한 이하면 한 패스에서 기각된다 — 누적을 기다리지
        않는다(축 2는 못 가르는 경우의 장치이지 모든 판정을 미루는 장치가 아니다)"""
        for path in ("/rotate2", "/rotate3", "/rotate4", "/rotate5"):
            _RotatingHandler.ROTATION.clear()
            _fails, last = self._sweep(path, passes=4)
            self.assertTrue(last["ok"], "%s: %s" % (path, last["detail"]))

    def test_user_samples_are_one_unbroken_block(self):
        """일반 표본은 요청 인덱스 상에서 **연속**이어야 한다.

        ⚠️같은 단언, 바뀐 근거: 16차엔 '연속 N개가 전 잔여류를 덮는다'가 이유였고
        그건 17차에 무너졌다. 지금 연속성이 필요한 이유는 **축 1(회전 감지)의
        전제**다 — 봇 요청을 블록 중간에 끼우면 일반 표본이 mod P에서 같은
        잔여류에 갇혀 주기 2짜리 회전조차 '변화 없음'으로 보이고, 그러면 회전
        페이지가 즉시 확정 경로를 타 버린다.
        """
        order = []
        real_fetch = security._fetch_view

        def spy(url, timeout, ua=checks.UA, referer=None):
            order.append("bot" if ua == security.BOT_UA else "user")
            return real_fetch(url, timeout, ua=ua, referer=referer)

        with mock.patch.object(security, "_fetch_view", side_effect=spy), \
             _fixed_samples():
            security.check_cloaking(self._site("/cloak"))  # 진짜 클로킹 = 전 표본 소진
        user_indexes = [i for i, who in enumerate(order) if who == "user"]
        block = user_indexes[1:]  # 1차 일반 표본 이후가 확인 블록
        self.assertEqual(len(block), FIXED_SAMPLES)
        self.assertEqual(block, list(range(block[0], block[0] + len(block))))

    def test_real_cloaking_still_detected(self):
        """반대 방향 — 진짜 클로킹(안정 페이지)은 **한 패스에서** 하드 FAIL이어야
        한다. 누적 도입이 탐지를 늦추면 안 되는 지점이다(축 1의 존재 이유)"""
        result = security.check_cloaking(self._site("/cloak"), {})
        self.assertTrue(_is_hard_fail(result))
        self.assertIn("바카라", result["detail"])

    def test_intermittent_cloaking_still_detected(self):
        """15차 P3-3: 봇에게 간헐 노출하는 클로커도 잡아야 한다.

        봇 표본 수가 무작위(축 3을 봇 쪽에도 적용 — 19차 P1-1)라 노출 1/2에서는
        과반 충족이 그 패스의 뽑기에 달렸다. 즉시 확정이 될 때도 있고 누적으로 갈
        때도 있으므로, 계약은 "한 패스"가 아니라 **CONFIRM_PASSES 안에 확정**이다.
        """
        site, memory = self._site("/cloak-intermittent2"), {}
        verdicts = [security.check_cloaking(site, memory)
                    for _ in range(cloak_decision.CONFIRM_PASSES)]
        self.assertTrue(any(_is_hard_fail(v) for v in verdicts),
                        [v["detail"] for v in verdicts])
        self.assertEqual([v for v in verdicts if v["ok"]], [])

    def test_low_exposure_cloaking_is_confirmed_and_never_green(self):
        """18차 P1-1 — 봇 노출률이 1/2 **미만**인 클로커.

        후보를 봇 1차 표본에서만 뽑으면 그 표본이 비는 패스마다 누적이 깎여
        확정 조건이 사실상 "봇 1차 히트율 > 1/2"가 된다. 수리 전 실측(14패스):
        1/3 노출 = 하드 FAIL 0회·거짓 초록 9회 / 1/4 노출 = 0회·7회.
        15차 P3-3(간헐 미탐 완화)이 통째로 재개방된 자리였다.
        추적 중인 후보가 있으면 봇 블록 전체로 다시 확인해 그 편향을 없앤다.
        """
        for path in ("/cloak-intermittent3", "/cloak-intermittent4"):
            _RotatingHandler.ROTATION.clear()
            site, memory = self._site(path), {}
            verdicts = [security.check_cloaking(site, memory) for _ in range(8)]
            self.assertTrue(any(_is_hard_fail(v) for v in verdicts),
                            "%s: 확정 0회 — %s" % (path, [v["detail"] for v in verdicts]))
            self.assertEqual([v for v in verdicts if v["ok"]], [],
                             "%s: 침해된 사이트에 단정형 🟢" % path)

    def test_detection_floor_is_where_the_measurement_says_it_is(self):
        """탐지 하한을 **경계 근처에서** 테스트로 박아둔다.

        20차 P3-5: 처음엔 1/6과 1/20만 단언해서 실측 경계(1/13~1/14)에서 양쪽 다
        멀었다 — 모델이 30% 틀려도 GREEN이었다. 경계 바로 아래위를 잡는다.
        (하한을 낮추려면 봇 표본을 늘려야 하고 그건 감시 대상 사이트의 부담이다)
        """
        def confirmed(path, passes=20):
            _RotatingHandler.ROTATION.clear()
            site, memory = self._site(path), {}
            return any(_is_hard_fail(security.check_cloaking(site, memory))
                       for _ in range(passes))

        self.assertTrue(confirmed("/cloak-intermittent12"), "1/12는 확정돼야 한다")
        self.assertFalse(confirmed("/cloak-intermittent16"),
                         "1/16이 확정된다면 하한이 바뀐 것 — 문서 수치를 고쳐야 한다")

    def test_intermittent_cloaking_never_reports_recovery(self):
        """간헐 클로커에서 🔴→🟢→🔴 플랩이 나면 알림 신뢰가 무너진다.
        봇이 이번 표본에 안 보여줬을 뿐인 패스는 WARN(감쇠 중)이어야 한다"""
        site = self._site("/cloak-intermittent2")
        memory = {}
        verdicts = [security.check_cloaking(site, memory) for _ in range(6)]
        self.assertTrue(any(_is_hard_fail(v) for v in verdicts))
        self.assertFalse(any(v["ok"] for v in verdicts),
                         [v["detail"] for v in verdicts])

    def test_rotation_rejection_does_not_hide_marker_loss(self):
        """15차 P3-1: 스팸이 기각돼도 마커 소실이 은폐되면 안 된다
        (14차에 주석만 달고 조기 반환을 남겨둔 것이 재적발됐다)"""
        def fake(url, timeout, ua=checks.UA, referer=None):
            if ua == security.BOT_UA:
                return "데모샵 바카라", ""      # 봇: 마커 소실 + 스팸
            return "데모샵 장바구니 바카라", ""  # 일반: 마커 있음 + 스팸도 있음(기각)

        with mock.patch.object(security, "_fetch_view", side_effect=fake), \
             _fixed_samples():
            result = security.check_cloaking(
                self._site("/rotate6", markers=["장바구니"]), {})
        self.assertFalse(result["ok"])
        self.assertTrue(result["warn"])
        self.assertIn("사라짐", result["detail"])

    def test_marker_loss_is_resampled_on_both_sides(self):
        """17차 P2-2 — 마커 소실 경로는 13~16차 내내 일반 1회·봇 1회 고정 비교였다
        (재표본 0회). 회전 페이지에서 주기 2가 20/20 영구 WARN이었던 자리.
        이제 같은 확장 표본을 경유하므로 회전으로 설명되는 소실은 기각된다."""
        site = self._site("/rotate2", markers=["배너0"])  # 회차마다 오가는 값
        results = [security.check_cloaking(site, {}) for _ in range(8)]
        self.assertEqual([r for r in results if not r["ok"]], [],
                         "회전으로 설명되는 마커 소실이 알림으로 샜다")


class CloakAxisNegativeControlTest(_RealServerCase):
    """축 3개가 **실제로 하중을 받는지** 하나씩 뜯어서 확인한다.

    17차 오답 24호: 결함 코드에서 RED를 확인하지 않은 회귀 테스트는 커버리지가
    0일 수 있다. 여기서는 반대로, 각 축을 제거했을 때 오탐이 되살아나는지를
    본다 — 되살아나지 않으면 그 축은 장식이다.
    """

    # 일반 5 + 봇 7이면 확장 패스의 요청 수가 정확히 13(일반1+봇1+일반5+봇6)이라
    # 주기 13과 물려 위상이 매 패스 제자리다 — 축 3을 뗀 상태를 재현하는 값이자,
    # 나머지 두 축을 결정적으로 관찰하기 위한 고정값이다. (무작위 표본 수를 그대로
    # 두면 음성 대조가 flaky해져 "RED를 봤다"는 근거 자체가 흔들린다 — 자체 대조에서
    # 겪었다.) ⚠️**양쪽 블록을 다 고정해야** 한다 — 봇 쪽을 흔든 채로 두면 패스
    # 길이가 흔들려 락이 안 걸리고, 대조가 아무것도 제거하지 않은 채 통과한다
    LOCKED_USER, LOCKED_BOT = 5, 7
    LOCKED_PATH = "/rotate13"

    def _hard_fails(self, passes, path=None):
        site = self._site(path or self.LOCKED_PATH)
        memory = {}
        with mock.patch.object(cloak_decision, "user_sample_count",
                               return_value=self.LOCKED_USER), \
             mock.patch.object(cloak_decision, "bot_sample_count",
                               return_value=self.LOCKED_BOT):
            return sum(1 for _ in range(passes)
                       if _is_hard_fail(security.check_cloaking(site, memory)))

    def test_axis1_removed_confirms_rotating_page_immediately(self):
        """축 1(회전 감지)만 무력화 → 회전 페이지가 안정으로 보여 첫 패스에 확정.

        `_immediate` 전체가 아니라 `is_rotating`만 패치한다 — 전자를 패치하면
        회전 감지와 봇 과반 두 자물쇠가 함께 사라져 축 1 **단독**의 하중을
        증명하지 못한다 (18차 P3-5).
        """
        with mock.patch.object(cloak_decision, "is_rotating", return_value=False):
            self.assertEqual(self._hard_fails(passes=1, path="/rotate13dense"), 1)
        # 대조군 — 축 1이 살아 있으면 같은 첫 패스가 확정으로 가지 않는다
        _RotatingHandler.ROTATION.clear()
        self.assertEqual(self._hard_fails(passes=1, path="/rotate13dense"), 0)

    def test_axis2_removed_confirms_on_a_single_pass(self):
        """축 2 제거 = 한 패스로 확정. 같은 첫 패스가 축 2가 있으면 WARN에 머문다
        — 대조군을 나란히 단언해 '장치가 실제로 하중을 받는지'를 고정한다"""
        with mock.patch.object(cloak_decision, "CONFIRM_PASSES", 1):
            self.assertEqual(self._hard_fails(passes=1), 1)
        _RotatingHandler.ROTATION.clear()
        self.assertEqual(self._hard_fails(passes=1), 0)

    def test_axis3_on_the_bot_block_is_load_bearing(self):
        """20차 P2-2 — 19차의 헤드라인 수리(봇 블록 무작위화)를 통째로 되돌려도
        스위트가 전부 GREEN이었다. 내 규율("결함 코드에서 RED를 먼저 봐라")을
        정작 그 수리에는 적용하지 않은 것. 인과를 짝으로 단언한다.

        봇 표본을 7로 고정하면 봇 시점 위상이 매 패스 정확히 7씩만 움직여, 노출
        주기가 12 이상인 클로커는 봇 표본이 스팸 회차를 영원히 못 밟는다.
        """
        def confirms(patch_bot):
            _RotatingHandler.ROTATION.clear()
            site = self._site("/cloak-intermittent12")
            memory = {}
            guard = (mock.patch.object(cloak_decision, "bot_sample_count",
                                       return_value=7)
                     if patch_bot else contextlib.nullcontext())
            with guard:
                return any(_is_hard_fail(security.check_cloaking(site, memory))
                           for _ in range(16))

        self.assertFalse(confirms(patch_bot=True), "봇 표본 고정인데 확정됐다 — 대조 실패")
        self.assertTrue(confirms(patch_bot=False), "봇 블록 무작위화가 확정을 못 만든다")

    def test_axis3_removed_locks_phase_and_accumulates_to_confirm(self):
        """축 3 제거 = 패스 길이 고정 → 위상 락 → 축 2의 누적이 그대로 차서 확정.

        17차 P=12 영구 오탐이 **축 2 위에서 그대로 재현되는** 자리다. 누적은
        표본이 패스마다 독립일 때만 뜻이 있다는 증거이고, 축 3이 왜 장식이
        아닌지의 근거다. (축 3을 되살린 같은 주기·같은 패스 수 = 위 스윕에서 0회)
        """
        self.assertGreater(self._hard_fails(passes=cloak_decision.CONFIRM_PASSES), 0)


class CloakDecisionTest(unittest.TestCase):
    """판정 순수 함수 — 서버·요청 없이 축 1·2의 계약만 고정한다"""

    def _eval(self, user_texts, bot_texts, memory, spam=("바카라",)):
        return cloak_decision.evaluate(list(spam), [], user_texts, bot_texts, memory)

    def test_stable_page_with_bot_majority_confirms_at_once(self):
        verdict = self._eval(["정상"] * 6, ["정상 바카라"] * 7, {})
        self.assertEqual(verdict["spam_confirmed"], ["바카라"])
        self.assertFalse(verdict["rotating"])

    def test_stable_page_without_bot_majority_waits(self):
        """봇 시점 과반 미달 = 요청마다 낮은 확률로 끼는 삽입과 구분 불가 (17차 P3-1)"""
        verdict = self._eval(["정상"] * 6, ["정상 바카라"] + ["정상"] * 6, {})
        self.assertEqual(verdict["spam_confirmed"], [])
        self.assertEqual(verdict["spam_suspect"], [("바카라", 1)])

    def test_rotating_page_needs_the_full_streak(self):
        """회전이 관측되면 즉시 확정 경로가 막히고 누적만 남는다"""
        memory = {}
        rotating_user = ["배너%d" % i for i in range(6)]
        for expected in range(1, cloak_decision.CONFIRM_PASSES):
            verdict = self._eval(rotating_user, ["배너9 바카라"] * 7, memory)
            self.assertTrue(verdict["rotating"])
            self.assertEqual(verdict["spam_suspect"], [("바카라", expected)])
        final = self._eval(rotating_user, ["배너9 바카라"] * 7, memory)
        self.assertEqual(final["spam_confirmed"], ["바카라"])

    def test_threshold_does_not_depend_on_this_pass_rotation(self):
        """19차 P2-1 — 임계를 그 패스의 회전 관측으로 정하면 누적은 공유되는데
        잣대만 흔들려, 아무것도 관측 안 된 패스의 **감쇠가 확정을 만들고**(5→4가
        낮아진 임계를 넘음) 후보를 다시 본 패스가 오히려 강등이 된다.
        임계를 하나로 통일해 그 클래스를 없앴다 — 회전이 오가도 잣대는 그대로다."""
        memory = {"spam": {"바카라": cloak_decision.CONFIRM_PASSES - 1}}
        rotating = self._eval(["배너1", "배너2"], ["배너9 바카라"] * 7, memory)
        self.assertEqual(rotating["spam_confirmed"], ["바카라"])
        stable = self._eval(["정상"] * 3, ["정상"] * 3, memory)  # 미관측 → 감쇠
        self.assertEqual(stable["spam_confirmed"], [])
        self.assertEqual(stable["spam_suspect"],
                         [("바카라", cloak_decision.CONFIRM_PASSES - 1)])

    def test_one_user_sighting_clears_the_streak(self):
        memory = {"spam": {"바카라": 3}}
        verdict = self._eval(["정상", "정상 바카라"], ["정상 바카라"], memory)
        self.assertEqual(verdict["spam_confirmed"], [])
        self.assertEqual(verdict["rejected_spam"], ["바카라"])
        self.assertEqual(memory["spam"], {})

    def test_marker_seen_by_any_bot_sample_is_rejected(self):
        """마커 판정은 봇 표본 **전부**에서 부재해야 성립한다 (17차 P2-2)"""
        verdict = cloak_decision.evaluate(
            [], ["장바구니"], ["데모샵 장바구니"] * 4,
            ["데모샵", "데모샵 장바구니"], {})
        self.assertEqual(verdict["marker_confirmed"], [])
        self.assertEqual(verdict["rejected_marker"], ["장바구니"])

    def test_corrupt_memory_is_sanitized_not_raised(self):
        """손상된 값 하나가 한 사이트를 영구 무감시로 만들지 않는다 (H-D와 같은 취지)"""
        memory = cloak_decision.load_memory(
            {"spam": {"바카라": "셋", "카지노": 2, 7: 1}, "marker": "이상함"})
        self.assertEqual(memory, {"spam": {"카지노": 2}, "marker": {}})

    def test_duplicate_candidate_does_not_double_count(self):
        """18차 P2-2 — 같은 문구가 후보 목록에 두 번 들어오면 한 패스에 누적이 2씩
        올라 확정 임계가 조용히 반토막 난다. 설정 파일에 내장 키워드를 다시 적기만
        해도 정상 통과하므로, 오탐 클래스가 설정 하나로 재개방되는 경로였다"""
        memory = {}
        cloak_decision.evaluate(["바카라", "바카라"], [], ["배너1", "배너2"],
                                ["배너9 바카라"], memory)
        self.assertEqual(memory["spam"], {"바카라": 1})
