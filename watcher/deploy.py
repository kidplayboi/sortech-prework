"""배포 집중 감시 모드 — `watcher deploy <site>` (D2 슬라이스 ②).

배포 직후가 가장 위험한 시간대라는 실사고 경험이 트리거 설계의 근거(스펙 §트리거).
평시 순찰(상태 전이 엔진·state.json)과 분리된 일회성 판정 세션 — 상태를 읽지도
쓰지도 않고, 시작·결과를 반드시 각 1회 통보한다 (무소식 없음 계약).

L3 기대 버전 앵커 (D1 게이트 기각-2에서 승계된 계약):
앵커 없이 "원본==사용자"만 보면, 배포가 서버에 아예 닿지 않아 둘 다 옛 버전인
상태를 "일치=정상"으로 오판한다. --expect-version이 있으면 원본·사용자 모두
그 값이어야 안정이다. --expect(기대 문구)는 서버를 만질 수 없는 빌더형
블랙박스(아임웹 등)용 — 실화면에 선언한 문구가 나타날 때까지 감시한다.
"""
import time

import requests

from . import checks, notify

VERDICT_OK, VERDICT_PENDING, VERDICT_FAIL = "ok", "pending", "fail"


def run_deploy_watch(key, site, expect=None, expect_version=None, interval=15,
                     stable_needed=3, max_wait=600, sleep=time.sleep):
    """반환: 종료코드 (0=안정, 1=실패/시간 초과). sleep 주입 = 테스트용."""
    name = site.get("name", key)
    started = time.monotonic()
    deadline = started + max_wait
    notify.send("🚀 [%s] 배포 검증 시작 — %s, %d초 간격 집중 감시"
                % (name, _goal_desc(site, expect, expect_version), interval))
    stable, fails, last_pending, last_detail = 0, 0, None, ""
    while True:
        verdict, detail, unknowns = _one_check(site, expect, expect_version)
        last_detail = detail
        print("[deploy] %s · %s" % (verdict, detail))
        if verdict == VERDICT_OK:
            stable += 1
            fails = 0
            if stable >= stable_needed:
                _notify_final(
                    "🟢 [%s] 배포 안정 — %s, %d회 연속 전 층 통과 (%d초 소요)%s"
                    % (name, detail, stable_needed, int(time.monotonic() - started),
                       _unknown_note(unknowns)), sleep)
                return 0
        elif verdict == VERDICT_PENDING:
            stable = 0
            fails = 0
            if detail != last_pending:  # 같은 사유를 15초마다 반복 통보하지 않는다
                if notify.send("🟠 [%s] 배포 미반영 — %s. 계속 감시" % (name, detail)):
                    last_pending = detail  # 전송 성공 시에만 소거 — 실패면 다시 시도 (H-C)
        else:
            stable = 0
            fails += 1
            if fails >= stable_needed:
                _notify_final("🔴 [%s] 배포 검증 실패 — %s · %d회 연속. 롤백 검토 필요"
                              % (name, detail, fails), sleep)
                return 1
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            _notify_final("🔴 [%s] 배포 검증 시간 초과(%d초) — 마지막 상태: %s"
                          % (name, max_wait, last_detail), sleep)
            return 1
        # 초과폭을 interval만큼 넘기지 않게 남은 시간으로 자른다 (13차 P3-1)
        sleep(min(interval, max(0, remaining)))


def _notify_final(text, sleep, attempts=3, retry_sec=5):
    """종말 통보(안정/실패/시간초과)는 전송 성공까지 재시도한다 — 모듈 계약이
    "결과를 반드시 1회 보고"이므로 한 번 실패로 무통보 종료하면 계약 위반이다
    (13차 P2-4). 끝까지 실패하면 콘솔에 명시하고 종료코드로 결과를 전한다."""
    for attempt in range(attempts):
        if notify.send(text):
            return True
        if attempt < attempts - 1:
            print("[deploy] 결과 통보 실패 — %d초 후 재시도 (%d/%d)"
                  % (retry_sec, attempt + 1, attempts))
            sleep(retry_sec)
    print("[deploy] ⚠️ 결과 통보를 %d회 모두 실패했습니다. 결과: %s" % (attempts, text))
    return False


def _unknown_note(unknowns):
    """안정 판정을 막지는 않되 무엇을 확인하지 못했는지는 반드시 부기한다"""
    if not unknowns:
        return ""
    return " · 미확인 항목: %s" % "; ".join(unknowns)


def _goal_desc(site, expect, expect_version):
    if expect_version:
        return "기대 버전 %s" % expect_version
    if expect:
        return "기대 문구 「%s」 출현" % expect
    if site.get("version_url"):
        return ("원본=사용자 버전 일치 (⚠️앵커 없음 — 둘 다 옛 버전이어도 일치로 "
                "보임, --expect-version 권장)")
    return "전 층 정상 (버전 목표 미지정)"


def _one_check(site, expect, expect_version):
    """한 번의 집중 체크 → (verdict, detail, unknown_notes).

    L3(버전 목표)는 이 모듈이 앵커 의미론으로 직접 판정한다 — 층 검증은
    version_url을 뗀 사본으로 돌려 이중 조회를 막는다. L4는 배포 직후가
    최위험이라 매 체크 포함 (평시 --render-every 간헐과 다름 — 스펙 §트리거).

    **"검증 불가"(unknown)는 미반영과 다르다** — 도구 미설치·키 미설정은 사이트
    상태가 아니므로 안정 판정을 막지 않고 결과 문구에만 부기한다. 이걸 pending으로
    묶으면 건강한 배포가 10분 뒤 "시간 초과 실패"로 오보된다 (13차 P2-3).
    """
    probe = dict(site)
    probe.pop("version_url", None)
    results = checks.check_site(probe, do_render=site.get("render") is True)
    unknowns = ["%s %s" % (r["layer"], r["detail"]) for r in results if r.get("unknown")]
    hard = [r for r in results if not r["ok"] and not r.get("warn")]
    if hard:
        return VERDICT_FAIL, "%s %s" % (hard[0]["layer"], hard[0]["detail"]), unknowns
    warns = [r for r in results
             if not r["ok"] and r.get("warn") and not r.get("unknown")]
    if warns:
        # 안정 판정은 깨끗한 통과만 센다 — warn은 실패도, 안정도 아니다
        return VERDICT_PENDING, "%s %s" % (warns[0]["layer"], warns[0]["detail"]), unknowns

    if expect_version:
        verdict, detail = _version_goal(site, expect_version)
    elif expect:
        verdict, detail = _expect_goal(site, expect)
    elif site.get("version_url"):
        verdict, detail = _match_goal(site)
    else:
        verdict, detail = VERDICT_OK, " · ".join("%s ✓" % r["layer"] for r in results)
    return verdict, detail, unknowns


def _version_goal(site, anchor):
    origin, user, policy, err = _both_versions(site)
    if err:
        return VERDICT_FAIL, err
    if origin != anchor:
        # 앵커 계약의 핵심 — 원본부터 옛 버전이면 배포가 서버에 닿지 않은 것
        return VERDICT_PENDING, ("원본이 아직 %s (기대 %s) — 배포가 서버에 반영되지 않음"
                                 % (origin, anchor))
    if user != anchor:
        return VERDICT_PENDING, "원본은 %s 갱신됨, 사용자 화면은 아직 %s%s" % (anchor, user, policy)
    return VERDICT_OK, "원본·사용자 모두 %s" % anchor


def _match_goal(site):
    origin, user, policy, err = _both_versions(site)
    if err:
        return VERDICT_FAIL, err
    if origin != user:
        return VERDICT_PENDING, "원본 %s / 사용자 화면 %s%s" % (origin, user, policy)
    return VERDICT_OK, "원본=사용자 %s" % user


def _both_versions(site):
    origin, origin_err, _ = checks._fetch_version(site, bust=True)
    user, user_err, policy = checks._fetch_version(site, bust=False)
    if origin is None or user is None:
        return None, None, "", "L3 버전 파일 조회 실패 (%s)" % (origin_err or user_err)
    return origin, user, policy, ""


def _expect_goal(site, phrase):
    """기대 문구를 사용자 시점 원문에서, 없고 render:true면 렌더된 화면에서 찾는다.
    (L1/L2가 방금 같은 URL을 읽었지만 본문을 반환하지 않는다 — 15초 간격의
    작은 페이지 재조회라 이중 조회 비용을 수용, 구조 단순함을 우선)"""
    try:
        status, body, headers, truncated = checks._bounded_get(
            site["url"], site.get("timeout_sec", 10)
        )
    except requests.RequestException as exc:
        return VERDICT_FAIL, "기대 문구 확인 실패: %s" % type(exc).__name__
    if status != 200:
        return VERDICT_FAIL, "기대 문구 확인 실패: HTTP %d" % status
    if phrase in checks._decode(body, headers):
        return VERDICT_OK, "기대 문구 「%s」 확인" % phrase
    if site.get("render") is True:
        from . import render  # 지연 임포트 — Playwright 없는 설치 보호

        rendered = render.fetch_rendered_text(site)
        if rendered is not None and phrase in rendered:
            return VERDICT_OK, "기대 문구 「%s」 확인 (렌더 후)" % phrase
    if truncated:
        return VERDICT_PENDING, "본문 부분 수신(크기 상한) — 기대 문구 확인 불가"
    return VERDICT_PENDING, "기대 문구 「%s」 아직 미출현" % phrase
