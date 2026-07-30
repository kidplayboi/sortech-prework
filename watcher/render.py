"""감지 계층 L4 — 헤드리스 브라우저 렌더링 검증.

HTML은 오는데 화면이 깨진 상태(JS 크래시·프론트/백 버전 불일치)를 잡는다.
정리 경로가 L1~L3(_bounded_get)과 다른 이유 = docs/04-D2-빌드노트.md 슬라이스 ①:
Playwright 작업은 자체 타임아웃으로 취소 가능하고 브라우저는 별도 OS 프로세스라,
트리클 사가(9~12차)를 만든 "취소 불가 블로킹 + 스레드 락" 클래스가 원천적으로
없다 — try/finally close로 충분하다. 브라우저는 체크마다 launch/close
(상주 브라우저 = 크래시 누적·좀비 위험, L4는 저빈도라 launch 비용 수용).
"""
import time

SETTLE_MS = 1000  # load 후 고정 대기 — 더 느리게 그리는 SPA는 한계로 문서화 (빌드노트)
INSTALL_HINT = "pip install playwright && python -m playwright install chromium"
DETAIL_MAX = 200


def check_render(site):
    """반환: L4 결과 dict {"layer","ok","detail"[,"warn"]}.

    Playwright 미설치는 조용한 통과가 아니라 WARN — noop이 실패를 성공처럼
    보고하는 클래스(계약메일 0통 사고의 뿌리)를 만들지 않는다.
    """
    try:
        from playwright.sync_api import Error as PwError
        from playwright.sync_api import sync_playwright
    except ImportError:
        return _unknown("Playwright 미설치 (%s)" % INSTALL_HINT)

    timeout_ms = site.get("timeout_sec", 10) * 1000
    page_errors, console_errors = [], []
    started = time.monotonic()
    try:
        with sync_playwright() as p:
            try:
                # 브라우저 기동 실패(chromium 미설치 등)는 체커 설치 문제다 —
                # 사이트 장애로 귀속하면 deploy 모드에서 롤백 오보까지 간다
                # (13차 P2-2: 패키지 부재는 WARN인데 브라우저 부재는 FAIL이던 불일치)
                browser = p.chromium.launch(headless=True, timeout=timeout_ms)
            except PwError as exc:
                return _unknown("브라우저 기동 실패: %s (%s)"
                                % (_first_line(str(exc)), INSTALL_HINT))
            try:
                page = browser.new_page()
                # goto 외 작업(inner_text 등)도 총 시한에 묶는다 — 기본 30초가
                # timeout_sec 계약을 벗어나던 문제 (13차 P3-5)
                page.set_default_timeout(timeout_ms)
                # str(Error)는 메시지만이라 예외 타입명이 빠진다 — stack 첫 줄이
                # "TypeError: cart is undefined" 형태 (스펙 알림 문구와 일치)
                page.on("pageerror", lambda e: page_errors.append(_err_repr(e)))
                page.on(
                    "console",
                    lambda m: console_errors.append(m.text) if m.type == "error" else None,
                )
                page.goto(site["url"], timeout=timeout_ms, wait_until="load")
                page.wait_for_timeout(SETTLE_MS)
                body_text = page.inner_text("body")
            finally:
                browser.close()
    except PwError as exc:
        return {"layer": "L4", "ok": False, "detail": "렌더 실패: %s" % _first_line(str(exc))}
    elapsed_ms = int((time.monotonic() - started) * 1000)

    if page_errors:
        return {
            "layer": "L4", "ok": False,
            "detail": "렌더링 에러: %s (JS 예외 %d건)"
            % (_first_line(page_errors[0]), len(page_errors)),
        }
    markers = site.get("markers") or []
    missing = [m for m in markers if m not in body_text]
    if missing:
        # L2(원본 HTML)와의 차별점 — JS가 그리는 SPA는 여기서만 잡힌다
        return {
            "layer": "L4", "ok": False,
            "detail": "렌더된 화면에 핵심 내용 없음: %s" % ", ".join(missing),
        }
    if console_errors:
        # 서드파티 스크립트·광고가 흔히 유발 — 🔴 대신 🟠 (오탐이 빨간 알림의
        # 신뢰를 깎는다는 N1 원칙과 동일 선상)
        return {
            "layer": "L4", "ok": False, "warn": True,
            "detail": "콘솔 error %d건 (첫: %s)"
            % (len(console_errors), _first_line(console_errors[0])),
        }
    return {
        "layer": "L4", "ok": True,
        "detail": "렌더 정상 · JS 예외 0 · 마커 %d/%d · %dms"
        % (len(markers), len(markers), elapsed_ms),
    }


def fetch_rendered_text(site):
    """렌더된 body 텍스트 (실패·미설치 시 None) — deploy 모드 기대 문구 확인용.
    None은 '확인 불가'지 '미출현'이 아니다 — 호출자가 pending으로 다루게 한다."""
    try:
        from playwright.sync_api import Error as PwError
        from playwright.sync_api import sync_playwright
    except ImportError:
        return None
    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            try:
                page = browser.new_page()
                page.goto(site["url"], timeout=site.get("timeout_sec", 10) * 1000,
                          wait_until="load")
                page.wait_for_timeout(SETTLE_MS)
                return page.inner_text("body")
            finally:
                browser.close()
    except PwError:
        return None


def _unknown(reason):
    """검증 불가 — 사이트 문제가 아니라 우리 쪽 도구 문제 (13차 P2-2·P2-3)"""
    return {"layer": "L4", "ok": False, "warn": True, "unknown": True,
            "detail": "검증 불가 — %s" % reason}


def _first_line(text):
    line = text.strip().splitlines()[0] if text.strip() else ""
    return line[:DETAIL_MAX]


def _err_repr(error):
    stack = getattr(error, "stack", None)
    if stack and stack.strip():
        return _first_line(stack)
    return _first_line(str(error))
