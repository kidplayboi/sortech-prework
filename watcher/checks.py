"""감지 계층 L1~L3.

L1 생존   — 응답이 오는가 (상태코드·응답시간)
L2 내용   — 페이지 안에 있어야 할 내용이 실제로 있는가 (200 거짓양성 차단)
L3 배포반영 — 원본(캐시 우회)과 사용자 화면(캐시 경유)의 버전이 같은가

앞 층이 FAIL이면 뒤 층은 실행하지 않는다 (이미 확정된 장애의 알림을 지연시키지 않기 위해).
모든 요청은 총 시한·크기 상한이 있다 — 찔끔찔끔 응답하는 서버 하나가
순차 루프 전체를 점유하는 것을 막는다 (Codex 게이트 P2-7).
"""
import time
import urllib.parse

import requests

UA = "deploy-watcher/0.1 (+https://github.com/kidplayboi/sortech-prework)"
MAX_BODY_BYTES = 2_000_000
VERSION_MAX_LEN = 64


def check_site(site):
    results = []

    l1, body, headers, truncated = _l1_alive(site)
    results.append(l1)
    if not l1["ok"]:
        return results

    l2 = _l2_content(site, body, headers, truncated)
    results.append(l2)
    if not l2["ok"]:
        return results

    if site.get("version_url"):
        results.append(_l3_deploy(site))

    return results


def _bounded_get(url, timeout_sec):
    """총 시한·크기 상한이 있는 GET. 반환: (status_code, body_bytes, headers, truncated)

    truncated=True는 본문이 '부분 수신'임을 뜻한다 — 이 신호 없이 부분 본문을
    정상 응답처럼 반환하면, 느린 사이트의 멀쩡한 페이지가 "내용 없음"으로
    오탐된다 (2차 게이트 N1 교정).
    """
    deadline = time.monotonic() + timeout_sec
    resp = requests.get(
        url, timeout=(5, timeout_sec), stream=True, headers={"User-Agent": UA}
    )
    chunks, size, truncated = [], 0, False
    with resp:  # 예외 경로에서도 커넥션 반환 (N11)
        for chunk in resp.iter_content(8192):
            chunks.append(chunk)
            size += len(chunk)
            if size > MAX_BODY_BYTES or time.monotonic() > deadline:
                truncated = True
                break
    return resp.status_code, b"".join(chunks), resp.headers, truncated


def _decode(body, headers):
    """응답 본문 디코딩. 헤더에 charset이 없으면 utf-8 → cp949 순으로 시도.

    (Codex 게이트 P1-1 교정: requests는 charset 없는 text/html을 ISO-8859-1로
    해석해 한글 마커가 영원히 매칭되지 않는다 — charset 없는 한글 사이트는 흔하다)
    """
    content_type = headers.get("Content-Type", "")
    if "charset=" in content_type.lower():
        charset = content_type.lower().split("charset=", 1)[1].split(";")[0].strip()
        try:
            return body.decode(charset, "replace")
        except LookupError:
            pass
    for encoding in ("utf-8", "cp949"):
        try:
            return body.decode(encoding)
        except UnicodeDecodeError:
            continue
    return body.decode("utf-8", "replace")


def _l1_alive(site):
    started = time.monotonic()
    try:
        status, body, headers, truncated = _bounded_get(
            site["url"], site.get("timeout_sec", 10)
        )
        elapsed_ms = int((time.monotonic() - started) * 1000)
        ok = status == 200
        return (
            {"layer": "L1", "ok": ok, "detail": "HTTP %d · %dms" % (status, elapsed_ms)},
            body,
            headers,
            truncated,
        )
    except requests.RequestException as exc:
        return (
            {"layer": "L1", "ok": False, "detail": "요청 실패: %s" % type(exc).__name__},
            b"",
            {},
            False,
        )


def _l2_content(site, body, headers, truncated=False):
    markers = site.get("markers", [])
    if not markers:
        # 마커 미설정을 조용한 통과로 두지 않는다 (P2-5) — 비활성임을 명시
        return {"layer": "L2", "ok": True, "detail": "비활성(마커 미설정)"}
    text = _decode(body, headers)
    missing = [m for m in markers if m not in text]
    if missing:
        if truncated:
            # 부분 수신 본문에서 마커 부재를 "내용 없음"으로 단정하지 않는다 (N1)
            return {
                "layer": "L2",
                "ok": False,
                "detail": "본문 부분 수신(%d바이트, 시한/크기 초과) — 내용 검증 불가"
                % len(body),
            }
        return {
            "layer": "L2",
            "ok": False,
            "detail": "응답은 200이지만 핵심 내용 없음: %s" % ", ".join(missing),
        }
    return {"layer": "L2", "ok": True, "detail": "마커 %d/%d" % (len(markers), len(markers))}


def _l3_deploy(site):
    """같은 버전 파일을 두 시점으로 실측한다.
    origin = 캐시 우회(?nc=타임스탬프) → 서버에 실제로 올라간 버전
    user   = 평범한 요청 → 사용자가 지금 보는 버전 (CDN 캐시 경유)

    알려진 한계: CDN이 쿼리스트링을 캐시 키에서 무시하도록 설정된 경우 ?nc= 우회가
    무효다 (GitHub Pages/Fastly는 쿼리를 캐시 키에 포함하므로 유효). README 참조.
    """
    origin, origin_err, _ = _fetch_version(site, bust=True)
    user, user_err, policy = _fetch_version(site, bust=False)
    if origin is None or user is None:
        return {
            "layer": "L3",
            "ok": False,
            "detail": "버전 파일 조회 실패 (%s)" % (origin_err or user_err),
        }
    if origin != user:
        return {
            "layer": "L3",
            "ok": False,
            "warn": True,
            "detail": "두 시점 버전 불일치 — 원본 %s / 사용자 화면 %s%s" % (origin, user, policy),
        }
    return {"layer": "L3", "ok": True, "detail": "%s=%s" % (origin, user)}


def _fetch_version(site, bust):
    """반환: (버전, 실패사유, 캐시정책). 실패 시 버전=None"""
    url = _bust_url(site["version_url"]) if bust else site["version_url"]
    try:
        status, body, headers, truncated = _bounded_get(url, site.get("timeout_sec", 10))
        if status != 200:
            return None, "HTTP %d" % status, ""
        if truncated:
            return None, "부분 수신(시한/크기 초과)", ""
        version = _decode(body, headers).strip().splitlines()[0].strip() if body.strip() else ""
        if not version or len(version) > VERSION_MAX_LEN:
            return None, "버전 파일 형식 이상(비었거나 %d자 초과)" % VERSION_MAX_LEN, ""
        return version, "", _cache_policy(headers)
    except requests.RequestException as exc:
        return None, type(exc).__name__, ""


def _bust_url(url):
    """fragment(#...)가 있어도 쿼리가 서버에 전달되도록 urlsplit으로 조립 (P3-4)"""
    parts = urllib.parse.urlsplit(url)
    query = parts.query + ("&" if parts.query else "") + "nc=%d" % int(time.time() * 1000)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, query, ""))


def _cache_policy(headers):
    """Cache-Control을 읽어 '브라우저 잔상 가능 시간'으로 요약 (버전 파일 응답 기준).

    no-cache/no-store는 브라우저가 재검증하므로 잔상 없음으로 취급 (P3-2).
    """
    cc = headers.get("Cache-Control", "").lower()
    directives = [part.strip() for part in cc.split(",")]
    if "no-cache" in directives or "no-store" in directives:
        return ""
    for part in directives:
        if part.startswith("max-age="):
            try:
                seconds = int(part.split("=", 1)[1])
            except ValueError:
                return ""
            if seconds <= 0:
                return ""
            if seconds < 60:
                return " · 브라우저 잔상 최대 %d초(max-age)" % seconds
            if seconds < 3600:
                return " · 브라우저 잔상 최대 %d분(max-age)" % (seconds // 60)
            return " · 브라우저 잔상 최대 %d시간(max-age)" % (seconds // 3600)
    return ""
