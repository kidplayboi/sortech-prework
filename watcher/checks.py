"""감지 계층 L1~L3.

L1 생존   — 응답이 오는가 (상태코드·응답시간)
L2 내용   — 페이지 안에 있어야 할 내용이 실제로 있는가 (200 거짓양성 차단)
L3 배포반영 — 원본(캐시 우회)과 사용자 화면(캐시 경유)의 버전이 같은가
"""
import time

import requests

UA = "deploy-watcher/0.1 (+https://github.com/kidplayboi/sortech-prework)"


def check_site(site):
    """한 사이트에 L1→L2→L3를 순서대로 실행. 앞 층이 죽으면 뒤 층은 스킵."""
    results = []

    l1, resp = _l1_alive(site)
    results.append(l1)
    if not l1["ok"]:
        return results

    results.append(_l2_content(site, resp))

    if site.get("version_url"):
        results.append(_l3_deploy(site))

    return results


def _l1_alive(site):
    started = time.time()
    try:
        resp = requests.get(
            site["url"], timeout=site.get("timeout_sec", 10), headers={"User-Agent": UA}
        )
        elapsed_ms = int((time.time() - started) * 1000)
        ok = resp.status_code == 200
        return (
            {"layer": "L1", "ok": ok, "detail": "HTTP %d · %dms" % (resp.status_code, elapsed_ms)},
            resp,
        )
    except requests.RequestException as exc:
        return ({"layer": "L1", "ok": False, "detail": "요청 실패: %s" % type(exc).__name__}, None)


def _l2_content(site, resp):
    markers = site.get("markers", [])
    missing = [m for m in markers if m not in resp.text]
    if missing:
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

    주의: CDN이 배포 시 캐시를 퍼지하는 호스팅(GitHub Pages 등)은 두 값이 금방
    일치한다. 그 경우에도 방문자 '브라우저' 캐시에는 max-age만큼 옛 버전이
    남으므로, 캐시 정책(max-age)을 함께 실측해 잔상 가능 시간을 보고한다.
    """
    origin, _ = _fetch_version(site, bust=True)
    user, policy = _fetch_version(site, bust=False)
    if origin is None or user is None:
        return {"layer": "L3", "ok": False, "detail": "버전 파일 조회 실패"}
    if origin != user:
        return {
            "layer": "L3",
            "ok": False,
            "warn": True,
            "detail": "원본은 v%s 갱신됨, 사용자 화면은 아직 v%s (CDN 캐시%s)"
            % (origin, user, policy),
        }
    return {"layer": "L3", "ok": True, "detail": "v%s=v%s" % (origin, user), "policy": policy}


def _fetch_version(site, bust):
    """반환: (버전 문자열, 캐시 정책 요약). 실패 시 (None, '')"""
    url = site["version_url"]
    if bust:
        url += ("&" if "?" in url else "?") + "nc=%d" % int(time.time() * 1000)
    try:
        resp = requests.get(url, timeout=site.get("timeout_sec", 10), headers={"User-Agent": UA})
        if resp.status_code != 200:
            return None, ""
        return resp.text.strip(), _cache_policy(resp)
    except requests.RequestException:
        return None, ""


def _cache_policy(resp):
    """Cache-Control max-age를 읽어 '브라우저 잔상 가능 시간'으로 요약."""
    cc = resp.headers.get("Cache-Control", "")
    for part in cc.split(","):
        part = part.strip()
        if part.startswith("max-age="):
            try:
                minutes = int(part.split("=", 1)[1]) // 60
            except ValueError:
                return ""
            if minutes > 0:
                return " · 브라우저 잔상 최대 %d분(max-age)" % minutes
    return ""
