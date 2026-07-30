"""감지 계층 L1~L3.

L1 생존   — 응답이 오는가 (상태코드·응답시간)
L2 내용   — 페이지 안에 있어야 할 내용이 실제로 있는가 (200 거짓양성 차단)
L3 배포반영 — 원본(캐시 우회)과 사용자 화면(캐시 경유)의 버전이 같은가

앞 층이 FAIL이면 뒤 층은 실행하지 않는다 (이미 확정된 장애의 알림을 지연시키지 않기 위해).
모든 요청은 총 시한·크기 상한이 있다 — 찔끔찔끔 응답하는 서버 하나가
순차 루프 전체를 점유하는 것을 막는다 (Codex 게이트 P2-7).
"""
import threading
import time
import urllib.parse

import requests
import urllib3.response

if not hasattr(urllib3.response.HTTPResponse, "read1"):  # urllib3 < 2.0
    # read1(수신 즉시 반환 읽기)이 없으면 트리클 워커 자가 종료(9차 N-A 수리)가
    # 성립하지 않는다 — 조용히 열화하는 대신 시작을 거부한다 (설정 오류로 취급)
    raise ImportError(
        "urllib3 2.x 필요 (HTTPResponse.read1) — requirements.txt 재설치 필요"
    )

UA = "deploy-watcher/0.1 (+https://github.com/kidplayboi/sortech-prework)"
MAX_BODY_BYTES = 2_000_000
VERSION_MAX_LEN = 64
READ1_CHUNK = 65536


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

    - 총 시한: 데몬 워커 스레드 + join(timeout)으로 강제한다. 시한 초과 시 호출자는
      requests.Timeout을 즉시 받는다. 워커 회수: 읽기가 read1(한 번의 수신이 도착하는
      즉시 반환)이라 데이터가 흐르는 한 매 수신마다 데드라인을 확인하고 자가 종료한다
      — 바이트 단위 트리클도 시한 직후 회수된다 (9차 게이트 N-A 수리, 7·8차의
      "회수 안 될 수 있음" 한계를 대체). 무응답 구간은 read timeout이 끊는다.
      남는 한계는 응답 헤더 단계에서 정체하는 서버(K-B)뿐 — README '알려진 한계'.
    - truncated=True는 '크기 상한으로 잘린 부분 본문'을 뜻한다 — 이 신호 없이
      부분 본문을 정상 응답처럼 반환하면 멀쩡한 페이지가 오탐된다 (2차 N1 교정).
    """
    holder, result = {}, {}

    deadline = time.monotonic() + timeout_sec

    def _fetch():
        try:
            resp = requests.get(
                url, timeout=(5, timeout_sec), stream=True, headers={"User-Agent": UA}
            )
            holder["resp"] = resp  # 시한 초과 시 정리 위임 스레드가 close()할 수 있게 공유
            chunks, size, truncated = [], 0, False
            with resp:  # 예외 경로에서도 커넥션 반환 (N11)
                while True:
                    if time.monotonic() > deadline:
                        # read1은 수신이 올 때마다 반환하므로 이 검사가 매 수신마다
                        # 실행된다 — iter_content(1024)는 1024바이트가 모일 때까지
                        # 블록해 바이트 트리클에서 워커가 수십 초 생존했다 (N-A 수리)
                        raise requests.Timeout("총 시한 초과(워커 자가 종료)")
                    chunk = resp.raw.read1(READ1_CHUNK, decode_content=True)
                    if not chunk:  # b"" = EOF (read1은 압축 해제 결과가 비면 내부 재시도)
                        break
                    chunks.append(chunk)
                    size += len(chunk)
                    if size > MAX_BODY_BYTES:
                        truncated = True
                        break
            result["value"] = (resp.status_code, b"".join(chunks), resp.headers, truncated)
        except Exception as exc:
            result["exc"] = exc

    # ThreadPoolExecutor 금지 — 비데몬 워커가 atexit join으로 프로세스 종료를
    # 응답이 끝날 때까지 막고(99.7초 실측), 시한 초과마다 스레드·소켓이 누적된다
    # (4차 게이트 H-A). 데몬 스레드 + 시한 초과 시 best-effort 회수한다.
    worker = threading.Thread(target=_fetch, daemon=True, name="watcher-fetch")
    worker.start()
    worker.join(timeout_sec)
    if worker.is_alive():
        resp = holder.get("resp")
        if resp is not None:
            # close()는 워커의 in-flight read가 끝나기를 기다리며 수 초 블록할 수
            # 있음이 계측됐다 (5차 게이트 K-A — 메인에서 동기 호출하면 시한이 다시
            # 깨진다). 데몬 스레드에 위임해 메인은 즉시 복귀한다. 워커 자체는
            # 수신 중이면 read1 데드라인, 무응답이면 read timeout으로 자가 종료한다.
            threading.Thread(target=resp.close, daemon=True, name="watcher-close").start()
        # 알려진 한계 (K-B): 응답 헤더 단계에서 정체하는 병적 서버는 requests.get()이
        # 반환하지 않아 holder가 비고, 닫을 핸들 자체가 없다. 워커는 데몬이라
        # 프로세스 종료는 막지 않지만, 헤더가 계속 찔끔 오는 한 회수는 늦어질 수 있다.
        raise requests.Timeout("총 시한 %d초 초과" % timeout_sec)
    if "exc" in result:
        raise result["exc"]
    return result["value"]


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
        partial = " (부분 수신)" if truncated else ""  # 잘림을 L1에서도 표기 (G7)
        return (
            {"layer": "L1", "ok": ok,
             "detail": "HTTP %d · %dms%s" % (status, elapsed_ms, partial)},
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
            # 부분 수신 본문에서 마커 부재를 "내용 없음"으로 단정하지 않는다 (N1).
            # 분류는 WARN — '크기 상한으로 잘렸을 뿐'인 사이트에 🔴을 주면 빨간
            # 알림의 신뢰가 무너진다. 시한 초과는 여기 오지 않고 L1 요청 실패(FAIL)로
            # 처리된다 — 느려서 시한을 넘기는 건 장애로 본다 (G6·H-E 경계 명시)
            return {
                "layer": "L2",
                "ok": False,
                "warn": True,
                "detail": "본문 부분 수신(%d바이트, 크기 상한 초과) — 내용 검증 불가"
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
            return None, "부분 수신(크기 상한 초과)", ""
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
