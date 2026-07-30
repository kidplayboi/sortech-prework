"""감지 계층 L1~L3.

L1 생존   — 응답이 오는가 (상태코드·응답시간)
L2 내용   — 페이지 안에 있어야 할 내용이 실제로 있는가 (200 거짓양성 차단)
L3 배포반영 — 원본(캐시 우회)과 사용자 화면(캐시 경유)의 버전이 같은가

앞 층이 FAIL이면 뒤 층은 실행하지 않는다 (이미 확정된 장애의 알림을 지연시키지 않기 위해).
모든 요청은 총 시한·크기 상한이 있다 — 찔끔찔끔 응답하는 서버 하나가
순차 루프 전체를 점유하는 것을 막는다 (Codex 게이트 P2-7).
"""
import socket
import threading
import time
import urllib.parse

import requests
import urllib3.response
from urllib3 import exceptions as u3exc

if not hasattr(urllib3.response.HTTPResponse, "read1") or not hasattr(
    urllib3.response.HTTPResponse, "shutdown"
):
    # read1(수신 즉시 반환)이 없으면 트리클 자가 종료가, shutdown()이 없으면
    # Connection: close 변종의 워커 회수가 성립하지 않는다 — 조용히 열화하는 대신
    # 시작을 거부한다. ⚠️도입 시점이 다르다: read1=2.2.0·shutdown=2.3.0 —
    # read1만 검사하면 2.2.x가 절반 가드를 통과해 누수가 부활한다 (11차 P2-1:
    # 그 창에서 자체 회귀 테스트 3개 FAIL 실측)
    raise ImportError(
        "urllib3 2.3+ 필요 (HTTPResponse.read1·shutdown) — requirements.txt 재설치 필요"
    )

UA = "deploy-watcher/0.1 (+https://github.com/kidplayboi/sortech-prework)"
MAX_BODY_BYTES = 2_000_000
VERSION_MAX_LEN = 64
READ1_CHUNK = 65536  # size cap 오버슈트 상한 = 이 값 — 본문이 상한+64KB까지 커질 수 있다 (9차 P3-3)


def check_site(site, do_render=True):
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

    if do_render and site.get("render") is True:
        # 하드 FAIL(비-warn)이 이미 있으면 무거운 L4를 돌려 확정 장애 알림을
        # 지연시키지 않는다 (앞 층 FAIL=뒤 층 생략 원칙의 연장). warn(L3 미반영
        # 등)은 렌더 확인이 오히려 유의미하므로 진행
        if not any(not r["ok"] and not r.get("warn") for r in results):
            from . import render  # 지연 임포트 — Playwright 없는 설치에서도 L1~L3 동작

            results.append(render.check_render(site))

    return results


def _bounded_get(url, timeout_sec):
    """총 시한·크기 상한이 있는 GET. 반환: (status_code, body_bytes, headers, truncated)

    - 총 시한: 데몬 워커 스레드 + join(timeout)으로 강제한다. 시한 초과 시 호출자는
      requests.Timeout을 즉시 받는다. 워커 회수 2중 구조 — ① 읽기가 read1(수신 즉시
      반환)이라 데이터가 산출되는 한 매 반환마다 데드라인 자가 종료 ② 프레이밍/압축
      내부 읽기에 갇혀 ①이 안 도는 구간(chunk-size 줄 드리블 등)은 시한 초과 시
      위임 스레드가 소켓을 shutdown으로 깨서 회수한다 (9~10차 게이트 — close()만으로는
      readline이 쥔 버퍼 락에 막혀 무기한 블록됨이 계측됐다. keep-alive와
      Connection: close 두 변종 모두 raw.shutdown() 경유로 커버). 무응답 구간은
      read timeout이 끊는다. 남는 한계 = 응답 헤더 단계 정체(K-B)와 https 프록시
      경유(TLS-in-TLS — shutdown API 부재) — README '알려진 한계'.
    - truncated=True는 '크기 상한으로 잘린 부분 본문'을 뜻한다 — 이 신호 없이
      부분 본문을 정상 응답처럼 반환하면 멀쩡한 페이지가 오탐된다 (2차 N1 교정).
    """
    holder, result = {}, {}

    deadline = time.monotonic() + timeout_sec

    def _fetch():
        try:
            # read timeout은 총 시한보다 1초 크게 — 같은 본문 중지 장애가 총시한/
            # read timeout 승자에 따라 두 문구(Timeout vs ConnectionError)로 갈리는
            # 비결정 제거 (10차 P3-2). 무응답 워커 자가 종료는 1초 늦어질 뿐 유지
            resp = requests.get(
                url, timeout=(5, timeout_sec + 1), stream=True, headers={"User-Agent": UA}
            )
            holder["resp"] = resp  # 시한 초과 시 정리 위임 스레드가 close()할 수 있게 공유
            chunks, size, truncated = [], 0, False
            with resp:  # 예외 경로에서도 커넥션 반환 (N11)
                while True:
                    if time.monotonic() > deadline:
                        # identity 응답에선 read1이 수신마다 반환해 이 검사가 돌지만,
                        # 압축·chunked 프레이밍은 urllib3 내부 루프가 산출 0바이트
                        # 수신을 흡수해 간격이 늘어질 수 있다 — 그 구간의 회수는
                        # 시한 초과 시 소켓 shutdown 위임이 담당한다 (9차 P1-1·P3-1)
                        raise requests.Timeout("총 시한 초과(워커 자가 종료)")
                    try:
                        chunk = resp.raw.read1(READ1_CHUNK, decode_content=True)
                    # raw 직접 읽기는 requests의 예외 번역(models.py iter_content)을
                    # 우회한다 — 같은 번역표를 미러해 계층 핸들러(RequestException
                    # 그물)가 사이트 장애를 "체크 자체 실패"로 오귀속하지 않게 한다
                    # (9차 P2-1: DecodeError/ProtocolError/ReadTimeoutError 누출 실측)
                    except u3exc.ProtocolError as exc:
                        raise requests.exceptions.ChunkedEncodingError(exc)
                    except u3exc.DecodeError as exc:
                        raise requests.exceptions.ContentDecodingError(exc)
                    except u3exc.ReadTimeoutError as exc:
                        raise requests.exceptions.ConnectionError(exc)
                    except u3exc.SSLError as exc:
                        raise requests.exceptions.SSLError(exc)
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
            # 정리 위임 (데몬 스레드 — 메인은 즉시 복귀, 5차 K-A). close()만으로는
            # 워커의 readline이 쥔 버퍼 락에 막혀 무기한 블록될 수 있음이 계측됐다
            # (9차 P1-1) — _force_close가 소켓 shutdown을 선행해 락 없이 recv를 깬다.
            threading.Thread(
                target=_force_close, args=(resp,), daemon=True, name="watcher-close"
            ).start()
        # 알려진 한계 (K-B): 응답 헤더 단계에서 정체하는 병적 서버는 requests.get()이
        # 반환하지 않아 holder가 비고, 닫을 핸들 자체가 없다. 워커는 데몬이라
        # 프로세스 종료는 막지 않지만, 서버가 계속 흘리는 한 회수는 사실상 안 될 수
        # 있다 — 상시 순찰에서 이런 서버를 만날 때마다 스레드·소켓이 누적된다.
        raise requests.Timeout("총 시한 %d초 초과" % timeout_sec)
    if "exc" in result:
        raise result["exc"]
    return result["value"]


def _force_close(resp):
    """시한 초과 정리 (위임 스레드 전용). raw.shutdown() 선행 → close 보장.

    close()는 워커의 readline이 쥔 BufferedReader 락을 기다리지만, shutdown은
    락 없이 블록된 recv를 즉시 깬다 (9차 P1-1). 진입점은 urllib3 2.x 공개 API
    HTTPResponse.shutdown() — Connection: close 응답은 소켓 소유권이 응답으로
    넘어가 _connection.sock이 None이 되므로 내부 속성 직접 접근은 keep-alive
    변종만 깨운다 (10차 P1-1 실측). urllib3는 정확히 그 이유로 소유권 이전 전에
    shutdown 참조를 저장해 둔다. shutdown 미탑재 버전(2.2.x 이하)은 임포트
    가드가 시작을 거부하므로(11차 P2-1) 아래 sock 폴백은 이중 방어일 뿐이며
    keep-alive 변종만 커버한다.
    예외는 전부 삼키고 close는 finally로 보장한다 (10차 P2-1 — TLS-in-TLS의
    SSLTransport는 shutdown API 자체가 없어 AttributeError/ValueError 경로 존재.
    그 환경의 프레이밍 드리블 회수는 잔존 한계 — README '알려진 한계').
    """
    raw = getattr(resp, "raw", None)
    try:
        raw.shutdown()
    except Exception:
        # _sock_shutdown 없음(SSLTransport의 ValueError)·이미 닫힘 등 —
        # keep-alive 한정 sock 직접 shutdown으로 폴백 (이중 방어)
        try:
            raw._connection.sock.shutdown(socket.SHUT_RDWR)
        except Exception:
            pass
    finally:
        try:
            resp.close()
        except Exception:
            pass


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
                "detail": "본문 부분 수신(%d바이트 ≥ 상한 %d) — 내용 검증 불가"
                % (len(body), MAX_BODY_BYTES),
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
