"""감지 계층 L5 — 보안·무결성 (외부 관찰 전용).

잡는 것 = "해킹당했는데 주인만 모르는 상태":
- 클로킹: 같은 URL이 일반 방문자와 검색봇(+검색 유입 referer)에게 다른 내용을
  보여주는 상태. 해킹된 사이트에 도박 스팸을 심고 검색봇에만 노출하는 수법이
  국내에서 실증됐고, 피해자는 몇 달을 모른다 (근거·출처 = docs/03-보안축-리서치.md)
- 평판: Google Safe Browsing 등재 여부 — 구글이 고객사를 위험 사이트로 낙인
  찍는 순간을 알린다 (후행 지표)

경계 (무설치 외부 관찰의 구조적 한계 — 문서와 알림 문구에서 과장하지 않는다):
- 서버 내부 파일 변조·웹쉘·DB 악성코드·인젝션 시도는 감지 불가 (외부 관찰자는
  자기가 유발한 응답만 본다)
- 진짜 검색봇 IP를 역방향 DNS로 검증하는 정교한 클로커는 못 잡는다 —
  잡는 건 저가형·대량 살포형(UA/referer 분기)
"""
import json
import urllib.parse

import requests

from . import checks

BOT_UA = ("Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")
SEARCH_REFERER = "https://www.google.com/search?q=site"
GSB_ENDPOINT = "https://safebrowsing.googleapis.com/v4/threatMatches:find"
GSB_THREATS = ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE",
               "POTENTIALLY_HARMFUL_APPLICATION"]
GSB_TIMEOUT = 10
SPAM_MAX_SHOW = 3
# 히트 확인 표본 설계 (15차 P2-1) — 일반 시점을 **연속 M회** 떠서 결정적 회전의
# 모든 회차를 덮는다. 연속 M개의 요청 인덱스 {i..i+M-1} mod P는 P<=M이면 전체
# 잔여류를 포함하므로, 스팸이 어느 회차에 실려 있어도 일반 시점이 반드시 본다.
# (고정 위치 표본은 P=2N에서 위상이 고정돼 영구 오탐이 났다 — 표본 수를 늘리는
#  방향이 아니라 "연속 구간으로 전 회차 커버"로 바꾼 것이 핵심)
USER_SAMPLES = 8      # 회전 주기 <=8까지 구조적으로 커버
BOT_SAMPLES = 3       # 봇 시점 표본 — 간헐 클로킹 미탐 완화(1회 이상 노출로 후보 유지)

# 클로킹 심은 페이지에 실제로 박히는 유인 문구들 (도박·성인 스팸 계열).
# 대량 살포형 시그니처 — 사이트별 추가는 sites.json의 spam_keywords로.
SPAM_KEYWORDS = [
    "카지노", "바카라", "슬롯머신", "토토사이트", "먹튀검증", "안전놀이터",
    "홀덤", "사설토토", "무료스핀", "첫충", "롤링", "성인용품",
    "온라인카지노", "라이브카지노", "메이저놀이터",
]


def check_security(site):
    """반환: L5 결과 리스트 (클로킹·평판 각 0~1건). 앞 층처럼 dict 형식."""
    results = [check_cloaking(site)]
    reputation = check_reputation(site)
    if reputation is not None:
        results.append(reputation)
    return results


def check_cloaking(site):
    """일반 방문자 시점 vs 검색봇 시점 본문 비교.

    판정: 봇 시점에만 스팸 문구가 있으면 FAIL(클로킹 의심) / 봇 시점에서 이 사이트의
    마커가 사라지면 WARN(수상한 분기 — 봇 차단 WAF일 수도 있어 단정하지 않는다).
    스팸 문구가 양쪽에 다 있으면 클로킹이 아니라 사이트 자체 성격이므로 통과.

    스팸 히트는 **일반 시점을 연속 USER_SAMPLES회 떠서 그 키워드가 단 한 번도
    나오지 않을 때만** 확정한다 (15차 P2-1). 고정 위치로 양쪽을 번갈아 뜨는
    방식은 회전 주기가 총 요청 수와 맞물리면(P=6, 요청 6개) 위상이 매 패스
    고정돼 영구 오탐이 났다 — 표본 수를 늘려도 P=2N에서 같은 문제가 재발한다.
    연속 구간으로 전 회차를 덮는 쪽으로 구조를 바꿨다. 봇 조건은 반대로 완화해
    (1회 이상 노출) 간헐 클로킹 미탐을 줄인다 — 오탐(위상)과 미탐(간헐)을
    서로 다른 장치로 다룬다 (15차 P3-3).
    """
    timeout = site.get("timeout_sec", 10)
    keywords = _keywords(site)
    try:
        user_text, user_note = _fetch_view(site["url"], timeout)
        bot_text, bot_note = _fetch_view(site["url"], timeout, ua=BOT_UA,
                                         referer=SEARCH_REFERER)
    except requests.RequestException as exc:
        return _unknown_cloak("요청 실패: %s" % type(exc).__name__)
    # 부분 수신·비200은 "일치"로 통과시키면 거짓 음성이 된다 (13차 P3-2)
    if user_note or bot_note:
        return _unknown_cloak(user_note or bot_note)

    rotating = ""
    bot_only = [k for k in keywords if k in bot_text and k not in user_text]
    if bot_only:
        try:
            verdict = _confirm_bot_only(site, timeout, bot_only, bot_text)
        except requests.RequestException as exc:
            return _unknown_cloak("재확인 실패: %s" % type(exc).__name__)
        if verdict.get("note"):
            return _unknown_cloak(verdict["note"])
        if verdict["confirmed"]:
            shown = ", ".join(verdict["confirmed"][:SPAM_MAX_SHOW])
            more = (" 외 %d개" % (len(verdict["confirmed"]) - SPAM_MAX_SHOW)
                    if len(verdict["confirmed"]) > SPAM_MAX_SHOW else "")
            return {
                "layer": "L5 클로킹", "ok": False,
                "detail": "검색봇에게만 보이는 스팸 문구: %s%s (일반 시점 %d회 전부 부재·"
                          "검색봇 시점 %d/%d 노출) — 침해 의심, 소스·서버 점검 필요"
                          % (shown, more, verdict["user_seen"],
                             verdict["bot_hits"], verdict["bot_seen"]),
            }
        # 기각 사유는 보관만 하고 마커 비교로 계속 진행한다 — 여기서 조기 반환하면
        # 봇 시점의 마커 소실(WARN)이 은폐된다 (14차 P3-2를 주석만 달고 return을
        # 남겨둔 것이 15차 P3-1로 재적발됐다 — 코드로 실제 이행)
        rotating = "회전 콘텐츠로 판단(일반 시점 %d회 중 노출 확인: %s)" % (
            verdict["user_seen"], ", ".join(bot_only[:SPAM_MAX_SHOW]))

    markers = site.get("markers") or []
    missing = [m for m in markers if m in user_text and m not in bot_text]
    if missing:
        return {
            "layer": "L5 클로킹", "ok": False, "warn": True,
            "detail": "검색봇 시점에서 핵심 내용 사라짐: %s (봇 차단 설정일 수도 있음)"
                      % ", ".join(missing),
        }
    return {"layer": "L5 클로킹", "ok": True,
            "detail": rotating or "일반/검색봇 시점 일치"}


def check_reputation(site):
    """Google Safe Browsing 등재 조회. 키가 없으면 조용히 통과하지 않고 WARN.

    v4 사용 근거(실측 후 결정): v5의 hashes:search는 protobuf만 반환하고
    JSON 요청이 400으로 거부됨 — 프로토버프 의존/수동 파싱은 이 스코프에
    과함. v4 종료 예정일은 2027-03-31이며 이 함수 한 곳만 바꾸면 이관된다
    (docs/04-D2-빌드노트.md 슬라이스 ④).
    """
    api_key = _gsb_key()
    if not api_key:
        return _unknown_rep("GSB_API_KEY 미설정 (.env 참조)")
    payload = {
        "client": {"clientId": "deploy-watcher", "clientVersion": "0.2"},
        "threatInfo": {
            "threatTypes": GSB_THREATS,
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": site["url"]}],
        },
    }
    try:
        resp = requests.post(
            GSB_ENDPOINT, params={"key": api_key}, json=payload, timeout=GSB_TIMEOUT
        )
    except requests.RequestException as exc:
        return _unknown_rep("조회 실패: %s" % type(exc).__name__)
    if resp.status_code != 200:
        # 응답 본문에 키가 반사될 수 있어 상태코드만 노출한다
        return _unknown_rep("조회 실패: HTTP %d" % resp.status_code)
    try:
        matches = (resp.json() or {}).get("matches") or []
    except (json.JSONDecodeError, ValueError):
        return _unknown_rep("조회 응답 형식 이상")
    if matches:
        kinds = sorted({m.get("threatType", "UNKNOWN") for m in matches})
        return {"layer": "L5 평판", "ok": False,
                "detail": "Google 위험 사이트 등재: %s — 방문자에게 경고 화면이 뜨는 상태"
                          % ", ".join(kinds)}
    return {"layer": "L5 평판", "ok": True, "detail": "Google 등재 없음"}


def _confirm_bot_only(site, timeout, candidates, first_bot_text):
    """봇 전용 스팸 후보를 확정/기각한다 (15차 P2-1 재설계).

    확정 조건 = 일반 시점 연속 USER_SAMPLES회에 **한 번도** 없고, 봇 시점
    BOT_SAMPLES회 중 **1회 이상** 노출. 일반 시점 연속 구간이 회전 주기(<=8)의
    모든 회차를 덮으므로 요청 위상과 무관하게 판정된다.

    후보가 일반 시점에서 관측되는 순간 즉시 기각하고 남은 표본을 생략한다 —
    회전 사이트에 매 패스 최대 요청을 쏟지 않기 위한 조기 종료 (15차 P3-5).
    반환: {confirmed, user_seen, bot_seen, bot_hits, note}
    """
    remaining = list(candidates)
    bot_hits = {k: 1 for k in remaining}  # 1차 봇 관측 포함
    bot_seen, user_seen = 1, 0
    for index in range(USER_SAMPLES):
        user_text, note = _fetch_view(site["url"], timeout)
        if note:
            return {"confirmed": [], "user_seen": user_seen, "bot_seen": bot_seen,
                    "bot_hits": 0, "note": note}
        user_seen += 1
        remaining = [k for k in remaining if k not in user_text]
        if not remaining:  # 일반 시점에도 있다 = 클로킹 아님 (조기 종료)
            return {"confirmed": [], "user_seen": user_seen, "bot_seen": bot_seen,
                    "bot_hits": 0, "note": ""}
        # 봇 표본을 일반 표본 사이에 흩어 뜬다 (한 시점만 보고 판단하지 않기 위해)
        if bot_seen < BOT_SAMPLES and index % 3 == 2:
            bot_text, note = _fetch_view(site["url"], timeout, ua=BOT_UA,
                                         referer=SEARCH_REFERER)
            if note:
                return {"confirmed": [], "user_seen": user_seen, "bot_seen": bot_seen,
                        "bot_hits": 0, "note": note}
            bot_seen += 1
            for key in remaining:
                if key in bot_text:
                    bot_hits[key] += 1
    confirmed = [k for k in remaining if bot_hits[k] >= 1]
    return {"confirmed": confirmed, "user_seen": user_seen, "bot_seen": bot_seen,
            "bot_hits": max([bot_hits[k] for k in confirmed], default=0), "note": ""}


def _fetch_view(url, timeout, ua=checks.UA, referer=None):
    """반환: (본문 텍스트, 비교 불가 사유). 사유가 있으면 텍스트를 믿지 않는다."""
    status, body, headers, truncated = checks._bounded_get(
        url, timeout, ua=ua, referer=referer
    )
    who = "검색봇" if ua == BOT_UA else "일반"
    if status != 200:
        return "", "%s 시점 응답 HTTP %d" % (who, status)
    if truncated:
        return "", "%s 시점 본문 부분 수신(크기 상한)" % who
    return checks._decode(body, headers), ""


def _unknown_cloak(reason):
    return {"layer": "L5 클로킹", "ok": False, "warn": True, "unknown": True,
            "detail": "비교 불가 — %s" % reason}


def _unknown_rep(reason):
    """검증 불가 — 사이트가 위험한 게 아니라 우리가 확인을 못 한 것 (13차 P2-3)"""
    return {"layer": "L5 평판", "ok": False, "warn": True, "unknown": True,
            "detail": "검증 불가 — %s" % reason}


def _keywords(site):
    extra = [k for k in (site.get("spam_keywords") or []) if isinstance(k, str) and k.strip()]
    return SPAM_KEYWORDS + extra


def _gsb_key():
    import os

    return os.environ.get("GSB_API_KEY", "").strip()


def bot_view_url(url):
    """녹화·수동 확인용 — 검색봇 시점을 사람이 재현할 수 있게 명령을 알려준다"""
    return "curl -A '%s' -e '%s' %s" % (BOT_UA, SEARCH_REFERER, urllib.parse.quote(url, safe=":/"))
