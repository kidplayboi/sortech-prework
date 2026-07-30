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
CONFIRM_SAMPLES = 3  # 스팸 히트 확정에 필요한 양쪽 표본 수 (14차 P2-1 — 회전 주기 2·3 커버)

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

    스팸 히트는 **양쪽을 여러 번, 순서를 뒤집어 표본해서** 모든 봇 표본에 있고
    모든 일반 표본에 없을 때만 확정한다 (14차 P2-1). 1회 재표본을 같은 순서
    (일반→봇)로 뜨면 콘텐츠 회전 주기가 요청 순서와 맞물려 위상이 유지되고,
    순차 회전 서버에서 오탐이 8/8 그대로 재현됐다 — "2회 연속 재현" 문구가
    오탐에 신뢰만 덧입혔다. 순서 반전 + 다표본으로 시점 상관을 끊는다.
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

    bot_only = [k for k in keywords if k in bot_text and k not in user_text]
    if bot_only:
        try:
            user_views, bot_views, note = _resample(site, timeout,
                                                    [user_text], [bot_text])
        except requests.RequestException as exc:
            return _unknown_cloak("재확인 실패: %s" % type(exc).__name__)
        if note:
            return _unknown_cloak(note)
        confirmed = [k for k in bot_only
                     if all(k in b for b in bot_views)
                     and not any(k in u for u in user_views)]
        if not confirmed:
            return {"layer": "L5 클로킹", "ok": True,
                    "detail": "1회 차이 관측(%s)이 %d회 교차 표본에서 재현되지 않음 — "
                              "회전 콘텐츠로 판단"
                              % (", ".join(bot_only[:SPAM_MAX_SHOW]), len(bot_views))}
        shown = ", ".join(confirmed[:SPAM_MAX_SHOW])
        more = (" 외 %d개" % (len(confirmed) - SPAM_MAX_SHOW)
                if len(confirmed) > SPAM_MAX_SHOW else "")
        return {
            "layer": "L5 클로킹", "ok": False,
            "detail": "검색봇에게만 보이는 스팸 문구: %s%s (%d회 교차 표본 전부 재현) — "
                      "침해 의심, 소스·서버 점검 필요" % (shown, more, len(bot_views)),
        }
    # 스팸이 미확정이어도 마커 비교는 계속한다 — 조기 반환하면 봇 시점의 마커
    # 소실(WARN)이 은폐된다 (14차 P3-2)
    markers = site.get("markers") or []
    missing = [m for m in markers if m in user_text and m not in bot_text]
    if missing:
        return {
            "layer": "L5 클로킹", "ok": False, "warn": True,
            "detail": "검색봇 시점에서 핵심 내용 사라짐: %s (봇 차단 설정일 수도 있음)"
                      % ", ".join(missing),
        }
    return {"layer": "L5 클로킹", "ok": True, "detail": "일반/검색봇 시점 일치"}


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


def _resample(site, timeout, user_views, bot_views):
    """히트 확인용 추가 표본 — **봇 먼저** 순서로 떠서 1차(일반→봇)와 위상을 어긋내고,
    양쪽 표본 수를 CONFIRM_SAMPLES까지 늘린다 (14차 P2-1).

    반환: (일반 표본들, 봇 표본들, 비교 불가 사유). 히트가 났을 때만 호출되므로
    정상 사이트에는 추가 요청이 발생하지 않는다.
    """
    while len(bot_views) < CONFIRM_SAMPLES:
        bot_text, note = _fetch_view(site["url"], timeout, ua=BOT_UA,
                                     referer=SEARCH_REFERER)
        if note:
            return user_views, bot_views, note
        bot_views.append(bot_text)
        user_text, note = _fetch_view(site["url"], timeout)
        if note:
            return user_views, bot_views, note
        user_views.append(user_text)
    return user_views, bot_views, ""


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
