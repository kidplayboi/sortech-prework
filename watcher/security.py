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
    """
    timeout = site.get("timeout_sec", 10)
    keywords = _keywords(site)
    try:
        user_text = _fetch_text(site["url"], timeout)
        bot_text = _fetch_text(site["url"], timeout, ua=BOT_UA, referer=SEARCH_REFERER)
    except requests.RequestException as exc:
        return {"layer": "L5 클로킹", "ok": False, "warn": True,
                "detail": "비교 불가 — 요청 실패: %s" % type(exc).__name__}

    bot_only = [k for k in keywords if k in bot_text and k not in user_text]
    if bot_only:
        shown = ", ".join(bot_only[:SPAM_MAX_SHOW])
        more = " 외 %d개" % (len(bot_only) - SPAM_MAX_SHOW) if len(bot_only) > SPAM_MAX_SHOW else ""
        return {
            "layer": "L5 클로킹", "ok": False,
            "detail": "검색봇에게만 보이는 스팸 문구: %s%s — 침해 의심, 소스·서버 점검 필요"
                      % (shown, more),
        }
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
        return {"layer": "L5 평판", "ok": False, "warn": True,
                "detail": "검증 불가 — GSB_API_KEY 미설정 (.env 참조)"}
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
        return {"layer": "L5 평판", "ok": False, "warn": True,
                "detail": "조회 실패: %s" % type(exc).__name__}
    if resp.status_code != 200:
        # 응답 본문에 키가 반사될 수 있어 상태코드만 노출한다
        return {"layer": "L5 평판", "ok": False, "warn": True,
                "detail": "조회 실패: HTTP %d" % resp.status_code}
    try:
        matches = (resp.json() or {}).get("matches") or []
    except (json.JSONDecodeError, ValueError):
        return {"layer": "L5 평판", "ok": False, "warn": True,
                "detail": "조회 응답 형식 이상"}
    if matches:
        kinds = sorted({m.get("threatType", "UNKNOWN") for m in matches})
        return {"layer": "L5 평판", "ok": False,
                "detail": "Google 위험 사이트 등재: %s — 방문자에게 경고 화면이 뜨는 상태"
                          % ", ".join(kinds)}
    return {"layer": "L5 평판", "ok": True, "detail": "Google 등재 없음"}


def _fetch_text(url, timeout, ua=checks.UA, referer=None):
    _status, body, headers, _truncated = checks._bounded_get(
        url, timeout, ua=ua, referer=referer
    )
    return checks._decode(body, headers)


def _keywords(site):
    extra = [k for k in (site.get("spam_keywords") or []) if isinstance(k, str) and k.strip()]
    return SPAM_KEYWORDS + extra


def _gsb_key():
    import os

    return os.environ.get("GSB_API_KEY", "").strip()


def bot_view_url(url):
    """녹화·수동 확인용 — 검색봇 시점을 사람이 재현할 수 있게 명령을 알려준다"""
    return "curl -A '%s' -e '%s' %s" % (BOT_UA, SEARCH_REFERER, urllib.parse.quote(url, safe=":/"))
