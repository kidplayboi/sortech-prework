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

from . import checks, cloak_decision

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


def check_security(site, memory=None):
    """반환: L5 결과 리스트 (클로킹·평판 각 0~1건). 앞 층처럼 dict 형식.

    memory = 이 사이트의 클로킹 누적 기억(dict). 제자리 갱신되므로 호출자가
    state.json에 보존한다. None이면 이 패스 한정 임시 기억으로 동작한다 —
    누적이 없으니 회전 페이지는 확정되지 않고 WARN까지만 간다(읽기 전용 축소).
    """
    results = [check_cloaking(site, memory)]
    reputation = check_reputation(site)
    if reputation is not None:
        results.append(reputation)
    return results


def check_cloaking(site, memory=None):
    """일반 방문자 시점 vs 검색봇 시점 본문 비교. **판정은 cloak_decision**이 한다.

    이 함수의 책임은 요청 배치와 결과 문구뿐이다. 판정 축 3개(회전 감지·패스 간
    누적·위상 무작위화)와 그 근거는 `watcher/cloak_decision.py` 모듈 docstring에
    있다 — 13~17차에 같은 오탐이 다섯 번 반복된 뒤 축을 바꾼 재설계다.

    요청 비용(실측): 아무 후보도 없는 평시 사이트는 **2회**(일반·봇 각 1)로 끝난다.
    확장은 이번 표본이 후보를 물었거나 **추적 중인 후보가 있을 때** 일어나고, 그
    패스는 최대 29회(일반 5~16 + 봇 5~12)까지 쓴다. 확정된 클로킹 사이트는 해소될
    때까지 매 패스 확장이 지속된다 — 남의 사이트에 주는 부담이라 후보가 반증되는
    즉시 조기 종료한다. (19차 P3-2: 수리 전 docstring이 "후보가 잡힌 패스만"이라고
    적혀 있었는데 추적 경로가 생긴 뒤로는 사실이 아니었다)
    """
    timeout = site.get("timeout_sec", 10)
    store = memory if isinstance(memory, dict) else {}
    working = cloak_decision.load_memory(store)
    keywords, markers = _keywords(site), _markers(site)
    try:
        user_first, user_note = _fetch_view(site["url"], timeout)
        bot_first, bot_note = _fetch_view(site["url"], timeout, ua=BOT_UA,
                                          referer=SEARCH_REFERER)
    except requests.RequestException as exc:
        return _unknown_cloak("요청 실패: %s" % type(exc).__name__)
    # 부분 수신·비200은 "일치"로 통과시키면 거짓 음성이 된다 (13차 P3-2).
    # 이 경로는 누적 기억을 건드리지 않는다 — 못 본 것을 반증으로 치지 않는다
    if user_note or bot_note:
        return _unknown_cloak(user_note or bot_note)

    user_texts, bot_texts = [user_first], [bot_first]
    # 확장 조건 = 이번 1차 표본이 후보를 물었거나, **이미 추적 중인 후보가 있거나**.
    # 후자가 18차 P1-1 수리다: 후보를 봇 1차 표본에서만 뽑으면 봇에게 1/2 미만으로
    # 노출하는 클로커는 그 표본이 비는 패스마다 누적이 깎여 확정 조건이 사실상
    # "봇 1차 히트율 > 1/2"가 된다. 실측(수리 전): 1/3 노출 클로커가 하드 FAIL 0회에
    # 거짓 초록 9/14. 추적 중이면 봇 블록 전체로 다시 확인해 그 편향을 없앤다
    tracked_spam, tracked_marker = cloak_decision.tracked(working)
    pre_spam = [k for k in keywords if k in bot_first and k not in user_first]
    pre_lost = [m for m in markers if m in user_first and m not in bot_first]
    if pre_spam or pre_lost or tracked_spam or tracked_marker:
        try:
            note = _gather(site, timeout,
                           _union(pre_spam, tracked_spam),
                           _union(pre_lost, tracked_marker), user_texts, bot_texts)
        except requests.RequestException as exc:
            return _unknown_cloak("재확인 실패: %s" % type(exc).__name__)
        if note:
            return _unknown_cloak(note)

    spam, lost = _candidates(keywords, markers, user_texts, bot_texts, working)
    verdict = cloak_decision.evaluate(spam, lost, user_texts, bot_texts, working)
    store.clear()
    store.update(working)
    return _cloak_result(verdict)


def _candidates(keywords, markers, user_texts, bot_texts, working):
    """판정에 올릴 후보 — **봇 표본 전체**를 본다(1차 표본만 보면 18차 P1-1).

    ⚠️여기서 "일반 시점에 보이니까 후보에서 빼자"고 거르면 안 된다 (19차 P2-3).
    거르면 그 문구는 `rejected`에도 못 들어가고, 그러면 evaluate의 **반증=즉시 소거**
    경로가 영영 안 돌아 누적이 감쇠로만 빠진다. 그 사이 알림에는 "일반 시점 N회
    부재"라는, 관측과 정반대인 근거 문장이 실려 나간다(실측 🔴 4패스 + 🟠 3패스).
    후보로 올리고 evaluate가 반증 처리하게 둔다 — 판정과 비용 결정은 별개다.
    (확장 표본을 쓸지 말지는 이미 위에서 `pre_spam`/`tracked`로 걸렀다)

    추적 중인 키도 후보에 넣는다 — 이번 표본에 안 보여도 감쇠 대상으로 살려야
    "미관측"과 "반증"이 구분된다.
    """
    tracked_spam, tracked_marker = cloak_decision.tracked(working)
    return (
        [k for k in keywords
         if any(k in text for text in bot_texts) or k in tracked_spam],
        # 마커는 "일반 시점 어딘가에 있는데 봇 시점 어딘가에서는 빠진" 것만 후보다.
        # 양쪽에 온전히 있는 평범한 마커까지 올리면 정상 사이트의 통과 문구에
        # 마커 이름이 줄줄이 붙는다
        [m for m in markers
         if (any(m in text for text in user_texts)
             and any(m not in text for text in bot_texts))
         or m in tracked_marker],
    )


def _union(first, second):
    merged = list(first)
    merged.extend(key for key in second if key not in merged)
    return merged


def _gather(site, timeout, spam, lost, user_texts, bot_texts):
    """후보가 잡힌 패스에만 도는 확장 표본 수집. 반환 = 비교 불가 사유(없으면 "").

    ① 일반 표본은 **끊기지 않는 한 블록**으로 뜬다. 16차에는 '연속 N개가 mod P의
       전 잔여류를 덮는다'가 근거였고 그 근거는 P>N에서 무너졌지만(17차), 연속성
       자체는 **축 1(회전 감지)의 전제**로 그대로 살아 있다 — 봇 요청을 중간에
       끼우면 일반 표본이 같은 잔여류에 갇혀 주기 2짜리 회전도 "변화 없음"으로
       오판된다. 즉 같은 코드 형태를 다른 이유로 유지한다.
    ② 봇 추가 표본은 블록 **뒤**에서 뜬다. 즉시 확정의 과반 조건과, 마커가 정말
       봇에게 안 보이는지의 재확인(17차 P2-2)이 여기에 달려 있다.
    ③ 후보가 전부 반증되면 즉시 종료 — 회전 사이트에 매 패스 최대 요청을 쏟지
       않는다 (15차 P3-5의 조기 종료 계약 유지).
    """
    for _ in range(cloak_decision.user_sample_count()):
        text, note = _fetch_view(site["url"], timeout)
        if note:
            return note
        user_texts.append(text)
        if not _alive(spam, lost, user_texts):
            return ""
    wanted = cloak_decision.bot_sample_count()
    while len(bot_texts) < wanted:
        text, note = _fetch_view(site["url"], timeout, ua=BOT_UA,
                                 referer=SEARCH_REFERER)
        if note:
            return note
        bot_texts.append(text)
    return ""


def _alive(spam, lost, user_texts):
    """일반 표본만으로 아직 살아 있는 후보가 있는가 (조기 종료 판정용)"""
    return (any(all(k not in text for text in user_texts) for k in spam)
            or any(all(m in text for text in user_texts) for m in lost))


def _cloak_result(verdict):
    """판정 → 층 결과 dict. 확정 FAIL > 확정 WARN > 의심 WARN > 통과 순."""
    if verdict["spam_confirmed"]:
        return {"layer": "L5 클로킹", "ok": False, "detail": _spam_detail(verdict)}
    warns = []
    if verdict["marker_confirmed"]:
        carried = (" · 이번 표본에서는 미관측(누적 유지)"
                   if all(m in verdict["marker_unseen"]
                          for m in verdict["marker_confirmed"]) else "")
        warns.append("검색봇 시점에서 핵심 내용 사라짐: %s (봇 차단 설정일 수도 있음)%s"
                     % (_show(verdict["marker_confirmed"]), carried))
    if verdict["spam_suspect"]:
        warns.append("클로킹 의심 — 검색봇 시점에만 스팸 문구: %s (%s)"
                     % (_show([k for k, _ in verdict["spam_suspect"]]),
                        _pending_note(verdict, verdict["spam_suspect"],
                                      verdict["spam_unseen"])))
    if verdict["marker_suspect"]:
        warns.append("검색봇 시점에서만 핵심 내용 사라짐 의심: %s (%s)"
                     % (_show([m for m, _ in verdict["marker_suspect"]]),
                        _pending_note(verdict, verdict["marker_suspect"],
                                      verdict["marker_unseen"])))
    if warns:
        return {"layer": "L5 클로킹", "ok": False, "warn": True,
                "detail": " · ".join(warns)}
    if verdict["rejected_spam"] or verdict["rejected_marker"]:
        # 기각 사유를 "회전"으로 단정하지 않는다 — 사이트 내용에 원래 그 문구가
        # 있는 경우(카지노 리뷰 사이트 등)와 회차마다 오가는 경우가 같은 관측이다
        return {"layer": "L5 클로킹", "ok": True,
                "detail": "일반 시점에서도 확인됨 — 클로킹 아님(일반 %d회 중: %s)"
                          % (verdict["user_seen"],
                             _show(verdict["rejected_spam"] + verdict["rejected_marker"]))}
    return {"layer": "L5 클로킹", "ok": True, "detail": "일반/검색봇 시점 일치"}


def _spam_detail(verdict):
    keys = verdict["spam_confirmed"]
    if all(k in verdict["spam_unseen"] for k in keys):
        # 이번 표본엔 안 나왔지만 확정은 유지된다 — 관측의 부재는 해소가 아니다.
        # 여기서 "정상"으로 돌리면 간헐 클로커가 매 패스 🔴🟢로 튄다
        return ("검색봇 전용 스팸 문구 확정 유지: %s (이번 표본에서는 미관측 — 봇에게만"
                " 간헐 노출하는 수법이라 한 번 안 보인 것은 해소가 아니다)" % _show(keys))
    hits = max((verdict["bot_hits"].get(k, 0) for k in keys), default=0)
    across = (" · 회전 페이지에서 %d패스 누적" % verdict["confirm_passes"]
              if verdict["rotating"] else "")
    return ("검색봇에게만 보이는 스팸 문구: %s (일반 시점 %d회 전부 부재·검색봇 시점 "
            "%d/%d 노출%s) — 침해 의심, 소스·서버 점검 필요"
            % (_show(keys), verdict["user_seen"], hits, verdict["bot_seen"], across))


def _pending_note(verdict, suspects, unseen):
    """왜 아직 확정하지 않는지를 그대로 쓴다 — 침묵도 빨간 오보도 아닌 중간 상태"""
    streak = max(n for _, n in suspects)
    if all(key in unseen for key, _ in suspects):
        why = "이번 표본에서는 미관측 — 누적 감쇠 중"
    elif verdict["rotating"]:
        why = "회전 콘텐츠라 한 패스로 확정하지 않음"
    else:
        why = "봇 시점 노출이 %d/%d — 과반 미달" % (
            max(verdict["bot_hits"].values(), default=0), verdict["bot_seen"])
    return "%s · %d/%d패스 · 일반 시점 %d회 부재" % (
        why, streak, verdict["confirm_passes"], verdict["user_seen"])


def _show(keys):
    more = (" 외 %d개" % (len(keys) - SPAM_MAX_SHOW)
            if len(keys) > SPAM_MAX_SHOW else "")
    return ", ".join(keys[:SPAM_MAX_SHOW]) + more


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
    if not isinstance(matches, list):
        # 응답 형태를 신뢰하면 벤더가 스키마를 바꾸는 날 예외가 층 밖으로 새고,
        # cli가 그걸 "체크 자체 실패" 🔴로 만들어 **사이트 장애로 오귀속**한다
        # (19차 P3-5). 우리 확인 실패는 unknown이지 사이트 상태가 아니다
        return _unknown_rep("조회 응답 형식 이상")
    if matches:
        kinds = sorted({m.get("threatType", "UNKNOWN") if isinstance(m, dict)
                        else "UNKNOWN" for m in matches})
        return {"layer": "L5 평판", "ok": False,
                "detail": "Google 위험 사이트 등재: %s — 방문자에게 경고 화면이 뜨는 상태"
                          % ", ".join(kinds)}
    return {"layer": "L5 평판", "ok": True, "detail": "Google 등재 없음"}


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
    """내장 시그니처 + 사이트별 추가. **중복 제거 필수** (18차 P2-2).

    설정에 내장 키워드와 같은 값이 들어오면(정상 통과하는 설정이다) 같은 문구가
    두 번 순회돼 한 패스에 누적이 2씩 올라가고, 확정 임계 4가 조용히 2패스로
    반토막 난다 — 13~17차 오탐 클래스가 설정 파일 하나로 재개방되는 경로다.
    """
    extra = [k for k in (site.get("spam_keywords") or [])
             if isinstance(k, str) and k.strip()]
    return cloak_decision.dedupe(SPAM_KEYWORDS + extra)


def _markers(site):
    return cloak_decision.dedupe(
        [m for m in (site.get("markers") or []) if isinstance(m, str)])


def _gsb_key():
    import os

    return os.environ.get("GSB_API_KEY", "").strip()


def bot_view_url(url):
    """녹화·수동 확인용 — 검색봇 시점을 사람이 재현할 수 있게 명령을 알려준다"""
    return "curl -A '%s' -e '%s' %s" % (BOT_UA, SEARCH_REFERER, urllib.parse.quote(url, safe=":/"))
