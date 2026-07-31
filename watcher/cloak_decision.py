"""L5 클로킹 판정 로직 — 순수 판정(HTTP·상태 파일 I/O 없음).

## 왜 모듈을 갈랐나

13~17차 게이트에서 **같은 오탐이 다섯 번** 반복됐다. 수리는 매번 달랐지만 축은
하나였다 — "한 패스 안에서 표본을 어떻게 배치할까". 그러나 결정적 유한 표본
패턴은 그 길이와 맞물리는 회전 주기에서 반드시 aliasing된다. 표본 수 N을 늘리면
P=2N에서, 배치를 바꾸면 그 배치 길이의 주기에서 다시 뚫린다. 이 축 위에는 해가
없다는 것이 17차의 결론이다 (설계 전문 = docs/06-L5-판정-재설계안.md).

그래서 축을 셋으로 쪼갰고, 판정만 여기로 떼어 요청 코드 없이 검증한다.

- **축 1 회전 감지** — 일반 시점 표본들이 서로 다른가. 다르면 "유한 표본에서
  안 보였다"는 결론이 될 수 없다(교란 원인을 직접 관측한다). 같더라도 그것만으론
  부족해서 봇 시점 **과반 재현**을 함께 요구한다 — 요청마다 낮은 확률로 끼는
  삽입형 문구(17차 P3-1)가 "안정 페이지"로 보이는 창을 막는 두 번째 자물쇠다.
- **축 2 패스 간 누적** — 한 패스로 확정하지 않는다. 재현될 때 +1, 관측되지
  않으면 −1인 **순증 누적**이 CONFIRM_PASSES에 닿을 때만 확정하고 그 전에는
  WARN(의심 n/K)로 노출한다. ⚠️"연속"이 아니라 순증이다(18차 P3-1 정정) —
  감쇠라서 회전 페이지는 순증을 못 만들지만, 위상이 잠기면 escalation이 연속으로
  일어나 순증이 쌓인다. **그 연속을 끊는 건 감쇠가 아니라 축 3이다**(18차 P3-2:
  "조용한 패스가 껴서 순증 0 이하"라고 썼던 초기 주석은 P=7·13~17에서 반증됐다).
  감쇠의 존재 이유는 하나뿐이다 — 간헐 클로커의 거짓 복구 차단.
- **축 3 위상 무작위화** — 패스당 요청 수를 흔든다. 고정이면 위상이 매 패스
  `R mod P`씩만 움직이고 `P | R`이면 영원히 제자리다(17차 P=12 영구 오탐).
  표본 수 범위를 **12개 연속 정수**로 둬서 패스 간 위상 증분이 12의 약수인
  주기(2·3·4·6·12)에서 정확히 균등해지게 했다.
  ⚠️축 3이 없으면 축 2는 결정적 회전에서 streak을 그대로 쌓아 K패스 뒤 똑같이
  오탐한다 — 누적은 표본이 패스마다 독립일 때만 뜻이 있다.

## 판정 밖에 남는 한계 (문서·README에 그대로 쓴다)

- 회전이 관측되는 페이지에서 **진짜 클로킹의 확정이 최대 K패스 지연**된다.
  침묵이 아니라 WARN으로 즉시 노출되므로 무소식은 아니다.
- 축 3은 확률적 보장이다 — "절대 안 뚫린다"가 아니라 "패스가 쌓일수록 0에
  수렴한다". 근거를 실제보다 세게 쓰면 다음 라운드에 그 문장이 반증된다(5라운드 교훈).
"""
import random

# 확정에 필요한 연속 재현 패스 수. 3이 아니라 4인 이유: 주기 12 결정적 회전에서
# 패스당 escalation 확률이 ~1/12이므로 K=3이면 하루 0.33건(288패스 기준) 오탐이
# 남는다. K=4면 0.03건/일 — 대신 회전 페이지의 확정이 1패스 더 늦다(WARN은 즉시).
CONFIRM_PASSES = 4
# 회전이 관측된 페이지는 임계를 더 높게 잡는다. 추적 중인 후보를 봇 블록 전체로
# 다시 확인하면(18차 P1-1 수리) 간헐 클로커는 살아나지만, 회전 페이지에서는 그
# 재확인이 **밀도까지 증거로 세어** 누적을 밀어 올린다 — 주기 16에서 하드 FAIL
# 2/1206이 실측됐다. 회전 중에는 "모두에게 같은 확률로 보인다"는 귀무가설이 아직
# 살아 있으므로 더 많은 증거를 요구하는 것이 맞다. 확정은 그만큼 늦지만(WARN은 즉시)
# 오탐은 임계 하나당 대략 한 자릿수씩 줄어든다
ROTATING_CONFIRM_PASSES = 6
# 일반 시점 확인 블록 길이 범위 (축 3). 12개 연속 정수 — 상한이 아니라 **폭**이
# 설계값이다. 하한 5는 주기 5 이하를 한 패스에서 구조적으로 덮는다.
USER_SAMPLE_MIN = 5
USER_SAMPLE_MAX = 16
# 봇 시점 표본 — 즉시 확정의 과반 판정과 마커 소실 재확인(17차 P2-2)에 쓰인다.
# 7인 이유는 실측이다: 5표본(과반 3)이면 요청마다 10% 확률로 끼는 삽입이 우연히
# 과반을 채워 0.5%/패스가 남았고, 7표본(과반 4)에서 그게 사라졌다. 간헐 클로커
# (봇 2회 중 1회 노출)는 7표본에서 4회 노출이라 즉시 확정이 그대로 유지된다
BOT_SAMPLES = 7

_KINDS = ("spam", "marker")


def user_sample_count(rand=random.randint):
    """이번 패스에 뜰 일반 표본 수 (축 3). rand 주입 = 테스트에서 위상 고정용."""
    return rand(USER_SAMPLE_MIN, USER_SAMPLE_MAX)


def dedupe(items):
    """순서 보존 중복 제거 — 후보가 겹치면 누적이 여러 번 오른다 (18차 P2-2)"""
    seen, unique = set(), []
    for item in items:
        if item not in seen:
            seen.add(item)
            unique.append(item)
    return unique


def load_memory(raw):
    """state.json에서 읽은 누적 기억을 검증해 안전한 형태로 만든다.

    손상된 값 하나가 매 패스 예외로 한 사이트를 영구 무감시로 만들지 않게
    타입까지 본다 (state._entry_broken의 H-D 교정과 같은 취지).
    """
    memory = {kind: {} for kind in _KINDS}
    if not isinstance(raw, dict):
        return memory
    for kind in _KINDS:
        bucket = raw.get(kind)
        if not isinstance(bucket, dict):
            continue
        for key, streak in bucket.items():
            if (isinstance(key, str) and isinstance(streak, int)
                    and not isinstance(streak, bool) and streak > 0):
                memory[kind][key] = streak
    return memory


def tracked(memory):
    """(추적 중인 스팸 키, 마커 키) — 호출자가 확장 표본을 뜰지 결정하는 데 쓴다.

    추적 중인 후보가 있으면 이번 봇 1차 표본이 비어도 확장해야 한다. 안 그러면
    확정 조건이 "봇 1차 표본 히트율 > 1/2"가 돼 그 아래로 노출하는 클로커는
    구조적으로 확정 불가가 된다 (18차 P1-1 — 1/3 노출에서 하드 FAIL 0회 실측).
    """
    return (sorted(memory.get("spam", {})), sorted(memory.get("marker", {})))


def evaluate(spam_candidates, marker_candidates, user_texts, bot_texts, memory,
             confirm_passes=None):
    """이번 패스의 관측 + 누적 기억 → 판정. **memory를 제자리 갱신한다.**

    반환 dict:
      rotating              회전 관측 여부 (축 1)
      spam_confirmed        확정된 봇 전용 스팸 문구 → 하드 FAIL 대상
      spam_suspect          [(문구, streak)] — 아직 확정 못 한 의심 → WARN
      marker_confirmed      봇 시점에서만 사라진 마커 → WARN
      marker_suspect        [(마커, streak)]
      rejected_spam / rejected_marker  이번 표본이 반증한 후보
      bot_hits, user_seen, bot_seen, confirm_passes  판정 근거 수치

    ⚠️confirm_passes 기본값을 인자 위치에 `=CONFIRM_PASSES`로 박지 않는다 —
    기본 인자는 정의 시점에 바인딩돼 상수를 바꿔도 반영되지 않고, 그러면 축 2를
    떼어내는 음성 대조가 **아무 일도 안 하면서 통과**한다(자체 음성 대조로 적발).
    """
    if confirm_passes is None:
        confirm_passes = CONFIRM_PASSES
    # 후보 중복은 한 패스에 누적을 여러 번 올려 확정 임계를 조용히 반토막 낸다
    # (18차 P2-2). 호출자도 걸러내지만 판정의 관문에서 한 번 더 막는다 — 이 함수는
    # 순수 함수라 아무 호출자나 붙을 수 있고, 임계는 오탐 방어의 마지막 선이다
    spam_candidates = dedupe(spam_candidates)
    marker_candidates = dedupe(marker_candidates)
    alive = {
        # 스팸: 일반 시점 **전부**에서 부재해야 후보로 남는다
        "spam": [k for k in spam_candidates
                 if all(k not in text for text in user_texts)],
        # 마커는 반대 방향 — 일반 시점 **전부**에 있고 봇 시점 **전부**에 없어야
        # 한다. 한 표본이라도 일반 시점에서 빠지면 회전으로 설명되고, 한 표본이라도
        # 봇 시점에 보이면 봇도 보는 것이다. 이 경로는 13~16차 내내 재표본이 0회인
        # 채 고정 1:1 비교로 남아 있었다 (17차 P2-2 — 증상만 고치고 형제를 안 막은 사례)
        "marker": [m for m in marker_candidates
                   if all(m in text for text in user_texts)
                   and all(m not in text for text in bot_texts)],
    }
    rotating = is_rotating(user_texts)
    bot_hits = {k: sum(1 for text in bot_texts if k in text) for k in alive["spam"]}
    verdict = {
        "rotating": rotating, "bot_hits": bot_hits, "confirm_passes": confirm_passes,
        "user_seen": len(user_texts), "bot_seen": len(bot_texts),
        "rejected_spam": [k for k in spam_candidates if k not in alive["spam"]],
        "rejected_marker": [m for m in marker_candidates if m not in alive["marker"]],
    }
    needed = ROTATING_CONFIRM_PASSES if rotating else confirm_passes
    verdict["confirm_passes"] = needed
    for kind in _KINDS:
        bucket = memory.setdefault(kind, {})
        _age(bucket, alive[kind], set(verdict["rejected_" + kind]))
        for key in alive[kind]:
            bucket[key] = min(bucket[key] + 1, needed * 2)
            if _immediate(kind, key, rotating, bot_hits, len(bot_texts)):
                bucket[key] = max(bucket[key], needed)
        verdict[kind + "_confirmed"] = [k for k, n in bucket.items() if n >= needed]
        verdict[kind + "_suspect"] = [(k, n) for k, n in bucket.items() if n < needed]
        verdict[kind + "_unseen"] = [k for k in bucket if k not in alive[kind]]
    return verdict


def _age(bucket, alive, disproved):
    """이번 패스의 관측을 누적에 반영하기 전, 두 종류의 '없음'을 갈라 처리한다.

    - **반증됨**(일반 시점에서 그 문구를 봤다 / 봇도 마커를 본다) = 적극적 증거 →
      즉시 소거. 한 번이라도 반증되면 그동안의 누적은 의미가 없다.
    - **미관측**(이번 봇 표본엔 안 나왔다) = 증거의 부재일 뿐 → 1씩 감쇠.
      여기서 0으로 리셋하면 간헐 클로커가 🔴→🟢"회복"→🔴로 튄다 — 못 본 것을
      정상으로 치는 거짓 복구이고, 13차 P1-1(간헐 층 승계)이 막은 것과 같은 클래스다.
      ⚠️감쇠가 결정적 회전을 막는 것은 **아니다**. 위상이 잠기면(N+8 ≡ 0 mod P)
      escalation이 연속으로 일어나 순증이 그대로 쌓인다 — P=7·13·14·15·16·17에서
      실측됐다(18차 P3-2). 회전을 막는 건 축 3이고, 감쇠의 역할은 거짓 복구 차단
      하나뿐이다. 근거를 실제보다 세게 쓰면 다음 라운드에 그 문장이 반증된다.

    누적 상한 = confirm_passes*2 → 확정 해제도 확정과 비슷한 수의 깨끗한 패스를
    요구한다(한 번 깨끗했다고 곧장 초록으로 돌아가는 비대칭 복구 금지).
    """
    for key in list(bucket):
        if key in alive:
            continue
        if key in disproved:
            del bucket[key]
            continue
        bucket[key] -= 1
        if bucket[key] <= 0:
            del bucket[key]
    bucket.update({k: bucket.get(k, 0) for k in alive})


def is_rotating(user_texts):
    """축 1 — 일반 시점 표본들이 서로 다른가.

    별도 함수인 이유는 음성 대조 때문이다: `_immediate` 전체를 패치하면 회전 감지와
    봇 과반 두 자물쇠가 함께 사라져 축 1 단독의 하중을 증명하지 못한다 (18차 P3-5).
    """
    return len(set(user_texts)) > 1


def _immediate(kind, key, rotating, bot_hits, bot_seen):
    """축 1 — 그 패스에서 바로 확정할 수 있는 조건.

    회전이 전혀 관측되지 않았고(일반 표본 본문이 전부 동일) 후보가 봇 표본
    **과반**에서 재현될 때만. 과반 조건이 두 번째 자물쇠다:
    - 낮은 확률로 끼는 무작위 삽입은 첫 봇 표본에 우연히 걸려도 과반까지 가긴
      어렵다 (17차 P3-1 실측 3.3%/패스 → 산식상 0.05% 수준)
    - 반대로 회전 페이지가 봇 과반을 채우려면 스팸 밀도가 높아야 하는데, 그러면
      같은 요청열에 붙어 있는 일반 블록에서도 반드시 보여 기각된다 — 위상이
      아니라 밀도로 갈리므로 주기와 무관하다
    """
    if rotating:
        return False
    if kind == "marker":
        # 마커는 후보 조건 자체가 이미 "봇 표본 전부에서 부재"다
        return True
    return bot_seen > 0 and bot_hits.get(key, 0) * 2 > bot_seen
