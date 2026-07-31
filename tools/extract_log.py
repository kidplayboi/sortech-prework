"""세션 트랜스크립트에서 **날것 대화**를 뽑아 공개 가능한 형태로 만든다.

왜 필요한가: 과제 요구사항이 AI 활용 기록에 대해 "날것 그대로 환영"인데,
`docs/ai-log`는 전부 사후 요약체다. 요약은 내가 고른 것만 남으므로 증거가 아니다.

안전 설계 (이 레포는 공개다):
- 트랜스크립트 한 폴더에 **전 프로젝트가 섞여 있다.** 그래서 레코드마다 `cwd`를
  확인해 소르테크 작업분만 통과시킨다(파일 단위가 아니라 **레코드 단위** 필터).
- 통과한 텍스트도 마스킹을 전수 적용한다 — 토큰·키·절대경로·타 프로젝트 식별어.
- 마스킹은 **화이트리스트가 아니라 블랙리스트**라 완전하지 않다. 그래서 산출물을
  커밋하기 전에 `--audit`으로 잔존 위험 문자열을 다시 훑는다.

사용법:
    python tools/extract_log.py --prompts     형 지시 전문 추출
    python tools/extract_log.py --audit FILE  산출물 잔존 위험 검사
"""
import argparse
import json
import pathlib
import re
import sys

TRANSCRIPTS = pathlib.Path(r"C:\Users\test\.claude\projects\C--Users-test")
PROJECT_MARK = "sortech-prework"
OUT_DIR = pathlib.Path(__file__).resolve().parent.parent / "docs" / "ai-log" / "raw"

# --- 마스킹 규칙 --------------------------------------------------------------
# 순서 중요: 넓은 패턴이 먼저 먹으면 좁은 패턴이 안 걸린다
PATTERNS = [
    # ⚠️env 대입 형태를 **가장 먼저** 지운다. 값의 모양을 보고 거르면 늦는다 —
    #   실제로 `${1}=<마스킹> 처럼 값이 잘려 적힌 줄이 있었고,
    #   콜론 뒤 30자를 요구하던 토큰 패턴을 그대로 통과했다. 챗 ID는 통째로 남았다.
    #   교훈: 시크릿은 '값의 생김새'가 아니라 **'이름'으로도 지워야 한다.
    (re.compile(r"(?i)\b([A-Z0-9_]*(TOKEN|SECRET|PASSWORD|PASSWD|APIKEY|API_KEY|"
                r"CHAT_ID|CLIENT_ID|CLIENT_SECRET|ACCESS_KEY|PRIVATE_KEY)[A-Z0-9_]*)"
                r"\s*[=:]\s*\S+"), r"\1=<마스킹>"),
    (re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{3,}\b"), "<텔레그램-봇토큰-마스킹>"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b"), "<구글-API키-마스킹>"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"), "<API키-마스킹>"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "<깃허브-토큰-마스킹>"),
    (re.compile(r"\b[A-Za-z0-9._%+-]+@(?!sortech\.co\.kr)[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
     "<이메일-마스킹>"),
    (re.compile(r"C:\\Users\\[^\\\s\"']+"), r"C:\\Users\\<user>"),
    (re.compile(r"/c/Users/[^/\s\"']+"), "/c/Users/<user>"),
]

# 타 프로젝트·클라이언트 식별어 — 공개 레포 가드의 핵심.
# 한 글자라도 새면 무관한 회사·개인 정보가 제출물에 들어간다.
OTHER_PROJECTS = [
    "<타-프로젝트-마스킹>", "<타-프로젝트-마스킹>", "<타-프로젝트-마스킹>-saas", "<타-프로젝트-마스킹>", "<타-프로젝트-마스킹>", "<타-프로젝트-마스킹>",
    "<타-프로젝트-마스킹>", "<타-프로젝트-마스킹>", "<타-프로젝트-마스킹>", "<타-프로젝트-마스킹>", "<타-프로젝트-마스킹>", "<타-프로젝트-마스킹>",
    "<타-프로젝트-마스킹>", "<타-프로젝트-마스킹>", "<타-프로젝트-마스킹>", "<타-프로젝트-마스킹>", "<타-프로젝트-마스킹>", "<타-프로젝트-마스킹>",
    "<타-프로젝트-마스킹>", "<타-프로젝트-마스킹>", "<타-프로젝트-마스킹>", "<타-프로젝트-마스킹>", "Nexus", "<타-프로젝트-마스킹>",
    "<타-프로젝트-마스킹>", "<타-프로젝트-마스킹>", "<타-프로젝트-마스킹>", "<타-프로젝트-마스킹>", "<타-프로젝트-마스킹>",
    "<타-프로젝트-마스킹>", "<타-프로젝트-마스킹>", "<타-프로젝트-마스킹>", "<타-프로젝트-마스킹>", "<타-프로젝트-마스킹>", "<타-프로젝트-마스킹>",
    "<타-프로젝트-마스킹>", "<타-프로젝트-마스킹>", "<타-프로젝트-마스킹>", "<타-프로젝트-마스킹>", "<타-프로젝트-마스킹>", "<타-프로젝트-마스킹>",
]
OTHER_RE = re.compile("|".join(re.escape(w) for w in OTHER_PROJECTS), re.IGNORECASE)

# 감사 단계에서 다시 훑을 위험 신호 (마스킹 후에도 남았으면 사람이 봐야 한다)
AUDIT_SIGNS = [
    # 시크릿은 대문자·소문자·숫자가 **섞인** 고엔트로피 문자열이다. 길이만 보면
    # git SHA(소문자 hex)·세션 UUID·snake_case 이름·MCP 툴명이 전부 걸려
    # 경고가 시끄러워지고, 시끄러운 경고는 결국 무시된다.
    (re.compile(r"\b(?=[A-Za-z0-9_-]{32,}\b)(?=[^\s]*[a-z])(?=[^\s]*[A-Z])"
                r"(?=[^\s]*\d)[A-Za-z0-9_-]{32,}\b"), "고엔트로피 문자열(키 가능성)"),
    (re.compile(r"\b\d{8,}\b"), "8자리 이상 숫자(봇·챗 ID 가능성)"),
    (OTHER_RE, "타 프로젝트 식별어"),
    (re.compile(r"C:\\Users\\(?!<user>)"), "마스킹 안 된 사용자 경로"),
    # 값이 실제로 붙어 있을 때만 문다. `TOKEN=` 처럼 규칙을 **설명하는** 문장까지
    # 걸면(내 문서가 실제로 걸렸다) 오탐이 쌓이고, 오탐이 쌓인 감사는 무시된다.
    (re.compile(r"(?i)(token|secret|password|api[_-]?key|chat_id)\s*[=:]\s*"
                r"[^\s<`'\"]{6,}"), "마스킹 안 된 시크릿 대입"),
]


def mask(text):
    for pattern, repl in PATTERNS:
        text = pattern.sub(repl, text)
    return OTHER_RE.sub("<타-프로젝트-마스킹>", text)


def text_of(message):
    """메시지 content에서 사람이 읽는 텍스트만 뽑는다 (툴 호출·결과는 제외)."""
    content = message.get("content")
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    parts = [b.get("text", "") for b in content
             if isinstance(b, dict) and b.get("type") == "text"]
    return "\n".join(p for p in parts if p)


# 시스템이 사용자 메시지에 **덧붙이는** 블록들. 통째로 버리면 진짜 지시까지 날아간다
# (첫 시도에서 1,127턴 중 66턴만 남은 원인) — 블록만 도려내고 사람이 친 말은 살린다.
STRIP_BLOCKS = [
    re.compile(r"<system-reminder>.*?</system-reminder>", re.S),
    re.compile(r"<local-command-(stdout|stderr|caveat)>.*?</local-command-\1>", re.S),
    re.compile(r"<command-(name|message|args)>.*?</command-\1>", re.S),
    re.compile(r"<task-notification>.*?</task-notification>", re.S),
    re.compile(r"^Caveat:.*?$", re.M),
    re.compile(r"\[Request interrupted[^\]]*\]"),
]
# 도려낸 뒤에도 사람의 말이 없는 턴(툴 결과·훅 출력 등)은 기록에서 뺀다
NOISE_ONLY = re.compile(r"^\s*(Stop hook feedback:|Tool ran without output|"
                        r"The user doesn't want to|\[SYSTEM NOTIFICATION)", re.M)


def human_text(body):
    for pattern in STRIP_BLOCKS:
        body = pattern.sub("", body)
    body = body.strip()
    return "" if not body or NOISE_ONLY.search(body) else body


def iter_turns(role):
    """소르테크 작업분의 해당 role 턴을 시간순으로 흘려보낸다."""
    seen = []
    for path in sorted(TRANSCRIPTS.glob("*.jsonl")):
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if PROJECT_MARK not in (rec.get("cwd") or ""):
                    continue          # ★레코드 단위 프로젝트 필터
                if rec.get("type") != role:
                    continue
                body = human_text(text_of(rec.get("message") or {}))
                if not body:
                    continue
                seen.append((rec.get("timestamp", ""), body))
    seen.sort(key=lambda x: x[0])
    return seen


def cmd_prompts():
    turns = iter_turns("user")
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    out = OUT_DIR / "00-지시-전문.md"
    # "ㄱㄱ" 같은 두 글자 승인도 지시다 — 길이로 버리지 않는다
    kept = [(ts, mask(body)) for ts, body in turns]
    short = 0
    with out.open("w", encoding="utf-8") as fh:
        fh.write("# 지시 전문 (날것) — 소르테크 사전 과제\n\n")
        fh.write("> 세션 트랜스크립트에서 **사람이 실제로 친 말**만 시간순으로 뽑았다.\n")
        fh.write("> 요약·각색 없음. 마스킹만 적용(토큰·키·경로·타 프로젝트 식별어).\n")
        fh.write("> 추출기 = `tools/extract_log.py` · 필터 = 레코드의 `cwd`가 이 레포인 것만\n\n")
        fh.write("총 %d턴 (3자 미만 응답 %d턴은 제외)\n\n---\n\n" % (len(kept), short))
        day = None
        for ts, body in kept:
            if ts[:10] != day:
                day = ts[:10]
                fh.write("\n## %s\n\n" % day)
            fh.write("**%s**\n> %s\n\n" % (ts[11:16], body.replace("\n", "\n> ")))
    print("작성: %s (%d턴)" % (out, len(kept)))
    return out


def cmd_audit(target):
    path = pathlib.Path(target)
    text = path.read_text(encoding="utf-8")
    total = 0
    for pattern, label in AUDIT_SIGNS:
        hits = pattern.findall(text)
        if hits:
            uniq = sorted(set(h if isinstance(h, str) else h[0] for h in hits))[:6]
            print("  ⚠️ %-28s %d건  예: %s" % (label, len(hits), ", ".join(uniq)))
            total += len(hits)
    print("잔존 위험 신호 %d건 — 0이 아니면 사람이 직접 확인할 것" % total)
    return total


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--prompts", action="store_true")
    ap.add_argument("--audit")
    args = ap.parse_args()
    if args.prompts:
        out = cmd_prompts()
        print("\n=== 자동 감사 (차단형) ===")
        if cmd_audit(out):
            # ⚠️경고만 찍고 파일을 남기면 사람이 그걸 커밋한다. 실제로 텔레그램
            #   챗 ID가 남은 산출물이 만들어졌고, 감사가 잡았지만 파일은 살아 있었다.
            #   위험 신호가 있으면 **산출물을 지운다** — 남기려면 규칙을 고쳐라.
            out.unlink()
            print("→ 위험 신호가 남아 산출물을 삭제했다. 마스킹 규칙을 고치고 다시 돌려라.")
            sys.exit(1)
        print("→ 잔존 위험 0 — 커밋 가능")
    elif args.audit:
        cmd_audit(args.audit)
    else:
        ap.print_help()
        sys.exit(2)


if __name__ == "__main__":
    main()
