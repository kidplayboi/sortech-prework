"""CLI — status(현재 상태 1회, 읽기 전용) / once(체크 1회+알림) / watch(주기 순찰)"""
import argparse
import datetime
import os
import sys
import time

from . import board, checks, deploy as deploy_mod, notify, state as state_mod
from .config import load_env, load_sites, validate_sites

DOT = {"OK": "\U0001f7e2", "WARN": "\U0001f7e0", "FAIL": "\U0001f534"}


def _now():
    return datetime.datetime.now().strftime("%H:%M:%S")


CARRY_LAYER_PREFIXES = ("L4", "L5")  # 간헐 실행 층 — 스킵 패스에 직전 결과를 승계


def _layer_rank(layer):
    """층 실행 순서 — "L5 클로킹"처럼 접미가 붙어도 숫자 부분으로 순위를 뽑는다.
    한 글자만 읽으면 L10이 1로 파싱돼 확장 시 억제 순서가 뒤집힌다 (16차 P3-2)."""
    digits = ""
    for char in layer[1:]:
        if not char.isdigit():
            break
        digits += char
    return int(digits) if digits else 99


def _carry_layers(results, carried):
    """이번 패스에 실행되지 않은 간헐 층의 직전 결과를 이어붙인다.

    13차 P1-1 수리: L4를 건너뛴 패스를 "L4 정상"과 구분하지 못해 🔴→🟢"회복"→🔴
    거짓 복구·플랩·미보고가 발생했다. 상태 엔진은 "이번에 본 층 전부"를 사이트
    상태로 환산하므로, 안 본 층은 **마지막으로 본 결과**를 그대로 들고 가야 한다
    (모르는 것을 정상으로 치지 않는다). 승계된 항목은 문구에 그 사실을 표시한다.
    """
    seen = {r["layer"] for r in results}
    # 앞 층이 확정 장애면 그 뒤 층은 애초에 실행되지 않는다 — 그 자리에 낡은
    # "L4 렌더 정상 (이전 관측)"을 끼워 넣으면 다운된 사이트 옆에 정상 표기가
    # 나란히 붙는다 (14차 P3-7). 억제는 **실패한 층보다 뒤**로만 한정한다 —
    # 전체 억제면 L5가 실패한 패스에서 앞서 관측한 L4 장애 정보가 사라진다
    # (15차 P3-2). 주입만 건너뛰고 이번에 실제로 돌린 층의 기록은 항상 남긴다
    # (기록까지 건너뛰면 승계가 사라져 13차 P1-1이 되살아난다 — 14차에 적발)
    fail_rank = min(
        [_layer_rank(r["layer"]) for r in results
         if not r["ok"] and not r.get("warn")], default=None)
    for layer, prev in carried.items():
        if layer in seen:
            continue
        if fail_rank is not None and _layer_rank(layer) > fail_rank:
            continue
        merged = dict(prev)
        if "(이전 관측)" not in merged["detail"]:
            merged["detail"] = "%s (이전 관측)" % merged["detail"]
        results.append(merged)
    for r in results:
        if r["layer"].startswith(CARRY_LAYER_PREFIXES) and "(이전 관측)" not in r["detail"]:
            carried[r["layer"]] = r
    return results


def run_pass(sites, st, alert, persist=True, do_render=True, carry=None):
    """전 사이트 1회 체크. 사이트 하나의 예외가 전체 순찰을 죽이지 않게 격리(P2-3).

    alert=False(status 명령)면 state를 읽지도 쓰지도 않는다 — 조회가 전이를
    소비해 장애 알림이 증발하던 문제(P1-2)의 교정. 그 계약 때문에 L5 클로킹의
    **패스 간 누적이 status에서는 성립하지 않는다** — 매번 빈 기억으로 시작하므로
    회전 페이지는 확정까지 못 가고(WARN까지), 간헐 노출 사이트는 그 회차 봇 표본이
    비면 확장조차 하지 않아 🟢으로 보일 수 있다. 즉 status는 `watch`보다 **약하게**
    보고한다(18차 P3-4 — "WARN까지만"이라고 쓴 초기 서술은 후자를 빠뜨렸다).
    조회 명령이 판정을 앞당기지 않는 쪽이 옳다는 계약의 대가다.
    do_render=False면 이 패스에서 L4(무거움)를 생략 — watch의 --render-every 주기.
    carry(dict)를 주면 스킵된 간헐 층의 직전 결과를 승계한다 (P1-1 — 거짓 복구 차단).
    반환: (rows, sent_texts) — 상태보드(D2 슬라이스 ③)가 소비. rows의 layers는
    체크 자체가 죽었으면 빈 리스트.
    """
    rows, sent_texts = [], []
    for key, site in sites.items():
        results = []
        cloak_memory = state_mod.read_cloak(st, key) if alert else None
        try:
            results = checks.check_site(site, do_render=do_render,
                                        cloak_memory=cloak_memory)
            if carry is not None:
                results = _carry_layers(results, carry.setdefault(key, {}))
            status, reason = state_mod.summarize(results)
        except Exception as exc:
            # 체크 예외도 FAIL 상태로 만들어 알림 경로를 태운다 — 예외를 콘솔에만
            # 남기면 그 사이트는 영구 무감시·무알림이 된다 (3차 게이트 G2 교정)
            status, reason = "FAIL", "체크 자체 실패: %s" % type(exc).__name__
        print("%s [%s] %s %s" % (_now(), site.get("name", key), DOT[status], reason))
        rows.append({"key": key, "name": site.get("name", key),
                     "status": status, "reason": reason, "layers": results})
        if not alert:
            continue
        try:  # 상태·알림 단계도 사이트별 격리 (N3)
            obs = state_mod.observe(
                st, key, status, reason, confirm=site.get("confirm_checks", 1)
            )
            # observe 뒤에 쓴다 — 스키마 손상 엔트리를 observe가 재초기화하므로
            # 앞에서 쓰면 첫 패스의 누적이 그대로 증발한다
            state_mod.write_cloak(st, key, cloak_memory)
            # 현재 진행 중인 장애를 먼저 — 과거 순단의 사후 보고가 지금의 🔴을
            # 선점하면 안 된다 (K-C: elif 구조였을 때 1인터벌 지연·once 1회 누락)
            if obs["status"] is not None and obs["status"] != obs["prev_notified"]:
                text = notify.fmt_transition(
                    site.get("name", key), obs["status"], obs["reason"],
                    obs["prev_notified"], obs["duration_sec"],
                )
                if notify.send(text):
                    state_mod.mark_notified(st, key)
                    sent_texts.append(text)
            if obs.get("missed_reason"):
                text = notify.fmt_missed(
                    site.get("name", key), obs["missed_reason"],
                    obs.get("missed_duration", 0))
                if notify.send(text):
                    state_mod.clear_missed(st, key)  # 전달 성공 시에만 소거 — 실패면 재시도 (H-C)
                    sent_texts.append(text)
        except Exception as exc:
            print("%s [%s] ⚠️ 상태 처리 실패: %s" % (_now(), site.get("name", key), type(exc).__name__))
    if alert and persist:
        state_mod.save_state(st)
    return rows, sent_texts


def cmd_status(sites, _args):
    run_pass(sites, {}, alert=False)  # 읽기 전용 계약 — 보드 파일도 쓰지 않는다


def _update_board(rows, sent_texts):
    """보드 생성 실패가 감시를 죽이면 안 된다 — 격리 후 경고만 (가용성 우선)"""
    try:
        board.update_board(rows, sent_texts)
    except Exception as exc:
        print("[경고] 상태보드 갱신 실패: %s" % type(exc).__name__)


def cmd_once(sites, _args):
    st = state_mod.load_state()
    rows, sent = run_pass(sites, st, alert=True)
    _update_board(rows, sent)


def cmd_watch(sites, args):
    st = state_mod.load_state()
    interval = args.interval
    print("순찰 시작 — %d초 간격, 대상 %d개 (중단: Ctrl+C)" % (interval, len(sites)))
    next_run = time.monotonic()
    pass_index = 0
    carry = {}  # 사이트별 간헐 층 직전 결과 — 스킵 패스의 거짓 복구 차단 (P1-1)
    try:
        while True:
            # 평시엔 L1~L3 위주, 무거운 L4는 N패스마다 1회 (스펙 트리거 설계 —
            # 첫 패스는 포함해 기동 직후 렌더 상태를 확보)
            rows, sent = run_pass(sites, st, alert=True, carry=carry,
                                  do_render=(pass_index % args.render_every == 0))
            _update_board(rows, sent)
            pass_index += 1
            next_run += interval
            if next_run < time.monotonic():
                # 절전 복귀·긴 패스 뒤 밀린 주기를 연속 실행으로 몰아치지 않는다 (M-F)
                next_run = time.monotonic() + interval
            time.sleep(max(0, next_run - time.monotonic()))
    except KeyboardInterrupt:
        print("\n순찰 종료")


def cmd_deploy(sites, args):
    if args.site not in sites:
        print("사이트 키 '%s' 없음 — 사용 가능: %s" % (args.site, ", ".join(sites)))
        sys.exit(2)
    site = sites[args.site]
    if args.expect and args.expect_version:
        # 둘 다 주면 한쪽이 조용히 무시돼 "안정" 오보가 난다 (13차 P2-7)
        print("[사용 오류] --expect와 --expect-version은 함께 쓸 수 없습니다"
              " (검증 목표는 하나여야 합니다)")
        sys.exit(2)
    if args.expect_version and not site.get("version_url"):
        print("[설정 오류] --expect-version은 version_url이 있는 사이트에서만 쓸 수 있습니다"
              " (버전 파일이 없으면 앵커를 실측할 수 없음)")
        sys.exit(2)
    sys.exit(deploy_mod.run_deploy_watch(
        args.site, site, expect=args.expect, expect_version=args.expect_version,
        interval=args.interval, stable_needed=args.stable, max_wait=args.max_wait,
    ))


def _positive_interval(value):
    interval = int(value)
    if interval < 5:
        raise argparse.ArgumentTypeError("간격은 5초 이상이어야 합니다")
    return interval


def _positive_count(value):
    count = int(value)
    if count < 1:
        raise argparse.ArgumentTypeError("1 이상이어야 합니다")
    return count


def main():
    # 한글 Windows(cp949) 콘솔/리다이렉트에서 한글·이모지 출력이 죽지 않게 (N9·G10)
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")
    load_env()
    # 텔레그램 반쪽 설정은 조용한 오설정(G5) — 단, 기동을 막지는 않는다.
    # 사이트 설정 오류를 스킵으로 처리한 가용성 원칙과 동일하게, 크게 경고하고
    # 콘솔 알림 모드로 감시는 계속한다 (4차 게이트 H-G — 차단은 원칙 불일치)
    has_token = bool(os.environ.get("TELEGRAM_BOT_TOKEN"))
    has_chat = bool(os.environ.get("TELEGRAM_CHAT_ID"))
    if has_token != has_chat:
        print("[설정 경고] TELEGRAM 토큰/챗ID 중 하나만 설정됨 — 텔레그램 발송 불가, "
              "콘솔 알림 모드로 동작합니다. 텔레그램을 쓰려면 둘 다 설정하세요")
    elif not has_token:
        print("[안내] 텔레그램 미설정 — 알림은 콘솔로 출력됩니다 (데모 모드)")
    parser = argparse.ArgumentParser(prog="watcher", description="배포 검증 워처")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status", help="현재 상태 1회 출력 (읽기 전용 — 알림·기록 없음)")
    sub.add_parser("once", help="체크 1회 + 상태 전이 시 알림")
    watch = sub.add_parser("watch", help="주기 순찰")
    watch.add_argument("--interval", type=_positive_interval, default=300,
                       help="순찰 간격(초), 기본 300, 최소 5")
    watch.add_argument("--render-every", type=_positive_count, default=5,
                       help="L4 렌더링 검증을 N패스마다 1회 (기본 5, render:true 사이트만)")
    dep = sub.add_parser("deploy", help="배포 직후 집중 검증 — 안정/실패를 반드시 1회 보고")
    dep.add_argument("site", help="sites.json의 사이트 키")
    dep.add_argument("--expect", help="실화면에 나타나야 할 기대 문구 (빌더형 블랙박스용)")
    dep.add_argument("--expect-version",
                     help="기대 버전 앵커 — 원본·사용자 모두 이 값이어야 안정 판정")
    dep.add_argument("--interval", type=_positive_interval, default=15,
                     help="집중 체크 간격(초), 기본 15, 최소 5")
    dep.add_argument("--stable", type=_positive_count, default=3,
                     help="연속 N회 전 층 통과 시 안정 판정 (기본 3)")
    dep.add_argument("--max-wait", type=_positive_count, default=600,
                     help="최대 대기(초), 초과 시 실패 보고 (기본 600 — CDN 캐시 여유)")
    args = parser.parse_args()

    sites = load_sites()
    if not sites:
        print("감시 대상이 없습니다. sites.json을 확인하세요.")
        sys.exit(2)
    errors, warnings, bad_keys = validate_sites(sites)
    for warning in warnings:
        print("[경고] %s" % warning)
    for error in errors:
        print("[설정 오류 → 해당 사이트 제외] %s" % error)
    sites = {k: v for k, v in sites.items() if k not in bad_keys}
    if not sites:  # 전멸일 때만 기동 차단 — 일부 오류는 스킵하고 나머지는 감시 (가용성 우선)
        print("유효한 감시 대상이 없습니다.")
        sys.exit(2)

    {"status": cmd_status, "once": cmd_once, "watch": cmd_watch,
     "deploy": cmd_deploy}[args.command](sites, args)


if __name__ == "__main__":
    main()
