"""CLI — status(현재 상태 1회, 읽기 전용) / once(체크 1회+알림) / watch(주기 순찰)"""
import argparse
import datetime
import os
import sys
import time

from . import checks, notify, state as state_mod
from .config import load_env, load_sites, validate_sites

DOT = {"OK": "\U0001f7e2", "WARN": "\U0001f7e0", "FAIL": "\U0001f534"}


def _now():
    return datetime.datetime.now().strftime("%H:%M:%S")


def run_pass(sites, st, alert, persist=True):
    """전 사이트 1회 체크. 사이트 하나의 예외가 전체 순찰을 죽이지 않게 격리(P2-3).

    alert=False(status 명령)면 state를 읽지도 쓰지도 않는다 — 조회가 전이를
    소비해 장애 알림이 증발하던 문제(P1-2)의 교정.
    """
    for key, site in sites.items():
        try:
            results = checks.check_site(site)
            status, reason = state_mod.summarize(results)
        except Exception as exc:
            # 체크 예외도 FAIL 상태로 만들어 알림 경로를 태운다 — 예외를 콘솔에만
            # 남기면 그 사이트는 영구 무감시·무알림이 된다 (3차 게이트 G2 교정)
            status, reason = "FAIL", "체크 자체 실패: %s" % type(exc).__name__
        print("%s [%s] %s %s" % (_now(), site.get("name", key), DOT[status], reason))
        if not alert:
            continue
        try:  # 상태·알림 단계도 사이트별 격리 (N3)
            obs = state_mod.observe(
                st, key, status, reason, confirm=site.get("confirm_checks", 1)
            )
            # 현재 진행 중인 장애를 먼저 — 과거 순단의 사후 보고가 지금의 🔴을
            # 선점하면 안 된다 (K-C: elif 구조였을 때 1인터벌 지연·once 1회 누락)
            if obs["status"] is not None and obs["status"] != obs["prev_notified"]:
                sent = notify.send(
                    notify.fmt_transition(
                        site.get("name", key), obs["status"], obs["reason"],
                        obs["prev_notified"], obs["duration_sec"],
                    )
                )
                if sent:
                    state_mod.mark_notified(st, key)
            if obs.get("missed_reason"):
                if notify.send(notify.fmt_missed(
                        site.get("name", key), obs["missed_reason"], obs["duration_sec"])):
                    state_mod.clear_missed(st, key)  # 전달 성공 시에만 소거 — 실패면 재시도 (H-C)
        except Exception as exc:
            print("%s [%s] ⚠️ 상태 처리 실패: %s" % (_now(), site.get("name", key), type(exc).__name__))
    if alert and persist:
        state_mod.save_state(st)


def cmd_status(sites, _args):
    run_pass(sites, {}, alert=False)


def cmd_once(sites, _args):
    st = state_mod.load_state()
    run_pass(sites, st, alert=True)


def cmd_watch(sites, args):
    st = state_mod.load_state()
    interval = args.interval
    print("순찰 시작 — %d초 간격, 대상 %d개 (중단: Ctrl+C)" % (interval, len(sites)))
    next_run = time.monotonic()
    try:
        while True:
            run_pass(sites, st, alert=True)
            next_run += interval
            time.sleep(max(0, next_run - time.monotonic()))
    except KeyboardInterrupt:
        print("\n순찰 종료")


def _positive_interval(value):
    interval = int(value)
    if interval < 5:
        raise argparse.ArgumentTypeError("간격은 5초 이상이어야 합니다")
    return interval


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

    {"status": cmd_status, "once": cmd_once, "watch": cmd_watch}[args.command](sites, args)


if __name__ == "__main__":
    main()
