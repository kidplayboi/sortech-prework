"""CLI — status(현재 상태 1회, 읽기 전용) / once(체크 1회+알림) / watch(주기 순찰)"""
import argparse
import datetime
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
        try:  # 격리 범위 = 루프 본문 전체 — observe/알림 단계의 예외도 다음 사이트로 전파 금지 (N3)
            results = checks.check_site(site)
            status, reason = state_mod.summarize(results)
            print("%s [%s] %s %s" % (_now(), site.get("name", key), DOT[status], reason))
            if not alert:
                continue
            obs = state_mod.observe(
                st, key, status, reason, confirm=site.get("confirm_checks", 1)
            )
            if obs["alert"]:
                sent = notify.send(
                    notify.fmt_transition(
                        site.get("name", key), obs["status"], obs["reason"],
                        obs["prev_notified"], obs["duration_sec"],
                    )
                )
                if sent:
                    state_mod.mark_notified(st, key)
        except Exception as exc:
            print("%s [%s] ⚠️ 처리 실패: %s" % (_now(), site.get("name", key) if isinstance(site, dict) else key, type(exc).__name__))
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
    # 한글 Windows(cp949) 콘솔/리다이렉트에서 이모지 출력이 죽지 않게 (N9)
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    load_env()
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
