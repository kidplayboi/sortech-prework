"""CLI — status(현재 상태 1회 출력) / once(체크 1회+전이 알림) / watch(주기 순찰)"""
import argparse
import datetime
import time

from . import checks, notify, state as state_mod
from .config import load_env, load_sites

DOT = {"OK": "\U0001f7e2", "WARN": "\U0001f7e0", "FAIL": "\U0001f534"}


def _now():
    return datetime.datetime.now().strftime("%H:%M:%S")


def run_pass(sites, st, alert):
    """전 사이트 1회 체크. alert=True면 상태 전이 시 알림 발송."""
    for key, site in sites.items():
        results = checks.check_site(site)
        status, reason = state_mod.summarize(results)
        changed, prev, duration = state_mod.transition(st, key, status, reason)
        print("%s [%s] %s %s" % (_now(), site["name"], DOT[status], reason))
        if alert and changed:
            notify.send(notify.fmt_transition(site["name"], status, reason, prev, duration))


def cmd_status(sites, _args):
    st = state_mod.load_state()
    run_pass(sites, st, alert=False)


def cmd_once(sites, _args):
    st = state_mod.load_state()
    run_pass(sites, st, alert=True)


def cmd_watch(sites, args):
    st = state_mod.load_state()
    interval = args.interval
    print("순찰 시작 — %d초 간격, 대상 %d개 (중단: Ctrl+C)" % (interval, len(sites)))
    while True:
        run_pass(sites, st, alert=True)
        time.sleep(interval)


def main():
    load_env()
    parser = argparse.ArgumentParser(prog="watcher", description="배포 검증 워처")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("status", help="현재 상태 1회 출력 (알림 없음)")
    sub.add_parser("once", help="체크 1회 + 상태 전이 시 알림")
    watch = sub.add_parser("watch", help="주기 순찰")
    watch.add_argument("--interval", type=int, default=300, help="순찰 간격(초), 기본 300")
    args = parser.parse_args()

    sites = load_sites()
    if not sites:
        print("감시 대상이 없습니다. sites.json을 확인하세요.")
        return

    {"status": cmd_status, "once": cmd_once, "watch": cmd_watch}[args.command](sites, args)


if __name__ == "__main__":
    main()
