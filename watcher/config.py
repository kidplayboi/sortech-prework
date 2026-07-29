"""설정 로더 — .env(시크릿)와 sites.json(감시 대상)을 읽는다."""
import json
import os
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
SITES_PATH = ROOT / "sites.json"
STATE_PATH = ROOT / "state.json"


def load_env():
    """루트 .env를 환경변수로 주입. 이미 설정된 값은 덮지 않는다.

    utf-8-sig로 읽어 BOM 오염을 막고(P2-1 — 메모장 저장 시 키가 \\ufeff로 시작해
    토큰이 조용히 무시되던 문제), 따옴표·export 접두·인라인 주석을 걷어낸다.
    """
    env_path = ROOT / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        if line.startswith("export "):
            line = line[len("export "):]
        key, value = line.split("=", 1)
        value = value.split(" #", 1)[0].strip().strip("'\"")
        os.environ.setdefault(key.strip(), value)


def load_sites():
    if not SITES_PATH.exists():
        return {}
    return json.loads(SITES_PATH.read_text(encoding="utf-8"))


def validate_sites(sites):
    """기동 시 스키마 검증 (P2-3). 반환: (차단 오류 목록, 경고 목록)"""
    errors, warnings = [], []
    for key, site in sites.items():
        if not isinstance(site, dict):
            errors.append("%s: 객체가 아님" % key)
            continue
        for field in ("name", "url"):
            if not site.get(field):
                errors.append("%s: 필수 항목 '%s' 없음" % (key, field))
        if not site.get("markers"):
            warnings.append("%s: markers 미설정 — L2 내용 검증 비활성" % key)
    return errors, warnings
