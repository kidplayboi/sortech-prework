"""설정 로더 — .env(시크릿)와 sites.json(감시 대상)을 읽는다."""
import json
import os
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
SITES_PATH = ROOT / "sites.json"
STATE_PATH = ROOT / "state.json"


def load_env():
    """루트 .env를 읽어 환경변수로 주입한다. 이미 설정된 값은 덮지 않는다."""
    env_path = ROOT / ".env"
    if not env_path.exists():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip())


def load_sites():
    if not SITES_PATH.exists():
        return {}
    return json.loads(SITES_PATH.read_text(encoding="utf-8"))


def save_sites(sites):
    SITES_PATH.write_text(
        json.dumps(sites, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
