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
    """기동 시 스키마+타입 검증 (P2-3·N3·N5).

    반환: (오류 목록, 경고 목록, 오류 사이트 키 집합).
    오류 사이트는 기동을 막지 않고 건너뛴다 — 감시 도구는 가용성 우선:
    설정 오타 한 줄이 나머지 정상 사이트의 감시까지 중단시키면 안 된다.
    """
    errors, warnings, bad_keys = [], [], set()
    for key, site in sites.items():
        if not isinstance(site, dict):
            errors.append("%s: 객체가 아님" % key)
            bad_keys.add(key)
            continue
        for field in ("name", "url"):
            if not site.get(field):
                errors.append("%s: 필수 항목 '%s' 없음" % (key, field))
                bad_keys.add(key)
        markers = site.get("markers")
        if markers is not None and (
            not isinstance(markers, list)
            or any(not isinstance(m, str) or not m.strip() for m in markers)
        ):  # 빈 문자열 마커는 모든 페이지를 통과시켜 L2를 무음 무력화한다 (H-B)
            errors.append("%s: markers는 비어있지 않은 문자열 리스트여야 함" % key)
            bad_keys.add(key)
        version_url = site.get("version_url")
        if version_url is not None and not isinstance(version_url, str):
            errors.append("%s: version_url은 문자열이어야 함" % key)
            bad_keys.add(key)
        for field in ("confirm_checks", "timeout_sec"):
            value = site.get(field)
            if value is not None and (
                not isinstance(value, int) or isinstance(value, bool) or value < 1
            ):  # bool은 int의 하위 타입이라 명시 제외 (G9)
                errors.append("%s: %s는 1 이상 정수여야 함 (현재 %r)" % (key, field, value))
                bad_keys.add(key)
        if not markers:
            warnings.append("%s: markers 미설정 — L2 내용 검증 비활성" % key)
    return errors, warnings, bad_keys
