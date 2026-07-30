"""설정 로더 — .env(시크릿)와 sites.json(감시 대상)을 읽는다."""
import json
import os
import pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
SITES_PATH = ROOT / "sites.json"
STATE_PATH = ROOT / "state.json"
BOARD_PATH = ROOT / "board.html"
BOARD_HISTORY_PATH = ROOT / "board_history.json"


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
    """state.json과 같은 클래스의 방어 — 설정 오타가 트레이스백으로 죽지 않게 (M-B)"""
    if not SITES_PATH.exists():
        return {}
    try:
        data = json.loads(SITES_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        print("[설정 오류] sites.json 파싱 실패(%s)" % type(exc).__name__)
        return {}
    if not isinstance(data, dict):
        print("[설정 오류] sites.json 최상위는 객체여야 합니다")
        return {}
    return data


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
        name = site.get("name")
        if not name or not isinstance(name, str):
            errors.append("%s: name은 비어있지 않은 문자열이어야 함" % key)
            bad_keys.add(key)
        url = site.get("url")
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            errors.append("%s: url은 http(s):// 로 시작하는 문자열이어야 함" % key)
            bad_keys.add(key)
        markers = site.get("markers")
        if markers is not None and (
            not isinstance(markers, list)
            or any(not isinstance(m, str) or not m.strip() for m in markers)
        ):  # 빈 문자열 마커는 모든 페이지를 통과시켜 L2를 무음 무력화한다 (H-B)
            errors.append("%s: markers는 비어있지 않은 문자열 리스트여야 함" % key)
            bad_keys.add(key)
        version_url = site.get("version_url")
        if version_url is not None and (
            not isinstance(version_url, str)
            or not version_url.startswith(("http://", "https://"))
        ):  # url과 같은 기준 — 같은 함수 안에서 같은 종류 필드를 다르게 다루지 않는다 (N-D)
            errors.append("%s: version_url은 http(s):// 로 시작하는 문자열이어야 함" % key)
            bad_keys.add(key)
        # JSON null 처리 — .get(field, 기본값)이 null을 그대로 반환해 기본값을
        # 우회한다 (11차 P3-1). 등급은 런타임 영향 기준으로 나눈다 (12차 P3-1):
        # confirm_checks/timeout_sec null = 매 체크 TypeError → error(제외),
        # markers/version_url null = L2 비활성/L3 생략과 동일해 무해 → 경고만
        # (가용성 우선 H-G — 단일 사이트 설정에서 감시 전면 중단을 만들지 않는다)
        if "version_url" in site and version_url is None:
            warnings.append(
                "%s: version_url이 null — 미설정으로 처리(L3 생략). 키를 빼는 걸 권장" % key
            )
        render = site.get("render")
        if "render" in site and render is None:
            warnings.append(
                "%s: render가 null — 미설정으로 처리(L4 비활성). 키를 빼는 걸 권장" % key
            )
        elif render is not None and not isinstance(render, bool):
            # true 외의 truthy(문자열 "false" 등)를 켜짐으로 오해하는 사고 방지
            errors.append("%s: render는 true/false여야 함 (현재 %r)" % (key, render))
            bad_keys.add(key)
        for field in ("confirm_checks", "timeout_sec"):
            if field in site and site[field] is None:
                errors.append("%s: %s가 null — 미사용이면 키 자체를 뺄 것" % (key, field))
                bad_keys.add(key)
                continue
            value = site.get(field)
            if value is not None and (
                not isinstance(value, int) or isinstance(value, bool) or value < 1
            ):  # bool은 int의 하위 타입이라 명시 제외 (G9)
                errors.append("%s: %s는 1 이상 정수여야 함 (현재 %r)" % (key, field, value))
                bad_keys.add(key)
        if not markers:
            if "markers" in site and markers is None:
                # 같은 값에 경고 두 개를 내지 않는다 (12차 P3-1 자기모순 출력)
                warnings.append(
                    "%s: markers가 null — 미설정으로 처리(L2 비활성). 키를 빼는 걸 권장" % key
                )
            else:
                warnings.append("%s: markers 미설정 — L2 내용 검증 비활성" % key)
    return errors, warnings, bad_keys
