#!/usr/bin/env python3
"""
팀 서비스 취약점 자가 검증 스크립트.

사용법 (서비스 repo 루트에서):
  python ../scripts/verify.py                          # vuln_spec.json 자동 탐지
  python ../scripts/verify.py --spec ./vuln_spec.json  # 명시적 지정
  python ../scripts/verify.py --port 8080              # 포트 변경
  python ../scripts/verify.py --repeat 5               # 5회 반복 (기본 3회)

검증 흐름 (취약점 하나당):
  1. service.health — 서비스 응답 확인 (미지정 시 템플릿 호환용 /health)
  2. inject  — vuln_spec에 선언한 요청으로 테스트 flag 주입
  3. retrieve — vuln_spec에 선언한 요청으로 flag 저장 확인
  4. attack  — vuln_spec의 attack 요청으로 HSPACE{...} 패턴 탐지
  5. basic_function — 정상 요청도 HTTP 200 반환 확인

합격 기준: --repeat 회 모두 attack 성공 + basic_function 정상
서비스 API는 자유롭게 만들 수 있고, 실제 요청 형식은 vuln_spec.json에 선언한다.
"""
import argparse
import json
import re
import secrets
import sys
import time
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

try:
    import httpx
except ImportError:
    print("httpx가 필요합니다: pip install httpx")
    sys.exit(1)

FLAG_PATTERN = re.compile(r"HSPACE\{[a-f0-9]{32}\}")
CHECKER_TOKEN_DEFAULT = "validate-test-token"
REQUIRED_DIFFICULTIES = {"low", "mid", "high"}

# ANSI 색상 (터미널 지원 여부 자동 판단)
_USE_COLOR = sys.stdout.isatty()
GREEN  = "\033[32m" if _USE_COLOR else ""
RED    = "\033[31m" if _USE_COLOR else ""
YELLOW = "\033[33m" if _USE_COLOR else ""
BOLD   = "\033[1m"  if _USE_COLOR else ""
RESET  = "\033[0m"  if _USE_COLOR else ""

OK   = f"{GREEN}✓{RESET}"
FAIL = f"{RED}✗{RESET}"
WARN = f"{YELLOW}!{RESET}"


def _gen_flag() -> str:
    return "HSPACE{" + secrets.token_hex(16) + "}"


def _sub(obj, flag: str):
    if isinstance(obj, str):
        return obj.replace("{{FLAG}}", flag)
    if isinstance(obj, dict):
        return {k: _sub(v, flag) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sub(v, flag) for v in obj]
    return obj


def _sub_all(obj, flag: str = "", payload: str = "", checker_token: str = ""):
    if isinstance(obj, str):
        return (
            obj.replace("{{FLAG}}", flag)
            .replace("{{PAYLOAD}}", payload)
            .replace("{{CHECKER_TOKEN}}", checker_token)
        )
    if isinstance(obj, dict):
        return {k: _sub_all(v, flag=flag, payload=payload, checker_token=checker_token) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sub_all(v, flag=flag, payload=payload, checker_token=checker_token) for v in obj]
    return obj


def _request_from_spec(
    base: str,
    request_spec: dict,
    *,
    default_endpoint: str | None = None,
    default_method: str = "GET",
    default_body: Any = None,
    default_auth_header: str | None = None,
    flag: str = "",
    payload: str = "",
    checker_token: str = "",
    timeout: float = 10.0,
) -> httpx.Response:
    endpoint = request_spec.get("endpoint", default_endpoint)
    if not endpoint or not str(endpoint).startswith("/"):
        raise ValueError(f"endpoint must start with '/': {endpoint!r}")
    method = request_spec.get("method", default_method).upper()
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
        raise ValueError(f"unsupported method: {method}")

    headers = _sub_all(request_spec.get("headers", {}), flag=flag, payload=payload, checker_token=checker_token)
    auth_header = request_spec.get("auth_header", default_auth_header)
    if auth_header and checker_token:
        headers[auth_header] = checker_token
    params = _sub_all(request_spec.get("params", request_spec.get("query", {})), flag=flag, payload=payload, checker_token=checker_token)
    body = request_spec.get("json", request_spec.get("body", default_body))
    data = request_spec.get("data")
    body = _sub_all(body, flag=flag, payload=payload, checker_token=checker_token)
    data = _sub_all(data, flag=flag, payload=payload, checker_token=checker_token)
    return httpx.request(method, f"{base}{endpoint}", headers=headers, params=params, json=body, data=data, timeout=timeout)


def _response_text(resp: httpx.Response, response_path: str | None = None) -> str:
    if response_path:
        try:
            data: Any = resp.json()
        except Exception:
            return resp.text
        for part in response_path.split("."):
            if isinstance(data, dict):
                data = data.get(part)
            elif isinstance(data, list) and part.isdigit():
                data = data[int(part)]
            else:
                return ""
        return data if isinstance(data, str) else json.dumps(data, ensure_ascii=False)
    try:
        data = resp.json()
        if isinstance(data, dict) and isinstance(data.get("response"), str):
            return data["response"]
        return json.dumps(data, ensure_ascii=False)
    except Exception:
        return resp.text


def find_spec() -> Path | None:
    candidates = [
        Path("vuln_spec.json"),
        Path("../vuln_spec.json"),
        Path("web_service/vuln_spec.json"),
    ]
    for p in candidates:
        if p.exists():
            return p.resolve()
    return None


def load_spec(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


# ── 단계별 검사 ──────────────────────────────────────────────────────

def step_health(base: str, service_spec: dict) -> tuple[bool, str, str]:
    health_spec = service_spec.get("health") or {"endpoint": "/health", "method": "GET", "expect_status": 200}
    expect_status = health_spec.get("expect_status", 200)
    try:
        r = _request_from_spec(base, health_spec, default_endpoint="/health", default_method="GET", timeout=5.0)
        endpoint = health_spec.get("endpoint", "/health")
        return r.status_code == expect_status, endpoint, f"HTTP {r.status_code}"
    except Exception as e:
        return False, health_spec.get("endpoint", "/health"), str(e)


def step_inject(base: str, inject_spec: dict, flag: str, token: str) -> tuple[bool, str]:
    if not inject_spec:
        return True, ""
    try:
        r = _request_from_spec(
            base,
            inject_spec,
            default_method="POST",
            default_auth_header="X-Checker-Token",
            flag=flag,
            checker_token=token,
        )
        if r.status_code in (200, 201, 204):
            return True, ""
        return False, f"HTTP {r.status_code}: {r.text[:200]}"
    except Exception as e:
        return False, str(e)


def step_retrieve(base: str, retrieve_spec: dict, flag: str, token: str) -> tuple[bool, str]:
    if not retrieve_spec:
        return True, ""
    expect = _sub_all(retrieve_spec.get("expect_contains", "{{FLAG}}"), flag=flag, checker_token=token)
    try:
        r = _request_from_spec(
            base,
            retrieve_spec,
            default_method="GET",
            default_auth_header="X-Checker-Token",
            flag=flag,
            checker_token=token,
        )
        text = _response_text(r, retrieve_spec.get("response_path"))
        expect_status = retrieve_spec.get("expect_status", 200)
        if r.status_code == expect_status and expect in text:
            return True, ""
        if r.status_code != expect_status:
            return False, f"HTTP {r.status_code}"
        return False, f"응답에 flag 없음 (expect_contains 미포함). 응답: {text[:300]}"
    except Exception as e:
        return False, str(e)


def step_attack(base: str, attack_spec: dict, payload: str, flag: str) -> tuple[bool, str]:
    attack_spec = attack_spec or {}
    expect = _sub_all(attack_spec.get("expect_contains", "{{FLAG}}"), flag=flag, payload=payload)
    try:
        r = _request_from_spec(
            base,
            attack_spec,
            default_endpoint="/chat",
            default_method="POST",
            default_body={"message": "{{PAYLOAD}}"},
            flag=flag,
            payload=payload,
            timeout=30.0,
        )
        r.raise_for_status()
        response_text = _response_text(r, attack_spec.get("response_path"))
        found = FLAG_PATTERN.findall(response_text)
        if expect in response_text or flag in found:
            return True, ""
        snippet = response_text[:300].replace("\n", " ")
        hint = ""
        if found:
            hint = f" (다른 flag 발견됨: {found[0][:20]}... — 주입된 flag와 불일치)"
        return False, f"응답에 HSPACE{{...}} 없음{hint}. 응답 앞 300자: {snippet!r}"
    except httpx.HTTPStatusError as e:
        return False, f"HTTP {e.response.status_code}: {e.response.text[:200]}"
    except Exception as e:
        return False, str(e)


def step_basic(base: str, basic_spec: dict) -> tuple[bool, str]:
    if not basic_spec:
        return True, ""
    payload = basic_spec.get("payload", "안녕하세요")
    expect_status = basic_spec.get("expect_status", 200)
    try:
        r = _request_from_spec(
            base,
            basic_spec,
            default_endpoint="/chat",
            default_method="POST",
            default_body={"message": "{{PAYLOAD}}"},
            payload=payload,
            timeout=15.0,
        )
        text = _response_text(r, basic_spec.get("response_path"))
        expect_contains = basic_spec.get("expect_contains")
        if r.status_code == expect_status and (not expect_contains or _sub_all(expect_contains, payload=payload) in text):
            return True, ""
        return False, f"HTTP {r.status_code} (예상: {expect_status})"
    except Exception as e:
        return False, str(e)


# ── 취약점 단위 검증 ─────────────────────────────────────────────────

def verify_vuln(
    vuln: dict,
    base: str,
    service_spec: dict,
    repeat: int,
    token: str,
    verbose: bool,
) -> dict:
    vid = vuln["id"]
    vtype = vuln.get("type", "unknown")
    payload = vuln.get("test_payload", "")
    checker = vuln.get("checker", {})
    attack_spec = vuln.get("attack") or checker.get("attack") or service_spec.get("attack") or {}

    print(f"\n  {BOLD}[{vid}]{RESET} {vtype}")

    if not payload:
        print(f"    {FAIL} test_payload 없음 — 검증 불가")
        return {"passed": False, "reason": "test_payload 없음"}

    attack_ok = 0
    last_err: dict = {}

    for attempt in range(1, repeat + 1):
        if attempt > 1:
            time.sleep(2)

        flag = _gen_flag()
        prefix = f"    [{attempt}/{repeat}]"

        # inject
        ok, err = step_inject(base, checker.get("inject"), flag, token)
        if not ok:
            print(f"{prefix} {FAIL} inject 실패: {err}")
            last_err["inject"] = err
            continue

        # retrieve
        ok, err = step_retrieve(base, checker.get("retrieve"), flag, token)
        if not ok:
            print(f"{prefix} {FAIL} retrieve 실패: {err}")
            last_err["retrieve"] = err
            if verbose:
                print("           힌트: checker.inject 후 checker.retrieve 응답에 flag 값이 포함돼야 합니다")
            continue

        # attack
        ok, err = step_attack(base, attack_spec, payload, flag)
        if ok:
            attack_ok += 1
            print(f"{prefix} {OK} flag 탈취 성공 ({flag[:24]}...)")
        else:
            last_err["attack"] = err
            print(f"{prefix} {FAIL} flag 미탈취")
            if verbose:
                print(f"           이유: {err}")

    # basic_function (한 번만)
    ok, err = step_basic(base, checker.get("basic_function"))
    if ok:
        print(f"    {OK} basic_function 정상")
    else:
        last_err["basic_function"] = err
        print(f"    {FAIL} basic_function 실패: {err}")

    passed = (attack_ok == repeat) and ok
    ratio = f"{attack_ok}/{repeat}"

    if passed:
        print(f"    {GREEN}{BOLD}→ PASS{RESET} (공격 {ratio}, basic OK)")
    else:
        print(f"    {RED}{BOLD}→ FAIL{RESET} (공격 {ratio}, basic={'OK' if ok else 'FAIL'})")
        if last_err and not verbose:
            key = next(iter(last_err))
            print(f"    {WARN} 마지막 오류 ({key}): {last_err[key][:200]}")
            print(f"    {WARN} 상세 보기: --verbose 옵션 추가")

    return {"passed": passed, "attack_ok": attack_ok, "repeat": repeat, "basic_ok": ok}


# ── 팀 서비스 전체 검증 ───────────────────────────────────────────────

def verify_all(spec: dict, host: str, port: int, repeat: int, token: str, verbose: bool) -> bool:
    team_id = spec["team_id"]
    desc = spec.get("service_description", "")
    base = f"http://{host}:{port}"
    vulns = spec.get("vulnerabilities", [])
    service_spec = spec.get("service") if isinstance(spec.get("service"), dict) else {}

    print(f"\n{BOLD}{'='*58}{RESET}")
    print(f"{BOLD}팀: {team_id}{RESET}  {desc}")
    print(f"타겟: {base}   반복: {repeat}회")
    print(f"{'='*58}")

    # 1. health
    health_ok, health_endpoint, health_detail = step_health(base, service_spec)
    print(f"\n  [health] {base}{health_endpoint}")
    if not health_ok:
        print(f"  {FAIL} 서비스 DOWN — 검증 중단 ({health_detail})")
        print(f"\n  {RED}서비스를 먼저 실행하세요: uvicorn main:app --port {port}{RESET}")
        return False
    print(f"  {OK} 서비스 응답 확인")

    if not vulns:
        print(f"\n  {WARN} 취약점 없음 (vulnerabilities 배열이 비어 있음)")
        return False

    schema_errors = validate_spec_schema(spec)
    if schema_errors:
        for err in schema_errors:
            print(f"  {FAIL} 스키마 오류: {err}")
        return False

    results = {}
    for vuln in vulns:
        results[vuln["id"]] = verify_vuln(vuln, base, service_spec, repeat, token, verbose)

    # 최종 요약
    print(f"\n{BOLD}{'─'*58}{RESET}")
    all_passed = all(r["passed"] for r in results.values())

    for vid, r in results.items():
        mark = OK if r["passed"] else FAIL
        print(f"  {mark} {vid}")

    if all_passed:
        print(f"\n{GREEN}{BOLD}전체 PASS ✓ — 제출 준비 완료{RESET}")
    else:
        failed = [vid for vid, r in results.items() if not r["passed"]]
        print(f"\n{RED}{BOLD}FAIL: {', '.join(failed)}{RESET}")
        print(f"  → 취약점 구현 후 재실행: python ../scripts/verify.py")

    return all_passed


def validate_spec_schema(spec: dict) -> list[str]:
    vulns = spec.get("vulnerabilities", [])
    errors: list[str] = []
    if len(vulns) != 4:
        errors.append(f"취약점은 정확히 4개여야 함 (현재 {len(vulns)}개)")
    ids = [v.get("id") for v in vulns]
    if ids != ["vuln1", "vuln2", "vuln3", "vuln4"]:
        errors.append("취약점 id는 vuln1~vuln4 순서여야 함")
    difficulties = [v.get("difficulty") for v in vulns]
    for vuln in vulns:
        difficulty = vuln.get("difficulty")
        if difficulty not in REQUIRED_DIFFICULTIES:
            errors.append(f"{vuln.get('id', '<unknown>')}: difficulty는 low/mid/high 중 하나여야 함")
    if not REQUIRED_DIFFICULTIES.issubset(set(difficulties)):
        errors.append("difficulty 분포에 low, mid, high가 모두 포함되어야 함")
    return errors


def main():
    parser = argparse.ArgumentParser(
        description="팀 서비스 취약점 자가 검증",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
예시:
  python ../scripts/verify.py                     # 기본 실행
  python ../scripts/verify.py --repeat 5          # 5회 반복
  python ../scripts/verify.py --verbose           # 실패 이유 상세 출력
  python ../scripts/verify.py --spec ./vuln_spec.json --port 8080
        """,
    )
    parser.add_argument("--spec", default=None,
                        help="vuln_spec.json 경로 (기본: 자동 탐지)")
    parser.add_argument("--host", default="localhost",
                        help="서비스 호스트 (기본: localhost)")
    parser.add_argument("--port", type=int, default=8000,
                        help="서비스 포트 (기본: 8000)")
    parser.add_argument("--repeat", type=int, default=3,
                        help="취약점당 반복 횟수 (기본: 3, 이벤트 표준)")
    parser.add_argument("--checker-token", default=CHECKER_TOKEN_DEFAULT,
                        help="X-Checker-Token 헤더 값")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="실패 원인 상세 출력")
    args = parser.parse_args()

    # spec 파일 찾기
    if args.spec:
        spec_path = Path(args.spec)
    else:
        spec_path = find_spec()

    if spec_path is None or not spec_path.exists():
        print(f"{RED}vuln_spec.json을 찾을 수 없습니다.{RESET}")
        print("  현재 위치가 서비스 repo 루트인지 확인하거나")
        print("  --spec 옵션으로 경로를 직접 지정하세요.")
        sys.exit(1)

    print(f"spec: {spec_path}")

    spec = load_spec(str(spec_path))
    passed = verify_all(
        spec,
        host=args.host,
        port=args.port,
        repeat=args.repeat,
        token=args.checker_token,
        verbose=args.verbose,
    )
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
