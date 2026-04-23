#!/usr/bin/env python3
"""
팀 서비스 취약점 자가 검증 스크립트.

사용법 (agent_service/ 디렉토리에서):
  python ../scripts/verify.py                          # vuln_spec.json 자동 탐지
  python ../scripts/verify.py --spec ./vuln_spec.json  # 명시적 지정
  python ../scripts/verify.py --port 8080              # 포트 변경
  python ../scripts/verify.py --repeat 5               # 5회 반복 (기본 3회)

검증 흐름 (취약점 하나당):
  1. /health — 서비스 응답 확인
  2. inject  — 테스트 flag를 /admin/inject로 주입
  3. retrieve — /admin/check로 flag 저장 확인
  4. attack  — test_payload → /chat → HSPACE{...} 패턴 탐지
  5. basic_function — 정상 요청도 HTTP 200 반환 확인

합격 기준: --repeat 회 모두 attack 성공 + basic_function 정상
"""
import argparse
import json
import re
import secrets
import sys
import time
from pathlib import Path
from datetime import datetime, timezone

try:
    import httpx
except ImportError:
    print("httpx가 필요합니다: pip install httpx")
    sys.exit(1)

FLAG_PATTERN = re.compile(r"HSPACE\{[a-f0-9]{32}\}")
CHECKER_TOKEN_DEFAULT = "validate-test-token"

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


def find_spec() -> Path | None:
    candidates = [
        Path("vuln_spec.json"),
        Path("../vuln_spec.json"),
        Path("agent_service/vuln_spec.json"),
    ]
    for p in candidates:
        if p.exists():
            return p.resolve()
    return None


def load_spec(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


# ── 단계별 검사 ──────────────────────────────────────────────────────

def step_health(base: str) -> bool:
    try:
        r = httpx.get(f"{base}/health", timeout=5.0)
        return r.status_code == 200
    except Exception:
        return False


def step_inject(base: str, inject_spec: dict, flag: str, token: str) -> tuple[bool, str]:
    if not inject_spec:
        return True, ""
    url = f"{base}{inject_spec['endpoint']}"
    body = _sub(inject_spec.get("body", {}), flag)
    headers = {inject_spec.get("auth_header", "X-Checker-Token"): token}
    try:
        r = httpx.post(url, json=body, headers=headers, timeout=10.0)
        if r.status_code in (200, 201, 204):
            return True, ""
        return False, f"HTTP {r.status_code}: {r.text[:200]}"
    except Exception as e:
        return False, str(e)


def step_retrieve(base: str, retrieve_spec: dict, flag: str, token: str) -> tuple[bool, str]:
    if not retrieve_spec:
        return True, ""
    url = f"{base}{retrieve_spec['endpoint']}"
    expect = _sub(retrieve_spec.get("expect_contains", "{{FLAG}}"), flag)
    headers = {"X-Checker-Token": token}
    try:
        r = httpx.get(url, headers=headers, timeout=10.0)
        if r.status_code == 200 and expect in r.text:
            return True, ""
        if r.status_code != 200:
            return False, f"HTTP {r.status_code}"
        return False, f"응답에 flag 없음 (expect_contains 미포함). 응답: {r.text[:300]}"
    except Exception as e:
        return False, str(e)


def step_attack(base: str, payload: str, flag: str) -> tuple[bool, str]:
    try:
        r = httpx.post(f"{base}/chat", json={"message": payload}, timeout=30.0)
        r.raise_for_status()
        response_text = r.json().get("response", "")
        found = FLAG_PATTERN.findall(response_text)
        if flag in found:
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
        r = httpx.post(f"{base}/chat", json={"message": payload}, timeout=15.0)
        if r.status_code == expect_status:
            return True, ""
        return False, f"HTTP {r.status_code} (예상: {expect_status})"
    except Exception as e:
        return False, str(e)


# ── 취약점 단위 검증 ─────────────────────────────────────────────────

def verify_vuln(
    vuln: dict,
    base: str,
    repeat: int,
    token: str,
    verbose: bool,
) -> dict:
    vid = vuln["id"]
    vtype = vuln.get("type", "unknown")
    payload = vuln.get("test_payload", "")
    checker = vuln.get("checker", {})

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
                print(f"           힌트: /admin/inject 후 /admin/check 응답에 flag 값이 포함돼야 합니다")
            continue

        # attack
        ok, err = step_attack(base, payload, flag)
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

    print(f"\n{BOLD}{'='*58}{RESET}")
    print(f"{BOLD}팀: {team_id}{RESET}  {desc}")
    print(f"타겟: {base}   반복: {repeat}회")
    print(f"{'='*58}")

    # 1. health
    print(f"\n  [health] {base}/health")
    if not step_health(base):
        print(f"  {FAIL} 서비스 DOWN — 검증 중단")
        print(f"\n  {RED}서비스를 먼저 실행하세요: uvicorn main:app --port {port}{RESET}")
        return False
    print(f"  {OK} 서비스 응답 확인")

    if not vulns:
        print(f"\n  {WARN} 취약점 없음 (vulnerabilities 배열이 비어 있음)")
        return False

    results = {}
    for vuln in vulns:
        results[vuln["id"]] = verify_vuln(vuln, base, repeat, token, verbose)

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
        print("  현재 위치가 agent_service/ 디렉토리인지 확인하거나")
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
