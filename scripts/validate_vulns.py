"""
취약점 검증 스크립트 (live-fire 방식).

팀 사용법 (제출 전 자기 서비스 검증):
  python validate_vulns.py --spec vuln_spec.json --host localhost --port 8000

주최측 사용법 (전 팀 일괄 검증):
  python validate_vulns.py --all --spec-dir ../vuln_specs --hosts-file hosts.json

반복 검증 (재현성 확인, N/N 성공):
  python validate_vulns.py --spec vuln_spec.json --host localhost --port 8000 --repeat 3

결과 저장:
  python validate_vulns.py --all ... --repeat 3 --save-report validation_report.json

검증 흐름 (live-fire):
  1. /health 확인
  2. checker.inject: 테스트 flag를 서비스에 주입
  3. checker.retrieve: flag가 서비스에 저장됐는지 확인
  4. 공격 (test_payload → /chat): 응답에서 HSPACE{...} 패턴 탐지
  5. checker.basic_function: 기본 기능 동작 확인
"""
import argparse
import json
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

SCRIPTS_DIR = Path(__file__).parent
COORDINATOR_DIR = SCRIPTS_DIR.parent / "coordinator"
sys.path.insert(0, str(COORDINATOR_DIR))

from flag_manager import generate_flag, FLAG_PATTERN

CHECKER_TOKEN_DEFAULT = "validate-test-token"


def load_spec(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def load_hosts(path: str) -> dict:
    with open(path) as f:
        return json.load(f)


def _inject_flag(host: str, port: int, inject_spec: dict, flag: str, checker_token: str) -> bool:
    if not inject_spec:
        return True
    url = f"http://{host}:{port}{inject_spec['endpoint']}"
    method = inject_spec.get("method", "POST").upper()
    auth_header = inject_spec.get("auth_header", "X-Checker-Token")
    body = _sub(inject_spec.get("body", {}), flag)
    headers = {auth_header: checker_token}
    try:
        if method == "POST":
            r = httpx.post(url, json=body, headers=headers, timeout=10.0)
        else:
            r = httpx.get(url, headers=headers, timeout=10.0)
        return r.status_code in (200, 201, 204)
    except Exception as e:
        print(f"    inject 오류: {e}")
        return False


def _retrieve_flag(host: str, port: int, retrieve_spec: dict, flag: str, checker_token: str) -> bool:
    if not retrieve_spec:
        return True
    url = f"http://{host}:{port}{retrieve_spec['endpoint']}"
    method = retrieve_spec.get("method", "GET").upper()
    expect = _sub(retrieve_spec.get("expect_contains", "{{FLAG}}"), flag)
    headers = {"X-Checker-Token": checker_token}
    try:
        if method == "GET":
            r = httpx.get(url, headers=headers, timeout=10.0)
        else:
            r = httpx.post(url, json={}, headers=headers, timeout=10.0)
        return r.status_code == 200 and expect in r.text
    except Exception as e:
        print(f"    retrieve 오류: {e}")
        return False


def _attack(host: str, port: int, payload: str, flag: str) -> tuple[bool, str]:
    """test_payload로 공격 후 응답에서 flag 패턴 탐지."""
    url = f"http://{host}:{port}/chat"
    try:
        r = httpx.post(url, json={"message": payload}, timeout=30.0)
        r.raise_for_status()
        response_text = r.json().get("response", "")
        # 응답에서 HSPACE{...} 패턴 추출
        found = FLAG_PATTERN.findall(response_text)
        success = flag in found
        return success, response_text[:300]
    except Exception as e:
        return False, f"[오류: {e}]"


def _basic_function(host: str, port: int, basic_spec: dict) -> bool:
    if not basic_spec:
        return True
    url = f"http://{host}:{port}/chat"
    payload = basic_spec.get("payload", "안녕하세요")
    expect_status = basic_spec.get("expect_status", 200)
    try:
        r = httpx.post(url, json={"message": payload}, timeout=15.0)
        return r.status_code == expect_status
    except Exception:
        return False


def validate_single(
    spec: dict,
    host: str,
    port: int,
    repeat: int = 1,
    checker_token: str = CHECKER_TOKEN_DEFAULT,
) -> dict:
    """
    단일 팀 전체 취약점 검증.

    Returns:
        {
          "passed": bool,
          "vulns": {
            vuln_id: {
              "health": bool, "inject": bool, "retrieve": bool,
              "attack_success": int, "attack_attempts": int,
              "basic_func": bool, "passed": bool, "failure_snippet": str
            }
          }
        }
    """
    team_id = spec["team_id"]
    vulns = spec.get("vulnerabilities", [])
    base_url = f"http://{host}:{port}"

    print(f"\n{'='*55}")
    print(f"팀: {team_id}  ({spec.get('service_description', '')})")
    print(f"타겟: {base_url}  (반복: {repeat}회)")
    print(f"{'='*55}")

    # 1. health 확인
    try:
        r = httpx.get(f"{base_url}/health", timeout=5.0)
        health_ok = r.status_code == 200
    except Exception as e:
        health_ok = False
        print(f"  ✗ health 실패: {e}")

    if not health_ok:
        print(f"  ✗ 서비스 DOWN — 이후 검증 생략")
        return {"passed": False, "vulns": {}, "health": False}

    print(f"  ✓ health OK")

    team_result = {"passed": True, "health": True, "vulns": {}}

    for vuln in vulns:
        vid = vuln["id"]
        vuln_type = vuln.get("type", "unknown")
        checker_spec = vuln.get("checker", {})
        test_payload = vuln.get("test_payload", "")

        print(f"\n  [{vid}] {vuln_type}")

        if not test_payload:
            print(f"    SKIP — test_payload 없음")
            team_result["vulns"][vid] = {"passed": False, "failure_snippet": "test_payload 없음"}
            team_result["passed"] = False
            continue

        vuln_ok = True
        vuln_r = {
            "inject": False, "retrieve": False,
            "attack_success": 0, "attack_attempts": repeat,
            "basic_func": False, "passed": False, "failure_snippet": "",
        }

        for attempt in range(1, repeat + 1):
            if attempt > 1:
                time.sleep(2)

            # 테스트용 임시 flag 생성
            test_flag = generate_flag()

            # 2. inject
            inject_spec = checker_spec.get("inject")
            inject_ok = _inject_flag(host, port, inject_spec, test_flag, checker_token)
            vuln_r["inject"] = inject_ok
            if not inject_ok:
                print(f"    시도 {attempt}/{repeat}: inject 실패")
                vuln_ok = False
                continue

            # 3. retrieve
            retrieve_spec = checker_spec.get("retrieve")
            retrieve_ok = _retrieve_flag(host, port, retrieve_spec, test_flag, checker_token)
            vuln_r["retrieve"] = retrieve_ok
            if not retrieve_ok:
                print(f"    시도 {attempt}/{repeat}: retrieve 실패")
                vuln_ok = False
                continue

            # 4. attack
            attack_ok, snippet = _attack(host, port, test_payload, test_flag)
            if attack_ok:
                vuln_r["attack_success"] += 1
                print(f"    시도 {attempt}/{repeat}: ✓ flag 탈취 성공")
            else:
                vuln_r["failure_snippet"] = snippet
                print(f"    시도 {attempt}/{repeat}: ✗ flag 미탈취")

        # 5. basic_function (1번만)
        basic_spec = checker_spec.get("basic_function")
        basic_ok = _basic_function(host, port, basic_spec)
        vuln_r["basic_func"] = basic_ok
        if not basic_ok:
            print(f"    basic_function 실패")

        # 최종 판정: N/N 공격 성공 + basic_function 정상
        vuln_passed = (vuln_r["attack_success"] == repeat and basic_ok)
        vuln_r["passed"] = vuln_passed

        if vuln_passed:
            print(f"    ✓ PASS ({repeat}/{repeat} 공격 성공, basic_func OK)")
        else:
            print(f"    ✗ FAIL (공격 {vuln_r['attack_success']}/{repeat}, basic_func={basic_ok})")
            team_result["passed"] = False

        team_result["vulns"][vid] = vuln_r

    status = "모든 취약점 검증 통과 ✓" if team_result["passed"] else "일부 취약점 검증 실패 ✗"
    print(f"\n  결과: {status}")
    return team_result


def main():
    parser = argparse.ArgumentParser(description="AI A&D 취약점 검증 스크립트 (live-fire)")
    parser.add_argument("--spec", help="vuln_spec.json 경로 (단일 팀)")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--all", action="store_true", help="전 팀 일괄 검증")
    parser.add_argument("--spec-dir", help="vuln_specs 디렉토리")
    parser.add_argument("--hosts-file", help="팀별 IP 매핑 JSON")
    parser.add_argument("--repeat", type=int, default=1,
                        help="취약점당 반복 횟수, N/N 성공해야 PASS (이벤트 표준: 3)")
    parser.add_argument("--save-report", metavar="PATH")
    parser.add_argument("--checker-token", default=CHECKER_TOKEN_DEFAULT,
                        help="X-Checker-Token 값 (서비스 /admin/inject 인증용)")
    args = parser.parse_args()

    if args.repeat < 1:
        print("ERROR: --repeat 은 1 이상")
        sys.exit(1)

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repeat_n": args.repeat,
        "all_passed": False,
        "teams": {},
    }

    # 단일 팀
    if args.spec:
        spec = load_spec(args.spec)
        result = validate_single(spec, args.host, args.port,
                                 repeat=args.repeat, checker_token=args.checker_token)
        report["teams"][spec["team_id"]] = result
        report["all_passed"] = result["passed"]
        if args.save_report:
            Path(args.save_report).write_text(json.dumps(report, indent=2, ensure_ascii=False))
            print(f"\n리포트 저장: {args.save_report}")
        sys.exit(0 if result["passed"] else 1)

    # 전 팀 일괄
    if args.all:
        if not args.spec_dir or not args.hosts_file:
            print("ERROR: --all 사용 시 --spec-dir 과 --hosts-file 필요")
            sys.exit(1)

        hosts = load_hosts(args.hosts_file)
        spec_dir = Path(args.spec_dir)

        for spec_file in sorted(spec_dir.glob("*.json")):
            if spec_file.name == "example.json":
                continue
            spec = load_spec(str(spec_file))
            team_id = spec["team_id"]
            host = hosts.get(team_id)
            if not host:
                print(f"\n[{team_id}] SKIP — hosts_file에 IP 없음")
                continue
            result = validate_single(spec, host, args.port,
                                     repeat=args.repeat, checker_token=args.checker_token)
            report["teams"][team_id] = result

        all_passed = all(r["passed"] for r in report["teams"].values())
        report["all_passed"] = all_passed

        print(f"\n{'='*55}")
        print("전체 결과 요약")
        print(f"{'='*55}")
        for team, r in report["teams"].items():
            mark = "✓" if r["passed"] else "✗"
            print(f"  {mark} {team}")

        if args.save_report:
            Path(args.save_report).write_text(json.dumps(report, indent=2, ensure_ascii=False))
            print(f"\n리포트 저장: {args.save_report}")

        if not all_passed:
            failed = [t for t, r in report["teams"].items() if not r["passed"]]
            print(f"\n검증 실패 팀: {', '.join(failed)}")
            sys.exit(1)
        else:
            print("\n전 팀 검증 통과")
        return

    parser.print_help()


def _sub(obj, flag: str):
    """{{FLAG}} 치환."""
    if isinstance(obj, str):
        return obj.replace("{{FLAG}}", flag)
    if isinstance(obj, dict):
        return {k: _sub(v, flag) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_sub(v, flag) for v in obj]
    return obj


if __name__ == "__main__":
    main()
