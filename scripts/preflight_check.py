"""
이벤트 시작 전 원클릭 전체 시스템 사전검증.
일반 운영자는 `python scripts/gitctf.py admin preflight --repeat 3`를 사용한다.

사용법:
  python scripts/gitctf.py admin preflight --repeat 3
  python scripts/gitctf.py admin preflight --hosts-file hosts.json

검증 항목:
  1. coordinator /health 응답 확인
  2. 모든 팀 서비스 health 응답 확인 (vuln_spec.service.health, 미지정 시 /health)
  3. 모든 팀 취약점 --repeat 회 반복 검증 (N/N 성공)
  4. 전체 통과 시 POST /admin/preflight-done 호출
"""
import argparse
import json
import os
import sys
from pathlib import Path

import httpx

SCRIPTS_DIR = Path(__file__).parent
COORDINATOR_DIR = SCRIPTS_DIR.parent / "coordinator"
VULN_SPEC_DIR = SCRIPTS_DIR.parent / "vuln_specs"

# validate_vulns.py와 동일한 로직 재사용
sys.path.insert(0, str(SCRIPTS_DIR))
sys.path.insert(0, str(COORDINATOR_DIR))
from validate_vulns import load_spec, validate_single


def check_coordinator_health(coordinator_url: str) -> bool:
    print(f"\n[1/3] Coordinator 헬스 체크: {coordinator_url}/health")
    try:
        r = httpx.get(f"{coordinator_url}/health", timeout=5.0)
        if r.status_code == 200:
            data = r.json()
            print(f"  ✓ OK — round={data.get('round')}, active={data.get('round_active')}")
            return True
        else:
            print(f"  ✗ FAIL — HTTP {r.status_code}")
            return False
    except Exception as e:
        print(f"  ✗ FAIL — 연결 오류: {e}")
        return False


def _team_specs() -> dict[str, dict]:
    specs = {}
    for spec_file in sorted(VULN_SPEC_DIR.glob("*.json")):
        if spec_file.name == "example.json":
            continue
        spec = load_spec(str(spec_file))
        if spec.get("team_id"):
            specs[spec["team_id"]] = spec
    return specs


def _health_spec(team_spec: dict | None) -> dict:
    if team_spec and isinstance(team_spec.get("service"), dict):
        health = team_spec["service"].get("health")
        if isinstance(health, dict):
            return health
    return {"endpoint": "/health", "method": "GET", "expect_status": 200}


def check_team_health(teams: dict, specs: dict[str, dict]) -> dict[str, bool]:
    print(f"\n[2/3] 팀 서비스 헬스 체크 ({len(teams)}팀)")
    results = {}
    for team_id, info in teams.items():
        spec = _health_spec(specs.get(team_id))
        endpoint = spec.get("endpoint", "/health")
        url = f"http://{info['ip']}:{info['port']}{endpoint}"
        method = spec.get("method", "GET").upper()
        try:
            r = httpx.request(
                method,
                url,
                headers=spec.get("headers", {}),
                params=spec.get("params", spec.get("query", {})),
                json=spec.get("json", spec.get("body")),
                data=spec.get("data"),
                timeout=5.0,
            )
            ok = r.status_code == spec.get("expect_status", 200)
            results[team_id] = ok
            mark = "✓" if ok else "✗"
            print(f"  {mark} {team_id} ({url}) — HTTP {r.status_code}")
        except Exception as e:
            results[team_id] = False
            print(f"  ✗ {team_id} ({url}) — 연결 오류: {e}")
    return results


def _missing_team_specs(teams: dict, specs: dict[str, dict]) -> list[str]:
    return [team_id for team_id in teams if team_id not in specs]


def validate_all_vulns(
    teams: dict,
    specs: dict[str, dict],
    port: int,
    repeat: int,
    report_path: str,
    checker_token: str,
) -> bool:
    print(f"\n[3/3] 취약점 검증 (반복 {repeat}회, N/N 성공 조건)")

    from datetime import datetime, timezone
    import json

    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repeat_n": repeat,
        "all_passed": False,
        "teams": {},
    }

    all_passed = True
    missing_specs = _missing_team_specs(teams, specs)
    if missing_specs:
        all_passed = False
        print(f"  ✗ 팀별 vuln_spec 누락: {', '.join(missing_specs)}")
        for team_id in missing_specs:
            report["teams"][team_id] = {
                "passed": False,
                "health": False,
                "failure": "vuln_spec missing",
            }

    for team_id in teams:
        spec = specs.get(team_id)
        if not spec:
            continue
        info = teams[team_id]
        result = validate_single(
            spec,
            info["ip"],
            info.get("port", port),
            repeat=repeat,
            checker_token=checker_token,
        )
        report["teams"][team_id] = result
        if not result["passed"]:
            all_passed = False

    report["all_passed"] = all_passed
    Path(report_path).write_text(json.dumps(report, indent=2, ensure_ascii=False))
    print(f"\n검증 리포트 저장: {report_path}")
    return all_passed


def mark_preflight_done(coordinator_url: str, admin_secret: str) -> bool:
    try:
        r = httpx.post(
            f"{coordinator_url}/admin/preflight-done",
            headers={"X-Admin-Secret": admin_secret},
            timeout=5.0,
        )
        return r.status_code == 200
    except Exception as e:
        print(f"  경고: preflight-done 호출 실패 — {e}")
        return False


def load_teams_from_config() -> dict:
    """config.py에서 TEAMS를 로드한다."""
    sys.path.insert(0, str(COORDINATOR_DIR))
    from config import TEAMS
    return TEAMS


def main():
    env_values = {}
    env_file = COORDINATOR_DIR / ".env"
    if env_file.exists():
        for line in env_file.read_text(encoding="utf-8").splitlines():
            if "=" not in line or line.strip().startswith("#"):
                continue
            key, value = line.split("=", 1)
            env_values[key.strip()] = value.strip().strip('"').strip("'")

    parser = argparse.ArgumentParser(description="AI A&D 이벤트 사전검증 스크립트")
    parser.add_argument("--coordinator", default="http://localhost:42000",
                        help="Coordinator URL (기본: http://localhost:42000)")
    parser.add_argument("--hosts-file", metavar="PATH",
                        help="팀 IP 매핑 JSON (없으면 config.py TEAMS 사용)")
    parser.add_argument("--port", type=int, default=8000,
                        help="팀 서비스 포트 (기본: 8000)")
    parser.add_argument("--repeat", type=int, default=3,
                        help="취약점 반복 검증 횟수 (기본: 3)")
    parser.add_argument("--checker-token", default=os.environ.get("CHECKER_TOKEN") or env_values.get("CHECKER_TOKEN", "checker-token-changeme"),
                        help="서비스 checker 인증 토큰 (기본: CHECKER_TOKEN, coordinator/.env, 또는 checker-token-changeme)")
    parser.add_argument("--report", default=str(SCRIPTS_DIR / "validation_report.json"),
                        help="검증 리포트 저장 경로")
    parser.add_argument("--skip-vuln", action="store_true",
                        help="취약점 검증 생략 (헬스 체크만)")
    args = parser.parse_args()

    admin_secret = os.environ.get("ADMIN_SECRET") or env_values.get("ADMIN_SECRET", "")
    if not admin_secret:
        print("경고: ADMIN_SECRET 없음 — preflight-done 호출 생략됩니다")

    # 팀 정보 로드
    if args.hosts_file:
        with open(args.hosts_file) as f:
            hosts_raw = json.load(f)
        teams = {tid: {"ip": ip, "port": args.port} for tid, ip in hosts_raw.items()}
    else:
        teams = load_teams_from_config()

    hosts = {tid: info["ip"] for tid, info in teams.items()}
    specs = _team_specs()

    failures = []

    # 1. Coordinator 헬스
    if not check_coordinator_health(args.coordinator):
        failures.append("coordinator health")

    # 2. 팀 서비스 헬스
    team_health = check_team_health(teams, specs)
    failed_teams = [t for t, ok in team_health.items() if not ok]
    if failed_teams:
        failures.append(f"팀 서비스 다운: {', '.join(failed_teams)}")

    # 3. 취약점 검증
    if not args.skip_vuln:
        vuln_ok = validate_all_vulns(
            teams,
            specs,
            args.port,
            args.repeat,
            args.report,
            args.checker_token,
        )
        if not vuln_ok:
            failures.append("취약점 검증 실패")
    else:
        print("\n[3/3] 취약점 검증 생략 (--skip-vuln)")

    # 결과 출력
    print(f"\n{'='*50}")
    if failures:
        print("사전검증 FAIL ✗")
        for f in failures:
            print(f"  - {f}")
        print("\n이벤트 시작 전 위 항목을 해결하세요.")
        sys.exit(1)
    else:
        print("사전검증 PASS ✓ — 이벤트 시작 준비 완료")
        if admin_secret:
            ok = mark_preflight_done(args.coordinator, admin_secret)
            if ok:
                print("  coordinator preflight-done 플래그 설정 완료")
            else:
                print("  경고: preflight-done 플래그 설정 실패 (수동으로 ?force=true 사용)")
        sys.exit(0)


if __name__ == "__main__":
    main()
