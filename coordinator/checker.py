"""
Checker 시스템 (FAUST CTF / iCTF 방식).

매 라운드 시작 전 coordinator가 실행:
  1. 서비스 liveness 확인 (/health)
  2. Flag 주입 (vuln_spec의 checker.inject 블록)
  3. Flag 회수 확인 (checker.retrieve 블록) — 서비스가 데이터 보존 중인지
  4. 기본 기능 동작 확인 (checker.basic_function)

상태:
  OK      → 모든 단계 통과. 가용성 보너스 + 공격 허용
  FAULTY  → flag 주입은 됐으나 회수 실패, 또는 기본 기능 이상.
             가용성 보너스 없음. 공격은 허용 (서비스는 살아있음)
  DOWN    → health 실패. 가용성 보너스 없음. 공격 불가 (타겟 없음)

FAULTY 판정 중요성:
  팀이 취약점을 패치했으나 서비스 로직을 망가뜨렸다면 FAULTY.
  → "서비스 죽이기" 방어 전략 차단 (DOWN이면 공격도 안 받지만 보너스도 없음)
"""
import logging
from dataclasses import dataclass, field
from typing import Optional

import httpx

import db

logger = logging.getLogger(__name__)

SERVICE_STATUS = {"OK", "FAULTY", "DOWN"}


@dataclass
class CheckResult:
    team_id: str
    status: str                          # OK / FAULTY / DOWN
    health_ok: bool = False
    inject_ok: bool = False
    retrieve_ok: bool = False
    basic_func_ok: bool = False
    detail: str = ""
    vuln_results: dict = field(default_factory=dict)  # {vuln_id: {inject, retrieve}}


async def check_team(
    team_id: str,
    team_info: dict,
    vulns: list[dict],
    round_flags: dict[str, str],         # {vuln_id: flag}
    checker_token: str,
    timeout: float = 8.0,
) -> CheckResult:
    """
    단일 팀 전체 checker 실행.

    Args:
        team_info: {"ip": str, "port": int}
        vulns: vuln_spec의 vulnerabilities 리스트
        round_flags: 이번 라운드 flag {vuln_id: flag_string}
        checker_token: /admin/inject 인증용 토큰 (X-Checker-Token 헤더)
    """
    result = CheckResult(team_id=team_id, status="DOWN")
    base_url = f"http://{team_info['ip']}:{team_info['port']}"

    async with httpx.AsyncClient(timeout=timeout) as client:

        # ── 1. liveness ──────────────────────────────────────────────
        try:
            r = await client.get(f"{base_url}/health")
            result.health_ok = r.status_code == 200
        except Exception as e:
            result.detail = f"health 실패: {e}"
            db.set_service_status(team_id, "DOWN", result.detail)
            return result  # DOWN 반환

        if not result.health_ok:
            result.detail = "health HTTP 200 아님"
            db.set_service_status(team_id, "DOWN", result.detail)
            return result

        # 이 시점부터 최소 FAULTY 가능
        result.status = "FAULTY"

        # ── 2 & 3. vuln별 inject + retrieve ─────────────────────────
        all_vulns_ok = True
        for vuln in vulns:
            vuln_id = vuln["id"]
            flag = round_flags.get(vuln_id, "")
            checker_spec = vuln.get("checker", {})
            vuln_r = {"inject": False, "retrieve": False}

            # inject
            inject_spec = checker_spec.get("inject")
            if inject_spec and flag:
                inject_ok = await _do_inject(client, base_url, inject_spec, flag, checker_token)
                vuln_r["inject"] = inject_ok
                if not inject_ok:
                    all_vulns_ok = False
                    result.detail += f" vuln {vuln_id}: inject 실패;"
            else:
                # inject 스펙 없으면 env var 주입으로 충분 → OK 처리
                vuln_r["inject"] = True

            # retrieve
            retrieve_spec = checker_spec.get("retrieve")
            if retrieve_spec and flag:
                retrieve_ok = await _do_retrieve(client, base_url, retrieve_spec, flag, checker_token)
                vuln_r["retrieve"] = retrieve_ok
                if not retrieve_ok:
                    all_vulns_ok = False
                    result.detail += f" vuln {vuln_id}: retrieve 실패;"
            else:
                vuln_r["retrieve"] = True

            result.vuln_results[vuln_id] = vuln_r

        # ── 4. 기본 기능 확인 ────────────────────────────────────────
        basic_spec = None
        for vuln in vulns:
            if vuln.get("checker", {}).get("basic_function"):
                basic_spec = vuln["checker"]["basic_function"]
                break

        if basic_spec:
            result.basic_func_ok = await _do_basic_function(client, base_url, basic_spec)
            if not result.basic_func_ok:
                result.detail += " 기본 기능 실패;"
        else:
            result.basic_func_ok = True  # 스펙 없으면 생략

        # ── 최종 상태 결정 ───────────────────────────────────────────
        if all_vulns_ok and result.basic_func_ok:
            result.status = "OK"
        else:
            result.status = "FAULTY"

    db.set_service_status(team_id, result.status, result.detail.strip())
    return result


async def run_all_checkers(
    teams: dict,
    vuln_specs: dict[str, list],
    round_flags_by_team: dict[str, dict[str, str]],
    checker_token: str,
) -> dict[str, CheckResult]:
    """모든 팀 checker를 순차 실행 (이벤트 루프 내에서 병렬 실행 가능하나 순차가 안전)."""
    results = {}
    for team_id, team_info in teams.items():
        vulns = vuln_specs.get(team_id, [])
        flags = round_flags_by_team.get(team_id, {})
        try:
            result = await check_team(team_id, team_info, vulns, flags, checker_token)
        except Exception as e:
            logger.error("checker 실행 오류 (%s): %s", team_id, e)
            result = CheckResult(team_id=team_id, status="DOWN", detail=str(e))
            db.set_service_status(team_id, "DOWN", str(e))
        results[team_id] = result
        logger.info("checker: team=%s status=%s", team_id, result.status)
    return results


# ── 내부 헬퍼 ──────────────────────────────────────────────────────────

async def _do_inject(
    client: httpx.AsyncClient,
    base_url: str,
    spec: dict,
    flag: str,
    checker_token: str,
) -> bool:
    """
    vuln_spec.checker.inject 스펙에 따라 flag를 서비스에 주입.

    spec 형식:
      {
        "endpoint": "/admin/inject",
        "method": "POST",
        "body": {"location": "search_cache", "value": "{{FLAG}}"},
        "auth_header": "X-Checker-Token"   # 선택
      }
    """
    url = base_url + spec["endpoint"]
    method = spec.get("method", "POST").upper()
    headers = {}
    auth_header = spec.get("auth_header", "X-Checker-Token")
    headers[auth_header] = checker_token

    body = _substitute_flag(spec.get("body", {}), flag)

    try:
        if method == "POST":
            r = await client.post(url, json=body, headers=headers)
        elif method == "PUT":
            r = await client.put(url, json=body, headers=headers)
        else:
            r = await client.get(url, headers=headers)
        return r.status_code in (200, 201, 204)
    except Exception as e:
        logger.debug("inject 실패 (%s): %s", url, e)
        return False


async def _do_retrieve(
    client: httpx.AsyncClient,
    base_url: str,
    spec: dict,
    flag: str,
    checker_token: str,
) -> bool:
    """
    vuln_spec.checker.retrieve 스펙에 따라 flag가 여전히 서비스에 있는지 확인.

    spec 형식:
      {
        "endpoint": "/admin/check",
        "method": "GET",
        "expect_contains": "{{FLAG}}"
      }
    """
    url = base_url + spec["endpoint"]
    method = spec.get("method", "GET").upper()
    headers = {"X-Checker-Token": checker_token}
    expect = _substitute_flag(spec.get("expect_contains", "{{FLAG}}"), flag)

    try:
        if method == "GET":
            r = await client.get(url, headers=headers)
        else:
            r = await client.post(url, json={}, headers=headers)
        return r.status_code == 200 and expect in r.text
    except Exception as e:
        logger.debug("retrieve 실패 (%s): %s", url, e)
        return False


async def _do_basic_function(
    client: httpx.AsyncClient,
    base_url: str,
    spec: dict,
) -> bool:
    """
    서비스 기본 기능 동작 확인 (/chat 엔드포인트에 정상 메시지 전송).

    spec 형식:
      {
        "payload": "안녕하세요",
        "expect_status": 200
      }
    """
    url = base_url + "/chat"
    payload = spec.get("payload", "안녕하세요")
    expect_status = spec.get("expect_status", 200)

    try:
        r = await client.post(url, json={"message": payload})
        return r.status_code == expect_status
    except Exception as e:
        logger.debug("basic_function 실패 (%s): %s", url, e)
        return False


def _substitute_flag(obj, flag: str):
    """dict/str에서 '{{FLAG}}'를 실제 flag 값으로 치환."""
    if isinstance(obj, str):
        return obj.replace("{{FLAG}}", flag)
    if isinstance(obj, dict):
        return {k: _substitute_flag(v, flag) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_substitute_flag(v, flag) for v in obj]
    return obj
