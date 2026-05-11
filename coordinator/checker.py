"""
Checker 시스템 (FAUST CTF / iCTF 방식).

매 라운드 시작 전 coordinator가 실행:
  1. 서비스 liveness 확인 (vuln_spec.service.health, 미지정 시 템플릿 호환용 /health)
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
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

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
    team_spec: dict | list[dict],
    round_flags: dict[str, str],         # {vuln_id: flag}
    checker_token: str,
    timeout: float = 8.0,
) -> CheckResult:
    """
    단일 팀 전체 checker 실행.

    Args:
        team_info: {"ip": str, "port": int}
        team_spec: 전체 vuln_spec 또는 vulnerabilities 리스트
        round_flags: 이번 라운드 flag {vuln_id: flag_string}
        checker_token: checker 요청 인증용 토큰
    """
    result = CheckResult(team_id=team_id, status="DOWN")
    base_url = f"http://{team_info['ip']}:{team_info['port']}"
    vulns = _get_vulnerabilities(team_spec)
    service_spec = _get_service_config(team_spec)

    async with httpx.AsyncClient(timeout=timeout) as client:

        # ── 1. liveness ──────────────────────────────────────────────
        health_ok, health_detail = await _do_health(client, base_url, service_spec)
        result.health_ok = health_ok
        if not result.health_ok:
            result.detail = f"health 실패: {health_detail}"
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
    vuln_specs: dict[str, dict | list],
    round_flags_by_team: dict[str, dict[str, str]],
    checker_token: str,
) -> dict[str, CheckResult]:
    """모든 팀 checker를 순차 실행 (이벤트 루프 내에서 병렬 실행 가능하나 순차가 안전)."""
    results = {}
    for team_id, team_info in teams.items():
        team_spec = vuln_specs.get(team_id, [])
        flags = round_flags_by_team.get(team_id, {})
        try:
            result = await check_team(team_id, team_info, team_spec, flags, checker_token)
        except Exception as e:
            logger.error("checker 실행 오류 (%s): %s", team_id, e)
            result = CheckResult(team_id=team_id, status="DOWN", detail=str(e))
            db.set_service_status(team_id, "DOWN", str(e))
        results[team_id] = result
        logger.info("checker: team=%s status=%s", team_id, result.status)
    return results


# ── 내부 헬퍼 ──────────────────────────────────────────────────────────


def _get_vulnerabilities(team_spec: dict | list[dict]) -> list[dict]:
    if isinstance(team_spec, dict):
        vulns = team_spec.get("vulnerabilities", [])
        return vulns if isinstance(vulns, list) else []
    return team_spec if isinstance(team_spec, list) else []


def _get_service_config(team_spec: dict | list[dict]) -> dict:
    if isinstance(team_spec, dict) and isinstance(team_spec.get("service"), dict):
        return team_spec["service"]
    return {}


async def _do_health(
    client: httpx.AsyncClient,
    base_url: str,
    service_spec: dict,
) -> tuple[bool, str]:
    spec = service_spec.get("health") or {"endpoint": "/health", "method": "GET", "expect_status": 200}
    expect_status = spec.get("expect_status", 200)
    try:
        resp = await _send_spec_request(
            client,
            base_url,
            spec,
            default_endpoint="/health",
            default_method="GET",
        )
        if resp.status_code == expect_status:
            return True, ""
        return False, f"HTTP {resp.status_code}"
    except Exception as e:
        return False, str(e)


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
    try:
        r = await _send_spec_request(
            client,
            base_url,
            spec,
            default_method="POST",
            default_auth_header="X-Checker-Token",
            flag=flag,
            checker_token=checker_token,
        )
        return r.status_code in (200, 201, 204)
    except Exception as e:
        logger.debug("inject 실패: %s", e)
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
    expect = _substitute_flag(spec.get("expect_contains", "{{FLAG}}"), flag=flag, checker_token=checker_token)
    expect_status = spec.get("expect_status", 200)

    try:
        r = await _send_spec_request(
            client,
            base_url,
            spec,
            default_method="GET",
            default_auth_header="X-Checker-Token",
            flag=flag,
            checker_token=checker_token,
        )
        return r.status_code == expect_status and expect in _response_text(r, spec.get("response_path"))
    except Exception as e:
        logger.debug("retrieve 실패: %s", e)
        return False


async def _do_basic_function(
    client: httpx.AsyncClient,
    base_url: str,
    spec: dict,
) -> bool:
    """
    서비스 기본 기능 동작 확인. endpoint 미지정 시 템플릿 호환용 /chat 사용.

    spec 형식:
      {
        "payload": "안녕하세요",
        "expect_status": 200
      }
    """
    payload = spec.get("payload", "안녕하세요")
    expect_status = spec.get("expect_status", 200)

    try:
        r = await _send_spec_request(
            client,
            base_url,
            spec,
            default_endpoint="/chat",
            default_method="POST",
            default_body={"message": "{{PAYLOAD}}"},
            payload=payload,
        )
        expect_contains = spec.get("expect_contains")
        text = _response_text(r, spec.get("response_path"))
        return r.status_code == expect_status and (
            not expect_contains or _substitute_flag(expect_contains, payload=payload) in text
        )
    except Exception as e:
        logger.debug("basic_function 실패: %s", e)
        return False


async def _send_spec_request(
    client: httpx.AsyncClient,
    base_url: str,
    spec: dict,
    *,
    default_endpoint: str | None = None,
    default_method: str = "GET",
    default_body: Any = None,
    default_auth_header: str | None = None,
    flag: str = "",
    payload: str = "",
    checker_token: str = "",
) -> httpx.Response:
    endpoint = spec.get("endpoint", default_endpoint)
    if not endpoint or not str(endpoint).startswith("/"):
        raise ValueError(f"endpoint must start with '/': {endpoint!r}")
    method = spec.get("method", default_method).upper()
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
        raise ValueError(f"unsupported method: {method}")

    headers = _substitute_flag(
        spec.get("headers", {}),
        flag=flag,
        payload=payload,
        checker_token=checker_token,
    )
    auth_header = spec.get("auth_header", default_auth_header)
    if auth_header and checker_token:
        headers[auth_header] = checker_token
    params = _substitute_flag(
        spec.get("params", spec.get("query", {})),
        flag=flag,
        payload=payload,
        checker_token=checker_token,
    )
    body = spec.get("json", spec.get("body", default_body))
    data = spec.get("data")
    body = _substitute_flag(body, flag=flag, payload=payload, checker_token=checker_token)
    data = _substitute_flag(data, flag=flag, payload=payload, checker_token=checker_token)
    return await client.request(method, base_url + endpoint, headers=headers, params=params, json=body, data=data)


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


def _substitute_flag(obj, flag: str = "", payload: str = "", checker_token: str = ""):
    """dict/str에서 spec 템플릿 변수를 실제 값으로 치환."""
    if isinstance(obj, str):
        return (
            obj.replace("{{FLAG}}", flag)
            .replace("{{PAYLOAD}}", payload)
            .replace("{{CHECKER_TOKEN}}", checker_token)
        )
    if isinstance(obj, dict):
        return {k: _substitute_flag(v, flag=flag, payload=payload, checker_token=checker_token) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_substitute_flag(v, flag=flag, payload=payload, checker_token=checker_token) for v in obj]
    return obj
