"""
동적 Flag 생성 / 주입 / 만료 관리.

라운드 시작 시:
  generate_round_flags(round_num, team_ids, vuln_specs)
    → 팀×취약점별 HSPACE{...} flag 생성 후 DB 저장

실제 서비스 런타임 주입은 checker spec의 /admin/inject로 수행한다.

라운드 종료 시:
  expire_round_flags(round_num)
    → active_flags에 만료 시각 기록 (이후 제출 불가)

Flag 형식: HSPACE{[a-f0-9]{32}}
  → 무작위 hex 32자 → 직접 추측 불가 (2^128 공간)
  → LLM 응답에서 regex로 쉽게 추출
  → 라운드마다 갱신 → replay 불가
"""
import asyncio
import logging
import re
import secrets

import httpx

import db

logger = logging.getLogger(__name__)

FLAG_PATTERN = re.compile(r"HSPACE\{[a-f0-9]{32}\}")


def generate_flag() -> str:
    return "HSPACE{" + secrets.token_hex(16) + "}"


def extract_flags_from_text(text: str) -> list[str]:
    """응답 텍스트에서 HSPACE{...} 패턴을 모두 추출."""
    return FLAG_PATTERN.findall(text)


def generate_round_flags(
    round_num: int,
    team_ids: list[str],
    vuln_specs: dict[str, list],
) -> dict[str, dict[str, str]]:
    """
    라운드별 팀×취약점 flag 생성 후 DB 저장.

    Returns:
        { team_id: { vuln_id: flag_string } }
    """
    flags: dict[str, dict[str, str]] = {}

    for team_id in team_ids:
        vulns = vuln_specs.get(team_id, [])
        if not vulns:
            logger.warning("팀 %s: vuln_spec 없음, flag 생성 건너뜀", team_id)
            continue

        flags[team_id] = {}
        for vuln in vulns:
            vuln_id = vuln["id"]
            flag = generate_flag()
            db.upsert_flag(round_num, team_id, vuln_id, flag)
            flags[team_id][vuln_id] = flag
            logger.debug("Flag 생성: round=%d team=%s vuln=%s flag=%s", round_num, team_id, vuln_id, flag)

    return flags


async def inject_flags_via_checker(
    team_info: dict,
    team_flags: dict[str, str],
    vulns: list[dict],
    checker_token: str,
    timeout: float = 10.0,
    attempts: int = 10,
    retry_delay: float = 0.5,
) -> bool:
    """
    Runtime flag injection through each vuln's checker.inject spec.

    This is the canonical path after a service container has already started.
    It keeps service implementations independent from process env reload
    behavior and matches the required /admin/inject contract.
    """
    base_url = f"http://{team_info['ip']}:{team_info['port']}"
    ok = True
    async with httpx.AsyncClient(timeout=timeout) as client:
        for vuln in vulns:
            vuln_id = vuln.get("id")
            flag = team_flags.get(vuln_id or "")
            inject_spec = vuln.get("checker", {}).get("inject")
            if not vuln_id or not flag or not inject_spec:
                continue

            endpoint = inject_spec["endpoint"]
            method = inject_spec.get("method", "POST").upper()
            auth_header = inject_spec.get("auth_header", "X-Checker-Token")
            headers = {auth_header: checker_token}
            body = _substitute_flag(inject_spec.get("body", {}), flag)
            url = base_url + endpoint

            injected = False
            last_error = ""
            for attempt in range(1, attempts + 1):
                try:
                    if method == "POST":
                        resp = await client.post(url, json=body, headers=headers)
                    elif method == "PUT":
                        resp = await client.put(url, json=body, headers=headers)
                    else:
                        resp = await client.get(url, headers=headers)
                    if resp.status_code in (200, 201, 204):
                        injected = True
                        break
                    last_error = f"HTTP {resp.status_code}"
                except Exception as exc:
                    last_error = str(exc)

                if attempt < attempts:
                    await asyncio.sleep(retry_delay)

            if not injected:
                logger.error("checker flag inject failed after retries: %s %s %s", method, url, last_error)
                ok = False
    return ok


def _substitute_flag(obj, flag: str):
    if isinstance(obj, str):
        return obj.replace("{{FLAG}}", flag)
    if isinstance(obj, dict):
        return {k: _substitute_flag(v, flag) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_substitute_flag(v, flag) for v in obj]
    return obj


def expire_round_flags(round_num: int) -> None:
    """라운드 종료 시 해당 라운드의 모든 flag를 만료 처리."""
    db.expire_flags(round_num)
    logger.info("라운드 %d flag 만료 처리 완료", round_num)
