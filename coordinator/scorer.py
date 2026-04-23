"""
채점 로직.

live-fire 방식:
  1. 공격 에이전트가 /attack으로 페이로드 전송
  2. 응답에서 HSPACE{ 패턴 추출 (flag_manager.extract_flags_from_text)
  3. 추출한 flag를 /submit-flag로 제출
  4. coordinator가 active_flags와 대조 → 점수 부여

SLA 상태 반영:
  OK     → 가용성 보너스 획득 가능 + 방어 패널티 감점 대상
  FAULTY → 가용성 보너스 없음, 방어 패널티 적용
  DOWN   → 가용성 보너스 없음, 방어 패널티 없음 (서비스 자체가 없음)
"""
import json
import logging
import os
import re
from typing import Dict, Optional

import httpx

import db
from flag_manager import FLAG_PATTERN, extract_flags_from_text

logger = logging.getLogger(__name__)


def load_vuln_specs(vuln_spec_dir: str) -> Dict[str, list]:
    """팀별 취약점 전체 스펙 로드. {team_id: [vuln_dict, ...]}"""
    specs: Dict[str, list] = {}
    if not os.path.exists(vuln_spec_dir):
        return specs
    for fname in os.listdir(vuln_spec_dir):
        if not fname.endswith(".json") or fname == "example.json":
            continue
        path = os.path.join(vuln_spec_dir, fname)
        with open(path) as f:
            data = json.load(f)
        team_id = data.get("team_id")
        vulns = data.get("vulnerabilities", [])
        if team_id and vulns:
            specs[team_id] = vulns
    return specs


def scan_response_for_flags(response_text: str) -> list[str]:
    """응답 텍스트에서 HSPACE{ 패턴을 모두 추출."""
    return extract_flags_from_text(response_text)


def verify_and_record_flag(
    flag: str,
    attacker: str,
    round_num: int,
) -> Optional[dict]:
    """
    flag 검증 + 제출 기록 저장.

    Returns:
        성공: {"defender": str, "vuln_id": str, "first_capture": bool}
        실패(오답/자기팀/만료/중복): None
    """
    from flag_manager import verify_flag_submission

    # 유효성 검증
    match = verify_flag_submission(flag, attacker, round_num)
    if not match:
        # 기록은 남기되 valid=0
        db.submit_flag(round_num, attacker, flag, valid=False)
        return None

    # 제출 기록 (UNIQUE 제약으로 중복 제출 자동 차단)
    is_new = db.submit_flag(
        round_num, attacker, flag,
        valid=True,
        defender=match["defender"],
        vuln_id=match["vuln_id"],
    )
    if not is_new:
        return None  # 이미 제출됨 (다른 공격자 또는 자신이 먼저 제출)

    return {
        "defender": match["defender"],
        "vuln_id": match["vuln_id"],
        "first_capture": True,
    }


async def check_availability(teams: dict) -> Dict[str, bool]:
    """각 팀 방어 에이전트 /health 체크. SLA 계산용."""
    results = {}
    async with httpx.AsyncClient(timeout=5.0) as client:
        for team_id, info in teams.items():
            url = f"http://{info['ip']}:{info['port']}/health"
            try:
                r = await client.get(url)
                results[team_id] = r.status_code == 200
            except Exception:
                results[team_id] = False
    return results


def compute_round_scores(
    team_ids: list[str],
    round_num: int,
    availability: Dict[str, bool],
    attack_reward: int,
    attack_penalty: int,
    availability_bonus: int,
) -> dict:
    """
    라운드 종료 시 점수 계산.

    SLA 규칙:
      OK + 살아있음     → availability_bonus 획득
      DOWN              → 패널티 없음 (서비스 없어서 공격 못 받음)
      FAULTY            → 패널티 적용, 보너스 없음
    """
    service_statuses = db.get_service_statuses()
    flag_captures = db.count_valid_captures(round_num)

    score_changes: Dict[str, int] = {t: 0 for t in team_ids}

    # 가용성 보너스
    for team in team_ids:
        if availability.get(team, False):
            status = service_statuses.get(team, "UNKNOWN")
            if status == "OK":
                score_changes[team] += availability_bonus

    # flag 탈취 점수
    subs = db.get_flag_submissions(round_num=round_num)
    processed_defenders = {}  # {(attacker, defender): True} 중복 방지

    for sub in subs:
        if not sub["valid"]:
            continue
        attacker = sub["attacker"]
        defender = sub["defender"]
        key = (attacker, defender)
        if key in processed_defenders:
            continue
        processed_defenders[key] = True

        defender_status = service_statuses.get(defender, "UNKNOWN")

        score_changes[attacker] = score_changes.get(attacker, 0) + attack_reward

        if defender_status != "DOWN":
            score_changes[defender] = score_changes.get(defender, 0) - attack_penalty

    return {
        "score_changes": score_changes,
        "service_statuses": service_statuses,
        "flag_captures": flag_captures,
    }
