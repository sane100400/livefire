"""
채점 로직.

PoC 방식:
  1. 공격 에이전트가 /attack으로 탐색
  2. 재현 가능한 poc*.py를 /pocs로 제출
  3. accepted PoC를 라운드마다 runner가 실행
  4. coordinator가 active_flags와 대조 → 점수 부여

SLA 상태 반영:
  OK     → 가용성 보너스 획득 가능 + 방어 패널티 감점 대상
  FAULTY → 가용성 보너스 없음, 방어 패널티 적용
  DOWN   → 가용성 보너스 없음, 방어 패널티 없음 (서비스 자체가 없음)
"""
import json
import logging
import os
from typing import Dict

import httpx

import db
from flag_manager import extract_flags_from_text

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

    availability_changes: Dict[str, int] = {t: 0 for t in team_ids}

    # 가용성 보너스
    for team in team_ids:
        if availability.get(team, False):
            status = service_statuses.get(team, "UNKNOWN")
            if status == "OK":
                availability_changes[team] += availability_bonus

    poc_changes = db.sum_poc_score_deltas(round_num, team_ids)
    score_changes = {
        team: availability_changes.get(team, 0)
        + poc_changes.get(team, 0)
        for team in team_ids
    }

    return {
        "score_changes": score_changes,
        "availability_score_changes": availability_changes,
        "poc_score_changes": poc_changes,
        "service_statuses": service_statuses,
    }
