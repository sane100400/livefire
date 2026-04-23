"""
공격 에이전트 Docker 컨테이너 실행 모듈.

라운드 시작 시 각 팀의 attack_agent 이미지를 백그라운드로 실행.
컨테이너에는 아래 환경 변수가 전달된다:

  COORDINATOR_URL  코디네이터 엔드포인트 (예: http://172.20.0.2:9000)
  ATTACKER_TEAM    이 컨테이너를 실행한 팀 ID (예: teamA)
  TEAM_TOKEN       /attack 호출 시 X-Team-Token 헤더에 사용할 인증 토큰
  ROUND            현재 라운드 번호
  TARGETS          다른 팀 정보 JSON {"teamB": {"ip": ..., "port": ..., "name": ...}, ...}
"""
import json
import logging
import os
import subprocess
from typing import Dict

logger = logging.getLogger(__name__)

# Docker 네트워크: docker-compose.yml의 scoring-net 이름
ATTACK_DOCKER_NETWORK = os.getenv("ATTACK_DOCKER_NETWORK", "hackathon_scoring-net")

# 라운드별 실행 중인 컨테이너 추적 (cleanup용)
# key: (team_id, round_num), value: Popen
_running: Dict[tuple, subprocess.Popen] = {}


def run_attack_agents(
    round_num: int,
    teams: dict,
    coordinator_url: str,
    team_tokens: dict,
    agent_images: dict,
) -> list[subprocess.Popen]:
    """각 팀의 공격 에이전트를 Docker 컨테이너로 비동기 실행."""
    procs = []

    for team_id, token in team_tokens.items():
        image = agent_images.get(team_id)
        if not image:
            logger.warning("%s: 공격 에이전트 이미지 미등록, 건너뜀", team_id)
            continue

        targets = {t: info for t, info in teams.items() if t != team_id}

        cmd = [
            "docker", "run", "--rm",
            "--network", ATTACK_DOCKER_NETWORK,
            "--cpus", "0.5",
            "--memory", "512m",
            "--stop-timeout", "60",
            "-e", f"COORDINATOR_URL={coordinator_url}",
            "-e", f"ATTACKER_TEAM={team_id}",
            "-e", f"TEAM_TOKEN={token}",
            "-e", f"ROUND={round_num}",
            "-e", f"TARGETS={json.dumps(targets, ensure_ascii=False)}",
            image,
        ]

        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            procs.append(proc)
            _running[(team_id, round_num)] = proc
            logger.info("%s 공격 에이전트 시작 (PID %d, 라운드 %d)", team_id, proc.pid, round_num)
        except FileNotFoundError:
            logger.error("'docker' 명령어를 찾을 수 없음 — Docker 설치 여부 확인")
        except Exception as exc:
            logger.error("%s 공격 에이전트 실행 실패: %s", team_id, exc)

    return procs


def stop_round_agents(round_num: int) -> None:
    """라운드 종료 시 해당 라운드의 아직 실행 중인 컨테이너를 정리."""
    keys_to_remove = [k for k in _running if k[1] == round_num]
    for key in keys_to_remove:
        proc = _running.pop(key)
        team_id = key[0]
        if proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=65)
                logger.info("%s 공격 에이전트 라운드 %d 종료됨", team_id, round_num)
            except subprocess.TimeoutExpired:
                proc.kill()
                logger.warning("%s 공격 에이전트 강제 종료 (SIGKILL)", team_id)
            except Exception as exc:
                logger.error("%s 에이전트 종료 실패: %s", team_id, exc)
