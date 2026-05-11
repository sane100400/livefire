"""
공격 에이전트 Docker 컨테이너 실행 모듈.

라운드 시작 시 각 팀의 attack_agent 이미지를 백그라운드로 실행.
컨테이너에는 아래 환경 변수가 전달된다:

  COORDINATOR_URL  코디네이터 엔드포인트 (예: http://10.89.20.2:9000)
  TEAM_ID          이 컨테이너를 실행한 팀 ID (예: teamA)
  MODE             attack
  TARGET_TEAM      이번 agent run의 타겟 팀
  TEAM_TOKEN       /attack 호출 시 X-Team-Token 헤더에 사용할 인증 토큰
  RUNNER_SECRET    공식 agent run 생성용 secret (운영 환경에서만 설정)
  ROUND            현재 라운드 번호
  TARGETS          허용 공격 대상 JSON {"teamC": {"ip": ..., "port": ..., "name": ...}, ...}
  TARGET_REPO_URL  타겟 팀 git smart HTTP URL (읽기 공개)
"""
import json
import logging
import os
import subprocess
from pathlib import Path
from typing import Dict

from rotation import get_attack_targets, get_defense_target

logger = logging.getLogger(__name__)

# Docker 네트워크: docker-compose.yml의 scoring-net 이름
ATTACK_DOCKER_NETWORK = os.getenv("ATTACK_DOCKER_NETWORK", "hackathon_scoring-net")
RUNNER_SECRET = os.getenv("RUNNER_SECRET", "")
AGENT_LOG_DIR = Path(os.getenv(
    "AGENT_LOG_DIR",
    str(Path(__file__).parent.parent / "data" / "agent_logs"),
))

# 라운드별 실행 중인 컨테이너 추적 (cleanup용)
# key: (team_id, round_num), value: Popen
_running: Dict[tuple, subprocess.Popen] = {}


def _run_agent_container(
    *,
    team_id: str,
    target_team: str,
    mode: str,
    round_num: int,
    coordinator_url: str,
    token: str,
    image: str,
    targets: dict,
) -> subprocess.Popen | None:
    cmd = [
        "docker", "run", "--rm",
        "--network", ATTACK_DOCKER_NETWORK,
        "--cpus", "0.5",
        "--memory", "512m",
        "--stop-timeout", "60",
        "-e", f"COORDINATOR_URL={coordinator_url}",
        "-e", f"TEAM_ID={team_id}",
        "-e", f"MODE={mode}",
        "-e", f"TARGET_TEAM={target_team}",
        "-e", f"TEAM_TOKEN={token}",
        "-e", f"ROUND={round_num}",
        "-e", f"TARGETS={json.dumps(targets, ensure_ascii=False)}",
        "-e", f"TARGET_REPO_URL={coordinator_url.rstrip('/')}/git/{target_team}",
        image,
    ]
    if RUNNER_SECRET:
        cmd[-1:-1] = ["-e", f"RUNNER_SECRET={RUNNER_SECRET}"]

    try:
        AGENT_LOG_DIR.mkdir(parents=True, exist_ok=True)
        log_path = AGENT_LOG_DIR / f"round{round_num}-{mode}-{team_id}-to-{target_team}.log"
        with log_path.open("ab") as log_file:
            log_file.write(
                f"\n--- start mode={mode} team={team_id} target={target_team} round={round_num} ---\n".encode()
            )
            proc = subprocess.Popen(
                cmd,
                stdout=log_file,
                stderr=subprocess.STDOUT,
            )
        _running[(mode, team_id, target_team, round_num)] = proc
        logger.info(
            "%s 에이전트 시작 mode=%s target=%s (PID %d, 라운드 %d, log=%s)",
            team_id,
            mode,
            target_team,
            proc.pid,
            round_num,
            log_path,
        )
        return proc
    except FileNotFoundError:
        logger.error("'docker' 명령어를 찾을 수 없음 — Docker 설치 여부 확인")
    except Exception as exc:
        logger.error("%s→%s %s 에이전트 실행 실패: %s", team_id, target_team, mode, exc)
    return None


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

        allowed_targets = get_attack_targets(team_id)
        targets = {t: teams[t] for t in allowed_targets}

        for target_team in allowed_targets:
            proc = _run_agent_container(
                team_id=team_id,
                target_team=target_team,
                mode="attack",
                round_num=round_num,
                coordinator_url=coordinator_url,
                token=token,
                image=image,
                targets=targets,
            )
            if proc:
                procs.append(proc)

    return procs


def run_defense_agents(
    round_num: int,
    teams: dict,
    coordinator_url: str,
    defense_tokens: dict,
    agent_images: dict,
) -> list[subprocess.Popen]:
    """각 팀의 방어 에이전트를 Docker 컨테이너로 비동기 실행."""
    procs = []
    for team_id, token in defense_tokens.items():
        image = agent_images.get(team_id)
        if not image:
            logger.warning("%s: 방어 에이전트 이미지 미등록, 건너뜀", team_id)
            continue
        target_team = get_defense_target(team_id)
        targets = {target_team: teams[target_team]}
        proc = _run_agent_container(
            team_id=team_id,
            target_team=target_team,
            mode="defense",
            round_num=round_num,
            coordinator_url=coordinator_url,
            token=token,
            image=image,
            targets=targets,
        )
        if proc:
            procs.append(proc)
    return procs


def stop_round_agents(round_num: int) -> None:
    """라운드 종료 시 해당 라운드의 아직 실행 중인 컨테이너를 정리."""
    keys_to_remove = [k for k in _running if k[-1] == round_num]
    for key in keys_to_remove:
        proc = _running.pop(key)
        mode, team_id = key[0], key[1]
        if proc.poll() is None:
            try:
                proc.terminate()
                proc.wait(timeout=65)
                logger.info("%s %s 에이전트 라운드 %d 종료됨", team_id, mode, round_num)
            except subprocess.TimeoutExpired:
                proc.kill()
                logger.warning("%s %s 에이전트 강제 종료 (SIGKILL)", team_id, mode)
            except Exception as exc:
                logger.error("%s %s 에이전트 종료 실패: %s", team_id, mode, exc)
