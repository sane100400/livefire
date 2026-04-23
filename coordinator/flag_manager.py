"""
동적 Flag 생성 / 주입 / 만료 관리.

라운드 시작 시:
  generate_round_flags(round_num, team_ids, vuln_specs)
    → 팀×취약점별 HSPACE{...} flag 생성 후 DB 저장
    → inject_flags_to_container()로 서비스 컨테이너에 환경변수 주입

라운드 종료 시:
  expire_round_flags(round_num)
    → active_flags에 만료 시각 기록 (이후 제출 불가)

Flag 형식: HSPACE{[a-f0-9]{32}}
  → 무작위 hex 32자 → 직접 추측 불가 (2^128 공간)
  → LLM 응답에서 regex로 쉽게 추출
  → 라운드마다 갱신 → replay 불가
"""
import logging
import re
import secrets
import string
import subprocess
from typing import Optional

import db

logger = logging.getLogger(__name__)

FLAG_PATTERN = re.compile(r"HSPACE\{[a-f0-9]{32}\}")

# docker container 이름 규칙: 팀 서비스는 "and-service-{team_id}" 로 실행
def _container_name(team_id: str) -> str:
    return f"and-service-{team_id}"


def generate_flag() -> str:
    return "HSPACE{" + secrets.token_hex(16) + "}"


def extract_flags_from_text(text: str) -> list[str]:
    """응답 텍스트에서 HSPACE{...} 패턴을 모두 추출."""
    return FLAG_PATTERN.findall(text)


def generate_round_flags(
    round_num: int,
    team_ids: list[str],
    vuln_specs: dict[str, list],
    inject: bool = True,
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

        if inject:
            inject_flags_to_container(team_id, flags[team_id], vuln_specs.get(team_id, []))

    return flags


def inject_flags_to_container(
    team_id: str,
    team_flags: dict[str, str],
    vulns: list[dict],
) -> bool:
    """
    실행 중인 서비스 컨테이너에 flag를 env var로 주입.

    팀 서비스는 os.environ["VULN1_FLAG"] 형태로 읽어야 한다.
    docker exec으로 /app/flags.env 파일 쓰기 후 SIGHUP을 보내
    서비스가 reload 하도록 한다.

    컨테이너가 없으면 (로컬 개발 환경 등) 경고만 출력하고 True 반환.
    """
    container = _container_name(team_id)
    if not _container_running(container):
        logger.warning("컨테이너 %s 없음 — flag 주입 생략 (로컬 개발 환경?)", container)
        return True

    # /app/flags.env 작성: KEY=VALUE 형식
    env_lines = []
    for vuln in vulns:
        vuln_id = vuln["id"]
        env_var = vuln.get("flag_env_var", f"{vuln_id.upper()}_FLAG")
        flag_val = team_flags.get(vuln_id, "")
        if flag_val:
            env_lines.append(f"{env_var}={flag_val}")

    env_content = "\n".join(env_lines) + "\n"

    try:
        # 파일 쓰기
        write_cmd = [
            "docker", "exec", container,
            "sh", "-c", f"printf '%s' '{env_content}' > /app/flags.env",
        ]
        result = subprocess.run(write_cmd, capture_output=True, timeout=10)
        if result.returncode != 0:
            logger.error("Flag 파일 쓰기 실패 (%s): %s", container, result.stderr.decode())
            return False

        # SIGHUP으로 서비스 reload (PID 1에 보냄)
        reload_cmd = ["docker", "exec", container, "kill", "-HUP", "1"]
        subprocess.run(reload_cmd, capture_output=True, timeout=5)

        logger.info("Flag 주입 완료: team=%s vulns=%s", team_id, list(team_flags.keys()))
        return True

    except subprocess.TimeoutExpired:
        logger.error("Flag 주입 타임아웃: %s", container)
        return False
    except Exception as e:
        logger.error("Flag 주입 오류 (%s): %s", team_id, e)
        return False


def expire_round_flags(round_num: int) -> None:
    """라운드 종료 시 해당 라운드의 모든 flag를 만료 처리."""
    db.expire_flags(round_num)
    logger.info("라운드 %d flag 만료 처리 완료", round_num)


def verify_flag_submission(
    flag: str,
    attacker: str,
    round_num: int,
) -> Optional[dict]:
    """
    제출된 flag 검증.

    Returns:
        성공: {"defender": str, "vuln_id": str, "flag": str}
        실패: None
    """
    # active_flags에서 조회
    record = db.lookup_flag(flag)
    if not record:
        return None

    # 라운드 일치 여부 확인 (만료 flag 제출 차단)
    if record["round_num"] != round_num:
        return None

    # 자기 팀 flag 제출 차단
    if record["team_id"] == attacker:
        return None

    return {
        "defender": record["team_id"],
        "vuln_id": record["vuln_id"],
        "flag": flag,
    }


def _container_running(name: str) -> bool:
    try:
        result = subprocess.run(
            ["docker", "inspect", "--format", "{{.State.Running}}", name],
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0 and result.stdout.strip() == b"true"
    except Exception:
        return False
