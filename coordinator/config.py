import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).with_name(".env"))

# ── 팀 설정 (행사 시작 전 주최측이 IP 채워넣기) ────────────────────
# 각 팀은 agent_service/ 를 기본 포트 8000으로 실행한다.
def _team_port(team_suffix: str) -> int:
    return int(os.getenv(f"PORT_TEAM_{team_suffix}", "8000"))


TEAMS = {
    "teamA": {"ip": os.getenv("IP_TEAM_A", "10.89.21.10"), "port": _team_port("A"), "name": "Team A"},
    "teamB": {"ip": os.getenv("IP_TEAM_B", "10.89.21.11"), "port": _team_port("B"), "name": "Team B"},
    "teamC": {"ip": os.getenv("IP_TEAM_C", "10.89.21.12"), "port": _team_port("C"), "name": "Team C"},
    "teamD": {"ip": os.getenv("IP_TEAM_D", "10.89.21.13"), "port": _team_port("D"), "name": "Team D"},
    "teamE": {"ip": os.getenv("IP_TEAM_E", "10.89.21.14"), "port": _team_port("E"), "name": "Team E"},
    "teamF": {"ip": os.getenv("IP_TEAM_F", "10.89.21.15"), "port": _team_port("F"), "name": "Team F"},
}
TEAM_ORDER = ["teamA", "teamB", "teamC", "teamD", "teamE", "teamF"]

STARTING_SCORE      = 1000
MAX_ATTACKS_ROUND   = 10    # 팀당 라운드 외부 요청 횟수 (전 타겟 합산, 내부 추론 스텝은 무제한)
ATTACK_REWARD       = 10    # 익스플로잇 성공 시 공격팀 획득
ATTACK_PENALTY      = 10    # 익스플로잇 성공 시 방어팀 차감
AVAILABILITY_BONUS  = 10    # 서비스 살아있으면 라운드당 획득
TOTAL_ROUNDS        = 20
COORDINATOR_PORT    = 9000

# ── 시크릿 (반드시 .env 에서 로드, 없으면 시작 시 KeyError로 크래시) ─
ADMIN_SECRET = os.environ["ADMIN_SECRET"]

# ── 팀 인증 토큰 (행사 당일 .env에서 로드 후 각 팀에게 배포) ────────
TEAM_TOKENS = {
    "teamA": os.environ["TOKEN_TEAM_A"],
    "teamB": os.environ["TOKEN_TEAM_B"],
    "teamC": os.environ["TOKEN_TEAM_C"],
    "teamD": os.environ["TOKEN_TEAM_D"],
    "teamE": os.environ["TOKEN_TEAM_E"],
    "teamF": os.environ["TOKEN_TEAM_F"],
}

# 디펜스 에이전트 전용 토큰. 운영에서는 오프라인 참가자에게만 배포한다.
# 로컬 개발 편의를 위해 미설정 시 팀 토큰으로 fallback한다.
DEFENSE_TOKENS = {
    "teamA": os.getenv("DEFENSE_TOKEN_TEAM_A", TEAM_TOKENS["teamA"]),
    "teamB": os.getenv("DEFENSE_TOKEN_TEAM_B", TEAM_TOKENS["teamB"]),
    "teamC": os.getenv("DEFENSE_TOKEN_TEAM_C", TEAM_TOKENS["teamC"]),
    "teamD": os.getenv("DEFENSE_TOKEN_TEAM_D", TEAM_TOKENS["teamD"]),
    "teamE": os.getenv("DEFENSE_TOKEN_TEAM_E", TEAM_TOKENS["teamE"]),
    "teamF": os.getenv("DEFENSE_TOKEN_TEAM_F", TEAM_TOKENS["teamF"]),
}

# 공식 agent run 생성 보호용. 운영 환경에서는 반드시 설정하고, coordinator가
# 실행하는 attack/defense agent 컨테이너에만 주입한다. 미설정이면 로컬 개발
# 편의를 위해 기존 팀 토큰 기반 run 생성을 허용한다.
RUNNER_SECRET = os.getenv("RUNNER_SECRET", "")

# ── 공격 에이전트 Docker 이미지 (행사 전 팀 제출물 빌드 후 등록) ─────
# docker build -t and-attack-teama:latest ./attack_agent_teamA/
ATTACK_AGENT_IMAGES = {
    "teamA": "and-attack-teama:latest",
    "teamB": "and-attack-teamb:latest",
    "teamC": "and-attack-teamc:latest",
    "teamD": "and-attack-teamd:latest",
    "teamE": "and-attack-teame:latest",
    "teamF": "and-attack-teamf:latest",
}

DEFENSE_AGENT_IMAGES = {
    "teamA": "and-defense-teama:latest",
    "teamB": "and-defense-teamb:latest",
    "teamC": "and-defense-teamc:latest",
    "teamD": "and-defense-teamd:latest",
    "teamE": "and-defense-teame:latest",
    "teamF": "and-defense-teamf:latest",
}

COORDINATOR_URL = os.getenv("COORDINATOR_URL", "http://localhost:9000")

# ── OpenRouter gateway ───────────────────────────────────────────────
OPENROUTER_API_KEY = os.getenv("OPENROUTER_API_KEY", "")
OPENROUTER_BASE_URL = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1")

# ── PoC 저장/실행 ───────────────────────────────────────────────────
DATA_DIR = os.getenv("DATA_DIR", os.path.join(os.path.dirname(__file__), "..", "data"))
POC_TIMEOUT_SEC = int(os.getenv("POC_TIMEOUT_SEC", "20"))
POC_MAX_BYTES = int(os.getenv("POC_MAX_BYTES", str(64 * 1024)))
POC_OUTPUT_MAX_BYTES = int(os.getenv("POC_OUTPUT_MAX_BYTES", str(64 * 1024)))
POC_RUNNER_MODE = os.getenv("POC_RUNNER_MODE", "auto")  # auto / docker / local
POC_DOCKER_NETWORK = os.getenv("POC_DOCKER_NETWORK", "hackathon_target-net")
POC_DOCKER_IMAGE = os.getenv("POC_DOCKER_IMAGE", "python:3.11-slim")
# Docker socket 사용 시 host daemon은 컨테이너 내부 DATA_DIR 경로를 모른다.
# docker-compose는 이 값을 host의 ./data 절대경로로 넘긴다.
POC_HOST_DATA_DIR = os.getenv("POC_HOST_DATA_DIR", "")

# ── 파일 경로 ────────────────────────────────────────────────────────
VULN_SPEC_DIR = os.getenv("VULN_SPEC_DIR", os.path.join(os.path.dirname(__file__), "..", "vuln_specs"))
DB_PATH = os.getenv("DB_PATH", os.path.join(os.path.dirname(__file__), "game_state.db"))

# ── 모델 화이트리스트 ────────────────────────────────────────────────
# 선정 기준:
#   1) OpenRouter에서 실제 사용 가능한 모델
#   2) 2026년 이전 출시 (신규 플래그십 제외)
#   3) 공식 공격/방어 런타임에서 단발 한계가 분명한 저성능·경량·mini/flash/small 계열
#
# 매칭: model ID가 아래 prefix 중 하나로 시작하면 허용.
# OpenRouter 형식: "{provider}/{model-name}" 또는 "{provider}/{model-name}:free"
ALLOWED_MODEL_PREFIXES: list[str] = [
    "qwen/qwen-2.5-14b",
    "openai/gpt-4o-mini",
    "google/gemini-flash-1.5",
    "google/gemini-2.0-flash-001",
    "microsoft/phi-4",
    "mistralai/mistral-small-3.1",
    "xiaomi/mimo",
]
