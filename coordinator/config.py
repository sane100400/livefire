import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).with_name(".env"))


def _env_bool(name: str, default: str = "0") -> bool:
    return os.getenv(name, default).strip().lower() in {"1", "true", "yes", "on"}

# ── 팀 설정 (행사 시작 전 주최측이 IP 채워넣기) ────────────────────
# 각 팀은 web_service/ 를 기본 포트 8000으로 실행한다.
TEAM_SUFFIXES = tuple(
    suffix.strip().upper()
    for suffix in os.getenv("TEAM_SUFFIXES", "1,2,3,4,5,6").split(",")
    if suffix.strip()
)


def _team_id(team_suffix: str) -> str:
    return f"team{team_suffix.upper()}"


def _team_port(team_suffix: str) -> int:
    return int(os.getenv(f"PORT_TEAM_{team_suffix}", "8000"))


def _team_ip(team_suffix: str, index: int) -> str:
    return os.getenv(f"IP_TEAM_{team_suffix}", f"10.89.21.{10 + index}")


TEAMS = {
    _team_id(suffix): {
        "ip": _team_ip(suffix, index),
        "port": _team_port(suffix),
        "name": f"Team {suffix}",
    }
    for index, suffix in enumerate(TEAM_SUFFIXES)
}
TEAM_ORDER = list(TEAMS.keys())

STARTING_SCORE      = 1000
MAX_ATTACKS_ROUND   = int(os.getenv("MAX_ATTACKS_ROUND", "10"))  # 팀당 라운드 탐색 요청 수
ATTACK_REWARD       = 10    # 익스플로잇 성공 시 공격팀 획득
ATTACK_PENALTY      = 10    # 익스플로잇 성공 시 방어팀 차감
AVAILABILITY_BONUS  = 10    # 서비스 살아있으면 라운드당 획득
TOTAL_ROUNDS        = 20
COORDINATOR_PORT    = 9000

# ── 시크릿 (반드시 .env 에서 로드, 없으면 시작 시 KeyError로 크래시) ─
ADMIN_SECRET = os.environ["ADMIN_SECRET"]
CHECKER_TOKEN = os.getenv("CHECKER_TOKEN", "checker-token-changeme")

# ── 팀 인증 토큰 (행사 당일 .env에서 로드 후 각 팀에게 배포) ────────
TEAM_TOKENS = {_team_id(suffix): os.environ[f"TOKEN_TEAM_{suffix}"] for suffix in TEAM_SUFFIXES}

# 디펜스 에이전트 전용 토큰. 운영에서는 오프라인 참가자에게만 배포하고,
# 팀 토큰과 다른 값으로 설정한다. 미설정 시 로컬 개발 편의를 위해 팀 토큰으로 fallback한다.
DEFENSE_TOKENS = {
    _team_id(suffix): os.getenv(f"DEFENSE_TOKEN_TEAM_{suffix}", TEAM_TOKENS[_team_id(suffix)])
    for suffix in TEAM_SUFFIXES
}

# 공식 agent run 생성 보호용. 운영 환경에서는 반드시 설정하고, coordinator가
# 실행하는 attack/defense agent 컨테이너에만 주입한다.
RUNNER_SECRET = os.getenv("RUNNER_SECRET", "")
ALLOW_UNSAFE_AGENT_RUNS = _env_bool("ALLOW_UNSAFE_AGENT_RUNS")
ALLOW_STUDENT_AGENT_RUNS = _env_bool("ALLOW_STUDENT_AGENT_RUNS")

# ── 공격 에이전트 Docker 이미지 (행사 전 팀 제출물 빌드 후 등록) ─────
# docker build -t and-attack-team1:latest ./attack_agent_team1/
ATTACK_AGENT_IMAGES = {
    _team_id(suffix): f"and-attack-team{suffix.lower()}:latest"
    for suffix in TEAM_SUFFIXES
}

DEFENSE_AGENT_IMAGES = {
    _team_id(suffix): f"and-defense-team{suffix.lower()}:latest"
    for suffix in TEAM_SUFFIXES
}

COORDINATOR_URL = os.getenv("COORDINATOR_URL", "http://localhost:42000")

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

# ── 요청 크기/비용 제한 ─────────────────────────────────────────────
MAX_LLM_MESSAGES = int(os.getenv("MAX_LLM_MESSAGES", "32"))
MAX_LLM_PROMPT_BYTES = int(os.getenv("MAX_LLM_PROMPT_BYTES", str(128 * 1024)))
MAX_LLM_MAX_TOKENS = int(os.getenv("MAX_LLM_MAX_TOKENS", "4096"))
MAX_ATTACK_REQUEST_BYTES = int(os.getenv("MAX_ATTACK_REQUEST_BYTES", str(64 * 1024)))
MAX_ATTACK_RESPONSE_BYTES = int(os.getenv("MAX_ATTACK_RESPONSE_BYTES", str(128 * 1024)))

# ── 요청 빈도 제한 ─────────────────────────────────────────────────
# 키 기준: agent run token > bearer token > team token > admin secret > client IP.
# 기본값은 6팀 동시 운영 기준으로, 정상 agent 루프는 통과시키되 runaway loop는 빠르게 429로 막는다.
_LEGACY_RATE_LIMIT_AGENT_RUNS = os.getenv("RATE_LIMIT_AGENT_RUNS")
RATE_LIMIT_ATTACK_AGENT_RUNS = os.getenv(
    "RATE_LIMIT_ATTACK_AGENT_RUNS",
    _LEGACY_RATE_LIMIT_AGENT_RUNS or "10/minute",
)
RATE_LIMIT_DEFENSE_AGENT_RUNS = os.getenv(
    "RATE_LIMIT_DEFENSE_AGENT_RUNS",
    _LEGACY_RATE_LIMIT_AGENT_RUNS or "5/minute",
)
RATE_LIMIT_AGENT_RUNS = _LEGACY_RATE_LIMIT_AGENT_RUNS or RATE_LIMIT_ATTACK_AGENT_RUNS
RATE_LIMIT_REPO_ARCHIVE = os.getenv("RATE_LIMIT_REPO_ARCHIVE", "6/minute")
RATE_LIMIT_LLM = os.getenv("RATE_LIMIT_LLM", "30/minute")
RATE_LIMIT_ATTACK = os.getenv("RATE_LIMIT_ATTACK", "20/minute")
RATE_LIMIT_POC_SUBMIT = os.getenv("RATE_LIMIT_POC_SUBMIT", "12/minute")
RATE_LIMIT_TOOLS = os.getenv("RATE_LIMIT_TOOLS", "60/minute")

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
