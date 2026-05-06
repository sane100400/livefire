import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(Path(__file__).with_name(".env"))

# ── 팀 설정 (행사 시작 전 주최측이 IP 채워넣기) ────────────────────
# 각 팀은 agent_service/ 를 기본 포트 8000으로 실행한다.
def _team_port(team_suffix: str) -> int:
    return int(os.getenv(f"PORT_TEAM_{team_suffix}", "8000"))


TEAMS = {
    "teamA": {"ip": os.getenv("IP_TEAM_A", "172.21.0.10"), "port": _team_port("A"), "name": "Team A"},
    "teamB": {"ip": os.getenv("IP_TEAM_B", "172.21.0.11"), "port": _team_port("B"), "name": "Team B"},
    "teamC": {"ip": os.getenv("IP_TEAM_C", "172.21.0.12"), "port": _team_port("C"), "name": "Team C"},
    "teamD": {"ip": os.getenv("IP_TEAM_D", "172.21.0.13"), "port": _team_port("D"), "name": "Team D"},
    "teamE": {"ip": os.getenv("IP_TEAM_E", "172.21.0.14"), "port": _team_port("E"), "name": "Team E"},
    "teamF": {"ip": os.getenv("IP_TEAM_F", "172.21.0.15"), "port": _team_port("F"), "name": "Team F"},
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

# ── 크레딧 ──────────────────────────────────────────────────────────
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

# ── 공격 에이전트 Docker 이미지 (행사 전 팀 제출물 빌드 후 등록) ─────
# docker build -t and-attack-teamA:latest ./attack_agent_teamA/
ATTACK_AGENT_IMAGES = {
    "teamA": "and-attack-teamA:latest",
    "teamB": "and-attack-teamB:latest",
    "teamC": "and-attack-teamC:latest",
    "teamD": "and-attack-teamD:latest",
    "teamE": "and-attack-teamE:latest",
    "teamF": "and-attack-teamF:latest",
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

# legacy /submit-flag 즉시 채점은 신규 PoC 채점 모델과 충돌하므로 기본 비활성화.
ENABLE_LEGACY_SUBMIT_FLAG = os.getenv("ENABLE_LEGACY_SUBMIT_FLAG", "0") == "1"

# ── 파일 경로 ────────────────────────────────────────────────────────
VULN_SPEC_DIR = os.getenv("VULN_SPEC_DIR", os.path.join(os.path.dirname(__file__), "..", "vuln_specs"))
DB_PATH = os.getenv("DB_PATH", os.path.join(os.path.dirname(__file__), "game_state.db"))

# ── 모델 화이트리스트 ────────────────────────────────────────────────
# 선정 기준:
#   1) OpenRouter에서 실제 사용 가능한 모델
#   2) 2026년 이전 출시 (신규 플래그십 제외)
#   3) 7B–14B 급 — 단발 프롬프트로는 한계, 오케스트레이션 시 성능 3× 이상 향상 구간
#
# 매칭: model ID가 아래 prefix 중 하나로 시작하면 허용.
# OpenRouter 형식: "{provider}/{model-name}" 또는 "{provider}/{model-name}:free"
ALLOWED_MODEL_PREFIXES: list[str] = [
    "qwen/qwen-2.5-14b",
    "qwen/qwen-2.5-32b",
    "meta-llama/llama-3.1-70b",
    "google/gemma-3-27b",
    "openai/gpt-4o-mini",
    "google/gemini-flash-1.5",
    "google/gemini-2.0-flash-001",
    "microsoft/phi-4",
    "mistralai/mistral-small-3.1",
    "deepseek/deepseek-chat",
    "xiaomi/mimo",
]
