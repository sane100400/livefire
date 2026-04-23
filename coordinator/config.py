import os
from dotenv import load_dotenv

load_dotenv()

# ── 팀 설정 (행사 시작 전 주최측이 IP 채워넣기) ────────────────────
# 각 팀은 agent_service/ 를 포트 8000으로 실행
TEAMS = {
    "teamA": {"ip": os.getenv("IP_TEAM_A", "172.21.0.10"), "port": 8000, "name": "Team A"},
    "teamB": {"ip": os.getenv("IP_TEAM_B", "172.21.0.11"), "port": 8000, "name": "Team B"},
    "teamC": {"ip": os.getenv("IP_TEAM_C", "172.21.0.12"), "port": 8000, "name": "Team C"},
    "teamD": {"ip": os.getenv("IP_TEAM_D", "172.21.0.13"), "port": 8000, "name": "Team D"},
    "teamE": {"ip": os.getenv("IP_TEAM_E", "172.21.0.14"), "port": 8000, "name": "Team E"},
    "teamF": {"ip": os.getenv("IP_TEAM_F", "172.21.0.15"), "port": 8000, "name": "Team F"},
}

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
CREDIT_PER_TEAM = 2.0   # 팀당 LLM API 크레딧 총액 (USD)

# ── 팀 인증 토큰 (행사 당일 .env에서 로드 후 각 팀에게 배포) ────────
TEAM_TOKENS = {
    "teamA": os.environ["TOKEN_TEAM_A"],
    "teamB": os.environ["TOKEN_TEAM_B"],
    "teamC": os.environ["TOKEN_TEAM_C"],
    "teamD": os.environ["TOKEN_TEAM_D"],
    "teamE": os.environ["TOKEN_TEAM_E"],
    "teamF": os.environ["TOKEN_TEAM_F"],
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
