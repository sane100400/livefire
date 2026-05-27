import hashlib
import hmac
import json
import os
import secrets
import time
import asyncio
import httpx
from fastapi import FastAPI, HTTPException, Header, Request, Query, UploadFile, File, Form
from fastapi.responses import JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from limits import parse as parse_rate_limit
from limits.storage import MemoryStorage
from limits.strategies import FixedWindowRateLimiter
from pydantic import BaseModel
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from uuid import uuid4

import db
import flag_manager as fm
import checker as chk
from git_handler import router as git_router, init_all_repos, handle_service_deployed, archive_team_repo
from config import (
    TEAMS, STARTING_SCORE, MAX_ATTACKS_ROUND,
    ATTACK_REWARD, ATTACK_PENALTY, AVAILABILITY_BONUS,
    TOTAL_ROUNDS, COORDINATOR_PORT, ADMIN_SECRET,
    TEAM_TOKENS, ATTACK_AGENT_IMAGES, COORDINATOR_URL,
    DEFENSE_TOKENS, DEFENSE_AGENT_IMAGES,
    RUNNER_SECRET, CHECKER_TOKEN,
    ALLOWED_MODEL_PREFIXES,
    VULN_SPEC_DIR, DB_PATH,
    OPENROUTER_API_KEY, OPENROUTER_BASE_URL,
    DATA_DIR, POC_TIMEOUT_SEC, POC_MAX_TIMEOUT_SEC, POC_MAX_BYTES, POC_OUTPUT_MAX_BYTES,
    MAX_POCS_PER_VULN_ROUND,
    POC_RUNNER_MODE, POC_DOCKER_NETWORK, POC_DOCKER_IMAGE, POC_HOST_DATA_DIR,
    SCORING_SNAPSHOT_ENABLED, SCORING_SNAPSHOT_NETWORK,
    SCORING_SNAPSHOT_IP_PREFIX, SCORING_SNAPSHOT_IP_START,
    SCORING_SNAPSHOT_STARTUP_GRACE_SEC, SCORING_SNAPSHOT_KEEP_CONTAINERS,
    ALLOW_STUDENT_AGENT_RUNS, ALLOW_UNSAFE_AGENT_RUNS,
    MAX_LLM_MESSAGES, MAX_LLM_PROMPT_BYTES, MAX_LLM_MAX_TOKENS,
    MAX_ATTACK_REQUEST_BYTES, MAX_ATTACK_RESPONSE_BYTES,
    RATE_LIMIT_ATTACK_AGENT_RUNS, RATE_LIMIT_DEFENSE_AGENT_RUNS,
    RATE_LIMIT_REPO_ARCHIVE, RATE_LIMIT_LLM,
    RATE_LIMIT_ATTACK, RATE_LIMIT_POC_SUBMIT, RATE_LIMIT_TOOLS,
)
from rotation import (
    assert_attack_allowed,
    assert_defense_allowed,
    get_attack_targets,
    get_defense_target,
    get_defender,
)
from state import GameState
from scorer import (
    load_vuln_specs,
    scan_response_for_flags, compute_round_scores,
)
from agent_runner import run_attack_agents, run_defense_agents, stop_round_agents
from poc_runner import run_pocs_for_round
from scoring_snapshot import create_round_snapshot, cleanup_round_snapshot

SDK_NAME = "hspace-agent-sdk/1"
SDK_SIGNATURE_MAX_SKEW_SEC = 300


def _limiter_secret_key(prefix: str, value: str) -> str:
    return f"{prefix}:{hashlib.sha256(value.encode('utf-8')).hexdigest()[:20]}"


def _rate_limit_key(request: Request) -> str:
    run_token = request.headers.get("X-Agent-Run-Token")
    if run_token:
        return _limiter_secret_key("run", run_token)

    authorization = request.headers.get("Authorization", "")
    bearer_prefix = "Bearer "
    if authorization.lower().startswith(bearer_prefix.lower()):
        bearer = authorization[len(bearer_prefix):].strip()
        if bearer:
            return _limiter_secret_key("bearer", bearer)

    team_token = request.headers.get("X-Team-Token")
    if team_token:
        return _limiter_secret_key("team", team_token)

    admin_secret = request.headers.get("X-Admin-Secret")
    if admin_secret:
        return _limiter_secret_key("admin", admin_secret)

    return f"ip:{get_remote_address(request)}"


limiter = Limiter(key_func=_rate_limit_key)
agent_run_limiter = FixedWindowRateLimiter(MemoryStorage())

state = GameState(list(TEAMS.keys()), STARTING_SCORE)
vuln_specs: dict = {}


@asynccontextmanager
async def lifespan(app: FastAPI):
    state.load(DB_PATH)
    vuln_specs.update(load_vuln_specs(VULN_SPEC_DIR))
    print(f"Loaded vuln specs for: {list(vuln_specs.keys())}")
    init_all_repos(list(TEAMS.keys()))
    yield


app = FastAPI(lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])
app.include_router(git_router)


def _tool_path(name: str) -> Path:
    if name not in {"gitctf.py", "validate_vulns.py", "agent.py"}:
        raise HTTPException(404, "tool not found")
    candidates = [
        Path(os.getenv("GITCTF_TOOLS_DIR", "/app/tools")) / name,
        Path(__file__).resolve().parents[1] / "scripts" / name,
    ]
    for path in candidates:
        if path.exists():
            return path
    raise HTTPException(404, "tool not found")


@app.get("/tools/{name}", include_in_schema=False)
@limiter.limit(RATE_LIMIT_TOOLS)
def get_participant_tool(request: Request, name: str):
    path = _tool_path(name)
    content = path.read_bytes()
    return Response(
        content,
        media_type="text/x-python; charset=utf-8",
        headers={"X-Content-SHA256": hashlib.sha256(content).hexdigest()},
    )


# ── 모델 ──────────────────────────────────────────────────────────────

class AttackRequest(BaseModel):
    agent_run_id: str
    llm_call_id: int
    attacker_team: str
    target_team: str
    payload: str = ""
    model: str | None = None
    session_id: str | None = None
    history: list[dict] | None = None
    path: str | None = None
    method: str = "POST"
    query: dict[str, Any] | None = None
    headers: dict[str, str] | None = None
    json_body: Any | None = None
    data: str | None = None


class ServiceDeployedRequest(BaseModel):
    team_id: str
    commit: str = ""
    pusher_team_id: str | None = None
    agent_run_id: str | None = None


class DefensePushValidationRequest(BaseModel):
    repo_team_id: str
    pusher_team_id: str
    commit: str
    agent_run_id: str


class AgentRunCreateRequest(BaseModel):
    team_id: str
    mode: str
    target_team: str
    round_num: int
    agent_image: str | None = None
    agent_image_digest: str | None = None
    agent_commit: str | None = None


class AgentRunFinishRequest(BaseModel):
    status: str
    error: str = ""


class LLMRequest(BaseModel):
    agent_run_id: str
    model: str
    messages: list[dict]
    temperature: float = 0.2
    max_tokens: int = 2048
    purpose: str = "general"


class AgentAttackActionRequest(BaseModel):
    payload: str = ""
    session_id: str | None = None
    history: list[dict] | None = None
    path: str | None = None
    method: str = "POST"
    query: dict[str, Any] | None = None
    headers: dict[str, str] | None = None
    json_body: Any | None = None
    data: str | None = None
    llm_call_id: int | None = None


class PocReviewRequest(BaseModel):
    reason: str = ""


class RunPocsRequest(BaseModel):
    round_num: int | None = None
    only_poc_id: str | None = None


ALLOWED_LLM_PURPOSES = {"general", "scan", "poc", "defense"}


def _json_bytes(value: object) -> int:
    return len(json.dumps(value, ensure_ascii=False, default=str).encode("utf-8"))


def _require_json_size(label: str, value: object, max_bytes: int) -> None:
    size = _json_bytes(value)
    if size > max_bytes:
        raise HTTPException(413, f"{label} 크기 초과 ({size} > {max_bytes})")


def _check_llm_purpose(purpose: str) -> None:
    if purpose not in ALLOWED_LLM_PURPOSES:
        allowed = ", ".join(sorted(ALLOWED_LLM_PURPOSES))
        raise HTTPException(400, f"purpose는 다음 값만 허용: {allowed}")


def _check_model(model: str | None) -> None:
    if model is None:
        raise HTTPException(400, "model 필드 필수 (사용한 LLM 모델 ID를 명시하세요)")
    if _model_allowed(model):
        return
    allowed = ", ".join(ALLOWED_MODEL_PREFIXES)
    raise HTTPException(403, f"허용되지 않은 모델: '{model}'. 허용 목록: {allowed}")


def _check_llm_limits(req: LLMRequest) -> None:
    if not isinstance(req.messages, list):
        raise HTTPException(400, "messages는 list여야 함")
    if len(req.messages) > MAX_LLM_MESSAGES:
        raise HTTPException(413, f"messages 개수 초과 ({len(req.messages)} > {MAX_LLM_MESSAGES})")
    if req.max_tokens < 1 or req.max_tokens > MAX_LLM_MAX_TOKENS:
        raise HTTPException(400, f"max_tokens는 1~{MAX_LLM_MAX_TOKENS} 범위만 허용")
    if req.temperature < 0 or req.temperature > 2:
        raise HTTPException(400, "temperature는 0~2 범위만 허용")
    _require_json_size(
        "LLM prompt",
        {
            "messages": req.messages,
            "temperature": req.temperature,
            "max_tokens": req.max_tokens,
        },
        MAX_LLM_PROMPT_BYTES,
    )


def _model_allowed(model: str) -> bool:
    lower = model.lower()
    return any(lower.startswith(prefix.lower()) for prefix in ALLOWED_MODEL_PREFIXES)


def verify_admin(secret: str) -> None:
    if secret != ADMIN_SECRET:
        raise HTTPException(403, "Admin secret 불일치")


def verify_team_token(team_id: str, token: str) -> None:
    expected_token = TEAM_TOKENS.get(team_id)
    if expected_token is None or token != expected_token:
        raise HTTPException(403, "팀 토큰 불일치")


def verify_agent_token(team_id: str, mode: str, token: str) -> None:
    tokens = DEFENSE_TOKENS if mode == "defense" else TEAM_TOKENS
    expected_token = tokens.get(team_id)
    if expected_token is None or token != expected_token:
        raise HTTPException(403, "agent 토큰 불일치")


def _canonical_hash(data: object) -> str:
    raw = json.dumps(data, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(raw.encode()).hexdigest()


def _hash_run_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _verify_runner_secret(secret: str | None) -> None:
    if not RUNNER_SECRET and not ALLOW_UNSAFE_AGENT_RUNS:
        raise HTTPException(503, "RUNNER_SECRET 미설정: 공식 agent run 생성을 차단합니다")
    if RUNNER_SECRET and not secrets.compare_digest(secret or "", RUNNER_SECRET):
        raise HTTPException(403, "runner secret 불일치")


def _verify_run_token(run: dict, token: str | None) -> None:
    expected = run.get("run_token_hash")
    if not expected:
        return
    if not token or not secrets.compare_digest(_hash_run_token(token), expected):
        raise HTTPException(403, "agent run token 불일치")


def _sdk_signature(run: dict, method: str, path: str, timestamp: str) -> str:
    key = str(run.get("run_token_hash") or "").encode("utf-8")
    payload = "\n".join([method.upper(), path, run["id"], timestamp]).encode("utf-8")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def _verify_sdk_request(
    request: Request,
    run: dict,
    token: str | None,
    sdk_name: str | None,
    timestamp: str | None,
    signature: str | None,
) -> None:
    _verify_run_token(run, token)
    if not run.get("run_token_hash"):
        return
    if sdk_name != SDK_NAME:
        raise HTTPException(403, "Agent SDK 요청만 허용")
    if not timestamp or not signature:
        raise HTTPException(403, "Agent SDK 서명 헤더 누락")
    try:
        ts = int(timestamp)
    except ValueError as exc:
        raise HTTPException(403, "Agent SDK timestamp 형식 오류") from exc
    if abs(int(time.time()) - ts) > SDK_SIGNATURE_MAX_SKEW_SEC:
        raise HTTPException(403, "Agent SDK timestamp 만료")
    expected = _sdk_signature(run, request.method, request.url.path, timestamp)
    if not secrets.compare_digest(signature, expected):
        raise HTTPException(403, "Agent SDK 서명 불일치")


def _bearer_token(request: Request) -> str:
    authorization = request.headers.get("Authorization", "")
    prefix = "Bearer "
    if not authorization.startswith(prefix):
        raise HTTPException(401, "Bearer agent run token 필요")
    token = authorization[len(prefix):].strip()
    if not token:
        raise HTTPException(401, "Bearer agent run token 필요")
    return token


def _require_bearer_run(request: Request, mode: str | None = None) -> dict:
    token = _bearer_token(request)
    run_id = request.headers.get("X-Agent-Run-ID")
    if run_id:
        run = _require_run(run_id, mode=mode)
        _verify_run_token(run, token)
        return run
    run = db.get_agent_run_by_token_hash(_hash_run_token(token))
    if not run:
        raise HTTPException(403, "agent run token 불일치")
    if mode and run["mode"] != mode:
        raise HTTPException(403, "agent run mode 불일치")
    return run


def _latest_or_requested_llm_call(agent_run_id: str, llm_call_id: int | None = None) -> dict:
    if llm_call_id is not None:
        return _require_llm_call(agent_run_id, llm_call_id)
    call = db.get_latest_llm_call(agent_run_id, allowed_only=True, successful_only=True)
    if not call:
        raise HTTPException(403, "OpenRouter wrapper LLM 호출 기록이 없습니다")
    return call


def _validate_agent_run_request(req: AgentRunCreateRequest) -> None:
    if req.team_id not in TEAMS:
        raise HTTPException(400, "알 수 없는 팀")
    if req.target_team not in TEAMS:
        raise HTTPException(400, "알 수 없는 타겟팀")
    if req.mode not in {"attack", "defense"}:
        raise HTTPException(400, "mode는 attack 또는 defense만 허용")
    try:
        if req.mode == "attack":
            assert_attack_allowed(req.team_id, req.target_team)
        else:
            assert_defense_allowed(req.team_id, req.target_team)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc


def _require_run(
    run_id: str,
    team_id: str | None = None,
    mode: str | None = None,
    target_team: str | None = None,
) -> dict:
    run = db.get_agent_run(run_id)
    if not run:
        raise HTTPException(403, "agent_run_id 없음")
    if team_id and run["team_id"] != team_id:
        raise HTTPException(403, "agent run 팀 불일치")
    if mode and run["mode"] != mode:
        raise HTTPException(403, "agent run mode 불일치")
    if target_team and run["target_team"] != target_team:
        raise HTTPException(403, "agent run target 불일치")
    return run


def _require_llm_call(agent_run_id: str, llm_call_id: int, purpose: str | None = None) -> dict:
    call = db.get_llm_call(llm_call_id)
    if not call:
        raise HTTPException(403, "llm_call_id 없음")
    if call["agent_run_id"] != agent_run_id:
        raise HTTPException(403, "llm_call_id가 agent_run_id와 연결되지 않음")
    if not call["allowed"] or call["status"] != "completed":
        raise HTTPException(403, "llm_call_id가 성공한 whitelist /llm 호출이 아님")
    if purpose and call.get("purpose") != purpose:
        raise HTTPException(403, f"llm_call_id purpose가 {purpose!r}가 아님")
    return call


def _round_flags_by_team(round_num: int) -> dict[str, dict[str, str]]:
    flags: dict[str, dict[str, str]] = {team_id: {} for team_id in TEAMS}
    for row in db.get_flags_for_round(round_num):
        flags.setdefault(row["team_id"], {})[row["vuln_id"]] = row["flag"]
    return flags


# ── 헬스 엔드포인트 ───────────────────────────────────────────────────

@app.get("/health")
def health():
    if not db.ping():
        raise HTTPException(503, "DB unreachable")
    meta = db.get_meta()
    return {"status": "ok", "round": meta.current_round, "round_active": meta.round_active}


# ── agent provenance / LLM gateway ────────────────────────────────────

def _create_agent_run_response(
    req: AgentRunCreateRequest,
    default_agent_image: str | None = None,
    default_agent_commit: str | None = None,
) -> dict:
    _validate_agent_run_request(req)

    run_token = secrets.token_urlsafe(32)
    run = db.create_agent_run(
        run_id=str(uuid4()),
        team_id=req.team_id,
        mode=req.mode,
        target_team=req.target_team,
        round_num=req.round_num,
        run_token_hash=_hash_run_token(run_token),
        agent_image=req.agent_image or default_agent_image,
        agent_image_digest=req.agent_image_digest,
        agent_commit=req.agent_commit or default_agent_commit,
    )
    return {
        "agent_run_id": run["id"],
        "agent_run_token": run_token,
        "allowed_models": ALLOWED_MODEL_PREFIXES,
    }


def _agent_run_rate_limit_for_mode(mode: str) -> str:
    if mode == "attack":
        return RATE_LIMIT_ATTACK_AGENT_RUNS
    if mode == "defense":
        return RATE_LIMIT_DEFENSE_AGENT_RUNS
    return RATE_LIMIT_ATTACK_AGENT_RUNS


def _check_agent_run_rate_limit(request: Request, req: AgentRunCreateRequest) -> None:
    raw_limit = _agent_run_rate_limit_for_mode(req.mode)
    limit = parse_rate_limit(raw_limit)
    key = f"agent-runs:{req.mode}:{_rate_limit_key(request)}"
    if not agent_run_limiter.hit(limit, key):
        raise HTTPException(429, f"agent run 생성 제한 초과 ({req.mode}: {raw_limit})")


@app.post("/agent-runs")
def create_agent_run(
    request: Request,
    req: AgentRunCreateRequest,
    x_team_token: str = Header(...),
    x_runner_secret: str | None = Header(default=None),
    x_agent_sdk: str | None = Header(default=None),
):
    verify_agent_token(req.team_id, req.mode, x_team_token)
    _verify_runner_secret(x_runner_secret)
    if RUNNER_SECRET and x_agent_sdk != SDK_NAME:
        raise HTTPException(403, "Agent SDK 요청만 허용")
    _check_agent_run_rate_limit(request, req)
    return _create_agent_run_response(req)


@app.post("/student/agent-runs")
def create_student_agent_run(
    request: Request,
    req: AgentRunCreateRequest,
    x_team_token: str = Header(...),
):
    if not ALLOW_STUDENT_AGENT_RUNS:
        raise HTTPException(404, "student agent run endpoint disabled")
    verify_agent_token(req.team_id, req.mode, x_team_token)
    _check_agent_run_rate_limit(request, req)
    return _create_agent_run_response(
        req,
        default_agent_image="student-web-ui",
        default_agent_commit="browser",
    )



@app.post("/agent-runs/{run_id}/finish")
def finish_agent_run(
    run_id: str,
    request: Request,
    req: AgentRunFinishRequest,
    x_team_token: str = Header(...),
    x_agent_run_token: str | None = Header(default=None),
    x_agent_sdk: str | None = Header(default=None),
    x_agent_sdk_timestamp: str | None = Header(default=None),
    x_agent_sdk_signature: str | None = Header(default=None),
):
    run = _require_run(run_id)
    verify_agent_token(run["team_id"], run["mode"], x_team_token)
    _verify_sdk_request(
        request, run, x_agent_run_token, x_agent_sdk,
        x_agent_sdk_timestamp, x_agent_sdk_signature,
    )
    if req.status not in {"completed", "failed", "cancelled"}:
        raise HTTPException(400, "status는 completed, failed, cancelled만 허용")
    if not db.finish_agent_run(run_id, req.status, req.error):
        raise HTTPException(404, "agent run 없음")
    return {"ok": True, "agent_run_id": run_id, "status": req.status}


@app.post("/agent/finish")
def finish_agent_run_bearer(request: Request, req: AgentRunFinishRequest):
    run = _require_bearer_run(request)
    if req.status not in {"completed", "failed", "cancelled"}:
        raise HTTPException(400, "status는 completed, failed, cancelled만 허용")
    if not db.finish_agent_run(run["id"], req.status, req.error):
        raise HTTPException(404, "agent run 없음")
    return {"ok": True, "agent_run_id": run["id"], "status": req.status}


@app.get("/agent-runs/{run_id}/target-repo.tar")
@limiter.limit(RATE_LIMIT_REPO_ARCHIVE)
def target_repo_archive(
    request: Request,
    run_id: str,
    x_team_token: str = Header(...),
    x_agent_run_token: str | None = Header(default=None),
    x_agent_sdk: str | None = Header(default=None),
    x_agent_sdk_timestamp: str | None = Header(default=None),
    x_agent_sdk_signature: str | None = Header(default=None),
):
    run = _require_run(run_id, mode="attack")
    verify_agent_token(run["team_id"], run["mode"], x_team_token)
    _verify_sdk_request(
        request, run, x_agent_run_token, x_agent_sdk,
        x_agent_sdk_timestamp, x_agent_sdk_signature,
    )
    if run["round_num"] != state.current_round:
        raise HTTPException(400, "agent run round 불일치")
    if not state.round_active:
        raise HTTPException(400, "진행 중인 라운드 없음")

    content, commit = archive_team_repo(run["target_team"])
    return Response(
        content=content,
        media_type="application/x-tar",
        headers={
            "X-Repo-Team": run["target_team"],
            "X-Repo-Commit": commit,
            "Content-Disposition": f'attachment; filename="{run["target_team"]}-{commit[:12]}.tar"',
        },
    )


@app.get("/agent/target-repo.tar")
@limiter.limit(RATE_LIMIT_REPO_ARCHIVE)
def target_repo_archive_bearer(request: Request):
    run = _require_bearer_run(request, mode="attack")
    if run["round_num"] != state.current_round:
        raise HTTPException(400, "agent run round 불일치")
    if not state.round_active:
        raise HTTPException(400, "진행 중인 라운드 없음")
    content, commit = archive_team_repo(run["target_team"])
    return Response(
        content=content,
        media_type="application/x-tar",
        headers={
            "X-Repo-Team": run["target_team"],
            "X-Repo-Commit": commit,
            "Content-Disposition": f'attachment; filename="{run["target_team"]}-{commit[:12]}.tar"',
        },
    )


def _openrouter_extra_payload(body: dict[str, Any]) -> dict[str, Any]:
    blocked = {"agent_run_id", "metadata", "messages", "model", "purpose", "stream"}
    return {key: value for key, value in body.items() if key not in blocked}


async def _perform_llm_call(req: LLMRequest, extra_payload: dict[str, Any] | None = None) -> dict:
    _check_llm_purpose(req.purpose)
    _check_llm_limits(req)

    prompt_hash = _canonical_hash(
        {
            "messages": req.messages,
            "temperature": req.temperature,
            "max_tokens": req.max_tokens,
        }
    )

    if not _model_allowed(req.model):
        db.append_llm_call(
            agent_run_id=req.agent_run_id,
            model=req.model,
            allowed=False,
            prompt_hash=prompt_hash,
            purpose=req.purpose,
            status="rejected",
            error="model not allowed",
        )
        allowed = ", ".join(ALLOWED_MODEL_PREFIXES)
        raise HTTPException(403, f"허용되지 않은 모델: '{req.model}'. 허용 목록: {allowed}")

    if not OPENROUTER_API_KEY:
        db.append_llm_call(
            agent_run_id=req.agent_run_id,
            model=req.model,
            allowed=True,
            prompt_hash=prompt_hash,
            purpose=req.purpose,
            response_hash=None,
            status="error",
            error="OPENROUTER_API_KEY not configured",
        )
        raise HTTPException(503, "coordinator OPENROUTER_API_KEY 미설정")

    payload = {
        "model": req.model,
        "messages": req.messages,
        "temperature": req.temperature,
        "max_tokens": req.max_tokens,
    }
    if extra_payload:
        payload.update(extra_payload)
    headers = {
        "Authorization": f"Bearer {OPENROUTER_API_KEY}",
        "Content-Type": "application/json",
        "X-Title": "HSPACE AI Agent A&D CTF",
    }

    try:
        async with httpx.AsyncClient(timeout=60.0) as client:
            resp = await client.post(f"{OPENROUTER_BASE_URL}/chat/completions", json=payload, headers=headers)
        request_id = resp.headers.get("x-request-id")
        resp.raise_for_status()
        data = resp.json()
    except httpx.HTTPStatusError as exc:
        db.append_llm_call(
            agent_run_id=req.agent_run_id,
            model=req.model,
            allowed=True,
            prompt_hash=prompt_hash,
            purpose=req.purpose,
            status="error",
            error=f"OpenRouter HTTP {exc.response.status_code}",
        )
        raise HTTPException(502, f"OpenRouter 오류: HTTP {exc.response.status_code}") from exc
    except Exception as exc:
        db.append_llm_call(
            agent_run_id=req.agent_run_id,
            model=req.model,
            allowed=True,
            prompt_hash=prompt_hash,
            purpose=req.purpose,
            status="error",
            error=str(exc),
        )
        raise HTTPException(502, f"OpenRouter 호출 실패: {exc}") from exc

    choice = (data.get("choices") or [{}])[0]
    message = choice.get("message") or {}
    content = message.get("content") or ""
    usage = data.get("usage") or {}
    response_hash = hashlib.sha256(content.encode()).hexdigest()
    request_id = request_id or data.get("id")

    llm_call_id = db.append_llm_call(
        agent_run_id=req.agent_run_id,
        model=req.model,
        allowed=True,
        prompt_hash=prompt_hash,
        purpose=req.purpose,
        response_hash=response_hash,
        openrouter_request_id=request_id,
        prompt_tokens=usage.get("prompt_tokens"),
        completion_tokens=usage.get("completion_tokens"),
        total_tokens=usage.get("total_tokens"),
        status="completed",
    )

    return {
        "llm_call_id": llm_call_id,
        "model": req.model,
        "content": content,
        "usage": {
            "prompt_tokens": usage.get("prompt_tokens"),
            "completion_tokens": usage.get("completion_tokens"),
            "total_tokens": usage.get("total_tokens"),
        },
        "request_id": request_id,
        "openrouter_response": data,
    }


@app.post("/llm")
@limiter.limit(RATE_LIMIT_LLM)
async def llm_gateway(
    request: Request,
    req: LLMRequest,
    x_team_token: str = Header(...),
    x_agent_run_token: str | None = Header(default=None),
    x_agent_sdk: str | None = Header(default=None),
    x_agent_sdk_timestamp: str | None = Header(default=None),
    x_agent_sdk_signature: str | None = Header(default=None),
):
    run = _require_run(req.agent_run_id)
    verify_agent_token(run["team_id"], run["mode"], x_team_token)
    _verify_sdk_request(
        request, run, x_agent_run_token, x_agent_sdk,
        x_agent_sdk_timestamp, x_agent_sdk_signature,
    )
    result = await _perform_llm_call(req)
    result.pop("openrouter_response", None)
    return result


async def _openrouter_chat_completions(request: Request) -> JSONResponse:
    run = _require_bearer_run(request)
    body = await request.json()
    if not isinstance(body, dict):
        raise HTTPException(400, "OpenRouter request body는 JSON object여야 함")
    if body.get("stream"):
        raise HTTPException(400, "stream 응답은 지원하지 않습니다")

    metadata = body.get("metadata") if isinstance(body.get("metadata"), dict) else {}
    purpose = (
        request.headers.get("X-Agent-Purpose")
        or metadata.get("purpose")
        or body.get("purpose")
        or ("defense" if run["mode"] == "defense" else "general")
    )
    llm_req = LLMRequest(
        agent_run_id=run["id"],
        model=str(body.get("model") or ""),
        messages=body.get("messages") or [],
        temperature=float(body.get("temperature", 0.2)),
        max_tokens=int(body.get("max_tokens", 2048)),
        purpose=str(purpose),
    )
    result = await _perform_llm_call(llm_req, extra_payload=_openrouter_extra_payload(body))
    data = dict(result["openrouter_response"])
    data["hspace"] = {
        "agent_run_id": run["id"],
        "llm_call_id": result["llm_call_id"],
        "purpose": llm_req.purpose,
    }
    return JSONResponse(
        data,
        headers={
            "X-Agent-Run-ID": run["id"],
            "X-LLM-Call-ID": str(result["llm_call_id"]),
        },
    )


@app.post("/openrouter/api/v1/chat/completions")
@limiter.limit(RATE_LIMIT_LLM)
async def openrouter_chat_completions(request: Request):
    return await _openrouter_chat_completions(request)


@app.post("/v1/chat/completions")
@limiter.limit(RATE_LIMIT_LLM)
async def openai_compatible_chat_completions(request: Request):
    return await _openrouter_chat_completions(request)


# ── 공격 엔드포인트 ───────────────────────────────────────────────────


def _decode_target_response(resp: httpx.Response) -> Any:
    try:
        return resp.json()
    except Exception:
        return None


def _target_response_text(data: Any, fallback: str) -> str:
    if isinstance(data, dict):
        if isinstance(data.get("response"), str):
            return data["response"]
        return json.dumps(data, ensure_ascii=False)
    if isinstance(data, list):
        return json.dumps(data, ensure_ascii=False)
    return fallback


_BLOCKED_PROXY_HEADERS = {
    "host",
    "content-length",
    "connection",
    "transfer-encoding",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "upgrade",
}


def _check_attack_request_limits(req: AttackRequest) -> None:
    _require_json_size(
        "attack request",
        {
            "payload": req.payload,
            "session_id": req.session_id,
            "history": req.history,
            "path": req.path,
            "method": req.method,
            "query": req.query,
            "headers": req.headers,
            "json_body": req.json_body,
            "data": req.data,
        },
        MAX_ATTACK_REQUEST_BYTES,
    )


async def _execute_attack(req: AttackRequest, run: dict, llm_call: dict) -> dict:
    if run["round_num"] != state.current_round:
        raise HTTPException(400, "agent run round 불일치")
    if req.attacker_team not in TEAMS:
        raise HTTPException(400, "알 수 없는 공격팀")
    if req.target_team not in TEAMS:
        raise HTTPException(400, "알 수 없는 타겟팀")
    try:
        assert_attack_allowed(req.attacker_team, req.target_team)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    if not state.round_active:
        raise HTTPException(400, "진행 중인 라운드 없음")
    _check_attack_request_limits(req)

    # 타겟 서비스 SLA 상태 확인 — DOWN이면 공격 불가
    statuses = db.get_service_statuses()
    if statuses.get(req.target_team, "UNKNOWN") == "DOWN":
        raise HTTPException(503, f"타겟 서비스({req.target_team})가 DOWN 상태 — 공격 불가")

    if state.get_attack_count(req.attacker_team) >= MAX_ATTACKS_ROUND:
        raise HTTPException(429, f"이번 라운드 공격 횟수 초과 ({MAX_ATTACKS_ROUND}턴 한도)")

    # 타겟 서비스에 요청 전달. path/json_body가 없으면 기존 /chat 템플릿 호환 모드.
    target = TEAMS[req.target_team]
    method = req.method.upper()
    if method not in {"GET", "POST", "PUT", "PATCH", "DELETE"}:
        raise HTTPException(400, "method는 GET/POST/PUT/PATCH/DELETE만 허용")
    path = req.path or "/chat"
    if len(path) > 512 or not path.startswith("/") or "://" in path or ".." in path or "\\" in path:
        raise HTTPException(400, "path는 target service 내부 절대경로여야 함")
    url = f"http://{target['ip']}:{target['port']}{path}"

    outbound_headers = {
        key: value
        for key, value in (req.headers or {}).items()
        if key.lower() not in _BLOCKED_PROXY_HEADERS
    }

    json_body = req.json_body
    if json_body is None and req.data is None and req.path is None:
        json_body = {"message": req.payload}
        if req.session_id:
            json_body["session_id"] = req.session_id
        if req.history:
            json_body["history"] = req.history

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.request(
                method,
                url,
                params=req.query or {},
                headers=outbound_headers,
                json=json_body,
                data=req.data,
            )
            resp.raise_for_status()
    except httpx.HTTPStatusError as e:
        raise HTTPException(502, f"타겟 서비스 오류: {e.response.status_code}")
    except Exception as e:
        raise HTTPException(503, f"타겟 서비스 응답 없음: {str(e)}")

    response_truncated = len(resp.content) > MAX_ATTACK_RESPONSE_BYTES
    response_body = resp.content[:MAX_ATTACK_RESPONSE_BYTES]
    response_body_text = response_body.decode(resp.encoding or "utf-8", errors="replace")
    data = None if response_truncated else _decode_target_response(resp)
    response_text = _target_response_text(data, response_body_text)

    state.record_attack(req.attacker_team)

    found_flags = scan_response_for_flags(response_text)

    request_fingerprint = json.dumps(
        {
            "method": method,
            "path": path,
            "query": req.query or {},
            "payload": req.payload,
            "json_body": json_body,
            "data": req.data,
        },
        sort_keys=True,
        ensure_ascii=False,
        default=str,
    )
    db.append_audit(
        round_num=state.current_round,
        attacker=req.attacker_team,
        target=req.target_team,
        payload_hash=hashlib.sha256(request_fingerprint.encode()).hexdigest(),
        model=llm_call.get("model") or req.model,
        exploited=bool(found_flags),
        scored=False,
        response_hash=hashlib.sha256(response_text.encode()).hexdigest(),
        agent_run_id=req.agent_run_id,
        llm_call_id=req.llm_call_id,
    )

    return {
        "status_code": resp.status_code,
        "response": response_text,
        "body": response_body_text,
        "json": data if isinstance(data, (dict, list)) else None,
        "tool_calls": data.get("tool_calls", []) if isinstance(data, dict) else [],
        "flags_found": found_flags,
        "hint": "발견된 flag가 재현되도록 poc.py를 제출하세요" if found_flags else None,
        "truncated": response_truncated,
        "turns_remaining": MAX_ATTACKS_ROUND - state.get_attack_count(req.attacker_team),
    }


@app.post("/attack")
@limiter.limit(RATE_LIMIT_ATTACK)
async def attack(
    request: Request,
    req: AttackRequest,
    x_team_token: str = Header(...),
    x_agent_run_token: str | None = Header(default=None),
    x_agent_sdk: str | None = Header(default=None),
    x_agent_sdk_timestamp: str | None = Header(default=None),
    x_agent_sdk_signature: str | None = Header(default=None),
):
    verify_team_token(req.attacker_team, x_team_token)

    run = _require_run(
        req.agent_run_id,
        team_id=req.attacker_team,
        mode="attack",
        target_team=req.target_team,
    )
    _verify_sdk_request(
        request, run, x_agent_run_token, x_agent_sdk,
        x_agent_sdk_timestamp, x_agent_sdk_signature,
    )
    llm_call = _require_llm_call(req.agent_run_id, req.llm_call_id, purpose="scan")
    return await _execute_attack(req, run, llm_call)


@app.post("/agent/attack")
@limiter.limit(RATE_LIMIT_ATTACK)
async def agent_attack(request: Request, req: AgentAttackActionRequest):
    run = _require_bearer_run(request, mode="attack")
    llm_call = _latest_or_requested_llm_call(run["id"], req.llm_call_id)
    attack_req = AttackRequest(
        agent_run_id=run["id"],
        llm_call_id=int(llm_call["id"]),
        attacker_team=run["team_id"],
        target_team=run["target_team"],
        payload=req.payload,
        session_id=req.session_id,
        history=req.history,
        path=req.path,
        method=req.method,
        query=req.query,
        headers=req.headers,
        json_body=req.json_body,
        data=req.data,
    )
    return await _execute_attack(attack_req, run, llm_call)


# ── PoC 제출/실행 ────────────────────────────────────────────────────

_POC_NAME_RE = r"^poc[A-Za-z0-9_.-]*\.py$"
_POC_BANNED_PATTERNS = [
    "import subprocess",
    "from subprocess",
    "os.system",
    "os.popen",
    "eval(",
    "exec(",
    "__import__",
    "ctypes",
    "pickle.loads",
    "shutil.rmtree",
]


def _validate_poc_static(file_name: str, content: bytes) -> str:
    import re

    if not re.match(_POC_NAME_RE, file_name):
        return "파일명은 poc*.py 형식이어야 함"
    if len(content) > POC_MAX_BYTES:
        return f"PoC 파일 크기 초과 ({len(content)} > {POC_MAX_BYTES})"
    try:
        text = content.decode("utf-8")
    except UnicodeDecodeError:
        return "PoC는 UTF-8 Python 텍스트 파일이어야 함"
    lowered = text.lower()
    for pattern in _POC_BANNED_PATTERNS:
        if pattern in lowered:
            return f"금지 패턴 포함: {pattern}"
    return ""


def _run_pocs(
    round_num: int,
    only_poc_id: str | None = None,
    teams_override: dict | None = None,
) -> list[dict]:
    return run_pocs_for_round(
        round_num=round_num,
        teams=teams_override or TEAMS,
        data_dir=DATA_DIR,
        timeout_sec=POC_TIMEOUT_SEC,
        output_max_bytes=POC_OUTPUT_MAX_BYTES,
        attack_reward=ATTACK_REWARD,
        attack_penalty=ATTACK_PENALTY,
        poc_timeout_overrides=_poc_timeout_overrides(vuln_specs),
        only_poc_id=only_poc_id,
        runner_mode=POC_RUNNER_MODE,
        docker_network=POC_DOCKER_NETWORK,
        docker_image=POC_DOCKER_IMAGE,
        host_data_dir=POC_HOST_DATA_DIR,
    )


def _poc_timeout_overrides(specs: dict) -> dict[str, dict[str, int]]:
    overrides: dict[str, dict[str, int]] = {}
    for team_id, team_spec in specs.items():
        vulns = team_spec.get("vulnerabilities", []) if isinstance(team_spec, dict) else team_spec
        if not isinstance(vulns, list):
            continue
        for vuln in vulns:
            if not isinstance(vuln, dict):
                continue
            raw_timeout = vuln.get("poc_timeout_sec")
            if raw_timeout is None:
                checker_spec = vuln.get("checker", {})
                if isinstance(checker_spec, dict):
                    raw_timeout = checker_spec.get("poc_timeout_sec")
            if raw_timeout is None:
                continue
            try:
                timeout = int(raw_timeout)
            except (TypeError, ValueError):
                continue
            timeout = max(1, min(timeout, POC_MAX_TIMEOUT_SEC))
            overrides.setdefault(team_id, {})[str(vuln.get("id"))] = timeout
    return overrides


def _submit_poc_content(
    *,
    run: dict,
    llm_call: dict,
    attacker_team: str,
    target_team: str,
    flag_id: str,
    file_name: str,
    content: bytes,
    submitted_sha: str | None = None,
) -> dict:
    if not state.round_active:
        raise HTTPException(400, "진행 중인 라운드 없음")
    if run["round_num"] != state.current_round:
        raise HTTPException(400, "agent run round 불일치")
    if target_team not in TEAMS:
        raise HTTPException(400, "알 수 없는 타겟팀")
    if flag_id not in {"vuln1", "vuln2", "vuln3", "vuln4"}:
        raise HTTPException(400, "flag_id는 vuln1~vuln4만 허용")
    try:
        assert_attack_allowed(attacker_team, target_team)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc

    actual_sha = hashlib.sha256(content).hexdigest()
    if submitted_sha and actual_sha != submitted_sha:
        raise HTTPException(400, "sha256 불일치")

    safe_file_name = Path(file_name or "poc.py").name
    reason = _validate_poc_static(safe_file_name, content)
    if reason:
        raise HTTPException(400, reason)

    duplicate = db.find_poc_by_sha(attacker_team, target_team, actual_sha, run["round_num"])
    if duplicate:
        return {
            "poc_id": duplicate["id"],
            "status": "merged",
            "canonical_poc_id": duplicate.get("canonical_poc_id") or duplicate["id"],
            "sha256": actual_sha,
            "queued": True,
        }

    current_count = db.count_active_poc_submissions_for_vuln(
        attacker_team,
        target_team,
        flag_id,
        run["round_num"],
    )
    if current_count >= MAX_POCS_PER_VULN_ROUND:
        raise HTTPException(
            429,
            f"PoC 제출 제한 초과: 라운드당 {attacker_team}->{target_team} {flag_id}는 "
            f"최대 {MAX_POCS_PER_VULN_ROUND}개까지 제출 가능",
        )

    poc_id = str(uuid4())
    storage_dir = Path(DATA_DIR) / "pocs" / str(run["round_num"]) / poc_id
    storage_dir.mkdir(parents=True, exist_ok=True)
    storage_path = storage_dir / safe_file_name
    storage_path.write_bytes(content)

    poc = db.create_poc_submission(
        poc_id=poc_id,
        agent_run_id=run["id"],
        llm_call_id=int(llm_call["id"]),
        attacker_team=attacker_team,
        target_team=target_team,
        defender_team=get_defender(target_team),
        flag_id=flag_id,
        submitted_round=run["round_num"],
        file_name=safe_file_name,
        sha256=actual_sha,
        storage_path=str(storage_path),
    )
    return {
        "poc_id": poc["id"],
        "status": poc["status"],
        "sha256": poc["sha256"],
        "queued": True,
    }


@app.post("/pocs")
@limiter.limit(RATE_LIMIT_POC_SUBMIT)
async def submit_poc(
    request: Request,
    agent_run_id: str = Form(...),
    llm_call_id: int = Form(...),
    attacker_team: str = Form(...),
    target_team: str = Form(...),
    flag_id: str = Form(...),
    sha256: str = Form(...),
    file: UploadFile = File(...),
    x_team_token: str = Header(...),
    x_agent_run_token: str | None = Header(default=None),
    x_agent_sdk: str | None = Header(default=None),
    x_agent_sdk_timestamp: str | None = Header(default=None),
    x_agent_sdk_signature: str | None = Header(default=None),
):
    verify_team_token(attacker_team, x_team_token)
    run = _require_run(agent_run_id, team_id=attacker_team, mode="attack", target_team=target_team)
    _verify_sdk_request(
        request, run, x_agent_run_token, x_agent_sdk,
        x_agent_sdk_timestamp, x_agent_sdk_signature,
    )
    if not state.round_active:
        raise HTTPException(400, "진행 중인 라운드 없음")
    llm_call = _require_llm_call(agent_run_id, llm_call_id, purpose="poc")
    content = await file.read(POC_MAX_BYTES + 1)
    return _submit_poc_content(
        run=run,
        llm_call=llm_call,
        attacker_team=attacker_team,
        target_team=target_team,
        flag_id=flag_id,
        file_name=file.filename or "poc.py",
        content=content,
        submitted_sha=sha256,
    )


@app.post("/agent/pocs")
@limiter.limit(RATE_LIMIT_POC_SUBMIT)
async def submit_agent_poc(
    request: Request,
    flag_id: str = Form(...),
    source: str | None = Form(default=None),
    sha256: str | None = Form(default=None),
    llm_call_id: int | None = Form(default=None),
    file: UploadFile | None = File(default=None),
):
    run = _require_bearer_run(request, mode="attack")
    llm_call = _latest_or_requested_llm_call(run["id"], llm_call_id)
    if file is not None:
        content = await file.read(POC_MAX_BYTES + 1)
        file_name = file.filename or "poc.py"
    elif source is not None:
        content = source.encode("utf-8")
        file_name = "poc.py"
    else:
        raise HTTPException(400, "file 또는 source가 필요합니다")
    return _submit_poc_content(
        run=run,
        llm_call=llm_call,
        attacker_team=run["team_id"],
        target_team=run["target_team"],
        flag_id=flag_id,
        file_name=file_name,
        content=content,
        submitted_sha=sha256,
    )


@app.get("/admin/pocs")
def list_pocs(
    x_admin_secret: str = Header(...),
    status: str | None = Query(default=None),
    limit: int = Query(default=500, le=2000),
):
    verify_admin(x_admin_secret)
    return {"pocs": db.list_poc_submissions(status=status, limit=limit)}


@app.post("/admin/pocs/{poc_id}/reject")
def reject_poc(poc_id: str, req: PocReviewRequest, x_admin_secret: str = Header(...)):
    verify_admin(x_admin_secret)
    if not db.get_poc_submission(poc_id):
        raise HTTPException(404, "PoC 없음")
    db.update_poc_status(poc_id, "rejected", req.reason)
    return {"ok": True, "poc_id": poc_id, "status": "rejected", "reason": req.reason}


@app.post("/admin/run-pocs")
def run_pocs(req: RunPocsRequest, x_admin_secret: str = Header(...)):
    verify_admin(x_admin_secret)
    round_num = req.round_num if req.round_num is not None else state.current_round
    results = _run_pocs(round_num, only_poc_id=req.only_poc_id)
    return {"round": round_num, "results": results}


@app.get("/admin/poc-results")
def list_poc_results(
    x_admin_secret: str = Header(...),
    round_num: int | None = Query(default=None),
    limit: int = Query(default=500, le=2000),
):
    verify_admin(x_admin_secret)
    return {"results": db.list_poc_results(round_num=round_num, limit=limit)}


# ── 어드민 엔드포인트 ─────────────────────────────────────────────────

@app.post("/admin/start-round")
async def start_round(
    x_admin_secret: str = Header(...),
    force: bool = Query(default=False),
):
    verify_admin(x_admin_secret)
    if state.round_active:
        raise HTTPException(400, f"라운드 {state.current_round} 이미 진행 중")
    next_round = state.current_round + 1
    if next_round > TOTAL_ROUNDS:
        raise HTTPException(400, "모든 라운드 완료")
    if not force and not db.get_meta().preflight_done:
        raise HTTPException(
            412,
            "사전검증 미완료. python scripts/gitctf.py admin preflight 실행 후 시도하거나 ?force=true 사용"
        )

    state.start_round(next_round)

    # flag 생성 + 주입
    round_flags = fm.generate_round_flags(next_round, list(TEAMS.keys()), vuln_specs)

    # checker 실행
    round_flags_by_team = {
        team_id: team_flags
        for team_id, team_flags in round_flags.items()
    }
    checker_results = await chk.run_all_checkers(
        TEAMS, vuln_specs, round_flags_by_team, CHECKER_TOKEN
    )

    # 공식 공격/방어 에이전트 컨테이너 실행
    run_attack_agents(next_round, TEAMS, COORDINATOR_URL, TEAM_TOKENS, ATTACK_AGENT_IMAGES)
    run_defense_agents(next_round, TEAMS, COORDINATOR_URL, DEFENSE_TOKENS, DEFENSE_AGENT_IMAGES)

    checker_summary = {tid: r.status for tid, r in checker_results.items()}
    return {
        "round": next_round,
        "message": f"라운드 {next_round} 시작",
        "checker": checker_summary,
        "flags_generated": {tid: len(flags) for tid, flags in round_flags.items()},
        "pocs_run": 0,
        "poc_execution": "deferred_until_round_end",
    }


@app.post("/admin/end-round")
async def end_round(x_admin_secret: str = Header(...)):
    verify_admin(x_admin_secret)
    if not state.round_active:
        raise HTTPException(400, "진행 중인 라운드 없음")

    current = state.current_round
    stop_round_agents(current)
    # Freeze the round before scoring. This closes PoC submission and defense
    # push windows while keeping active flags available for snapshot scoring.
    db.set_round_active(current, False)

    snapshot = None
    scoring_teams = TEAMS
    if SCORING_SNAPSHOT_ENABLED:
        snapshot = create_round_snapshot(
            round_num=current,
            teams=TEAMS,
            checker_token=CHECKER_TOKEN,
            network=SCORING_SNAPSHOT_NETWORK,
            ip_prefix=SCORING_SNAPSHOT_IP_PREFIX,
            ip_start=SCORING_SNAPSHOT_IP_START,
        )
        scoring_teams = snapshot.teams
        if SCORING_SNAPSHOT_STARTUP_GRACE_SEC > 0:
            await asyncio.sleep(SCORING_SNAPSHOT_STARTUP_GRACE_SEC)

    try:
        # 라운드 종료 snapshot 기준으로 checker를 실행한다.
        checker_results = await chk.run_all_checkers(
            scoring_teams, vuln_specs, _round_flags_by_team(current), CHECKER_TOKEN
        )
        availability = {
            team_id: result.health_ok
            for team_id, result in checker_results.items()
        }

        # checker가 snapshot에 현재 라운드 flag를 주입/검증한 뒤 제출 PoC를 batch 실행한다.
        poc_results = _run_pocs(current, teams_override=scoring_teams)

        # checker/PoC가 현재 라운드 flag를 모두 사용한 뒤 만료 처리한다.
        fm.expire_round_flags(current)

        # 점수 계산
        round_result = compute_round_scores(
            list(TEAMS.keys()), current, availability,
            ATTACK_REWARD, ATTACK_PENALTY, AVAILABILITY_BONUS,
        )

        # DB 점수 반영: PoC 점수는 batch 실행 시점에 이미 반영되므로
        # 라운드 종료 시에는 availability bonus만 적용한다.
        for team, delta in round_result["availability_score_changes"].items():
            if delta > 0:
                db.update_score(team, delta)

        scores_after = {tid: info["score"] for tid, info in db.get_all_scores().items()}
        exploits = db.get_round_exploits(current)

        db.append_history(
            current, exploits, availability,
            round_result["score_changes"], scores_after,
        )

        return {
            "round": current,
            "exploits": exploits,
            "availability": availability,
            "service_statuses": round_result["service_statuses"],
            "score_changes": round_result["score_changes"],
            "availability_score_changes": round_result["availability_score_changes"],
            "poc_score_changes": round_result["poc_score_changes"],
            "scores_after": scores_after,
            "pocs_run": len(poc_results),
            "scoring_snapshot": {
                "enabled": bool(snapshot),
                "images": snapshot.image_tags if snapshot else {},
            },
        }
    finally:
        if snapshot and not SCORING_SNAPSHOT_KEEP_CONTAINERS:
            cleanup_round_snapshot(snapshot)


@app.post("/admin/preflight-done")
def mark_preflight(x_admin_secret: str = Header(...)):
    verify_admin(x_admin_secret)
    db.set_preflight_done()
    return {"ok": True, "message": "사전검증 완료 표시됨"}


@app.post("/admin/service-deployed")
async def service_deployed(req: ServiceDeployedRequest, x_admin_secret: str = Header(...)):
    """git post-receive hook에서 호출 — 배포 후 flag 재주입."""
    verify_admin(x_admin_secret)
    if req.team_id not in TEAMS:
        raise HTTPException(400, f"알 수 없는 팀: {req.team_id}")
    spec_path = Path(VULN_SPEC_DIR) / f"{req.team_id}.json"
    if spec_path.exists():
        with spec_path.open() as f:
            spec_data = json.load(f)
        vuln_specs[req.team_id] = spec_data
    await handle_service_deployed(
        req.team_id,
        req.commit,
        state.current_round,
        vuln_specs,
        team_info=TEAMS[req.team_id],
        checker_token=CHECKER_TOKEN,
        pusher_team_id=req.pusher_team_id,
        agent_run_id=req.agent_run_id,
    )
    return {"ok": True, "team_id": req.team_id}


@app.post("/admin/validate-defense-push")
def validate_defense_push(req: DefensePushValidationRequest, x_admin_secret: str = Header(...)):
    verify_admin(x_admin_secret)
    if req.repo_team_id not in TEAMS or req.pusher_team_id not in TEAMS:
        raise HTTPException(400, "알 수 없는 팀")
    if get_defender(req.repo_team_id) != req.pusher_team_id:
        raise HTTPException(403, "해당 repo의 방어팀이 아님")
    run = _require_run(
        req.agent_run_id,
        team_id=req.pusher_team_id,
        mode="defense",
        target_team=req.repo_team_id,
    )
    if run.get("status") != "running":
        raise HTTPException(403, "이미 종료된 defense run은 push에 사용할 수 없음")
    if run["round_num"] != state.current_round:
        raise HTTPException(403, "defense run round 불일치")
    if get_defense_target(req.pusher_team_id) != req.repo_team_id:
        raise HTTPException(403, "defense target 불일치")
    if not db.has_llm_call(req.agent_run_id, allowed_only=True, successful_only=True, purpose="defense"):
        raise HTTPException(403, "해당 defense run에 성공한 whitelist /llm 호출이 없음")
    return {"ok": True, "agent_run_id": req.agent_run_id, "repo_team_id": req.repo_team_id}


@app.get("/admin/audit-log")
def get_audit_log(
    x_admin_secret: str = Header(...),
    attacker: str | None = Query(default=None),
    target: str | None = Query(default=None),
    round_num: int | None = Query(default=None),
    limit: int = Query(default=500, le=2000),
):
    verify_admin(x_admin_secret)
    entries = db.query_audit(attacker=attacker, target=target, round_num=round_num, limit=limit)
    return {"entries": entries}


@app.get("/admin/flags")
def get_active_flags(x_admin_secret: str = Header(...), round_num: int | None = Query(default=None)):
    """운영자용 현재 라운드 flag 확인 (사후 검증용)."""
    verify_admin(x_admin_secret)
    rn = round_num if round_num is not None else state.current_round
    flags = db.get_flags_for_round(rn)
    return {"round": rn, "flags": flags}


# ── 조회 엔드포인트 ───────────────────────────────────────────────────

@app.get("/scoreboard")
def scoreboard():
    poc_exploit_counts = db.count_successful_pocs_by_attacker()
    pending_poc_counts = db.count_pending_pocs_by_attacker(state.current_round)
    service_statuses = db.get_service_statuses()
    current_poc_results = []
    for result in db.list_poc_results(round_num=state.current_round, limit=200):
        safe_result = dict(result)
        flags = safe_result.pop("flags", []) or []
        safe_result.pop("target_team", None)
        safe_result.pop("defender_team", None)
        safe_result["flags_found"] = len(flags)
        current_poc_results.append(safe_result)
    queued_pocs = db.list_pending_pocs_public(round_num=state.current_round, limit=200)
    return {
        "round": state.current_round,
        "round_active": state.round_active,
        "total_rounds": TOTAL_ROUNDS,
        "scores": [
            {
                "team_id": tid,
                "name": TEAMS[tid]["name"],
                "score": state.scores.get(tid, 0),
                "turns_used": state.round_attacks.get(tid, 0),
                "turns_remaining": MAX_ATTACKS_ROUND - state.round_attacks.get(tid, 0),
                "exploit_count_total": poc_exploit_counts.get(tid, 0),
                "queued_poc_count": pending_poc_counts.get(tid, 0),
                "service_status": service_statuses.get(tid, "UNKNOWN"),
            }
            for tid in sorted(TEAMS, key=lambda t: state.scores.get(t, 0), reverse=True)
        ],
        "queued_pocs": queued_pocs,
        "poc_results": current_poc_results,
    }


@app.get("/status")
def status():
    meta = db.get_meta()
    return {
        "round": state.current_round,
        "round_active": state.round_active,
        "round_start_time": state.round_start_time,
        "total_rounds": TOTAL_ROUNDS,
        "preflight_done": meta.preflight_done,
    }


@app.get("/history")
def history():
    return {"history": state.history}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=COORDINATOR_PORT)
