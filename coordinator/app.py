import hashlib
import json
import httpx
from fastapi import FastAPI, HTTPException, Header, Request, Query, UploadFile, File, Form
from fastapi.responses import JSONResponse, Response
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from contextlib import asynccontextmanager
from pathlib import Path
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
    DEFENSE_TOKENS,
    ALLOWED_MODEL_PREFIXES,
    VULN_SPEC_DIR, DB_PATH,
    OPENROUTER_API_KEY, OPENROUTER_BASE_URL,
    DATA_DIR, POC_TIMEOUT_SEC, POC_MAX_BYTES, POC_OUTPUT_MAX_BYTES,
    POC_RUNNER_MODE, POC_DOCKER_NETWORK, POC_DOCKER_IMAGE, POC_HOST_DATA_DIR,
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
    load_vuln_specs, check_availability,
    scan_response_for_flags, compute_round_scores,
)
from agent_runner import run_attack_agents, stop_round_agents
from poc_runner import run_pocs_for_round

import os
CHECKER_TOKEN = os.getenv("CHECKER_TOKEN", "checker-token-changeme")


def _team_token_key(request: Request) -> str:
    return request.headers.get("X-Team-Token") or get_remote_address(request)


limiter = Limiter(key_func=_team_token_key)

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


# ── 모델 ──────────────────────────────────────────────────────────────

class AttackRequest(BaseModel):
    agent_run_id: str
    llm_call_id: int
    attacker_team: str
    target_team: str
    payload: str
    model: str | None = None
    session_id: str | None = None
    history: list[dict] | None = None


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


class PocReviewRequest(BaseModel):
    reason: str = ""


class RunPocsRequest(BaseModel):
    round_num: int | None = None
    only_poc_id: str | None = None


ALLOWED_LLM_PURPOSES = {"general", "scan", "poc", "defense"}


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


# ── 헬스 엔드포인트 ───────────────────────────────────────────────────

@app.get("/health")
def health():
    if not db.ping():
        raise HTTPException(503, "DB unreachable")
    meta = db.get_meta()
    return {"status": "ok", "round": meta.current_round, "round_active": meta.round_active}


# ── agent provenance / LLM gateway ────────────────────────────────────

@app.post("/agent-runs")
def create_agent_run(req: AgentRunCreateRequest, x_team_token: str = Header(...)):
    verify_agent_token(req.team_id, req.mode, x_team_token)
    _validate_agent_run_request(req)

    run = db.create_agent_run(
        run_id=str(uuid4()),
        team_id=req.team_id,
        mode=req.mode,
        target_team=req.target_team,
        round_num=req.round_num,
        agent_image=req.agent_image,
        agent_image_digest=req.agent_image_digest,
        agent_commit=req.agent_commit,
    )
    return {
        "agent_run_id": run["id"],
        "allowed_models": ALLOWED_MODEL_PREFIXES,
    }


@app.post("/agent-runs/{run_id}/finish")
def finish_agent_run(
    run_id: str,
    req: AgentRunFinishRequest,
    x_team_token: str = Header(...),
):
    run = _require_run(run_id)
    verify_agent_token(run["team_id"], run["mode"], x_team_token)
    if req.status not in {"completed", "failed", "cancelled"}:
        raise HTTPException(400, "status는 completed, failed, cancelled만 허용")
    if not db.finish_agent_run(run_id, req.status, req.error):
        raise HTTPException(404, "agent run 없음")
    return {"ok": True, "agent_run_id": run_id, "status": req.status}


@app.get("/agent-runs/{run_id}/target-repo.tar")
def target_repo_archive(run_id: str, x_team_token: str = Header(...)):
    run = _require_run(run_id, mode="attack")
    verify_agent_token(run["team_id"], run["mode"], x_team_token)
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


@app.post("/llm")
async def llm_gateway(req: LLMRequest, x_team_token: str = Header(...)):
    run = _require_run(req.agent_run_id)
    verify_agent_token(run["team_id"], run["mode"], x_team_token)
    _check_llm_purpose(req.purpose)

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
    }


# ── 공격 엔드포인트 ───────────────────────────────────────────────────

@app.post("/attack")
@limiter.limit("20/minute")
async def attack(request: Request, req: AttackRequest, x_team_token: str = Header(...)):
    verify_team_token(req.attacker_team, x_team_token)

    run = _require_run(
        req.agent_run_id,
        team_id=req.attacker_team,
        mode="attack",
        target_team=req.target_team,
    )
    if run["round_num"] != state.current_round:
        raise HTTPException(400, "agent run round 불일치")
    llm_call = _require_llm_call(req.agent_run_id, req.llm_call_id, purpose="scan")

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

    # 타겟 서비스 SLA 상태 확인 — DOWN이면 공격 불가
    statuses = db.get_service_statuses()
    if statuses.get(req.target_team, "UNKNOWN") == "DOWN":
        raise HTTPException(503, f"타겟 서비스({req.target_team})가 DOWN 상태 — 공격 불가")

    if state.get_attack_count(req.attacker_team) >= MAX_ATTACKS_ROUND:
        raise HTTPException(429, f"이번 라운드 공격 횟수 초과 ({MAX_ATTACKS_ROUND}턴 한도)")

    # 타겟 서비스에 페이로드 전달
    target = TEAMS[req.target_team]
    url = f"http://{target['ip']}:{target['port']}/chat"
    body: dict = {"message": req.payload}
    if req.session_id:
        body["session_id"] = req.session_id
    if req.history:
        body["history"] = req.history

    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(url, json=body)
            resp.raise_for_status()
            data = resp.json()
    except httpx.HTTPStatusError as e:
        raise HTTPException(502, f"타겟 서비스 오류: {e.response.status_code}")
    except Exception as e:
        raise HTTPException(503, f"타겟 서비스 응답 없음: {str(e)}")

    response_text = data.get("response", "")

    state.record_attack(req.attacker_team)

    # 응답에서 flag 패턴 스캔 (공격 에이전트에게 힌트 제공)
    found_flags = scan_response_for_flags(response_text)

    # 감사 로그
    db.append_audit(
        round_num=state.current_round,
        attacker=req.attacker_team,
        target=req.target_team,
        payload_hash=hashlib.sha256(req.payload.encode()).hexdigest(),
        model=llm_call.get("model") or req.model,
        exploited=bool(found_flags),
        scored=False,
        response_hash=hashlib.sha256(response_text.encode()).hexdigest(),
        agent_run_id=req.agent_run_id,
        llm_call_id=req.llm_call_id,
    )

    return {
        "response": response_text,
        "tool_calls": data.get("tool_calls", []),
        "flags_found": found_flags,
        "hint": "발견된 flag가 재현되도록 poc*.py를 제출하세요" if found_flags else None,
        "turns_remaining": MAX_ATTACKS_ROUND - state.get_attack_count(req.attacker_team),
    }


# ── PoC 제출/검수/실행 ────────────────────────────────────────────────

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


@app.post("/pocs")
async def submit_poc(
    agent_run_id: str = Form(...),
    llm_call_id: int = Form(...),
    attacker_team: str = Form(...),
    target_team: str = Form(...),
    flag_id: str = Form(...),
    sha256: str = Form(...),
    file: UploadFile = File(...),
    x_team_token: str = Header(...),
):
    verify_team_token(attacker_team, x_team_token)
    run = _require_run(agent_run_id, team_id=attacker_team, mode="attack", target_team=target_team)
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
    _require_llm_call(agent_run_id, llm_call_id, purpose="poc")

    content = await file.read()
    actual_sha = hashlib.sha256(content).hexdigest()
    if actual_sha != sha256:
        raise HTTPException(400, "sha256 불일치")

    file_name = Path(file.filename or "").name
    reason = _validate_poc_static(file_name, content)
    if reason:
        raise HTTPException(400, reason)

    duplicate = db.find_poc_by_sha(attacker_team, target_team, sha256)
    if duplicate:
        return {
            "poc_id": duplicate["id"],
            "status": "merged",
            "canonical_poc_id": duplicate.get("canonical_poc_id") or duplicate["id"],
            "sha256": sha256,
        }

    poc_id = str(uuid4())
    storage_dir = Path(DATA_DIR) / "pocs" / str(run["round_num"]) / poc_id
    storage_dir.mkdir(parents=True, exist_ok=True)
    storage_path = storage_dir / file_name
    storage_path.write_bytes(content)

    poc = db.create_poc_submission(
        poc_id=poc_id,
        agent_run_id=agent_run_id,
        llm_call_id=llm_call_id,
        attacker_team=attacker_team,
        target_team=target_team,
        defender_team=get_defender(target_team),
        flag_id=flag_id,
        submitted_round=run["round_num"],
        file_name=file_name,
        sha256=sha256,
        storage_path=str(storage_path),
    )
    return {"poc_id": poc["id"], "status": poc["status"], "sha256": poc["sha256"]}


@app.get("/admin/pocs")
def list_pocs(
    x_admin_secret: str = Header(...),
    status: str | None = Query(default=None),
    limit: int = Query(default=500, le=2000),
):
    verify_admin(x_admin_secret)
    return {"pocs": db.list_poc_submissions(status=status, limit=limit)}


@app.post("/admin/pocs/{poc_id}/accept")
def accept_poc(poc_id: str, req: PocReviewRequest, x_admin_secret: str = Header(...)):
    verify_admin(x_admin_secret)
    if not db.get_poc_submission(poc_id):
        raise HTTPException(404, "PoC 없음")
    db.update_poc_status(poc_id, "accepted", req.reason)
    return {"ok": True, "poc_id": poc_id, "status": "accepted"}


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
    results = run_pocs_for_round(
        round_num=round_num,
        teams=TEAMS,
        data_dir=DATA_DIR,
        timeout_sec=POC_TIMEOUT_SEC,
        output_max_bytes=POC_OUTPUT_MAX_BYTES,
        attack_reward=ATTACK_REWARD,
        attack_penalty=ATTACK_PENALTY,
        only_poc_id=req.only_poc_id,
        runner_mode=POC_RUNNER_MODE,
        docker_network=POC_DOCKER_NETWORK,
        docker_image=POC_DOCKER_IMAGE,
        host_data_dir=POC_HOST_DATA_DIR,
    )
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
            "사전검증 미완료. scripts/preflight_check.py 실행 후 시도하거나 ?force=true 사용"
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

    poc_results = run_pocs_for_round(
        round_num=next_round,
        teams=TEAMS,
        data_dir=DATA_DIR,
        timeout_sec=POC_TIMEOUT_SEC,
        output_max_bytes=POC_OUTPUT_MAX_BYTES,
        attack_reward=ATTACK_REWARD,
        attack_penalty=ATTACK_PENALTY,
        runner_mode=POC_RUNNER_MODE,
        docker_network=POC_DOCKER_NETWORK,
        docker_image=POC_DOCKER_IMAGE,
        host_data_dir=POC_HOST_DATA_DIR,
    )

    # 공격 에이전트 컨테이너 실행
    run_attack_agents(next_round, TEAMS, COORDINATOR_URL, TEAM_TOKENS, ATTACK_AGENT_IMAGES)

    checker_summary = {tid: r.status for tid, r in checker_results.items()}
    return {
        "round": next_round,
        "message": f"라운드 {next_round} 시작",
        "checker": checker_summary,
        "flags_generated": {tid: len(flags) for tid, flags in round_flags.items()},
        "pocs_run": len(poc_results),
    }


@app.post("/admin/end-round")
async def end_round(x_admin_secret: str = Header(...)):
    verify_admin(x_admin_secret)
    if not state.round_active:
        raise HTTPException(400, "진행 중인 라운드 없음")

    current = state.current_round
    stop_round_agents(current)

    # flag 만료
    fm.expire_round_flags(current)

    availability = await check_availability(TEAMS)

    # 점수 계산
    round_result = compute_round_scores(
        list(TEAMS.keys()), current, availability,
        ATTACK_REWARD, ATTACK_PENALTY, AVAILABILITY_BONUS,
    )

    # DB 점수 반영: PoC 점수는 발생 시점에 이미 반영되므로
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
    db.set_round_active(current, False)

    return {
        "round": current,
        "exploits": exploits,
        "availability": availability,
        "service_statuses": round_result["service_statuses"],
        "score_changes": round_result["score_changes"],
        "availability_score_changes": round_result["availability_score_changes"],
        "poc_score_changes": round_result["poc_score_changes"],
        "scores_after": scores_after,
    }


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
        vuln_specs[req.team_id] = spec_data.get("vulnerabilities", [])
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
    service_statuses = db.get_service_statuses()
    current_poc_results = db.list_poc_results(round_num=state.current_round, limit=200)
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
                "service_status": service_statuses.get(tid, "UNKNOWN"),
                "attack_targets": get_attack_targets(tid),
            }
            for tid in sorted(TEAMS, key=lambda t: state.scores.get(t, 0), reverse=True)
        ],
        "round_exploits": [
            {"attacker": a, "defender": d}
            for a, d in state.round_exploits
        ],
        "poc_results": current_poc_results,
    }


@app.get("/status")
def status():
    return {
        "round": state.current_round,
        "round_active": state.round_active,
        "round_start_time": state.round_start_time,
        "total_rounds": TOTAL_ROUNDS,
    }


@app.get("/history")
def history():
    return {"history": state.history}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=COORDINATOR_PORT)
