import hashlib
import httpx
from fastapi import FastAPI, HTTPException, Header, Request, Query
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from contextlib import asynccontextmanager
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address

import db
import flag_manager as fm
import checker as chk
from git_handler import router as git_router, init_all_repos, handle_service_deployed
from config import (
    TEAMS, STARTING_SCORE, MAX_ATTACKS_ROUND,
    ATTACK_REWARD, ATTACK_PENALTY, AVAILABILITY_BONUS,
    TOTAL_ROUNDS, COORDINATOR_PORT, ADMIN_SECRET,
    CREDIT_PER_TEAM, TEAM_TOKENS,
    ATTACK_AGENT_IMAGES, COORDINATOR_URL,
    ALLOWED_MODEL_PREFIXES,
    VULN_SPEC_DIR, DB_PATH,
)
from state import GameState
from scorer import (
    load_vuln_specs, check_availability,
    scan_response_for_flags, verify_and_record_flag, compute_round_scores,
)
from agent_runner import run_attack_agents, stop_round_agents

import os
CHECKER_TOKEN = os.getenv("CHECKER_TOKEN", "checker-token-changeme")


def _team_token_key(request: Request) -> str:
    return request.headers.get("X-Team-Token") or get_remote_address(request)


limiter = Limiter(key_func=_team_token_key)

state = GameState(list(TEAMS.keys()), STARTING_SCORE, CREDIT_PER_TEAM)
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
    attacker_team: str
    target_team: str
    payload: str
    session_id: str | None = None
    history: list[dict] | None = None
    step_cost: float = 0.0
    model: str | None = None


class FlagSubmitRequest(BaseModel):
    attacker_team: str
    flag: str


class ServiceDeployedRequest(BaseModel):
    team_id: str
    commit: str = ""


def _check_model(model: str | None) -> None:
    if model is None:
        raise HTTPException(400, "model 필드 필수 (사용한 LLM 모델 ID를 명시하세요)")
    lower = model.lower()
    for prefix in ALLOWED_MODEL_PREFIXES:
        if lower.startswith(prefix.lower()):
            return
    allowed = ", ".join(ALLOWED_MODEL_PREFIXES)
    raise HTTPException(403, f"허용되지 않은 모델: '{model}'. 허용 목록: {allowed}")


def verify_admin(secret: str) -> None:
    if secret != ADMIN_SECRET:
        raise HTTPException(403, "Admin secret 불일치")


# ── 헬스 엔드포인트 ───────────────────────────────────────────────────

@app.get("/health")
def health():
    if not db.ping():
        raise HTTPException(503, "DB unreachable")
    meta = db.get_meta()
    return {"status": "ok", "round": meta.current_round, "round_active": meta.round_active}


# ── 공격 엔드포인트 ───────────────────────────────────────────────────

@app.post("/attack")
@limiter.limit("20/minute")
async def attack(request: Request, req: AttackRequest, x_team_token: str = Header(...)):
    expected_token = TEAM_TOKENS.get(req.attacker_team)
    if expected_token is None or x_team_token != expected_token:
        raise HTTPException(403, "팀 토큰 불일치")

    _check_model(req.model)

    if req.attacker_team not in TEAMS:
        raise HTTPException(400, "알 수 없는 공격팀")
    if req.target_team not in TEAMS:
        raise HTTPException(400, "알 수 없는 타겟팀")
    if req.attacker_team == req.target_team:
        raise HTTPException(400, "자기 팀 공격 불가")
    if not state.round_active:
        raise HTTPException(400, "진행 중인 라운드 없음")

    # 타겟 서비스 SLA 상태 확인 — DOWN이면 공격 불가
    statuses = db.get_service_statuses()
    if statuses.get(req.target_team, "UNKNOWN") == "DOWN":
        raise HTTPException(503, f"타겟 서비스({req.target_team})가 DOWN 상태 — 공격 불가")

    if state.get_attack_count(req.attacker_team) >= MAX_ATTACKS_ROUND:
        raise HTTPException(429, f"이번 라운드 공격 횟수 초과 ({MAX_ATTACKS_ROUND}턴 한도)")

    if req.step_cost > 0 and state.get_credit(req.attacker_team) < req.step_cost:
        raise HTTPException(
            402,
            f"크레딧 부족 (잔액 ${state.get_credit(req.attacker_team):.4f}, "
            f"요청 ${req.step_cost:.4f})"
        )

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
    if req.step_cost > 0:
        state.deduct_credit(req.attacker_team, req.step_cost)

    # 응답에서 flag 패턴 스캔 (공격 에이전트에게 힌트 제공)
    found_flags = scan_response_for_flags(response_text)

    # 감사 로그
    db.append_audit(
        round_num=state.current_round,
        attacker=req.attacker_team,
        target=req.target_team,
        payload_hash=hashlib.sha256(req.payload.encode()).hexdigest(),
        model=req.model,
        step_cost=req.step_cost,
        exploited=bool(found_flags),
        scored=False,  # /submit-flag에서 채점
        response_hash=hashlib.sha256(response_text.encode()).hexdigest(),
    )

    return {
        "response": response_text,
        "tool_calls": data.get("tool_calls", []),
        "flags_found": found_flags,           # 응답에서 발견된 flag 목록
        "hint": "발견된 flag를 /submit-flag로 제출하세요" if found_flags else None,
        "turns_remaining": MAX_ATTACKS_ROUND - state.get_attack_count(req.attacker_team),
        "credit_remaining": state.get_credit(req.attacker_team),
    }


# ── flag 제출 엔드포인트 ───────────────────────────────────────────────

@app.post("/submit-flag")
@limiter.limit("30/minute")
async def submit_flag(request: Request, req: FlagSubmitRequest, x_team_token: str = Header(...)):
    # 팀 토큰 인증
    expected_token = TEAM_TOKENS.get(req.attacker_team)
    if expected_token is None or x_team_token != expected_token:
        raise HTTPException(403, "팀 토큰 불일치")

    if not state.round_active:
        raise HTTPException(400, "진행 중인 라운드 없음")

    result = verify_and_record_flag(
        flag=req.flag,
        attacker=req.attacker_team,
        round_num=state.current_round,
    )

    if result is None:
        return {"scored": False, "message": "오답, 만료된 flag, 자기 팀 flag, 또는 이미 제출됨"}

    # 점수 즉시 반영
    db.update_score(req.attacker_team, ATTACK_REWARD)
    db.update_score(result["defender"], -ATTACK_PENALTY)

    # round_exploits에도 기록 (scoreboard 표시용)
    state.record_exploit(req.attacker_team, result["defender"])

    return {
        "scored": True,
        "attacker": req.attacker_team,
        "defender": result["defender"],
        "vuln_id": result["vuln_id"],
        "reward": ATTACK_REWARD,
        "message": f"{result['defender']}의 {result['vuln_id']} flag 탈취 성공! +{ATTACK_REWARD}점",
    }


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
    round_flags = fm.generate_round_flags(next_round, list(TEAMS.keys()), vuln_specs, inject=True)

    # checker 실행
    round_flags_by_team = {
        team_id: team_flags
        for team_id, team_flags in round_flags.items()
    }
    checker_results = await chk.run_all_checkers(
        TEAMS, vuln_specs, round_flags_by_team, CHECKER_TOKEN
    )

    # 공격 에이전트 컨테이너 실행
    run_attack_agents(next_round, TEAMS, COORDINATOR_URL, TEAM_TOKENS, ATTACK_AGENT_IMAGES)

    checker_summary = {tid: r.status for tid, r in checker_results.items()}
    return {
        "round": next_round,
        "message": f"라운드 {next_round} 시작",
        "checker": checker_summary,
        "flags_generated": {tid: len(flags) for tid, flags in round_flags.items()},
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

    # DB 점수 반영 (availability bonus)
    for team, delta in round_result["score_changes"].items():
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
        "scores_after": scores_after,
        "flag_captures": round_result["flag_captures"],
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
    await handle_service_deployed(req.team_id, req.commit, state.current_round, vuln_specs)
    return {"ok": True, "team_id": req.team_id}


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
    exploit_counts = db.get_all_exploit_counts()
    service_statuses = db.get_service_statuses()
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
                "credit_remaining": state.get_credit(tid),
                "exploit_count_total": exploit_counts.get(tid, 0),
                "service_status": service_statuses.get(tid, "UNKNOWN"),
            }
            for tid in sorted(TEAMS, key=lambda t: state.scores.get(t, 0), reverse=True)
        ],
        "round_exploits": [
            {"attacker": a, "defender": d}
            for a, d in state.round_exploits
        ],
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
