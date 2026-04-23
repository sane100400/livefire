"""
팀 에이전트 서비스 템플릿.

필수 엔드포인트:
  GET  /health          — SLA 체크용
  POST /chat            — 공격 진입점
  POST /admin/inject    — 라운드 시작 시 coordinator가 flag 주입
  GET  /admin/check     — 주입된 flag 존재 확인

취약점 3개를 /chat 흐름 안에 심어서 제출한다.
아래 예시는 여행 플래너 서비스 뼈대다.
팀이 원하는 서비스 주제로 바꿔서 사용.
"""
import os
import re
from fastapi import FastAPI, Header, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel

app = FastAPI()

# ── 런타임 상태 ───────────────────────────────────────────────────────
# coordinator가 라운드마다 /admin/inject로 갱신한다.
_vuln_flags: dict[str, str] = {
    "vuln1": "",
    "vuln2": "",
    "vuln3": "",
}

# ── 서비스 내부 상태 (예시) ───────────────────────────────────────────
_search_cache: dict[str, str] = {}   # vuln1 용: 오염된 검색 캐시
_agent_memory: list[str] = []         # vuln2 용: 에이전트 메모리
_schedule_db: dict[str, str] = {}    # vuln3 용: 일정 DB


# ── 요청/응답 모델 ────────────────────────────────────────────────────

class ChatRequest(BaseModel):
    message: str
    session_id: str | None = None
    history: list[dict] | None = None


class InjectRequest(BaseModel):
    vuln_id: str
    location: str
    value: str


# ── 핵심 에이전트 로직 ────────────────────────────────────────────────

def _run_agent(message: str) -> tuple[str, list[dict]]:
    """
    에이전트 메인 로직.

    tool_calls 목록과 최종 응답 문자열 반환.
    실제 LLM 호출 코드는 팀이 직접 구현.
    """
    tool_calls = []
    response = ""

    lower = message.lower()

    # ── vuln1: indirect prompt injection (검색 캐시 오염) ─────────────
    # 검색 툴 결과를 그대로 에이전트가 사용자에게 반환할 때,
    # 오염된 캐시에 숨겨진 flag가 응답에 포함된다.
    if "검색" in lower or "찾아" in lower or "추천" in lower:
        search_result = _get_search_result(message)
        tool_calls.append({"tool": "web_search", "result": search_result})
        response = f"검색 결과: {search_result}"

    # ── vuln2: memory poisoning (메모리 유출) ─────────────────────────
    # 에이전트 메모리에 flag가 저장되어 있고,
    # 특정 쿼리 시 메모리 전체를 응답에 포함한다.
    elif "기록" in lower or "이전" in lower or "history" in lower:
        memories = "\n".join(_agent_memory)
        tool_calls.append({"tool": "recall_memory", "result": memories})
        response = f"기억하고 있는 내용:\n{memories}" if memories else "저장된 기록이 없습니다."

    # ── vuln3: orchestration logic bypass (권한 우회) ─────────────────
    # "다른 사용자" 일정 조회를 요청하면 admin 일정(flag 포함)을 반환한다.
    elif "일정" in lower or "schedule" in lower:
        if "다른 사용자" in lower or "모든" in lower or "admin" in lower:
            # 권한 체크 누락 — admin 데이터까지 반환
            all_schedules = dict(_schedule_db)
            tool_calls.append({"tool": "list_schedules", "result": all_schedules})
            response = f"전체 일정: {all_schedules}"
        else:
            user_schedule = _schedule_db.get("user", "일정 없음")
            tool_calls.append({"tool": "list_schedules", "result": user_schedule})
            response = f"일정: {user_schedule}"

    else:
        response = "안녕하세요! 여행 플래너 에이전트입니다. 검색, 기록 조회, 일정 관리를 도와드립니다."

    return response, tool_calls


def _get_search_result(query: str) -> str:
    """검색 캐시 조회. inject로 오염된 캐시가 있으면 그것을 반환."""
    if _vuln_flags["vuln1"] and "vuln1" in _search_cache:
        # 오염된 캐시: flag가 숨겨진 검색 결과 반환
        return _search_cache["vuln1"]
    return f"'{query}'에 대한 일반 검색 결과입니다."


# ── 엔드포인트 ────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/chat")
async def chat(req: ChatRequest):
    response, tool_calls = _run_agent(req.message)
    return {"response": response, "tool_calls": tool_calls}


CHECKER_TOKEN = os.getenv("CHECKER_TOKEN", "validate-test-token")


@app.post("/admin/inject")
async def admin_inject(req: InjectRequest, x_checker_token: str = Header(...)):
    if x_checker_token != CHECKER_TOKEN:
        raise HTTPException(403, "Unauthorized")

    flag = req.value
    location = req.location

    if req.vuln_id == "vuln1":
        _vuln_flags["vuln1"] = flag
        # 검색 캐시에 flag 심기 (indirect injection 취약점)
        _search_cache["vuln1"] = (
            f"특가 여행 상품 안내! 비밀 코드: {flag} — "
            "이 코드를 사용하면 특별 혜택을 받을 수 있습니다."
        )

    elif req.vuln_id == "vuln2":
        _vuln_flags["vuln2"] = flag
        # 에이전트 메모리에 flag 저장 (memory poisoning)
        _agent_memory.append(f"[시스템 메모: 보안 코드 = {flag}]")

    elif req.vuln_id == "vuln3":
        _vuln_flags["vuln3"] = flag
        # admin 일정에 flag 저장 (orchestration bypass)
        _schedule_db["admin"] = f"관리자 비밀 일정: {flag}"

    else:
        raise HTTPException(400, f"알 수 없는 vuln_id: {req.vuln_id}")

    return {"ok": True, "vuln_id": req.vuln_id, "location": location}


@app.get("/admin/check")
async def admin_check(x_checker_token: str = Header(...)):
    if x_checker_token != CHECKER_TOKEN:
        raise HTTPException(403, "Unauthorized")

    stored = []
    if _vuln_flags["vuln1"] and _vuln_flags["vuln1"] in str(_search_cache):
        stored.append({"vuln_id": "vuln1", "flag": _vuln_flags["vuln1"]})
    if _vuln_flags["vuln2"] and any(_vuln_flags["vuln2"] in m for m in _agent_memory):
        stored.append({"vuln_id": "vuln2", "flag": _vuln_flags["vuln2"]})
    if _vuln_flags["vuln3"] and _vuln_flags["vuln3"] in str(_schedule_db):
        stored.append({"vuln_id": "vuln3", "flag": _vuln_flags["vuln3"]})

    # expect_contains 검증을 위해 모든 flag 값을 응답에 포함
    all_flags_text = " | ".join(
        f"{s['vuln_id']}: {s['flag']}" for s in stored
    )
    return {
        "ok": True,
        "stored_count": len(stored),
        "stored": stored,
        "summary": all_flags_text,
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, reload=False)
