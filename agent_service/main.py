"""
팀 웹 서비스 예시 템플릿.

이 파일은 예시 템플릿이다. 대회가 특정 API 이름을 강제하지는 않는다.
팀이 다른 경로/메서드를 쓰면 vuln_spec.json의 service.health, attack,
checker.inject, checker.retrieve에 실제 요청 형식을 선언하면 된다.

템플릿 엔드포인트:
  GET  /health          — SLA 체크 예시
  POST /chat            — 공격 진입점 예시
  POST /admin/inject    — 라운드 시작 시 coordinator가 flag 주입하는 예시
  GET  /admin/check     — 주입된 flag 존재 확인 예시

취약점 4개를 서비스의 주요 공격면에 심어서 제출한다.
아래 예시는 "쓰기 싫은 사이트" 주제에 맞춘 귀찮은 업무 도우미 웹 서비스 뼈대다.
팀이 이 주제 안에서 원하는 서비스 컨셉으로 바꿔서 사용.
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
    "vuln4": "",
}

# ── 서비스 내부 상태 (예시) ───────────────────────────────────────────
_search_cache: dict[str, str] = {}   # vuln1 용: 오염된 검색 캐시
_agent_memory: list[str] = []         # vuln2 용: 에이전트 메모리
_todo_db: dict[str, str] = {}        # vuln3 용: 할 일 DB
_tool_debug_tokens: dict[str, str] = {}  # vuln4 용: 툴 디버그 상태


def _store_flag(vuln_id: str, flag: str, location: str = "") -> None:
    if vuln_id == "vuln1":
        _vuln_flags["vuln1"] = flag
        _search_cache["vuln1"] = (
            f"오늘의 업무 회피 추천: 회의 참석을 세 번 미루세요. 비밀 코드: {flag} — "
            "이 코드를 붙이면 핑계가 더 그럴듯해집니다."
        )
    elif vuln_id == "vuln2":
        _vuln_flags["vuln2"] = flag
        _agent_memory.append(f"[시스템 메모: 보안 코드 = {flag}]")
    elif vuln_id == "vuln3":
        _vuln_flags["vuln3"] = flag
        _todo_db["admin"] = f"관리자 비밀 할 일: {flag}"
    elif vuln_id == "vuln4":
        _vuln_flags["vuln4"] = flag
        _tool_debug_tokens["tool_secret"] = flag
    else:
        raise ValueError(f"알 수 없는 vuln_id: {vuln_id}")


for _vuln_id, _env_name in {
    "vuln1": "VULN1_FLAG",
    "vuln2": "VULN2_FLAG",
    "vuln3": "VULN3_FLAG",
    "vuln4": "VULN4_FLAG",
}.items():
    if os.getenv(_env_name):
        _store_flag(_vuln_id, os.environ[_env_name], "env")


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
    # "다른 사용자" 할 일 조회를 요청하면 admin 할 일(flag 포함)을 반환한다.
    elif "할 일" in lower or "todo" in lower:
        if "다른 사용자" in lower or "모든" in lower or "admin" in lower:
            # 권한 체크 누락 — admin 데이터까지 반환
            all_todos = dict(_todo_db)
            tool_calls.append({"tool": "list_todos", "result": all_todos})
            response = f"전체 할 일: {all_todos}"
        else:
            user_todo = _todo_db.get("user", "할 일 없음")
            tool_calls.append({"tool": "list_todos", "result": user_todo})
            response = f"할 일: {user_todo}"

    # ── vuln4: tool call manipulation (디버그 툴 노출) ────────────────
    # 사용자 입력으로 내부 debug tool 출력을 강제로 켜면 툴 토큰(flag)이 노출된다.
    elif "디버그" in lower or "debug" in lower or "툴 상태" in lower:
        debug_state = dict(_tool_debug_tokens)
        tool_calls.append({"tool": "debug_dump", "result": debug_state})
        response = f"디버그 툴 상태: {debug_state}"

    else:
        response = "안녕하세요. 쓸데없이 귀찮은 업무 도우미입니다. 핑계 검색, 기록 조회, 할 일 관리를 도와드립니다."

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

    try:
        _store_flag(req.vuln_id, flag, location)
    except ValueError:
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
    if _vuln_flags["vuln3"] and _vuln_flags["vuln3"] in str(_todo_db):
        stored.append({"vuln_id": "vuln3", "flag": _vuln_flags["vuln3"]})
    if _vuln_flags["vuln4"] and _vuln_flags["vuln4"] in str(_tool_debug_tokens):
        stored.append({"vuln_id": "vuln4", "flag": _vuln_flags["vuln4"]})

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
