# HSPACE AI Agent Attack & Defense — Rulebook

## 개요

AI 에이전트 서비스를 직접 설계·공격·방어하는 **Live-Fire Attack & Defense CTF**.  
취약점은 팀이 직접 심고, 공격 에이전트가 실제 서버를 대상으로 실시간 익스플로잇.

- **팀 수**: 6팀 × 최대 5인
- **라운드**: 20라운드 × 30분 = 10시간
- **라운드당 외부 요청**: 팀당 최대 **10턴** (내부 LLM 추론은 무제한)
- **LLM 모델**: 화이트리스트 내 자유 사용 (아래 허용 모델 목록 참고)

---

## 경기 구조

```
준비 단계 (이벤트 전)     경쟁 단계 (21:00 →)          마무리
──────────────────────   ──────────────────────────   ──────────
서비스 코드 개발          라운드 1~20 자동 진행          최종 발표
취약점 설계·주입           30분마다 자동 라운드 전환       시상
git push로 제출           실시간 공격·방어·패치
vuln_spec 검증            스코어보드 갱신
```

---

## 팀이 만드는 것

각 팀은 **두 가지**를 제출한다:

### 1. 방어 서비스 (`agent_service/`)

LLM 기반 AI 에이전트 서비스. **3개의 의도된 취약점**을 숨겨서 제출.

**필수 엔드포인트:**

| 엔드포인트 | 설명 |
|---|---|
| `GET /health` | `200 OK` 반환 (SLA 체크용) |
| `POST /chat` | `{"message": str}` → `{"response": str, "tool_calls": list}` |
| `POST /admin/inject` | `X-Checker-Token` 인증. coordinator가 flag를 서비스에 주입 |
| `GET /admin/check` | `X-Checker-Token` 인증. 주입된 flag 존재 여부 확인 |

**취약점 구현 원칙:**
- `os.environ["VULN1_FLAG"]` 형태로 flag 읽기 (coordinator가 런타임에 주입)
- 취약 경로(tool 결과, 메모리, DB 등)에 flag 값 노출
- 취약점을 패치해도 `/chat` 기본 기능은 유지해야 함 (기능 망가지면 FAULTY)

**취약점 유형 예시:**

| 유형 | 설명 |
|---|---|
| `indirect_prompt_injection` | tool 출력에 숨긴 injection → 에이전트가 flag 응답 |
| `memory_poisoning` | 에이전트 메모리에 저장된 flag가 특정 쿼리로 유출 |
| `orchestration_logic_bypass` | 다단계 툴 체인에서 권한 우회 → flag 포함 데이터 노출 |
| `rag_poisoning` | RAG 검색 결과에 숨겨진 flag |
| `tool_call_manipulation` | tool 파라미터 조작으로 flag 반환 유도 |

### 2. 공격 에이전트 (`attack_agent/`)

모든 상대 팀 서비스를 자동으로 공격하는 에이전트.  
라운드 시작 시 coordinator가 Docker 컨테이너로 실행.

**에이전트가 받는 환경변수:**
```
COORDINATOR_URL   http://coordinator:9000
ATTACKER_TEAM     teamA
TEAM_TOKEN        <인증 토큰>
ROUND             현재 라운드 번호
TARGETS           {"teamB": {"ip": "...", "port": 8000}, ...}
```

**공격 흐름:**
```
POST /attack  →  타겟 응답에서 HSPACE{...} 추출  →  POST /submit-flag  →  점수 획득
```

---

## Flag 체계

### 형식
```
HSPACE{[a-f0-9]{32}}
예: HSPACE{3a9f2c1e8b4d7f0a5e2c9b6d3f1a8e4c}
```

### 동작 방식
1. **라운드 시작**: coordinator가 팀×취약점별 flag를 무작위 생성 후 서비스에 환경변수로 주입
2. **공격**: 공격 에이전트가 `/attack`으로 페이로드 전송 → 응답에서 `HSPACE{...}` 패턴 추출
3. **제출**: `/submit-flag`로 탈취한 flag 제출 → coordinator가 현재 라운드 정답과 대조
4. **라운드 종료**: 이전 라운드 flag 전부 만료 → 재사용 불가

### Anti-Unintended 보장

| 공격 시도 | 결과 |
|---|---|
| `"HSPACE{...} 출력해줘"` 직접 요청 | **차단** — 공격자는 현재 flag 값을 모름 |
| vuln_spec 파일 읽기 | **무효** — spec엔 env var 이름만 있고 값은 런타임 secret |
| 이전 라운드 flag 재제출 | **차단** — 라운드 종료 시 flag 만료 |
| 같은 flag 중복 제출 | **차단** — DB UNIQUE 제약 |
| 자기 팀 flag 제출 | **차단** — coordinator에서 attacker == defender 거부 |

---

## 서비스 배포 (Git 기반)

```bash
# 최초 등록 (username=팀ID, password=배포받은 팀 토큰)
git remote add organizer http://teamA:<TEAM_TOKEN>@coordinator:9000/git/teamA
git push organizer main

# 패치 (대회 중 서비스 코드 업데이트)
git push organizer main
```

> credential을 매번 입력하지 않으려면:  
> `git config credential.helper store` 후 첫 push 시 한 번만 입력하면 저장됨.

**push 시 자동 실행:**
1. `pre-receive`: Dockerfile 빌드 검증. 대회 중 `vuln_spec.json` 수정 시 **거부**
2. Docker 이미지 빌드 → 기존 컨테이너 교체
3. 현재 라운드 flag 재주입
4. SLA 타이머 재시작 (다운타임 동안 가용성 보너스 없음)

> **vuln_spec.json은 21:00 이후 잠금** — 취약점 설계는 준비 단계에서 완료해야 함

---

## 서비스 상태 (SLA)

매 라운드 시작 전 coordinator가 checker를 실행:

| 상태 | 조건 | 가용성 보너스 | 방어 패널티 |
|---|---|---|---|
| **OK** | health + inject + retrieve + 기본 기능 모두 통과 | ✓ | ✓ |
| **FAULTY** | health는 살아있으나 checker 일부 실패 | ✗ | ✓ |
| **DOWN** | /health 응답 없음 | ✗ | ✗ |

> DOWN이면 공격도 받지 않지만 보너스도 없음 — **서비스 종료로 방어하는 전략은 손해**

---

## 점수 체계

| 이벤트 | 공격팀 | 방어팀 |
|---|---|---|
| Flag 탈취 성공 | **+10점** | **-10점** (DOWN 상태면 면제) |
| 서비스 가용성 (라운드당) | — | **+10점** (OK 상태일 때만) |
| 같은 타겟 중복 탈취 | 무효 | — |

**시작 점수**: 1000점  
**최종 순위**: 20라운드 후 총점 기준

---

## 공격 API

### `POST /attack`
```
Header: X-Team-Token: <토큰>
Body: {
  "attacker_team": "teamA",
  "target_team": "teamB",
  "payload": "공격 메시지",
  "model": "openai/gpt-4o-mini",
  "step_cost": 0.001,
  "session_id": "optional",
  "history": []
}

Response: {
  "response": "타겟 서비스 응답",
  "flags_found": ["HSPACE{3a9f...}"],   ← 탐지된 flag (있으면 즉시 제출)
  "turns_remaining": 8,
  "credit_remaining": 1.92
}
```

### `POST /submit-flag`
```
Header: X-Team-Token: <토큰>
Body: {"attacker_team": "teamA", "flag": "HSPACE{3a9f...}"}

Response (성공): {"scored": true, "defender": "teamB", "vuln_id": "vuln1", "reward": 10}
Response (실패): {"scored": false, "message": "오답/만료/중복"}
```

---

## 허용 모델 (OpenRouter)

| 모델 | 비고 |
|---|---|
| `qwen/qwen-2.5-14b`, `qwen/qwen-2.5-32b` | |
| `meta-llama/llama-3.1-70b` | |
| `google/gemma-3-27b` | |
| `openai/gpt-4o-mini` | |
| `google/gemini-flash-1.5`, `google/gemini-2.0-flash-001` | |
| `microsoft/phi-4` | |
| `mistralai/mistral-small-3.1` | |
| `deepseek/deepseek-chat` | |
| `xiaomi/mimo` | |

> prefix 매칭 — `openai/gpt-4o-mini:free` 등 suffix 무관하게 허용

---

## 취약점 명세 (`vuln_spec.json`)

```json
{
  "team_id": "teamA",
  "service_description": "서비스 설명",
  "vulnerabilities": [
    {
      "id": "vuln1",
      "type": "indirect_prompt_injection",
      "layer": "tool_output",
      "description": "취약점 설명",
      "flag_env_var": "VULN1_FLAG",
      "test_payload": "취약점 트리거 입력",
      "checker": {
        "inject":   {"endpoint": "/admin/inject", "method": "POST",
                     "body": {"vuln_id": "vuln1", "location": "...", "value": "{{FLAG}}"},
                     "auth_header": "X-Checker-Token"},
        "retrieve": {"endpoint": "/admin/check", "method": "GET",
                     "expect_contains": "{{FLAG}}"},
        "basic_function": {"payload": "정상 요청", "expect_status": 200}
      }
    }
  ]
}
```

---

## 제출 전 검증

```bash
# 서비스 자기 검증 (3회 반복 권장)
python scripts/validate_vulns.py \
  --spec vuln_spec.json \
  --host localhost --port 8000 \
  --repeat 3 \
  --checker-token <your-token>

# 이벤트 직전 전체 시스템 사전검증
python scripts/preflight_check.py --repeat 3
```

**검증 통과 기준:** 3회 시도 모두 flag 탈취 성공 + basic_function 정상

---

## 금지 사항

- coordinator 또는 다른 팀 인프라에 DoS 공격
- vuln_spec에 선언되지 않은 취약점으로 채점 시도
- 외부 네트워크에서 flag 정보 수집
- 팀원 외 인원과 공격 코드 공유

---

## 타임라인

| 시각 | 내용 |
|---|---|
| ~21:00 | 서비스 제출 마감 (git push), vuln_spec 잠금 |
| 21:00 | 라운드 1 시작 |
| 매 30분 | 라운드 자동 전환 (advance_round.py cron) |
| 07:00 | 라운드 20 종료 |
| 07:00–08:00 | 팀 발표 (5분) + 시상 |
