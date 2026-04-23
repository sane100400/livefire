# HSPACE AI Agent Attack & Defense CTF

실시간 공격·방어 CTF 플랫폼.  
팀이 **LLM 기반 에이전트 서비스에 취약점을 직접 심고**, 상대 팀 서비스를 자동으로 공격해 flag를 탈취하는 live-fire A&D.

---

## 목차

1. [아키텍처](#아키텍처)
2. [시스템 명세](#시스템-명세)
3. [빠른 시작](#빠른-시작)
4. [디렉토리 구조](#디렉토리-구조)
5. [구현 상태](#구현-상태)
6. [앞으로 구현할 것](#앞으로-구현할-것)

---

## 아키텍처

```
┌──────────────────────────────────────────────────────────────┐
│  Host (Ubuntu 22.04)                                          │
│                                                              │
│  ┌─────────────────── scoring-net 172.20.0.0/24 ──────────┐ │
│  │  coordinator :9000  ←── git push (팀 서비스 배포)        │ │
│  │  ├─ FastAPI app                                          │ │
│  │  ├─ SQLite WAL DB                                        │ │
│  │  ├─ flag_manager  (생성/주입/검증)                        │ │
│  │  ├─ checker       (SLA: OK/FAULTY/DOWN)                  │ │
│  │  ├─ git smart HTTP (bare repo + hooks)                   │ │
│  │  └─ agent_runner  (공격 에이전트 컨테이너 실행)            │ │
│  │                                                          │ │
│  │  attack-agent-teamA ──→ /attack ──→ coordinator         │ │
│  │  attack-agent-teamB ──→ /attack ──→ coordinator         │ │
│  │  ...                                                     │ │
│  └─────────────────────────────────────────────────────────┘ │
│           │ coordinator만 target-net 접근 가능                │
│  ┌──────── target-net 172.21.0.0/24 ──────────────────────┐  │
│  │  and-service-teamA  172.21.0.10:8000                    │  │
│  │  and-service-teamB  172.21.0.11:8000                    │  │
│  │  ...                                                    │  │
│  └────────────────────────────────────────────────────────┘  │
└──────────────────────────────────────────────────────────────┘

공격 흐름:
  attack-agent → POST /attack (payload)
    → coordinator가 target /chat에 전달
    → 응답에서 HSPACE{...} 추출
    → POST /submit-flag
    → 채점 (+10 공격팀, -10 방어팀)
```

---

## 시스템 명세

### Flag 체계

| 항목 | 내용 |
|---|---|
| 형식 | `HSPACE{[a-f0-9]{32}}` (128-bit random hex) |
| 생성 | 라운드 시작 시 팀×취약점별 독립 생성 (`secrets.token_hex(16)`) |
| 주입 | `docker exec` → `/app/flags.env` + `/admin/inject` 엔드포인트 양방향 |
| 만료 | 라운드 종료 시 `active_flags.expires_at` 기록 → 재제출 불가 |
| 검증 | DB `active_flags` 조회 → 라운드 일치 + 자기팀 아님 + 미중복 |

### SLA 상태

| 상태 | 조건 | 가용성 보너스 | 방어 패널티 |
|---|---|---|---|
| **OK** | health + inject + retrieve + basic_func 모두 통과 | +10 | 적용 |
| **FAULTY** | health는 살아있으나 checker 일부 실패 | 없음 | 적용 |
| **DOWN** | /health 무응답 | 없음 | **면제** |

> DOWN 상태면 공격도 차단됨 (`503` 반환) — 서비스 종료로 방어하면 보너스도 없어서 손해

### 점수 체계

| 이벤트 | 공격팀 | 방어팀 |
|---|---|---|
| Flag 탈취 | **+10** | **-10** (DOWN이면 면제) |
| 서비스 가용성 (라운드당) | — | **+10** (OK일 때만) |
| 시작 점수 | 1000 | 1000 |

### API 엔드포인트 (coordinator :9000)

| 메서드 | 경로 | 설명 |
|---|---|---|
| GET | `/health` | 코디네이터 헬스 체크 |
| GET | `/status` | 라운드 상태 조회 |
| GET | `/scoreboard` | 전체 스코어보드 |
| GET | `/history` | 라운드별 히스토리 |
| POST | `/attack` | 페이로드 전송 + flag 탐지 |
| POST | `/submit-flag` | 탈취한 flag 제출 |
| POST | `/admin/start-round` | 라운드 시작 (어드민) |
| POST | `/admin/end-round` | 라운드 종료 + 채점 (어드민) |
| POST | `/admin/service-deployed` | 팀 서비스 배포 알림 (훅) |
| GET | `/admin/flags` | 현재 라운드 flag 목록 (어드민) |
| GET | `/admin/audit-log` | 공격 감사 로그 (어드민) |
| GET | `/git/{team_id}/...` | git smart HTTP |

### SQLite 스키마

```
game_meta        — 현재 라운드, active 여부, preflight 완료 여부
scores           — 팀별 점수, LLM 크레딧 잔액
round_attacks    — 라운드 내 팀별 /attack 호출 횟수
round_exploits   — 라운드 내 (attacker, defender, round_num) 성공 기록
active_flags     — 라운드별 팀×취약점 flag (만료 시각 포함)
flag_submissions — 제출 기록 (UNIQUE(attacker, flag) — 중복 방지)
service_status   — 팀별 최신 SLA 상태
history          — 라운드별 결과 append-only 아카이브
audit_log        — 공격 감사 로그 (payload_hash, response_hash)
```

### 팀 서비스 필수 인터페이스

```
GET  /health          → 200 OK
POST /chat            {"message": str} → {"response": str, "tool_calls": list}
POST /admin/inject    X-Checker-Token  {"vuln_id", "location", "value"} → flag 주입
GET  /admin/check     X-Checker-Token  → 응답 본문에 주입된 flag 포함
```

### 허용 LLM 모델 (OpenRouter)

`qwen/qwen-2.5-14b`, `qwen/qwen-2.5-32b`, `meta-llama/llama-3.1-70b`,  
`google/gemma-3-27b`, `openai/gpt-4o-mini`, `google/gemini-flash-1.5`,  
`google/gemini-2.0-flash-001`, `microsoft/phi-4`, `mistralai/mistral-small-3.1`,  
`deepseek/deepseek-chat`, `xiaomi/mimo`

---

## 빠른 시작

### 주최측

```bash
# 1. 의존성 설치
pip3 install httpx python-dotenv fastapi uvicorn slowapi

# 2. 시크릿 생성
cd coordinator
cp .env.example .env
python3 -c "
import secrets
print('ADMIN_SECRET=' + secrets.token_hex(24))
for t in 'ABCDEF':
    print(f'TOKEN_TEAM_{t}=' + secrets.token_hex(16))
" >> .env

# 3. 코디네이터 + 스코어보드 기동
cd ..
docker compose up -d
curl http://localhost:9000/health  # → {"status":"ok"}

# 4. 이벤트 전 사전검증
python scripts/preflight_check.py --repeat 3

# 5. 라운드 자동 전환 cron 등록
# crontab -e → 0,30 21-23,0-7 * * * cd /opt/hackathon && python3 scripts/advance_round.py
```

### 팀 (방어 서비스 제출)

```bash
# 1. 서비스 로컬 테스트
cd agent_service/
make run &           # uvicorn main:app --port 8000

# 2. 취약점 검증 (3회 반복)
make verify          # python ../scripts/verify.py --repeat 3

# 3. git 제출
git init
git remote add organizer http://<코디네이터IP>:9000/git/teamA
git add .
git commit -m "initial submit"
git push organizer main

# 4. 대회 중 패치
vim main.py          # 취약점 패치
git add main.py && git commit -m "patch vuln2"
git push organizer main   # Dockerfile 빌드 검증 + 자동 재배포
```

### 팀 (공격 에이전트)

```bash
# attack_agent/main.py의 PAYLOADS 수정 후
docker build -t and-attack-teamA:latest attack_agent/
# 코디네이터가 라운드 시작 시 자동 실행
```

---

## 디렉토리 구조

```
hackathon/
├── coordinator/
│   ├── app.py            FastAPI 서버 (엔드포인트, 인증, rate limit)
│   ├── flag_manager.py   flag 생성·주입(docker exec)·만료·검증
│   ├── checker.py        FAUST-style SLA checker (inject→retrieve→basic)
│   ├── db.py             SQLite WAL 레이어 (9개 테이블, 트랜잭션)
│   ├── scorer.py         점수 계산 (SLA 반영, 중복 방지)
│   ├── git_handler.py    git smart HTTP + pre/post-receive 훅
│   ├── agent_runner.py   공격 에이전트 Docker 컨테이너 실행·정리
│   ├── state.py          게임 상태 (DB 연동 프록시)
│   ├── config.py         전체 설정 (env vars, 허용 모델 목록)
│   ├── .env.example      시크릿 템플릿
│   └── requirements.txt
├── vuln_specs/
│   └── example.json      취약점 명세 작성 예시
├── agent_service/        팀 방어 서비스 템플릿
│   ├── main.py           FastAPI + 3개 취약점 예시
│   ├── vuln_spec.json    취약점 명세 예시
│   ├── Dockerfile
│   ├── Makefile          make run / make verify
│   └── requirements.txt
├── attack_agent/         팀 공격 에이전트 템플릿
│   ├── main.py           /attack → /submit-flag 흐름
│   └── Dockerfile
├── scripts/
│   ├── verify.py         팀 자가검증 (독립 실행, httpx만 필요)
│   ├── validate_vulns.py 주최측 일괄 검증 (--all --repeat 3)
│   ├── preflight_check.py 이벤트 전 원클릭 사전검증
│   └── advance_round.py  cron 라운드 자동 전환
├── scoreboard/
│   └── index.html        실시간 스코어보드 (10초 자동 갱신)
├── docker-compose.yml    coordinator + nginx scoreboard + 팀 서비스 설정
├── RULEBOOK.md           참가팀 배포용 규칙서
├── ORGANIZER_GUIDE.md    주최측 운영북 (D-7 셋업 ~ 종료 체크리스트)
└── README.md             이 파일
```

---

## 구현 상태

### ✅ 완료

| 컴포넌트 | 파일 | 설명 |
|---|---|---|
| Coordinator API | `app.py` | FastAPI, SlowAPI rate limit, 감사 로그 |
| 영속성 레이어 | `db.py` | SQLite WAL, 9개 테이블, 트랜잭션 |
| Flag 시스템 | `flag_manager.py` | 생성·docker exec 주입·만료·검증 |
| SLA Checker | `checker.py` | inject→retrieve→basic_func, OK/FAULTY/DOWN |
| Git 배포 | `git_handler.py` | Smart HTTP, pre/post-receive 훅 |
| 점수 계산 | `scorer.py` | SLA 반영, 중복 차단 |
| 에이전트 실행 | `agent_runner.py` | Docker 리소스 제한, cleanup |
| 팀 서비스 템플릿 | `agent_service/` | 3-vuln 예시 + 필수 4 엔드포인트 |
| 공격 에이전트 템플릿 | `attack_agent/` | 환경변수 수신 → 공격 흐름 |
| 팀 자가검증 | `scripts/verify.py` | 독립 실행, 컬러 출력, --verbose |
| 주최측 검증 | `scripts/validate_vulns.py` | --all --repeat, report JSON |
| 사전검증 | `scripts/preflight_check.py` | coordinator + 팀 + 취약점 일괄 |
| 라운드 전환 | `scripts/advance_round.py` | cron용, .env 자동 로드 |
| 스코어보드 UI | `scoreboard/index.html` | 10초 폴링, 익스플로잇 표시 |
| 네트워크 격리 | `docker-compose.yml` | scoring-net / target-net 분리 |
| 규칙서 | `RULEBOOK.md` | 참가팀 배포용 |
| 운영북 | `ORGANIZER_GUIDE.md` | D-7~종료 체크리스트 |

---

## 앞으로 구현할 것

### 🔴 필수 (이벤트 전 반드시)

**1. 공격 에이전트 LLM 연동** (`attack_agent/main.py`)  
현재: 정적 페이로드 목록을 순서대로 전송.  
필요: OpenRouter API 실제 호출 → 타겟 응답을 분석해 다음 페이로드를 동적 생성.
```python
# 구현 위치: attack_agent/main.py
# OpenRouter endpoint: https://openrouter.ai/api/v1/chat/completions
# 환경변수: OPENROUTER_API_KEY
```

**2. vuln_spec git push 자동 추출** (`coordinator/git_handler.py`)  
현재: post-receive 훅이 서비스 코드만 배포, `vuln_spec.json`을 `vuln_specs/teamX.json`에 복사 안 함.  
필요: 훅 내에서 `git show newrev:vuln_spec.json > /app/vuln_specs/teamA.json` 추가.

**3. git push 팀 인증** (`coordinator/git_handler.py`)  
현재: HTTP Basic Auth 없음 → 누구나 어느 팀 repo에 push 가능.  
필요: git credential 체크 또는 pre-receive에서 팀 토큰 검증.

---

### 🟡 권장 (이벤트 품질 향상)

**4. 멀티턴 공격 세션 관리** (`coordinator/app.py`, `coordinator/db.py`)  
현재: `/attack`에 `session_id`/`history` 파라미터 있지만 서버 측 세션 저장소 없음.  
필요: `attack_sessions` 테이블 추가 → 이전 대화 히스토리 persist.

**5. 라운드 카운트다운 타이머** (`scoreboard/index.html`)  
현재: 라운드 번호만 표시, 남은 시간 없음.  
필요: `/status`의 `round_start_time`으로 30분 기준 남은 시간 계산 + 표시.

**6. 팀 서비스 이미지 빌드 스크립트** (`scripts/build_agents.sh`)  
현재: 팀 공격 에이전트 이미지를 주최측이 수동으로 빌드해야 함.  
필요: `repos/teamA.git`에서 checkout → `docker build` 자동화 스크립트.

**7. SLA 주기적 재체크** (`coordinator/app.py` 또는 별도 cron)  
현재: checker가 라운드 시작 시점에만 실행 → 라운드 중 DOWN 감지 안 됨.  
필요: 5~10분마다 checker 재실행, `service_status` 테이블 갱신.

**8. 스코어보드 서비스 상태 표시** (`scoreboard/index.html`)  
현재: 점수·턴·크레딧만 표시.  
필요: 팀별 SLA 상태(🟢 OK / 🟡 FAULTY / 🔴 DOWN) 배지 추가.

---

### 🟢 개선 (장기)

**9. SlowAPI rate limit 영속성**  
현재: in-memory → coordinator 재시작 시 카운터 초기화 (재시작으로 rate limit 우회 가능).  
방향: Redis 백엔드 사용 또는 DB 기반 카운터로 교체.

**10. LLM 크레딧 서버사이드 검증**  
현재: `step_cost`는 팀이 self-report → 실제 OpenRouter 잔액과 무관.  
방향: OpenRouter `/auth/key` API로 실잔액 주기적 동기화.

**11. 취약점 유형 예시 확장** (`agent_service/`, `vuln_specs/example.json`)  
현재: indirect_prompt_injection / memory_poisoning / orchestration_bypass 3종.  
필요: RAG poisoning, tool_call_manipulation 구현 예시 추가.

**12. 공격 결과 실시간 이벤트 스트림** (`coordinator/app.py`)  
현재: 스코어보드가 10초 폴링.  
방향: `/events` SSE 엔드포인트 → 익스플로잇 발생 즉시 스코어보드 갱신.

**13. 팀 대시보드** (신규)  
현재: 팀은 자기 점수·잔여턴을 API로만 확인 가능.  
방향: 팀 토큰으로 인증하는 `/dashboard` 페이지 (자기 팀 공격 내역, 방어 현황).

---

## 참고 문서

- [RULEBOOK.md](RULEBOOK.md) — 참가팀 배포용 규칙서
- [ORGANIZER_GUIDE.md](ORGANIZER_GUIDE.md) — 주최측 셋업·운영 가이드
- [coordinator/.env.example](coordinator/.env.example) — 시크릿 템플릿
- [agent_service/vuln_spec.json](agent_service/vuln_spec.json) — 취약점 명세 예시
