# Development Spec: HSPACE LiveFire AI Agent A&D

이 문서는 README의 운영 컨셉을 실제 개발 단위로 고정한다. 현재 구현 기준은 Agent SDK + repo 기반 scan + PoC 라운드 재실행 방식이다. 즉시 flag 제출 채점은 제거하고, 제출된 PoC를 시스템이 실행해 flag 반환 여부로 점수화한다.

## 목표

- 팀은 직접 사이트를 만들고 flag 4개를 심는다.
- 사이트는 시계 방향으로 한 칸 옆 팀이 방어한다.
- 공격과 방어 산출물은 반드시 팀 AI 에이전트가 만든 것으로 증명되어야 한다.
- 개발 과정에서는 외부 LLM, IDE AI, 오케스트레이션 LLM 사용을 허용한다.
- 공식 라운드 중 점수와 연결되는 attack/defense agent 실행은 OpenRouter 화이트리스트 저성능 모델만 사용한다.
- 팀은 OpenRouter API key를 직접 받지 않고, coordinator의 `/llm` gateway만 사용한다.
- 공격 에이전트가 제출한 `poc*.py`는 정적 검증을 통과하면 매 라운드 1회 실행된다.
- PoC가 해당 라운드에 flag를 탈취하면 공격팀 +10, 방어팀 -10을 기록한다.
- 같은 flag라도 새 PoC가 다음 라운드에 성공하면 다시 점수를 준다.

## 비목표

- 사람이 직접 만든 PoC나 수동 방어 패치를 허용하지 않는다.
- 팀 컨테이너에 OpenRouter API key를 지급하지 않는다.
- PoC runner에서 외부 인터넷 접근을 허용하지 않는다.
- 단순 파일명 변경 또는 복붙 PoC를 별도 PoC로 인정하지 않는다.

## 용어

| 용어 | 의미 |
|---|---|
| site owner | 사이트를 처음 만든 팀 |
| defender | 시계 방향으로 사이트를 넘겨받아 패치하는 팀 |
| attacker | PoC를 제출하는 팀 |
| agent run | attack 또는 defense agent 컨테이너의 1회 실행 |
| SDK-issued run id | Agent SDK가 자동으로 발급·전달하는 내부 실행 ID |
| agent run token | run 생성 시 coordinator가 발급하는 per-run bearer token. run id만 아는 직접 호출을 차단한다. |
| SDK signature | Agent SDK가 method, path, run id, timestamp를 run token hash로 HMAC 서명한 헤더. 공식 산출물 API는 이 서명이 있어야 한다. |
| runner secret | 운영자가 공식 agent launcher에만 주입하는 secret. 운영 환경에서는 `/agent-runs` 생성에 필요하다. |
| PoC | 하나의 flag 탈취를 재현하는 Python 단일 파일 |
| submitted PoC | 정적 검증을 통과해 매 라운드 실행 대상이 된 PoC |

## 시스템 구성

### coordinator

FastAPI 서버. 다음 책임을 가진다.

- 팀 토큰 인증
- `/agent-runs` 생성 및 종료 기록
- `/llm` OpenRouter gateway
- `/attack` 탐색 proxy 및 rate limit
- `/pocs` PoC 제출, 정적 검증, 실행 상태 관리
- PoC runner 실행 및 결과 채점
- git smart HTTP 수신, 방어 패치 provenance 검증
- flag 생성, 주입, 만료
- score, audit, scoreboard API 제공

### agent_sdk

팀이 직접 run id나 audit 필드를 만지지 않게 하는 공통 Python SDK.

필수 인터페이스:

```python
from agent_sdk import AgentContext

ctx = AgentContext.from_env()
repo = ctx.fetch_target_repo()
scan = ctx.llm(model="openai/gpt-4o-mini", messages=[...], purpose="scan")
ctx.attack("payload", llm_call_id=scan["llm_call_id"], target_team="teamC")
ctx.request_target("/api/search", method="POST", json_body={"q": "payload"}, llm_call_id=scan["llm_call_id"])
poc = ctx.llm(model="openai/gpt-4o-mini", messages=[...], purpose="poc")
ctx.submit_poc("poc1.py", llm_call_id=poc["llm_call_id"], target_team="teamC", flag_id="vuln2")
ctx.commit_patch("patch vuln2")
```

SDK 책임:

- 컨테이너 시작 시 `/agent-runs` 자동 생성
- `RUNNER_SECRET`이 환경에 있으면 `/agent-runs` 생성 시 `X-Runner-Secret` 헤더로 전달
- `/agent-runs` 응답의 `agent_run_token`을 저장하고 이후 API 호출에 `X-Agent-Run-Token`과 SDK HMAC 서명 헤더를 전달
- `TEAM_ID`, `MODE`, `TARGET_TEAM`, `ROUND`, `COORDINATOR_URL`, `TEAM_TOKEN` env 로드
- attack mode에서 target repo snapshot을 `/agent-runs/{id}/target-repo.tar`로 가져온다.
- `/llm` 호출 시 내부 run id 자동 첨부
- `/pocs` 업로드 시 내부 run id와 파일 sha256 자동 첨부
- defense mode에서 git commit trailer `Agent-Run-ID: <id>` 자동 삽입
- 실패 시 사람이 읽을 수 있는 에러 출력

### attack_agent

팀 공격 에이전트 템플릿.

- SDK를 사용해 배정된 target repo를 분석하고 live service를 탐색한다.
- `/attack` proxy로 target service에 접근한다.
- LLM 호출은 반드시 `ctx.llm()`만 사용한다.
- scan은 `purpose=scan`, PoC 생성은 `purpose=poc` LLM call id를 남긴다.
- 발견한 공격 경로를 `poc*.py`로 저장하고 `ctx.submit_poc(..., llm_call_id=...)`로 제출한다.
- PoC 파일은 runner에서 독립 실행 가능해야 한다.

### defense_agent

팀 방어 에이전트 템플릿.

- 시계 방향으로 넘겨받은 사이트 repo를 checkout한다.
- SDK를 사용해 취약점/PoC 결과/서비스 로그를 분석한다.
- 패치를 만든 뒤 `ctx.commit_patch()` 또는 제공 git wrapper로 커밋한다.
- SDK가 자동 삽입한 `Agent-Run-ID` trailer가 없는 push는 coordinator에서 거부된다.
- 운영 환경에서는 coordinator가 defense agent 컨테이너를 실행하고 `RUNNER_SECRET`을 주입한다.

### poc_runner

제출된 PoC를 라운드마다 실행하는 sandbox.

- 입력: `poc_id`, `round_num`, `target_team`, `flag_id`
- env: `TARGET_HOST`, `TARGET_PORT`, `TARGET_TEAM`, `FLAG_ID`
- 네트워크: target-net만 접근 가능
- 외부 인터넷: 차단
- 파일시스템: read-only base + per-run tmp
- 제한: timeout, stdout/stderr size cap, memory/CPU limit
- 출력: exit code, duration, stdout/stderr hash, stdout 마지막 non-empty line에서 검증한 flag 목록

## API 명세

모든 팀 API는 `X-Team-Token`으로 인증한다. run 생성 후 공식 산출물 API는 추가로
`X-Agent-Run-Token`과 SDK 서명 헤더를 요구한다. admin API는 `X-Admin-Secret`을 사용한다.

### POST /agent-runs

Agent SDK/runner만 호출한다. 운영 환경에서 `RUNNER_SECRET`이 설정되어 있으면
`X-Runner-Secret` 헤더가 일치해야 한다.

Headers:

```http
X-Team-Token: <team_or_defense_token>
X-Runner-Secret: <runner_secret>
X-Agent-SDK: hspace-agent-sdk/1
```

Request:

```json
{
  "team_id": "teamA",
  "mode": "attack",
  "target_team": "teamC",
  "round_num": 1,
  "agent_image": "and-attack-teama:latest",
  "agent_image_digest": "sha256:...",
  "agent_commit": "abc1234"
}
```

Response:

```json
{
  "agent_run_id": "uuid",
  "agent_run_token": "opaque-run-token",
  "allowed_models": ["openai/gpt-4o-mini"]
}
```

Rules:

- `mode`는 `attack` 또는 `defense`.
- attack run은 자기 팀과 자기 방어 대상 사이트를 target으로 둘 수 없다.
- defense run은 시계 방향으로 배정된 사이트만 target으로 둘 수 있다.
- 라운드 중복 실행 정책은 mode별로 둔다. MVP는 팀·mode·target·round당 여러 run 허용, dashboard에서 모두 표시한다.
- 이후 `/llm`, `/attack`, `/pocs`, `/agent-runs/{id}/finish`, `/agent-runs/{id}/target-repo.tar` 호출은 `X-Agent-Run-Token`과 SDK HMAC 서명이 일치해야 한다.

### POST /agent-runs/{id}/finish

SDK가 정상 종료 또는 실패 시 호출한다.

Request:

```json
{
  "status": "completed",
  "error": ""
}
```

### POST /llm

OpenRouter gateway. 팀 에이전트는 OpenRouter를 직접 호출하지 않는다.

Request:

```json
{
  "agent_run_id": "uuid",
  "model": "openai/gpt-4o-mini",
  "messages": [{"role": "user", "content": "analyze target"}],
  "purpose": "scan",
  "temperature": 0.2,
  "max_tokens": 2048
}
```

Response:

```json
{
  "llm_call_id": 123,
  "model": "openai/gpt-4o-mini",
  "content": "...",
  "usage": {
    "prompt_tokens": 123,
    "completion_tokens": 456,
    "total_tokens": 579
  },
  "request_id": "openrouter-request-id"
}
```

Rules:

- `model`은 `ALLOWED_MODEL_PREFIXES`와 prefix match되어야 한다.
- `X-Agent-Run-Token`과 SDK HMAC 서명이 해당 `agent_run_id`에 발급된 token과 일치해야 한다.
- request/response 원문은 기본 저장하지 않는다. hash, token usage, model, timestamp만 저장한다.
- 디버그 모드는 admin 설정으로만 원문 일부 저장 가능하게 한다.
- `/attack`은 `purpose=scan` LLM call id를 요구한다.
- `/pocs`는 `purpose=poc` LLM call id를 요구한다.
- `/llm` 호출이 0회이거나 목적이 맞지 않는 run에서 나온 PoC/patch는 reject한다.

### POST /attack

탐색 proxy. `agent_run_id`와 `purpose=scan` LLM call id가 없으면 거부한다.

Request:

```json
{
  "agent_run_id": "uuid",
  "llm_call_id": 123,
  "attacker_team": "teamA",
  "target_team": "teamC",
  "payload": "message",
  "session_id": "optional"
}
```

Rules:

- 팀당 10턴/라운드 제한은 `/attack`에만 적용한다.
- target이 DOWN이면 거부한다.
- 공격 가능 대상은 자기 사이트와 자기 방어 대상 제외 4개다.
- 응답에서 flag가 보여도 즉시 점수화하지 않는다. 점수는 제출된 PoC를 runner가 실행해 현재 flag를 확인할 때만 발생한다.

### POST /pocs

PoC 제출. SDK가 multipart 업로드를 감싼다.

Fields:

| field | 설명 |
|---|---|
| `agent_run_id` | SDK가 자동 첨부 |
| `llm_call_id` | SDK가 PoC 생성에 사용한 `purpose=poc` LLM 호출 id를 자동 첨부 |
| `attacker_team` | SDK env에서 자동 첨부 |
| `target_team` | 공격 대상 사이트 |
| `flag_id` | `vuln1`~`vuln4` |
| `file` | `poc*.py` 단일 파일 |
| `sha256` | SDK가 계산 |

Response:

```json
{
  "poc_id": "uuid",
  "status": "submitted",
  "sha256": "...",
  "run_result": {"status": "success"}
}
```

Submit rules:

- agent run이 존재해야 한다.
- run의 team/mode/target/round가 제출값과 맞아야 한다.
- `X-Agent-Run-Token`과 SDK HMAC 서명이 해당 run에 발급된 token과 일치해야 한다.
- 해당 run에 `purpose=poc`인 whitelist `/llm` 호출이 있어야 한다.
- 파일명은 `poc*.py`, 크기는 MVP 기준 64KB 이하.
- 금지 import 또는 위험 syscall 패턴은 1차 정적 검사에서 reject한다.
- sha256이 완전히 같으면 기존 PoC로 merge한다.

### POST /admin/pocs/{poc_id}/reject

비정상 제출물의 비활성화 사유를 기록한다.

### POST /admin/run-pocs

현재 라운드의 제출된 PoC를 실행한다. `/pocs` 제출 직후, `start-round` 직후, 또는 cron에서 호출한다.

Request:

```json
{
  "round_num": 4,
  "only_poc_id": null
}
```

Rules:

- 같은 `(round_num, poc_id)`는 한 번만 점수화한다.
- 재실행 요청은 idempotent해야 한다.
- target status가 DOWN이면 해당 PoC는 skipped로 기록하고 방어 패널티를 주지 않는다.

## DB 스키마 추가

기존 `audit_log`, `round_exploits`는 감사와 scoreboard 집계를 위해 유지하고, 신규 채점은 아래 테이블을 기준으로 한다.

### agent_runs

```sql
CREATE TABLE agent_runs (
    id                 TEXT PRIMARY KEY,
    team_id            TEXT NOT NULL,
    mode               TEXT NOT NULL CHECK(mode IN ('attack','defense')),
    target_team        TEXT NOT NULL,
    round_num          INTEGER NOT NULL,
    agent_image        TEXT,
    agent_image_digest TEXT,
    agent_commit       TEXT,
    status             TEXT NOT NULL DEFAULT 'running',
    started_at         TEXT NOT NULL,
    ended_at           TEXT,
    error              TEXT
);
```

### llm_calls

```sql
CREATE TABLE llm_calls (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    agent_run_id          TEXT NOT NULL REFERENCES agent_runs(id),
    ts                    TEXT NOT NULL,
    purpose               TEXT NOT NULL DEFAULT 'general',
    model                 TEXT NOT NULL,
    allowed               INTEGER NOT NULL,
    openrouter_request_id TEXT,
    prompt_hash           TEXT NOT NULL,
    response_hash         TEXT,
    prompt_tokens         INTEGER,
    completion_tokens     INTEGER,
    total_tokens          INTEGER,
    status                TEXT NOT NULL,
    error                 TEXT
);
```

### poc_submissions

```sql
CREATE TABLE poc_submissions (
    id                TEXT PRIMARY KEY,
    agent_run_id      TEXT NOT NULL REFERENCES agent_runs(id),
    llm_call_id       INTEGER NOT NULL REFERENCES llm_calls(id),
    attacker_team     TEXT NOT NULL,
    target_team       TEXT NOT NULL,
    defender_team     TEXT NOT NULL,
    flag_id           TEXT NOT NULL,
    submitted_round   INTEGER NOT NULL,
    file_name         TEXT NOT NULL,
    sha256            TEXT NOT NULL,
    storage_path      TEXT NOT NULL,
    status            TEXT NOT NULL DEFAULT 'submitted',
    canonical_poc_id  TEXT,
    review_reason     TEXT,
    created_at        TEXT NOT NULL,
    accepted_at       TEXT,
    UNIQUE(attacker_team, target_team, sha256)
);
```

`status`: `submitted`, `rejected`, `merged`, `disabled`. 기존 DB 호환을 위해 `pending`, `accepted`도 실행 대상으로 취급한다.

### poc_results

```sql
CREATE TABLE poc_results (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    round_num       INTEGER NOT NULL,
    poc_id          TEXT NOT NULL REFERENCES poc_submissions(id),
    attacker_team   TEXT NOT NULL,
    target_team     TEXT NOT NULL,
    defender_team   TEXT NOT NULL,
    flag_id         TEXT NOT NULL,
    status          TEXT NOT NULL,
    flags_json      TEXT NOT NULL,
    scored          INTEGER NOT NULL DEFAULT 0,
    attacker_delta  INTEGER NOT NULL DEFAULT 0,
    defender_delta  INTEGER NOT NULL DEFAULT 0,
    exit_code       INTEGER,
    duration_ms     INTEGER,
    stdout_hash     TEXT,
    stderr_hash     TEXT,
    detail          TEXT,
    created_at      TEXT NOT NULL,
    UNIQUE(round_num, poc_id)
);
```

`status`: `success`, `failed`, `timeout`, `skipped_down`, `runner_error`.

### service_deployments

```sql
CREATE TABLE service_deployments (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    team_id         TEXT NOT NULL,
    commit_sha      TEXT NOT NULL,
    agent_run_id    TEXT,
    mode            TEXT NOT NULL DEFAULT 'service',
    accepted        INTEGER NOT NULL DEFAULT 1,
    reject_reason   TEXT,
    deployed_at     TEXT NOT NULL
);
```

Defense patch push는 `mode='defense_patch'`, `agent_run_id` 필수다.

## 로테이션 규칙

팀 순서는 config에 고정한다.

```text
teamA -> teamB -> teamC -> teamD -> teamE -> teamF -> teamA
```

- `site_owner=teamA`의 defender는 `teamB`.
- `teamB`는 `teamA` 사이트만 방어할 수 있다.
- `teamB`는 공격 시 `teamB` 자기 사이트와 `teamA` 방어 대상 사이트를 제외한다.
- 따라서 6팀 기준 공격 대상은 4개다.

구현 위치:

- `coordinator/config.py`: `TEAM_ORDER`
- `coordinator/rotation.py`: `get_defender(site_owner)`, `get_defense_target(defender)`, `get_attack_targets(attacker)`
- `app.py`, `git_handler.py`, `poc_runner.py`에서 공통 helper만 사용

## 채점 규칙

PoC 성공 조건:

- runner 실행이 timeout 없이 종료된다.
- stdout의 마지막 non-empty line에서 `HSPACE{[a-f0-9]{32}}`가 발견된다.
- flag가 현재 또는 해당 라운드의 active flag로 확인된다.
- flag의 `team_id`가 PoC의 `target_team`과 일치한다.
- flag의 `vuln_id`가 PoC의 `flag_id`와 일치한다.
- 같은 `(round_num, poc_id)`가 아직 점수화되지 않았다.

점수:

- 성공: attacker +10, defender -10
- 실패/timeout: 점수 변화 없음
- target DOWN: `skipped_down`, 점수 변화 없음
- 같은 flag를 다른 PoC가 다른 라운드에 탈취: 성공 시 +10
- 같은 PoC가 여러 flag를 뽑아도 PoC에 선언된 `flag_id` 하나만 점수화한다.

## Git provenance

서비스 최초 제출:

- 대회 시작 전에는 일반 팀 token push 허용.
- `vuln_spec.json`은 시작 후 변경 금지.

방어 패치:

- 대회 시작 후 방어 대상 repo에 대한 push는 defense agent SDK/git wrapper를 통해서만 허용한다.
- commit message trailer:

```text
Agent-Run-ID: <uuid>
```

검증:

- trailer의 run id가 존재한다.
- run `mode='defense'`.
- run `team_id`가 push 권한 팀과 같다.
- run `target_team`이 해당 defender의 defense target과 같다.
- run이 아직 `running` 상태다.
- run에 `purpose=defense`인 whitelist `/llm` 호출이 최소 1회 있다.

## 파일 저장

권장 경로:

```text
data/
├── pocs/
│   └── <round>/<poc_id>/poc.py
├── poc_runs/
│   └── <round>/<poc_id>/
│       ├── stdout.txt
│       └── stderr.txt
└── agent_runs/
    └── <agent_run_id>/meta.json
```

운영 환경에서는 `DATA_DIR`로 override 가능해야 한다.

## 네트워크 정책

- coordinator: scoring-net, target-net 모두 연결
- attack/defense agent: scoring-net만 연결
- target service: target-net만 연결
- poc runner: target-net만 연결
- OpenRouter egress: coordinator만 허용

Docker socket 사용은 coordinator 내부 기능으로 제한한다. PoC runner는 Docker socket을 mount하지 않는다.

## 구현 단계

### Phase 1: Agent provenance 기반

1. `agent_sdk/` 생성
2. `/agent-runs`, `/agent-runs/{id}/finish` 구현
3. `/llm` gateway 구현
4. `llm_calls` audit 기록
5. attack_agent 템플릿을 SDK 사용 방식으로 변경

Acceptance:

- SDK로 시작한 attack agent가 `/llm` 호출을 남긴다.
- 비허용 모델은 403.
- 팀 컨테이너에 OpenRouter key 없이도 SDK `llm()`이 동작한다.

### Phase 2: PoC 제출과 자동 실행

1. `poc_submissions` 테이블 추가
2. `/pocs` multipart 업로드 구현
3. sha256, 파일명, 크기, run 검증 구현
4. 제출 직후 현재 라운드 자동 실행
5. scoreboard/admin API에서 submitted PoC와 실행 결과 표시

Acceptance:

- SDK `submit_poc()`로 제출하면 submitted 생성 후 시스템이 실행한다.
- `/llm` 호출 없는 run의 PoC는 reject.
- 같은 sha256은 merge 처리.

### Phase 3: PoC runner와 채점

1. `coordinator/poc_runner.py` 추가
2. `poc_results` 테이블 추가
3. submitted PoC 라운드 실행 API 구현
4. flag 검증 및 점수 반영
5. `round_exploits`를 PoC 결과 기반으로 갱신하거나 scoreboard 쿼리를 신규 테이블로 전환

Acceptance:

- `poc1.py`가 round 1, 2에서 성공하면 각각 +10.
- round 3 실패 시 +0.
- `poc2.py`가 같은 flag를 round 4에서 성공하면 +10.
- 같은 `(round,poc_id)` 재실행은 중복 점수 없음.

### Phase 4: Rotation과 defense patch enforcement

1. `rotation.py` 추가
2. `/attack`, `/pocs`, git push에서 공격/방어 대상 제한 적용
3. `defense_agent/` 템플릿 추가
4. git pre-receive에서 `Agent-Run-ID` trailer 검증
5. `service_deployments` 기록

Acceptance:

- 자기 사이트 공격 거부.
- 자기 방어 대상 공격 거부.
- 방어팀이 아닌 팀의 defense patch push 거부.
- 수동 git push 방어 패치 거부.

### Phase 5: SLA, UI, cleanup

1. SLA 주기적 checker loop
2. scoreboard에 PoC results, service status, agent provenance 노출
3. 즉시 flag 제출 채점 경로 제거 상태 유지
4. README, RULEBOOK, ORGANIZER_GUIDE 동기화

Acceptance:

- 운영자 화면에서 PoC별 모델, run, agent commit 추적 가능.
- DOWN target은 PoC skipped 처리.
- 이벤트 리허설에서 6팀, 20라운드 dry-run 가능.

## 테스트 계획

### Unit

- model whitelist prefix 검사
- rotation helper
- flag parser
- PoC sha256/merge 판정
- DB unique `(round_num, poc_id)` 보장

### Integration

- SDK -> `/agent-runs` -> `/llm` -> `/pocs`
- submitted PoC -> runner -> target service -> score update
- defense SDK commit -> git push -> trailer 검증 -> deploy
- target DOWN -> PoC skipped

### Security

- 팀 컨테이너에서 OpenRouter 직접 호출 실패
- PoC runner에서 외부 인터넷 접근 실패
- 비허용 모델 403
- run 없는 PoC 제출 403
- LLM 호출 없는 run의 PoC 제출 reject
- 수동 defense push reject

## 개발 준비 체크리스트

- [x] `.env.example`에 `OPENROUTER_API_KEY`, `DATA_DIR`, `POC_TIMEOUT_SEC`, `POC_HOST_DATA_DIR` 추가
- [x] `agent_sdk/` 패키지 생성
- [x] `defense_agent/` 템플릿 생성
- [x] `coordinator/rotation.py` 생성
- [x] `coordinator/poc_runner.py` 생성
- [x] DB migration 또는 `CREATE TABLE IF NOT EXISTS` 추가
- [x] README TODO와 본 문서 상태 동기화
- [x] 즉시 flag 제출 채점 제거: `/pocs` 제출/재실행만 점수화
