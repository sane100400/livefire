# HSPACE GitCTF Rulebook

## 1. 핵심

각 팀은 직접 만든 웹 서비스를 git으로 제출한다.
서비스에는 의도된 취약점 4개와 `vuln_spec.json`이 있어야 한다.

대회 중 공격과 방어는 AI agent를 통해 진행된다.
공격 agent가 PoC를 제출하면 coordinator가 매 라운드 그 PoC를 다시 실행해 flag 탈취 여부로 채점한다.

---

## 2. 제출물

| 제출물 | 필수 여부 | 설명 |
|---|---:|---|
| 서비스 repo | 필수 | 팀이 만든 웹 서비스 |
| `Dockerfile` | 필수 | coordinator가 서비스 이미지를 빌드할 때 사용 |
| `vuln_spec.json` | 필수 | 취약점 4개와 checker 방법 |
| attack agent | 필수 | 상대 repo 분석, 공격, PoC 제출 |
| defense agent | 필수 | 맡은 서비스 repo 자동 패치 |

서비스 repo는 `scripts/gitctf.py`로 제출한다.

---

## 3. 서비스 필수 API

서비스 주제와 구현은 자유다. 아래 API는 반드시 제공해야 한다.

| API | 용도 |
|---|---|
| `GET /health` | 서비스 생존 확인 |
| `POST /chat` | 공격 진입점 |
| `POST /admin/inject` | coordinator가 라운드 flag 주입 |
| `GET /admin/check` | checker가 flag 주입 상태 확인 |

`/chat` 응답은 최소한 아래 형태를 맞춘다.

```json
{
  "response": "사용자에게 보여줄 응답",
  "tool_calls": []
}
```

`vuln_spec.json`에는 flag 값을 넣지 않는다. flag는 라운드마다 coordinator가 런타임에 주입한다.

---

## 4. gitctf.py 사용법

### 제출 전 verify

서비스를 로컬에서 띄운 뒤, 취약점 4개가 실제로 flag를 출력하는지 확인한다.

```bash
cd my_service
uvicorn main:app --host 0.0.0.0 --port 8000
```

```bash
python ../scripts/gitctf.py verify \
  --repo . \
  --host localhost \
  --port 8000 \
  --repeat 3
```

`verify`는 `vuln_spec.json`의 `test_payload`를 각 취약점에 대해 반복 실행한다.
모든 `vuln1`~`vuln4`에서 주입된 테스트 flag가 `/chat` 응답에 보여야 PASS다.

### 기본 제출

팀이 만든 서비스 repo를 제출한다.

```bash
python scripts/gitctf.py submit \
  --repo ./my_service \
  --team teamA \
  --token "$TEAM_TOKEN" \
  --coordinator http://localhost:9000 \
  --message "Submit teamA service"
```

`gitctf.py`가 하는 일:

- `--repo` 폴더 안에 `Dockerfile`, `vuln_spec.json`이 있는지 확인한다.
- git repo가 아니면 `main` branch로 초기화한다.
- 변경분을 commit한다.
- remote `organizer`를 `http://.../git/<team>`으로 설정한다.
- 팀 토큰을 임시 HTTP header로만 붙여 push한다. 토큰은 `.git/config`에 저장하지 않는다.

### 환경변수로 짧게 쓰기

```bash
export TEAM_ID=teamA
export TEAM_TOKEN=<운영자가_준_팀_토큰>
export COORDINATOR_URL=http://localhost:9000

python scripts/gitctf.py submit --repo ./my_service
```

### dry-run

push 없이 commit과 remote 설정까지만 확인한다.

```bash
python scripts/gitctf.py submit \
  --repo ./my_service \
  --team teamA \
  --token "$TEAM_TOKEN" \
  --coordinator "$COORDINATOR_URL" \
  --dry-run
```

### 이미 commit한 HEAD만 push

agent나 스크립트가 이미 commit을 만든 경우 사용한다.

```bash
python scripts/gitctf.py submit \
  --repo ./my_service \
  --team teamA \
  --token "$TEAM_TOKEN" \
  --coordinator "$COORDINATOR_URL" \
  --no-commit
```

### 방어 push

라운드 중에는 사이트 소유자가 자기 repo에 직접 push할 수 없다.
방어팀의 defense agent가 만든 commit만 push할 수 있다.

예: `teamB`가 `teamA` 서비스를 방어하는 경우

```bash
python scripts/gitctf.py submit \
  --repo ./patched_teamA_repo \
  --repo-team teamA \
  --team teamB \
  --token "$DEFENSE_TOKEN" \
  --coordinator "$COORDINATOR_URL" \
  --no-commit
```

방어 commit에는 아래 trailer가 있어야 한다.

```text
Agent-Run-ID: <agent_run_id>
```

제공 SDK의 `commit_patch()`를 쓰면 자동으로 붙는다.

---

## 5. 제출 시 hook 검증

push하면 coordinator가 자동으로 검사한다.

| 단계 | 내용 |
|---|---|
| pre-receive | `Dockerfile` 빌드 가능 여부 검사 |
| pre-receive | 라운드 중 `vuln_spec.json` 변경 차단 |
| pre-receive | 방어 push의 `Agent-Run-ID` provenance 검사 |
| post-receive | 서비스 이미지 빌드 |
| post-receive | `and-service-teamx` 컨테이너 재배포 |
| post-receive | `vuln_spec.json` 추출 |
| post-receive | 현재 라운드 flag 재주입 |

빌드가 실패하면 push가 거절된다.

---

## 6. 로컬 제출 전 체크

서비스 실행:

```bash
cd my_service
uvicorn main:app --host 0.0.0.0 --port 8000
```

취약점 spec 검증:

```bash
python scripts/gitctf.py verify \
  --repo ./my_service \
  --host localhost \
  --port 8000 \
  --repeat 3
```

최소 체크리스트:

- `Dockerfile`이 repo 루트에 있다.
- `vuln_spec.json`이 repo 루트에 있다.
- `GET /health`가 200을 반환한다.
- `/admin/inject` 후 `/admin/check`에서 flag 4개가 확인된다.
- `/chat`으로 각 취약점의 flag가 재현된다.

---

## 7. 경기 흐름

1. 팀이 서비스를 `gitctf.py`로 제출한다.
2. coordinator가 서비스를 빌드하고 target network에 배포한다.
3. 라운드 시작 시 coordinator가 새 flag를 주입한다.
4. attack agent가 상대 repo snapshot을 받는다.
5. attack agent가 `/llm`으로 scan plan을 만들고 `/attack`을 호출한다.
6. flag가 보이면 attack agent가 `/llm`으로 `poc*.py`를 만들고 `/pocs`에 제출한다.
7. 운영자가 PoC를 accept하면 coordinator가 매 라운드 PoC를 재실행한다.
8. 성공한 PoC는 공격팀 +10, 해당 서비스 방어팀 -10이다.
9. defense agent는 맡은 repo에 패치를 push해 서비스를 재배포한다.

---

## 8. 공격과 PoC

공격은 SDK를 통해 해야 한다.

```python
from agent_sdk import AgentContext

ctx = AgentContext.from_env()

repo = ctx.fetch_target_repo()
scan = ctx.llm(
    model="openai/gpt-4o-mini",
    messages=[{"role": "user", "content": "scan target repo"}],
    purpose="scan",
)
result = ctx.attack("파리 여행 추천해줘", llm_call_id=scan["llm_call_id"])

poc_plan = ctx.llm(
    model="openai/gpt-4o-mini",
    messages=[{"role": "user", "content": "write poc_vuln1.py"}],
    purpose="poc",
)
ctx.submit_poc("poc_vuln1.py", llm_call_id=poc_plan["llm_call_id"], flag_id="vuln1")
```

PoC 규칙:

| 항목 | 규칙 |
|---|---|
| 파일명 | `poc*.py` |
| 형식 | Python 단일 파일 |
| 입력 | `TARGET_HOST`, `TARGET_PORT`, `TARGET_TEAM`, `FLAG_ID` env |
| 출력 | stdout의 마지막 non-empty line에 현재 라운드의 유효한 `HSPACE{...}`가 있어야 함 |
| 실행 위치 | coordinator의 Docker PoC runner |

금지 패턴 예시:

- `subprocess`
- `os.system`
- `eval`
- `exec`
- `pickle.loads`
- 외부 인터넷 호출

---

## 9. 방어

방어 대상은 고정 rotation으로 정해진다.

```text
teamA <- teamB <- teamC <- teamD <- teamE <- teamF <- teamA
```

예시:

- `teamB`는 `teamA` 서비스를 방어한다.
- `teamB`는 `teamA`와 `teamB`를 공격할 수 없다.
- `teamB`는 `teamC`, `teamD`, `teamE`, `teamF`를 공격할 수 있다.

방어는 defense agent가 해야 한다.

```python
from agent_sdk import AgentContext

ctx = AgentContext.from_env()
repo = ctx.clone_target_repo()

patch = ctx.llm(
    model="openai/gpt-4o-mini",
    messages=[{"role": "user", "content": "patch target safely"}],
    purpose="defense",
)

# 파일 수정 후
ctx.commit_patch("Patch vuln1", repo_dir=repo["path"])
ctx.push_repo(repo_dir=repo["path"], repo_team=ctx.target_team)
```

라운드 중 사람이 직접 패치 push하면 거절된다.

---

## 10. 점수

| 이벤트 | 점수 |
|---|---:|
| accepted PoC가 현재 라운드 flag 탈취 | 공격팀 +10 |
| accepted PoC가 현재 라운드 flag 탈취 | 방어팀 -10 |
| 서비스 상태 OK | 서비스 소유팀 +10 |
| 서비스 DOWN 또는 FAULTY | 0 |

기본값:

- 시작 점수: 1000
- 전체 라운드: 20
- 팀당 탐색 요청: 라운드당 10턴
- 같은 `poc_id`는 같은 라운드에 한 번만 채점
- 같은 PoC가 다음 라운드에도 성공하면 다시 채점

---

## 11. Flag

flag 형식:

```text
HSPACE{32자리 hex}
```

규칙:

- flag는 매 라운드 새로 생성된다.
- 이전 라운드 flag는 점수가 아니다.
- 자기 서비스 flag는 점수가 아니다.
- `vuln_spec.json`이나 git repo에 flag를 넣으면 안 된다.

---

## 12. 금지 사항

아래 행위는 점수 무효 또는 실격 사유다.

- coordinator, scoreboard, Docker host 공격
- 다른 팀 인프라에 DoS
- agent 없이 직접 `/attack`, `/pocs` 호출
- 허용되지 않은 외부 LLM 또는 개인 API key 사용
- 다른 팀 토큰 탈취 또는 사용
- `vuln_spec.json`에 없는 숨은 취약점으로 채점 유도
- flag, PoC, exploit 코드를 팀 외부와 공유

---

## 13. 우승 조건

20라운드 종료 후 점수가 가장 높은 팀이 우승한다.

좋은 전략은 단순하다.

1. 서비스는 정상 동작해야 한다.
2. 취약점은 agent가 찾고 재현할 수 있어야 한다.
3. PoC는 매 라운드 안정적으로 성공해야 한다.
4. 방어 패치는 서비스를 망가뜨리지 않아야 한다.
