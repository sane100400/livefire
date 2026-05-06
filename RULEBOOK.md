# HSPACE AI Agent A&D CTF Rulebook

## 1. 한 줄 요약

각 팀은 자유롭게 웹 서비스를 만들고, 그 서비스 안에 공격 가능한 취약점 4개를 심는다.
대회 중에는 AI 에이전트가 상대 웹 서비스 코드를 분석해 공격하고 PoC를 제출한다. 사람이 직접 공격하거나 직접 PoC를 내는 것은 점수로 인정하지 않는다.

---

## 2. 팀이 만드는 것

| 제출물 | 설명 |
|---|---|
| 서비스 repo | 자유로운 웹 서비스. 단, 운영 API와 의도된 취약점 4개 포함 |
| `vuln_spec.json` | 취약점 4개와 checker 방법 설명 |
| attack agent | 상대 repo를 분석하고 공격 PoC를 만드는 자동 에이전트 |
| defense agent | 맡은 서비스를 자동 패치하는 에이전트 |

서비스는 git으로 제출한다.

```bash
git remote add organizer http://teamA:<TEAM_TOKEN>@coordinator:9000/git/teamA
git push organizer main
```

---

## 3. 서비스 필수 API

서비스의 주제, 화면, 기능, 내부 구현은 자유다.
다만 coordinator가 로컬 서버를 검증하고 공격을 프록시하려면 아래 API는 반드시 있어야 한다.

| API | 용도 |
|---|---|
| `GET /health` | 살아있는지 확인 |
| `POST /chat` | 기본 공격 엔트리포인트 |
| `POST /admin/inject` | coordinator가 flag 주입 |
| `GET /admin/check` | flag가 제대로 들어갔는지 확인 |

`/chat` 응답 형식:

```json
{
  "response": "응답 내용",
  "tool_calls": []
}
```

---

## 4. 경기 흐름

1. 팀은 취약점 4개가 들어간 서비스를 git으로 제출한다.
2. coordinator가 서비스 Docker 이미지를 빌드하고 로컬 네트워크에 띄운다.
3. 라운드가 시작되면 coordinator가 새 flag를 각 서비스에 주입한다.
4. 공격 에이전트가 상대 팀 git repo snapshot을 받는다.
5. 공격 에이전트가 repo 코드를 LLM에 넣고 scan plan을 만든다.
6. 공격 에이전트가 `/attack`으로 실제 로컬 서비스에 공격 payload를 보낸다.
7. flag가 보이면 공격 에이전트가 LLM으로 `poc*.py`를 만든다.
8. coordinator가 PoC를 받아 검수하고, accepted PoC를 매 라운드 다시 실행해 채점한다.
9. 방어 에이전트는 맡은 서비스 repo에 패치를 push한다.

핵심 규칙:

- 스캔은 반드시 agent가 target repo를 분석해서 해야 한다.
- PoC 제작도 반드시 agent가 LLM 호출로 해야 한다.
- `/attack`은 `agent_run_id`와 `purpose=scan` LLM 기록이 있어야 통과한다.
- `/pocs`는 `purpose=poc` LLM 기록이 있어야 통과한다.

---

## 5. 공격/방어 대상

팀 순서는 고정이다.

```text
teamA -> teamB -> teamC -> teamD -> teamE -> teamF -> teamA
```

| 행동 | 대상 |
|---|---|
| 방어 | 내 앞 팀의 서비스 1개 |
| 공격 | 내 서비스와 내가 방어 중인 서비스 제외, 나머지 4개 |

예시:

- `teamB`는 `teamA` 서비스를 방어한다.
- `teamB`는 `teamB`와 `teamA`를 공격할 수 없다.
- `teamB`는 `teamC`, `teamD`, `teamE`, `teamF`를 공격할 수 있다.

---

## 6. Flag

형식:

```text
HSPACE{32자리 hex}
```

예시:

```text
HSPACE{3a9f2c1e8b4d7f0a5e2c9b6d3f1a8e4c}
```

중요:

- flag는 매 라운드 새로 생성된다.
- 이전 라운드 flag는 점수가 안 된다.
- `vuln_spec.json`에는 flag 값이 들어가지 않는다.
- flag는 런타임에 coordinator가 주입한다.

---

## 7. 점수

| 이벤트 | 공격팀 | 방어팀 |
|---|---:|---:|
| accepted PoC가 현재 라운드 flag 탈취 | +10 | -10 |
| 서비스 상태 OK | 0 | +10 |
| 서비스 DOWN | 0 | 0 |

기본값:

- 시작 점수: 1000점
- 라운드: 20라운드
- 라운드 길이: 30분
- 팀당 탐색 요청: 라운드당 10턴

PoC 점수 규칙:

- 같은 `poc_id`는 같은 라운드에 한 번만 점수화된다.
- 같은 PoC가 다음 라운드에도 성공하면 다시 점수를 받는다.
- 단순 복붙 PoC는 병합되거나 거절될 수 있다.

---

## 8. 서비스 상태

| 상태 | 의미 | 공격 가능 | 가용성 점수 |
|---|---|---|---:|
| OK | health, inject, check, 기본 기능 모두 정상 | 가능 | +10 |
| FAULTY | 켜져 있지만 checker 일부 실패 | 가능 | 0 |
| DOWN | `/health` 실패 | 불가 | 0 |

서비스를 내려서 방어하는 전략은 점수를 거의 못 얻는다.

---

## 9. 허용되는 LLM 사용

팀은 OpenRouter API key를 직접 받지 않는다.
모든 LLM 호출은 coordinator `/llm` 프록시를 통해야 한다.

허용 모델은 운영자가 정한 whitelist만 가능하다.

대표 예시:

- `openai/gpt-4o-mini`
- `qwen/qwen-2.5-14b`
- `qwen/qwen-2.5-32b`
- `meta-llama/llama-3.1-70b`
- `google/gemini-2.0-flash-001`
- `deepseek/deepseek-chat`

정확한 목록은 `coordinator/config.py`의 `ALLOWED_MODEL_PREFIXES`를 따른다.

---

## 10. PoC 규칙

PoC는 Python 단일 파일이다.

| 항목 | 규칙 |
|---|---|
| 파일명 | `poc*.py` |
| 입력 | `TARGET_HOST`, `TARGET_PORT` 환경변수 |
| 출력 | 응답 또는 stdout/stderr에 `HSPACE{...}` 포함 |
| 네트워크 | target 서비스 공격만 허용 |
| 제출 | SDK `submit_poc()` 사용 |

실행 예시:

```bash
TARGET_HOST=172.21.0.12 TARGET_PORT=8000 python poc_vuln1.py
```

금지 패턴 예시:

- `subprocess`
- `os.system`
- `eval`
- `exec`
- `pickle.loads`
- 외부 인터넷 호출

---

## 11. 방어 규칙

대회 중 서비스 패치는 defense agent를 통해서만 인정된다.

방어 패치 commit에는 자동으로 아래 trailer가 들어가야 한다.

```text
Agent-Run-ID: <agent run id>
```

라운드 중 사람이 직접 push한 패치는 거절된다.

---

## 12. 금지 사항

아래는 점수 무효 또는 실격 사유다.

- coordinator 공격
- 다른 팀 인프라에 DoS
- agent 없이 직접 `/attack` 또는 `/pocs` 시도
- 허용되지 않은 외부 LLM 사용
- OpenRouter API key를 agent 컨테이너에 직접 넣기
- 다른 팀 토큰 탈취 또는 사용
- vuln_spec에 없는 숨은 취약점으로 채점 유도
- flag, PoC, exploit 코드를 팀 외부와 공유

---

## 13. 제출 전 체크

서비스 실행:

```bash
cd agent_service
uvicorn main:app --host 0.0.0.0 --port 8000
```

취약점 검증:

```bash
python scripts/verify.py --host localhost --port 8000 --repeat 3
```

공격/방어 agent는 제공 SDK를 사용해야 한다.

```python
from agent_sdk import AgentContext

ctx = AgentContext.from_env()
repo = ctx.fetch_target_repo()
scan = ctx.llm(model="openai/gpt-4o-mini", messages=[...], purpose="scan")
result = ctx.attack("payload", llm_call_id=scan["llm_call_id"])
poc = ctx.llm(model="openai/gpt-4o-mini", messages=[...], purpose="poc")
ctx.submit_poc("poc_vuln1.py", llm_call_id=poc["llm_call_id"], flag_id="vuln1")
```

---

## 14. 승리 조건

20라운드 종료 후 점수가 가장 높은 팀이 우승한다.

잘하는 팀은 세 가지를 모두 잘해야 한다.

1. 잘 털리는 취약점을 심는다.
2. agent가 빠르게 상대 repo를 분석하고 PoC를 만든다.
3. 맡은 서비스를 망가뜨리지 않고 빠르게 패치한다.
