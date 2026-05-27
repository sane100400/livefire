# OpenRouter API 기반 에이전트 구현 환경 가이드

이 문서는 참가자가 `attack_agent/` 또는 `defense_agent/`를 구현할 때 OpenRouter API를 어떤 환경에서 써야 하는지 설명합니다.
에이전트 빌드와 로컬 디버그 명령은 기존 가이드와 동일하게 `python scripts/gitctf.py agent ...`만 사용합니다.

핵심 결론:

- 에이전트는 `https://openrouter.ai`를 직접 호출하지 않습니다.
- 실제 OpenRouter API key는 coordinator에만 있습니다.
- 에이전트에는 `AGENT_RUN_TOKEN`이 `OPENROUTER_API_KEY`처럼 주입됩니다.
- 에이전트는 `OPENROUTER_BASE_URL` 또는 `OPENAI_BASE_URL`로만 LLM을 호출합니다.
- `openai/gpt-5.5`처럼 허용 목록 밖 모델은 coordinator가 OpenRouter로 보내기 전에 `403`으로 거절합니다.
- 비허용 모델 호출만 남긴 상태에서는 `/agent/attack`도 성공할 수 없습니다. 성공한 whitelist LLM 호출 기록이 없기 때문입니다.

OpenRouter 공식 API는 OpenAI Chat Completions와 거의 같은 request/response 구조를 씁니다.
참고: https://openrouter.ai/docs/quickstart, https://openrouter.ai/docs/api/reference/overview

## 1. 실제 실행 구조

공식 라운드에서 실행 흐름은 아래와 같습니다.

```text
agent container
  -> OPENROUTER_BASE_URL=http://10.89.20.2:9000/openrouter/api/v1
  -> coordinator /openrouter/api/v1/chat/completions
  -> model whitelist 검사, prompt/audit 기록
  -> https://openrouter.ai/api/v1/chat/completions
```

즉 참가자 코드는 OpenRouter 형식으로 작성해도 되지만, base URL은 반드시 coordinator wrapper입니다.

금지:

```python
httpx.post("https://openrouter.ai/api/v1/chat/completions", ...)
httpx.post("https://api.openai.com/v1/chat/completions", ...)
```

허용:

```python
httpx.post(os.environ["OPENROUTER_BASE_URL"] + "/chat/completions", ...)
httpx.post(os.environ["OPENAI_BASE_URL"] + "/chat/completions", ...)
```

`OPENROUTER_BASE_URL`과 `OPENAI_BASE_URL`은 같은 coordinator wrapper를 가리킵니다. OpenAI-compatible client를 쓰는 코드도 이 URL로 붙이면 됩니다.

## 2. 에이전트 컨테이너 환경변수

공식 run에서 runner가 아래 값을 넣습니다.

| 변수 | 의미 |
|---|---|
| `TEAM_ID` | 내 팀 ID. 예: `team1` |
| `MODE` | `attack` 또는 `defense` |
| `TARGET_TEAM` | 이번 run에서 맡은 대상 팀 |
| `ROUND` | 현재 라운드 |
| `COORDINATOR_URL` | coordinator 내부 주소 |
| `AGENT_RUN_ID` | 이번 agent run ID |
| `AGENT_RUN_TOKEN` | 이번 run 전용 bearer token |
| `OPENROUTER_BASE_URL` | OpenRouter-compatible coordinator wrapper |
| `OPENROUTER_API_KEY` | 실제 OpenRouter key가 아니라 `AGENT_RUN_TOKEN` |
| `OPENAI_BASE_URL` | OpenAI-compatible coordinator wrapper |
| `OPENAI_API_KEY` | 실제 OpenAI key가 아니라 `AGENT_RUN_TOKEN` |
| `HSPACE_AGENT_BASE_URL` | `/agent/attack`, `/agent/pocs` 호출용 base URL |
| `TARGET_REPO_URL` | 대상 repo clone/fetch용 coordinator git URL |

참가자 코드에서 새 비밀값을 만들 필요가 없습니다. 환경변수를 그대로 읽어 쓰면 됩니다.

## 3. 하면 안 되는 것

아래 항목은 언어와 framework에 상관없이 금지입니다.

- 개인 OpenAI/OpenRouter API key를 코드에 넣지 마세요.
- `https://openrouter.ai`, `https://api.openai.com`, `https://api.anthropic.com` 같은 외부 AI API를 직접 호출하지 마세요.
- `OPENROUTER_BASE_URL` 또는 `OPENAI_BASE_URL` 대신 직접 만든 base URL을 쓰지 마세요.
- `OPENROUTER_API_KEY` 또는 `OPENAI_API_KEY` 값을 임의로 바꾸지 마세요. 이 값은 실제 외부 key가 아니라 run token입니다.
- 타겟 팀 서비스 IP/포트로 직접 요청하지 마세요. 공격 요청은 항상 `HSPACE_AGENT_BASE_URL + "/attack"`으로 보냅니다.
- PoC 제출을 직접 coordinator 내부 API나 팀 토큰으로 하지 마세요. `HSPACE_AGENT_BASE_URL + "/pocs"`만 씁니다.
- `openai/gpt-5.5`처럼 허용 목록 밖 모델을 쓰지 마세요. wrapper가 OpenRouter로 보내기 전에 막습니다.
- 성공한 LLM wrapper 호출 없이 `/agent/attack` 또는 `/agent/pocs`부터 호출하지 마세요.
- `stream: true`를 켜지 마세요. wrapper는 streaming 응답을 지원하지 않습니다.
- `429`가 왔을 때 즉시 무한 재시도하지 마세요. 잠깐 기다리거나 호출 수를 줄여야 합니다.
- PoC에 현재 flag 값을 하드코딩하지 마세요. PoC는 실행될 때 `TARGET_HOST`, `TARGET_PORT`를 보고 다시 공격해서 flag를 출력해야 합니다.

wrapper는 OpenRouter 사용 여부와 모델 허용 여부를 검사하고, 성공한 LLM 호출 기록이 있는 run만 공격/PoC wrapper를 계속 쓸 수 있게 합니다.

## 4. 언어와 런타임 규정

기본 배포 템플릿은 Python 기반입니다. 대회 운영과 로컬 검증도 Python agent를 가장 안정적으로 지원한다고 보면 됩니다.
참가자는 Python 안에서 직접 planner, state machine, multi-agent 구조를 자유롭게 만들면 됩니다.

하지만 규정상 agent 오케스트레이션이 반드시 Python이어야 하는 것은 아닙니다. `agent_manifest.json`에서 `cmd`를 지정하고 Dockerfile에 필요한 runtime을 설치하면 Node.js/TypeScript, Go, Rust 같은 언어도 실행할 수 있습니다.

예:

```json
{
  "attack": {
    "cmd": ["node", "attack_agent/index.js"]
  },
  "defense": {
    "cmd": ["node", "defense_agent/index.js"]
  }
}
```

단, 비-Python 구현은 기본 템플릿/검증 경로에서 벗어나므로 팀이 runtime과 wrapper API 계약을 직접 책임져야 합니다.
아래 계약은 언어와 무관하게 모든 자유 구현이 지켜야 합니다.

- `OPENROUTER_BASE_URL` 또는 `OPENAI_BASE_URL`로 LLM 호출
- `OPENROUTER_API_KEY` 또는 `OPENAI_API_KEY`를 Bearer token으로 사용
- `HSPACE_AGENT_BASE_URL + "/attack"`으로 대상 서비스 탐색
- `HSPACE_AGENT_BASE_URL + "/pocs"`로 PoC 제출
- 성공한 whitelist LLM 호출 기록을 만든 뒤 `/agent/attack`, `/agent/pocs` 사용
- 외부 `openrouter.ai`, `api.openai.com`, `api.anthropic.com` 직접 호출 금지

행사 운영 안정성 기준의 권장안:

```text
기본 가정: Python + 자유 오케스트레이션 + wrapper HTTP API 준수
비-Python 구현: manifest cmd + Dockerfile 수정 + wrapper HTTP API 직접 구현
```

## 5. 모델 허용 목록

현재 허용 prefix는 `coordinator/config.py`의 `ALLOWED_MODEL_PREFIXES`가 기준입니다.

```text
qwen/qwen-2.5-14b
openai/gpt-4o-mini
google/gemini-flash-1.5
google/gemini-2.0-flash-001
microsoft/phi-4
mistralai/mistral-small-3.1
xiaomi/mimo
```

허용 예:

```text
openai/gpt-4o-mini
openai/gpt-4o-mini:free
```

거절 예:

```text
openai/gpt-5.5
openai/gpt-5.2
anthropic/claude-3.5-sonnet
meta-llama/llama-3.1-70b
```

비허용 모델은 외부 OpenRouter로 전달되기 전 coordinator에서 `403`으로 끊깁니다. 이 거절도 audit에는 `allowed=false`, `status=rejected`로 남습니다.
개인 OpenAI/OpenRouter key로 외부 API를 직접 호출해도 coordinator에는 성공한 wrapper LLM 기록이 생기지 않으므로 `/agent/attack`과 `/agent/pocs`를 열 수 없습니다.

## 6. wrapper API 직접 호출 예시

기본 템플릿인 `attack_agent/main.py`와 `defense_agent/main.py`는 아래 wrapper API를 직접 호출합니다.
LangChain, AutoGen, 직접 만든 planner를 쓰고 싶으면 이 호출 부분만 같은 계약으로 유지하면 됩니다.

LLM 호출:

```python
import os
import httpx

llm_resp = httpx.post(
    os.environ["OPENROUTER_BASE_URL"] + "/chat/completions",
    headers={
        "Authorization": "Bearer " + os.environ["OPENROUTER_API_KEY"],
        "X-Agent-Purpose": "scan",
    },
    json={
        "model": "openai/gpt-4o-mini",
        "messages": [
            {"role": "user", "content": "target을 공격할 probe를 JSON으로 만들어줘"}
        ],
        "temperature": 0.2,
        "max_tokens": 700,
    },
    timeout=75,
)
llm_resp.raise_for_status()
llm_data = llm_resp.json()
llm_call_id = int(llm_resp.headers["X-LLM-Call-ID"])
content = llm_data["choices"][0]["message"]["content"]
```

대상 서비스 탐색:

```python
agent_auth = {"Authorization": "Bearer " + os.environ["AGENT_RUN_TOKEN"]}

attack_resp = httpx.post(
    os.environ["HSPACE_AGENT_BASE_URL"] + "/attack",
    headers=agent_auth,
    json={
        "llm_call_id": llm_call_id,
        "path": "/api/search",
        "method": "POST",
        "json_body": {"q": "payload"},
    },
    timeout=40,
)
attack_resp.raise_for_status()
attack_data = attack_resp.json()
```

PoC 제출:

```python
poc_resp = httpx.post(
    os.environ["HSPACE_AGENT_BASE_URL"] + "/pocs",
    headers=agent_auth,
    data={
        "llm_call_id": str(llm_call_id),
        "flag_id": "vuln1",
        "source": "print('HSPACE{0123456789abcdef0123456789abcdef}')\n",
    },
    timeout=30,
)
poc_resp.raise_for_status()
```

`llm_call_id`는 생략할 수도 있습니다. 생략하면 coordinator가 같은 run의 최신 성공 LLM 호출을 사용합니다. 그래도 여러 LLM 호출을 섞는 agent라면 명시하는 편이 안전합니다.

## 7. OpenAI-compatible Python client를 쓰는 경우

OpenAI-compatible Python client를 쓰고 싶으면 `attack_agent/requirements.txt` 또는 `defense_agent/requirements.txt`에 필요한 패키지를 직접 추가합니다.

```text
openai>=1.0.0
```

코드는 base URL만 coordinator wrapper로 바꿉니다.

```python
import os
from openai import OpenAI

client = OpenAI(
    base_url=os.environ["OPENROUTER_BASE_URL"],
    api_key=os.environ["OPENROUTER_API_KEY"],
    default_headers={"X-Agent-Purpose": "scan"},
)

resp = client.chat.completions.create(
    model="openai/gpt-4o-mini",
    messages=[{"role": "user", "content": "probe를 만들어줘"}],
)
print(resp.choices[0].message.content)
```

단, wrapper가 돌려주는 `X-LLM-Call-ID` 헤더를 정확히 써야 하는 흐름에서는 `httpx` 직접 호출이 더 단순합니다.

## 8. 자주 나는 에러

| 상태 | 의미 | 조치 |
|---:|---|---|
| `401` | Bearer token 없음 | `Authorization: Bearer $AGENT_RUN_TOKEN` 사용 |
| `403 허용되지 않은 모델` | whitelist 밖 모델 | 허용 prefix 모델로 변경 |
| `403 OpenRouter wrapper LLM 호출 기록이 없습니다` | 성공한 whitelist LLM 호출 없이 `/agent/attack` 또는 `/agent/pocs` 호출 | 먼저 wrapper LLM 호출 성공시키기 |
| `400 stream 응답은 지원하지 않습니다` | `stream: true` 사용 | streaming 끄기 |
| `429` | rate limit 초과 | backoff 후 재시도 |
| `503 coordinator OPENROUTER_API_KEY 미설정` | 운영 서버 coordinator에 실제 OpenRouter key 없음 | 운영자가 `coordinator/.env` 확인 |

## 9. GPT-5.5 같은 모델 우회 테스트 결과

저장소 테스트에 `test_disallowed_gpt55_model_cannot_unlock_agent_attack`를 추가했습니다.

검증하는 내용:

- agent token으로 `/v1/chat/completions`에 `model="openai/gpt-5.5"`를 보내면 `403`이 반환됩니다.
- mock OpenRouter 서버까지 요청이 전달되지 않습니다.
- DB audit에는 `allowed=false`, `status=rejected`로 남습니다.
- 그 상태에서 `/agent/attack`을 호출해도 성공한 whitelist LLM 호출 기록이 없어서 `403`으로 막힙니다.

로컬 확인:

```bash
python -m unittest tests.test_core.OpenRouterGatewayTests.test_disallowed_gpt55_model_cannot_unlock_agent_attack
```

전체 핵심 테스트:

```bash
python -m unittest tests.test_core
```
