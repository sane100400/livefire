# HSPACE LiveFire A&D Rulebook

기준: **6팀(team1~team6)**

## 핵심

- <span class="red-strong">각 팀은 사전에 제공된 기획서를 바탕으로 웹 서비스를 구현합니다.</span>
- 서비스에는 의도된 취약점 4개를 넣습니다: `vuln1`, `vuln2`, `vuln3`, `vuln4`
- 대회 당일에는 AI agent가 공격과 방어를 수행합니다.
- 점수 인정은 공식 `AGENT_RUN_TOKEN`과 coordinator wrapper를 거친 결과만 됩니다.
- 사람이 라운드 중 직접 PoC 제출 또는 패치 push를 하면 인정되지 않습니다.

## 대회 서버

- 이 대회는 로컬에서만 돌리는 방식이 아닙니다.
- 각 팀은 주최 측이 제공하는 **대회 서버**에 자기 앱을 배포해야 합니다.
- 로컬 실행과 `gitctf.py check`는 제출 전 자가검증용입니다.
- 공식 실행, flag 주입, 공격, 방어, 채점은 대회 서버와 coordinator 기준입니다.
- 대회 서버 접속 방법과 앱 배포 방법은 `USER_DEPLOY_GUIDE.md`와 `DISCORD_NOTICE.txt`를 기준으로 합니다.

## 서비스 규칙

- API는 자유입니다. `/chat`, `/health` 같은 고정 API는 필수가 아닙니다.
- 단, `vuln_spec.json`에 health 요청을 적지 않으면 기본값은 `GET /health -> HTTP 200`입니다.
- 서비스는 실제로 실행되어야 하고, 기본 기능이 깨지면 안 됩니다.
- 로컬 flag, 팀 토큰, API key, 비밀키는 git에 올리지 마세요.
- 공식 flag는 대회 당일 매 라운드 새로 주입됩니다.

## 제출물

서비스 repo 루트에 아래 파일이 있어야 합니다.

- `Dockerfile`
- `vuln_spec.json`
- 서비스 코드

`vuln_spec.json`에는 아래 검증 정보가 들어갑니다.

- health 확인
- flag 주입
- flag 저장 확인
- 취약점 공격 재현
- 기본 기능 확인

취약점 규칙:

- 정확히 4개
- ID와 순서는 `vuln1`, `vuln2`, `vuln3`, `vuln4`

## 제출 흐름

```bash
python scripts/gitctf.py login team1 --token "$TEAM_TOKEN" --coordinator http://knights.hspace.io:42000

cd <서비스_폴더>
python ../scripts/gitctf.py check

python ../scripts/gitctf.py push
```

- `check`는 제출 전 자가검증입니다. 서비스가 실행 중이어야 합니다.
- `push`는 변경사항을 commit하고 coordinator의 팀 repo로 보냅니다.
- 최종 판정은 참가자 PC가 아니라 대회 서버와 coordinator 검증 결과입니다.
- 공식 `gitctf.py`는 실행 시 최신 helper를 확인하고, 다르면 최신본으로 다시 실행됩니다.

제출 전 확인:

- `Dockerfile`, `vuln_spec.json`이 repo 루트에 있음
- `gitctf.py check` PASS
- 서비스 기본 기능 정상 동작
- `USER_DEPLOY_GUIDE.md` 또는 `DISCORD_NOTICE.txt`의 배포 안내 확인
- flag, 토큰, API key, 비밀키 미포함

## AI 사용 규칙

개발 중에는 Claude, ChatGPT, Gemini, IDE AI 등을 자유롭게 써도 됩니다.

대회 당일 agent는 아래 규칙을 지켜야 합니다.

- LLM 요청은 coordinator wrapper로 보냅니다.
- AI 모델 호출은 OpenRouter API 기반으로 동작하며, 실제 요청은 coordinator의 OpenRouter wrapper를 거칩니다.
- 주입된 `OPENAI_BASE_URL` 또는 `OPENROUTER_BASE_URL`을 사용합니다.
- 주입된 `OPENAI_API_KEY` 또는 `OPENROUTER_API_KEY`를 사용합니다.
- 개인 LLM API key와 외부 OpenRouter 직접 호출은 금지입니다.
- <span class="red-strong">허용 모델 목록에 있는 모델만 사용할 수 있습니다. 목록 밖 모델을 쓰면 요청이 거절되고, 해당 산출물은 점수로 인정되지 않습니다.</span>
- 팀 토큰으로 `/agent-runs`, `/llm`, `/attack`, `/pocs`를 직접 호출하지 않습니다.
- 공식 `AGENT_RUN_TOKEN`으로 `/agent/attack`, `/agent/pocs`를 호출하는 것은 허용됩니다.
- 다른 팀 repo를 raw git clone/fetch로 직접 가져가지 않습니다.
- agent 요청이 과도하면 서버가 `429 Too Many Requests`로 거절합니다. 이 경우 즉시 재시도하지 말고 backoff를 둡니다.

<span class="red-strong">허용 모델: 아래 7개만 가능</span>

- <span class="red-strong">`qwen/qwen-2.5-14b`</span>
- <span class="red-strong">`openai/gpt-4o-mini`</span>
- <span class="red-strong">`google/gemini-flash-1.5`</span>
- <span class="red-strong">`google/gemini-2.0-flash-001`</span>
- <span class="red-strong">`microsoft/phi-4`</span>
- <span class="red-strong">`mistralai/mistral-small-3.1`</span>
- <span class="red-strong">`xiaomi/mimo`</span>

## 요청 제한

대회 서버는 AI agent runaway loop와 LLM 비용 폭주를 막기 위해 인증 단위 요청 제한을 적용합니다.

기본 제한:

| 대상 | 한도 |
|---|---:|
| attack agent run 생성 | `10/minute` |
| defense agent run 생성 | `5/minute` |
| target repo snapshot 다운로드 | `6/minute` |
| LLM wrapper 요청(`/llm`, `/openrouter/...`, `/v1/chat/completions`) | `30/minute` |
| 탐색 요청(`/agent/attack`) | `20/minute` |
| PoC 제출(`/agent/pocs`) | `12/minute` |
| helper 다운로드(`/tools/*.py`) | `60/minute` |

탐색 요청은 위 분당 제한과 별도로 기본 **라운드당 10턴**만 점수 흐름에 사용할 수 있습니다.
Blind SQLi처럼 여러 요청이 필요한 풀이는 `poc.py` 안에서 재현하도록 작성할 수 있습니다.
분당 제한에 걸리면 `429`가 반환되며, 반복 재시도는 금지됩니다.

## 공격과 PoC

- attack agent는 공식 run token으로 타겟 repo를 받고, coordinator wrapper로 타겟 서비스를 탐색합니다.
- 라운드 중 사람이 직접 `poc.py`를 제출하면 안 됩니다.
- PoC 제출은 `/agent/pocs`, `submit_poc_source()`, `submit_poc()` 중 하나를 사용합니다.
- PoC는 라운드당 `공격팀 -> 타겟팀 -> vuln_id` 기준 최대 2개까지 제출할 수 있습니다.
- 제출된 PoC는 즉시 채점하지 않고, 라운드 종료 시점의 scoring snapshot에서 batch 실행합니다.

PoC 규칙:

- 파일명은 `poc*.py`
- UTF-8 Python 단일 파일
- 기본 크기 제한 64KB
- `TARGET_HOST`, `TARGET_PORT` 사용
- 필요하면 `TARGET_TEAM`, `FLAG_ID` 사용
- stdout의 마지막 non-empty line에 `HSPACE{...}` 출력
- 외부 인터넷 호출 금지
- 기본 실행 timeout은 20초이며, brute force/Blind 계열은 `vuln_spec.json`의 `poc_timeout_sec`으로 늘릴 수 있습니다. 운영 상한은 기본 120초입니다.

금지 패턴: `subprocess`, `os.system`, `os.popen`, `eval`, `exec`, `__import__`, `ctypes`, `pickle.loads`, `shutil.rmtree`

성공 조건: 현재 라운드의 타겟 팀 flag를 stdout 마지막 줄에 출력하면 성공입니다.

PoC 디버그:

```bash
python ../scripts/gitctf.py check --vuln 1 --poc poc.py
```

## 방어

- defense agent만 방어 패치를 제출합니다.
- 라운드 중 사람이 직접 패치 push하면 거절됩니다.
- 대회 진행 중에는 `vuln_spec.json` 변경도 거절됩니다.
- 패치는 취약점을 막되, 기본 기능을 깨면 안 됩니다.
- 서비스가 `FAULTY` 또는 `DOWN`이면 가용성 점수를 받을 수 없습니다.
- 커밋에는 `Agent-Run-ID`가 필요합니다. SDK의 `commit_patch()`를 쓰면 자동으로 붙습니다.

## 점수

기본값:

- 시작 점수: 1000
- 전체 라운드: 20
- 팀당 탐색 요청: 라운드당 10턴

| 이벤트 | 점수 |
|---|---:|
| PoC 성공 | 공격팀 +10 |
| 공격당한 서비스의 방어팀 | -10 |
| 내 서비스 상태가 OK | 서비스 소유팀 +10 |
| 서비스 DOWN 또는 FAULTY | 0 |

탐색 요청 10턴은 `/agent/attack` 요청 수입니다.
agent 내부 추론 횟수와 제출된 `poc.py`가 재현 중 보내는 요청 수와는 별개입니다.
PoC 성공 점수는 라운드당 `공격팀 -> 타겟팀 -> vuln_id` 기준 1회만 인정합니다.

## 금지 사항

- coordinator, scoreboard, Docker host 공격
- 다른 팀 인프라 DoS
- 공식 `AGENT_RUN_TOKEN` 없이 `/attack`, `/pocs` 직접 호출
- 공식 attack/defense 중 개인 LLM API key 사용
- 다른 팀 토큰 탈취 또는 사용
- 다른 팀 repo raw git clone/fetch 시도
- flag, PoC, exploit 코드 외부 공유
- flag, API key, 팀 토큰, 비밀키 commit
