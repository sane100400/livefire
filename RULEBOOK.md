# HSPACE LiveFire A&D 참가자 Rulebook

## 1. 대회 목표

각 팀은 웹 서비스를 하나 만든다.
서비스 안에는 의도된 취약점 4개를 넣는다.

본선에서는 AI 공격 에이전트가 다른 팀 서비스를 공격하고,
AI 방어 에이전트가 배정된 서비스를 패치한다.

점수로 인정되는 공격과 방어는 반드시 공식 agent run token과 coordinator wrapper를 통해 실행해야 한다.

---

## 2. 게임 방식

각 팀은 자기 서비스를 자유롭게 만든다.
본선에서는 방어 대상이 시계방향으로 한 칸씩 밀려 배정된다.

```text
teamA <- teamB <- teamC <- teamD <- teamE <- teamF <- teamG <- teamA
```

예를 들어 `teamB` 기준으로 보면:

- `teamB`가 만든 서비스는 `teamC`가 방어한다.
- `teamB`는 `teamA` 서비스를 방어한다.
- `teamB`는 자기 팀 서비스와 자기가 방어하는 `teamA` 서비스는 공격할 수 없다.
- 따라서 `teamB`는 `teamC`, `teamD`, `teamE`, `teamF`, `teamG` 총 5팀을 공격할 수 있다.

모든 팀이 같은 방식으로 돌아간다.

---

## 3. 서비스 개발 주제

이번 주제는 **"쓰기 싫은 사이트 만들기"**다.

쓸데없고, 답답하고, 일부러 쓰기 싫은 웹 서비스를 만든다.
그래도 서비스는 실제로 실행되고 기본 기능은 동작해야 한다.

예:

- 클릭할수록 귀찮아지는 할 일 관리 서비스
- 필요 없는 핑계만 추천하는 업무 도우미
- 답을 빙빙 돌리는 고객센터봇
- 지나치게 불편한 추천, 예약, 신청 서비스

서비스 안에는 의도된 취약점 4개를 넣는다.

---

## 4. 제출물

서비스 repo 루트에는 `Dockerfile`과 `vuln_spec.json`이 있어야 한다.
`Dockerfile`로 서비스가 빌드되고, `vuln_spec.json`으로 취약점 4개를 검증한다.

팀은 공격 에이전트와 방어 에이전트도 준비한다.
기본 예시는 `attack_agent/`, `defense_agent/`에 있다.

`vuln_spec.json`은 시스템이 취약점 4개를 확인할 때 쓰는 파일이다.
템플릿에는 예시가 들어 있지만, 참가자가 복잡한 형식을 외울 필요는 없다.

---

## 5. 서비스 규칙

서비스 컨셉과 API는 위 주제 안에서 자유다.
`/chat`, `/health` 같은 고정 필수 API는 없다.

취약점은 정확히 4개다.

```text
vuln1, vuln2, vuln3, vuln4
```

난이도는 `low`, `mid`, `high`가 모두 들어가야 한다.
예: low 1개, mid 2개, high 1개.

로컬 테스트용 flag는 `flags.env`처럼 git에 올라가지 않는 파일에 넣는다.
공식 flag는 본선 중 매 라운드 새로 주어진다.

---

## 6. 제출 방법

제출 순서는 아래와 같다.

1. 서비스 코드를 만든다.
2. 서비스 안에 `vuln1`~`vuln4` 취약점 4개를 심는다.
3. `vuln_spec.json`에 health, flag 주입, flag 회수, 취약점 공격 검증 요청을 적는다.
4. 서비스를 로컬에서 실행한다.
5. `gitctf.py check`가 PASS인지 확인한다.
6. PASS가 나오면 `gitctf.py push`로 제출한다.

처음 한 번만 로그인한다. 로그인은 제출 전 아무 때나 해도 된다.

```bash
python scripts/gitctf.py login teamA --token "$TEAM_TOKEN" --coordinator http://HOST:9000
```

서비스 폴더에서 확인한다. 이때 서비스는 이미 실행 중이어야 한다.

```bash
cd <서비스_폴더>
python ../scripts/gitctf.py check
```

PASS가 나오면 제출한다.

```bash
python ../scripts/gitctf.py push
```

`push`는 변경사항을 commit하고 coordinator에 push한다.
팀 토큰은 git 설정 파일에 저장하지 않는다.
공식 `gitctf.py`는 실행 시 coordinator에서 최신 helper를 확인하고, 다른 버전이면 최신본으로 다시 실행한다.
단, 참가자 PC의 helper는 편의 도구일 뿐이고 최종 제출 판정은 coordinator 서버 검증이 기준이다.

---

## 7. 제출 전 체크리스트

제출 전에 아래만 확인한다.

- `Dockerfile`이 있다.
- `gitctf.py check`가 PASS다.
- 서비스가 정상 동작한다.
- 로컬 테스트 flag나 비밀키가 git에 올라가지 않는다.

예시 템플릿은 아래처럼 확인한다.

터미널 1:

```bash
cd web_service
make run
```

터미널 2:

```bash
cd web_service
make check
```

---

## 8. AI와 모델 규칙

개발 중에는 Claude, ChatGPT, Gemini, IDE AI 등을 써도 된다.
공식 agent 내부에서도 skill, subagent, planner, 토큰 최적화 등 오케스트레이션 방식은 자유다.

본선 공격/방어에서 점수로 인정되려면 아래 규칙을 지켜야 한다.

- LLM 요청은 coordinator의 OpenRouter 호환 wrapper를 통해 보낸다.
- `agent_sdk`는 선택사항이다. 직접 쓰지 않아도 된다.
- 공격/방어 에이전트는 아래 허용 모델만 사용한다.
- 개인 LLM API key를 직접 쓰지 않는다.
- 외부 OpenRouter API를 agent 안에서 직접 호출하지 않는다.
- 팀 토큰으로 직접 `/agent-runs`, `/llm`, `/attack`, `/pocs`를 호출해 수동 PoC를 제출하지 않는다.
- 공식 agent가 받은 `AGENT_RUN_TOKEN`으로 `/agent/attack`, `/agent/pocs` wrapper를 호출하는 것은 허용된다.
- 다른 팀 repo를 raw git clone/fetch로 직접 가져가려고 시도하지 않는다.

허용 모델:

```text
qwen/qwen-2.5-14b
openai/gpt-4o-mini
google/gemini-flash-1.5
google/gemini-2.0-flash-001
microsoft/phi-4
mistralai/mistral-small-3.1
xiaomi/mimo
```

---

## 9. 공격과 PoC

공격 에이전트는 공식 run token으로 상대 repo를 받고, coordinator wrapper로 탐색 요청을 보낸 뒤 PoC를 제출한다.
라운드 중 사람이 `poc.py`를 직접 제출하지 않는다.

PoC는 에이전트가 `/agent/pocs` wrapper로 제출한다. `agent_sdk`의 `submit_poc_source()` 또는 `submit_poc()`를 써도 된다.

PoC 규칙:

- Python 단일 파일
- `TARGET_HOST`, `TARGET_PORT` 환경변수 사용
- 필요하면 `TARGET_TEAM`, `FLAG_ID` 환경변수 사용
- stdout의 마지막 non-empty line에 `HSPACE{...}` 출력
- 외부 인터넷 호출 금지
- `subprocess`, `eval`, `exec` 금지

아래 명령은 PoC runner 계약을 디버깅할 때만 선택적으로 사용한다.

```bash
python ../scripts/gitctf.py check --vuln 1 --poc poc.py
```

---

## 10. 방어

방어는 defense agent가 한다.
라운드 중 사람이 직접 패치 push하면 거절된다.

방어 패치는 취약점을 막되, 서비스를 망가뜨리면 안 된다.
SDK의 `commit_patch()`를 쓰면 필요한 `Agent-Run-ID`가 자동으로 붙는다. SDK를 쓰지 않는 경우에도 커밋 trailer는 같은 값으로 남아야 한다.

---

## 11. 점수

| 이벤트 | 점수 |
|---|---:|
| PoC가 현재 라운드 flag 탈취 성공 | 공격팀 +10 |
| 내가 맡은 방어 서비스가 뚫림 | 방어팀 -10 |
| 내 서비스 상태가 OK | 서비스 소유팀 +10 |
| 서비스 DOWN 또는 FAULTY | 0 |

기본값:

- 시작 점수: 1000
- 전체 라운드: 20
- 팀당 탐색 요청: 라운드당 10턴

---

## 12. 금지 사항

아래는 점수 무효 또는 실격 사유다.

- coordinator, scoreboard, Docker host 공격
- 다른 팀 인프라 DoS
- 공식 `AGENT_RUN_TOKEN` 없이 legacy `/attack`, `/pocs` 직접 호출
- 공식 공격/방어 중 개인 LLM API key 사용
- 다른 팀 토큰 탈취 또는 사용
- flag, PoC, exploit 코드를 팀 밖에 공유

---

## 13. 예시 화면

`gitctf.py check`가 성공하면 4개 취약점이 모두 PASS로 보인다.

![서비스 자가검증 PASS](docs/demo/service-verify.png)

run token 없는 wrapper 요청과 허용되지 않은 모델 요청은 거절된다.

![SDK 및 낮은 모델 게이트](docs/demo/sdk-gate.png)
