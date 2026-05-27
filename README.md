# HSPACE LiveFire AI Agent A&D

AI 에이전트가 웹 서비스를 공격하고 방어하는 Attack & Defense 해커톤 플랫폼입니다.

팀은 취약점 4개가 들어 있는 웹 서비스를 제출합니다. 운영 서버는 라운드마다 flag를 주입하고, 공격 에이전트가 제출한 PoC를 직접 실행해서 점수를 계산합니다. 방어 에이전트는 시스템이 지정한 서비스를 패치합니다.

## 핵심만 보기

실사용 명령은 `scripts/gitctf.py` 하나로 봅니다.

| 대상 | 하는 일 | 명령 |
|---|---|---|
| 참가자 | 로그인 | `python scripts/gitctf.py login team1 --token <TOKEN> --coordinator http://knights.hspace.io:42000` |
| 참가자 | 서비스 검증 | `python ../scripts/gitctf.py check` |
| 참가자 | 서비스 제출 | `python ../scripts/gitctf.py push` |
| 참가자 | 에이전트 빌드 | `python scripts/gitctf.py agent build team1` |
| 관리자 | 사전검증 | `python scripts/gitctf.py admin preflight --repeat 3` |
| 관리자 | 라운드 진행 | `python scripts/gitctf.py admin round next` |
| 관리자 | 상태 확인 | `python scripts/gitctf.py admin status` |

## 관리자 시작

```bash
scripts/setup_admin_env.sh
# coordinator/.env의 OPENROUTER_API_KEY와 팀 IP를 확인
docker compose up -d --build
curl http://localhost:42000/health
```

접속 주소:

| 주소 | 용도 |
|---|---|
| `http://localhost:42000` | 점수판 JSON. API는 `/health`, `/status`, `/scoreboard` 등 경로로 접근 |

포트 할당:

| 포트 | 용도 |
|---:|---|
| `42000` | 전체 관리용 gateway |
| `42001`~`42006` | team1~team6 서비스 지급용 |

행사 직전:

```bash
python scripts/gitctf.py admin preflight --repeat 3
python scripts/gitctf.py admin round next
```

서버 가용성 점검과 agent 요청 제한 운영값은 [SERVER_AVAILABILITY_GUIDE.md](SERVER_AVAILABILITY_GUIDE.md)를 기준으로 확인합니다.

운영 중:

```bash
python scripts/gitctf.py admin status
python scripts/gitctf.py admin round next
```

## 참가자 시작

로컬 실행과 `check`는 제출 전 자가검증용입니다. 공식 제출, 대회 당일 실행, 채점은 주최 측이 제공하는 대회 서버와 coordinator 기준으로 진행됩니다.
대회 서버 접속 방법과 앱 배포 절차는 `USER_DEPLOY_GUIDE.md`와 `DISCORD_NOTICE.txt`를 기준으로 합니다.

제출 순서는 **서비스 구현 → 취약점 4개 심기 → `vuln_spec.json` 작성 → 자가검증 → 대회 서버 배포 안내 확인 → `check` PASS → `push`** 입니다.
예시 서비스는 `web_service/`입니다. 현재 예시는 기획서 기반 업무 도우미 서비스이며, `vuln1`~`vuln4` 취약점 검증 흐름까지 포함합니다.

먼저 자기 서비스 폴더에서 아래 3가지를 준비합니다.

- 실제 서비스 코드
- `Dockerfile`
- `vuln_spec.json`: `vuln1`~`vuln4`의 flag 주입, 회수, 공격 검증 요청

터미널 1:

```bash
cd web_service
make run
```

터미널 2:

```bash
cd web_service
python ../scripts/gitctf.py login team1 --token <TOKEN> --coordinator http://knights.hspace.io:42000
python ../scripts/gitctf.py check
python ../scripts/gitctf.py push
```

## 제출물

서비스 repo 루트에는 최소 3가지가 있어야 합니다.

| 파일 | 역할 |
|---|---|
| `Dockerfile` | 서비스를 빌드하고 실행 |
| `vuln_spec.json` | health, flag 주입, 취약점 공격 검증 방법 선언 |
| 서비스 코드 | 실제 웹 서비스 구현 |

고정 API는 없습니다. `/health`, `/chat`을 꼭 쓸 필요도 없습니다. 실제 요청 형식은 `vuln_spec.json`에 선언하면 됩니다.

## 실제 공격은 누가 하나

사람이 라운드 중 `poc.py`를 직접 제출하지 않습니다.

1. coordinator가 공격 에이전트 컨테이너를 실행합니다.
2. 공격 에이전트가 target repo snapshot을 받습니다.
3. 공격 에이전트가 `/attack`으로 live service를 탐색합니다.
4. 공격 에이전트가 PoC 소스를 만들고 `/agent/pocs` wrapper 또는 `submit_poc_source()`로 제출합니다.
5. coordinator는 제출된 PoC를 queued 상태로 저장합니다.
6. 라운드 종료 시점에 팀 서비스 이미지를 scoring snapshot으로 고정합니다.
7. snapshot에 현재 라운드 flag를 다시 주입한 뒤 제출된 PoC를 batch 실행합니다.
8. stdout 마지막 non-empty line이 현재 flag면 점수가 반영됩니다.

PoC runner 계약을 디버깅할 때만 아래처럼 직접 확인합니다.

```bash
python ../scripts/gitctf.py check --vuln 1 --poc poc.py
```

attack/defense agent 준비와 로컬 디버그도 `scripts/gitctf.py` 안의 `agent` 명령만 사용하면 됩니다.
기본은 Python `attack_agent/main.py`, `defense_agent/main.py` 템플릿에서 시작하고, 내부 오케스트레이션은 자유롭게 바꾸면 됩니다.
OpenAI/OpenRouter 호환 클라이언트는 주입된 `OPENAI_BASE_URL` 또는 `OPENROUTER_BASE_URL`을 쓰면 coordinator의 OpenRouter wrapper를 거칩니다.
AI 모델 호출은 OpenRouter API 기반으로 동작하며, wrapper가 OpenRouter 호출과 모델 허용 여부를 검사합니다.
<span class="red-strong">대회 당일에는 허용 모델 목록에 있는 모델만 사용할 수 있으며, 목록 밖 모델은 서버가 거절합니다.</span>
처음 agent를 구현한다면 [OPENROUTER_AGENT_ENVIRONMENT.md](OPENROUTER_AGENT_ENVIRONMENT.md)의 환경변수와 예제 흐름을 먼저 확인합니다.
내부 helper인 `scripts/agent.py`는 coordinator를 알 수 있으면 `/tools/agent.py` 최신 공식본을 확인한 뒤 실행합니다.
공식 run 생성은 `RUNNER_SECRET`이 없으면 서버가 거부하며, raw git clone/fetch도 인증된 팀/방어팀만 가능합니다.
runner는 `agent_manifest.json`의 `attack`/`defense` entrypoint를 실행하므로 코드 위치를 바꿔도 manifest만 맞추면 같은 runner에서 동작합니다.
서비스 탐색과 PoC 제출은 `AGENT_RUN_TOKEN` Bearer 인증으로 `/agent/attack`, `/agent/pocs` wrapper를 호출하면 됩니다.

## 점수

| 이벤트 | 점수 |
|---|---:|
| PoC 성공 | 공격팀 `+10`, 방어팀 `-10` |
| 서비스 OK | 서비스 소유팀 `+10` |
| PoC 실패 | 변화 없음 |
| 서비스 DOWN/FAULTY | 가용성 점수 없음 |

PoC는 라운드당 `공격팀 -> 타겟팀 -> vuln_id` 기준 최대 2개까지 queued 상태로 유지됩니다. 같은 기준으로 3번째 PoC를 제출하면 가장 오래된 queued PoC가 교체되고, 성공 점수는 같은 기준으로 1회만 인정됩니다.

## 주요 폴더

| 경로 | 내용 |
|---|---|
| `coordinator/` | 라운드, flag, scoring, git push, PoC runner |
| `web_service/` | 참가자 서비스 예시 |
| `attack_agent/` | 공격 에이전트 템플릿 |
| `defense_agent/` | 방어 에이전트 템플릿 |
| `scripts/gitctf.py` | 참가자/관리자/agent 단일 CLI |
| `scripts/agent.py` | `gitctf.py agent`가 호출하는 호환용 agent helper |
| `tests/` | 핵심 흐름 테스트 |

## 더 읽기

| 문서 | 대상 |
|---|---|
| [RULEBOOK.md](RULEBOOK.md) | 참가자 규칙 |
| [AGENT_USAGE.txt](AGENT_USAGE.txt) | agent 빌드와 디버그 |
| [OPENROUTER_AGENT_ENVIRONMENT.md](OPENROUTER_AGENT_ENVIRONMENT.md) | OpenRouter wrapper 기반 agent 구현 환경 |
| [SCRIPT_USAGE.txt](SCRIPT_USAGE.txt) | 스크립트 빠른 사용법 |
| [ORGANIZER_GUIDE.md](ORGANIZER_GUIDE.md) | 관리자 운영 |
| [SERVER_AVAILABILITY_GUIDE.md](SERVER_AVAILABILITY_GUIDE.md) | 서버 가용성 점검과 요청 제한 |
| [PROJECT_GUIDE.md](PROJECT_GUIDE.md) | 처음 보는 사람용 구조 설명 |
| [DEVELOPMENT_SPEC.md](DEVELOPMENT_SPEC.md) | 내부 구현 상세 |
