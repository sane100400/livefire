# 처음 보는 사람을 위한 프로젝트 가이드

이 프로젝트는 **AI 에이전트 기반 Attack & Defense 해커톤 운영 플랫폼**입니다.
참가팀은 일부러 취약한 웹 서비스를 만들고, 공격 에이전트는 다른 팀 서비스에서 flag를 탈취하는 PoC를 제출하며, 방어 에이전트는 넘겨받은 서비스를 패치합니다. `coordinator`가 이 과정을 라운드 단위로 실행, 기록, 채점합니다.

## 1분 요약

- 참가팀은 "쓰기 싫은 사이트" 주제 안에서 자유롭게 웹 서비스를 만들고 취약점 4개를 심습니다. `agent_service/`는 참고용 예시입니다.
- 운영자는 팀 서비스를 Docker 이미지로 올리고, `coordinator`를 통해 flag 주입, SLA 체크, PoC 실행, 점수 계산을 합니다.
- 공격/방어 산출물은 팀 에이전트가 `agent_sdk/`를 통해 제출해야 하며, LLM 호출 기록과 산출물 해시가 남습니다.
- 점수는 시스템이 제출된 PoC를 실행해 현재 flag 탈취를 확인하면 공격팀 `+10`, 방어팀 `-10`, 서비스가 정상 상태이면 가용성 `+10`입니다.
- 실시간 현황은 `scoreboard/` 정적 UI가 보여줍니다.

## 실행 상태를 확인하는 가장 짧은 방법

### 운영자 플랫폼

```bash
docker compose config --quiet
docker compose up -d
curl http://localhost:9000/health
curl -I http://localhost:8080/
```

정상이라면 coordinator는 다음처럼 응답합니다.

```json
{"status":"ok","round":1,"round_active":false}
```

브라우저에서 확인할 주소:

- Coordinator API: `http://localhost:9000`
- Scoreboard: `http://localhost:8080`

현재 `docker-compose.yml`에서 실제 팀 서비스 6개는 주석 처리되어 있습니다. 팀별 이미지가 준비된 뒤 `teamA-service`부터 `teamF-service`까지 주석을 해제해 운영 환경에 붙입니다.

### 예시 서비스 템플릿

터미널 1:

```bash
cd agent_service
make run
```

터미널 2:

```bash
python scripts/gitctf.py check --repo agent_service --repeat 3
```

정상이라면 `vuln1`부터 `vuln4`까지 모두 `PASS`가 나옵니다.

PoC까지 확인할 때:

```bash
python scripts/gitctf.py check --repo agent_service --poc1 poc1.py --poc2 poc2.py --poc3 poc3.py --poc4 poc4.py
```

### 단위 테스트

```bash
python -m unittest discover -s tests -v
```

이 테스트는 로테이션 규칙, PoC 채점 중복 방지, stdout 마지막 줄 flag 검증, 라운드 점수 계산, LLM gateway 호출 형태, spec 기반 검증 로직, PoC 파일 검증 로직을 확인합니다.

## 현재 로컬 검증 결과

2026-05-12 기준으로 다음을 확인했습니다.

| 항목 | 결과 |
|---|---|
| `python -m unittest discover -s tests -v` | 9개 테스트 통과 |
| `docker compose config --quiet` | 통과 |
| `curl http://localhost:9000/health` | `{"status":"ok","round":1,"round_active":false}` |
| `curl -I http://localhost:8080/` | HTTP 200 |
| `python scripts/gitctf.py check --repo agent_service --repeat 1` | `vuln1`~`vuln4` 전체 PASS |
| `python scripts/gitctf.py check --repo agent_service --poc1 ... --poc4 ...` | PoC별 flag 출력 검증 PASS |

아직 전체 행사 preflight는 완성된 팀 이미지와 `vuln_specs/teamX.json`이 필요합니다. 현재 루트의 `vuln_specs/`에는 `example.json`만 있으므로 coordinator 로그에는 `Loaded vuln specs for: []`가 뜨는 것이 자연스럽습니다.

## 큰 구조

```text
참가팀 자유 웹 서비스 Docker 이미지
        │
        ▼
target-net ───────────────┐
                          │
                          ▼
                    coordinator
                          │
      ┌───────────────────┼───────────────────┐
      ▼                   ▼                   ▼
 attack agent        defense agent        poc runner
      │                   │                   │
      ▼                   ▼                   ▼
 /attack, /pocs       git patch        flag 탈취 여부 확인
      │                   │                   │
      └───────────────────┴───────────▶ score + audit log
                                      │
                                      ▼
                                  scoreboard
```

핵심은 `coordinator`입니다. 팀 서비스에 flag를 주입하고, 에이전트 실행 기록을 만들고, LLM 호출을 프록시하며, 제출된 PoC를 라운드마다 다시 실행해서 점수를 계산합니다.

## 디렉토리별 역할

| 경로 | 역할 |
|---|---|
| `coordinator/` | 운영 서버. FastAPI API, SQLite 상태 저장, git smart HTTP, flag 관리, checker, scoring, agent runner가 들어 있습니다. |
| `agent_service/` | 자유 웹 서비스 개발용 예시 템플릿입니다. `Dockerfile`, 예시 FastAPI 앱, `vuln_spec.json`, 로컬 검증용 `Makefile`이 있습니다. |
| `attack_agent/` | 공격 에이전트 템플릿입니다. target repo snapshot을 받고, LLM으로 분석한 뒤 `/attack`과 `/pocs`를 호출합니다. |
| `defense_agent/` | 방어 에이전트 템플릿입니다. 넘겨받은 서비스를 패치하고 `Agent-Run-ID` trailer가 붙은 커밋을 만듭니다. |
| `agent_sdk/` | 에이전트가 coordinator와 안전하게 통신하기 위한 공통 SDK입니다. run 생성, LLM 호출, PoC 제출, git trailer 처리를 맡습니다. |
| `scripts/` | 운영/검증 도구입니다. `verify.py`, `preflight_check.py`, `advance_round.py`, `gitctf.py`, `build_user_deploy.py`가 핵심입니다. |
| `scoreboard/` | 정적 HTML 스코어보드입니다. nginx로 `8080`에 서빙됩니다. |
| `vuln_specs/` | 운영자가 검증할 팀별 취약점 spec 위치입니다. 실제 운영 전 `teamA.json` 같은 파일이 들어와야 합니다. |
| `user_deploy/` | 참가자에게 줄 배포 번들 생성 결과입니다. coordinator와 운영자 시크릿은 포함하지 않습니다. |
| `tests/` | 핵심 규칙과 흐름을 검증하는 Python unittest입니다. |

## 한 라운드가 도는 방식

1. coordinator가 현재 라운드 flag를 생성합니다.
2. checker가 각 팀 서비스의 `vuln_spec.json`에 선언된 요청으로 flag를 주입합니다.
3. 공격 에이전트가 target repo snapshot을 받고, coordinator `/llm` 프록시로 허용 모델을 호출합니다.
4. 공격 에이전트가 `/attack`으로 탐색하고, 재현 가능한 `poc*.py`를 `/pocs`로 제출합니다.
5. 시스템이 제출된 PoC를 격리 환경에서 실행합니다.
6. stdout의 마지막 non-empty line이 현재 라운드 flag이면 공격 성공으로 채점합니다.
7. scorer가 PoC 점수와 가용성 보너스를 합산합니다.
8. scoreboard가 최신 상태를 폴링해서 보여줍니다.

## 사람들에게 설명할 때 쓰는 말

짧게 소개할 때:

> "이건 AI 에이전트가 직접 웹 서비스를 공격하고 방어하는 CTF 운영 플랫폼입니다. 참가팀은 취약한 서비스를 만들고, 운영 서버는 flag 주입, 에이전트 실행, PoC 검증, 점수 계산을 자동화합니다. 중요한 점은 공격과 방어 결과물이 모두 에이전트 SDK와 LLM 감사 로그에 묶여서, 사람이 몰래 제출한 산출물과 구분된다는 것입니다."

조금 더 길게 소개할 때:

> "일반 CTF는 사람이 문제를 풀지만, 여기서는 팀별 공격/방어 에이전트가 문제를 풉니다. 각 팀은 취약한 웹 서비스를 제출하고, 다른 팀은 그 서비스를 방어합니다. 공격 에이전트는 coordinator를 통해 LLM을 호출하고 탐색하며, 최종 점수는 제출된 PoC를 시스템 runner가 실행해 현재 flag를 반환하는지 확인해서 계산합니다. coordinator는 요청, LLM 호출, PoC 파일 해시, 실행 결과를 기록해서 공정하게 채점합니다."

## 시연 순서

1. `docker compose ps`로 `coordinator`와 `scoreboard`가 떠 있는지 보여줍니다.
2. `curl http://localhost:9000/health`로 coordinator 상태를 보여줍니다.
3. 브라우저에서 `http://localhost:8080` 스코어보드를 엽니다.
4. `agent_service/main.py`가 자유 웹 서비스 예시일 뿐이라는 점과 예시 취약점 4개를 설명합니다.
5. `python scripts/gitctf.py check --repo agent_service --repeat 1`를 실행해 flag 주입, 탈취, 기본 기능 검증이 자동으로 도는 것을 보여줍니다.
6. `python scripts/gitctf.py check --repo agent_service --vuln 1 --poc poc1.py` 형태로 PoC가 실제 flag를 출력해야 통과하는 것을 보여줍니다.
7. `tests/test_core.py`를 열어 채점 규칙이 단위 테스트로 고정되어 있음을 보여줍니다.

## 문서를 읽는 순서

처음 보는 사람은 이 순서로 보면 됩니다.

1. `PROJECT_GUIDE.md` - 전체 그림과 실행 확인
2. `README.md` - 상세 규칙과 아키텍처
3. `RULEBOOK.md` - 참가팀 입장에서 지켜야 할 규칙
4. `ORGANIZER_GUIDE.md` - 운영자 체크리스트
5. `DEVELOPMENT_SPEC.md` - 구현 상세와 내부 계약
6. `SPEC_SLA_MONITOR.md` - SLA 모니터링 상세 설계

## 아직 행사 전 확인해야 할 것

- `coordinator/.env`에 운영용 `ADMIN_SECRET`, `TOKEN_TEAM_A`~`TOKEN_TEAM_F`, 필요 시 `OPENROUTER_API_KEY`, `RUNNER_SECRET`이 들어 있어야 합니다.
- 팀별 서비스 이미지가 빌드되어야 하고, `docker-compose.yml`의 `teamA-service`~`teamF-service`가 실제 이미지 이름으로 연결되어야 합니다.
- 팀별 `vuln_spec.json`이 `vuln_specs/teamA.json` 같은 형태로 들어와야 합니다.
- 전체 리허설에서는 `python scripts/preflight_check.py --repeat 3`를 팀 서비스가 모두 떠 있는 상태에서 실행해야 합니다.
- 공식 라운드 전에는 `RUNNER_SECRET`을 설정하고, 팀 컨테이너에 OpenRouter API key를 직접 주지 않는지 확인해야 합니다.
