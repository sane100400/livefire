# HSPACE LiveFire 서버 가용성 가이드

이 문서는 운영자가 대회 서버 배포 전후에 확인할 항목만 분리한 가이드입니다. 참가자에게는 `RULEBOOK.md`와 함께 배포해도 되지만, 시크릿 값과 내부 호스트 정보는 포함하지 않습니다.

## 운영 기준

- 공개 진입점은 gateway `:42000` 하나를 기준으로 확인합니다.
- 팀 서비스 공개 포트는 `42001`~`42006`입니다.
- coordinator health가 실패하면 라운드를 시작하지 않습니다.
- 팀 서비스가 `OK`가 아니면 해당 팀은 가용성 점수를 받지 못합니다.
- `DOWN`인 서비스는 공격 대상에서 제외됩니다.
- `FAULTY`인 서비스는 공격은 가능하지만 가용성 점수는 없습니다.

## 빠른 가용성 점검

운영 서버에서 아래 순서대로 실행합니다.

```bash
docker compose config --quiet
docker compose up -d --build
docker compose ps

curl -fsS http://localhost:42000/health
curl -fsS http://localhost:42000/status
curl -fsS http://localhost:42000/scoreboard | python3 -m json.tool
```

팀 서비스 포트가 열려 있는지 확인합니다.

```bash
for port in 42001 42002 42003 42004 42005 42006; do
  printf ":%s " "$port"
  curl -fsS "http://localhost:${port}/health" >/dev/null && echo OK || echo FAIL
done
```

전체 사전검증은 라운드 시작 전 필수로 실행합니다.

```bash
python scripts/gitctf.py admin preflight --repeat 3
```

`preflight`는 coordinator health, 팀 서비스 health, flag 주입/회수, 기본 기능 검증을 함께 확인합니다. 하나라도 실패하면 라운드를 시작하지 않는 것을 기본 정책으로 둡니다.

## 가벼운 부하 점검

행사 직전 smoke burst로 gateway와 coordinator가 짧은 동시 요청을 버티는지 봅니다. 이 테스트는 공개 운영 중에는 실행하지 않습니다.

```bash
for i in $(seq 1 50); do
  curl -fsS http://localhost:42000/health >/dev/null &
done
wait

curl -fsS http://localhost:42000/health
docker compose ps
```

팀 서비스도 같은 방식으로 각 포트별 20~30회 정도만 확인합니다. 목적은 대규모 성능 측정이 아니라, nginx/gateway/coordinator/팀 서비스가 동시에 여러 연결을 받아도 죽지 않는지 확인하는 것입니다.

## Agent 요청 제한

AI agent는 실수로 루프가 돌면 짧은 시간에 LLM, 공격 탐색, PoC 제출 요청을 많이 만들 수 있습니다. coordinator는 앱 레벨에서 인증 단위 요청 제한을 적용합니다.

Limiter key 우선순위:

1. `X-Agent-Run-Token`
2. `Authorization: Bearer <AGENT_RUN_TOKEN>`
3. `X-Team-Token`
4. `X-Admin-Secret`
5. client IP

토큰 원문은 저장하지 않고 짧은 SHA-256 해시 prefix만 limiter key로 사용합니다.

기본값:

| 설정 | 기본값 | 적용 대상 | 의도 |
|---|---:|---|---|
| `RATE_LIMIT_ATTACK_AGENT_RUNS` | `10/minute` | attack `/agent-runs`, `/student/agent-runs` | 공격 agent 재시작 루프 차단 |
| `RATE_LIMIT_DEFENSE_AGENT_RUNS` | `5/minute` | defense `/agent-runs`, `/student/agent-runs` | 방어 agent 재시작 루프 차단 |
| `RATE_LIMIT_REPO_ARCHIVE` | `6/minute` | `/agent/target-repo.tar`, `/agent-runs/{id}/target-repo.tar` | repo snapshot 반복 다운로드 제한 |
| `RATE_LIMIT_LLM` | `30/minute` | `/llm`, `/openrouter/...`, `/v1/chat/completions` | LLM 비용/지연 폭주 방지 |
| `RATE_LIMIT_ATTACK` | `20/minute` | `/attack`, `/agent/attack` | 탐색 루프 완충. 라운드 점수용 탐색 턴은 별도 `10/round` |
| `RATE_LIMIT_POC_SUBMIT` | `12/minute` | `/pocs`, `/agent/pocs` | 동일 PoC 제출 루프 차단 |
| `RATE_LIMIT_TOOLS` | `60/minute` | `/tools/*.py` | helper 다운로드 반복 제한 |

정상 agent라면 위 기본값에 걸리지 않아야 합니다. 429가 자주 보이면 agent가 불필요한 루프를 돌고 있거나 한도가 실제 운영 패턴보다 낮은 것입니다.

## 튜닝 기준

기본값은 6팀 동시 운영 기준입니다.

- 정상 agent가 429를 자주 받으면 `RATE_LIMIT_LLM`을 `45/minute`까지 올립니다.
- OpenRouter 502/timeout, coordinator CPU spike, 비용 급증이 보이면 `RATE_LIMIT_LLM`을 `20/minute`로 낮춥니다.
- `/agent/attack`은 coarse 탐색용입니다. Blind SQLi처럼 요청을 많이 보내는 풀이는 제출된 `poc.py` 안에서 수행하게 두고, 필요하면 `POC_TIMEOUT_SEC`를 45~60초로 올립니다.
- agent가 탐색 단계에서도 다수 probe를 보내야 하는 문제를 낼 때만 `MAX_ATTACKS_ROUND`와 `RATE_LIMIT_ATTACK`을 같이 올립니다.
- `/agent-runs`는 정상적으로 라운드당 한 번 생성되므로 attack `10/minute`, defense `5/minute` 이상으로 올릴 필요가 거의 없습니다.
- repo archive는 용량이 커질 수 있으므로 `RATE_LIMIT_REPO_ARCHIVE`를 보수적으로 유지합니다.

운영 중 변경하려면 `coordinator/.env`를 수정한 뒤 coordinator를 재시작합니다.

```bash
docker compose up -d --build coordinator
curl -fsS http://localhost:42000/health
```

## 장애 판단

| 증상 | 확인 | 조치 |
|---|---|---|
| `/health` 실패 | `docker compose ps`, `docker compose logs coordinator --tail=200` | coordinator/env/DB 경로 확인 후 재시작 |
| 팀 포트 실패 | `curl :4200X/health`, 해당 팀 container logs | 팀 이미지/포트/vuln_spec health 확인 |
| 사전검증 실패 | `scripts/validation_report.json` | 실패한 inject/retrieve/basic_function 수정 |
| agent 429 다발 | coordinator logs, agent logs | agent 루프 수정 또는 해당 rate limit 소폭 조정 |
| OpenRouter 오류 증가 | `/admin/audit-log`, coordinator logs | 모델/프롬프트 크기/LLM rate limit 확인 |

## 배포 전 체크리스트

- [ ] `coordinator/.env`에 운영용 `ADMIN_SECRET`, `RUNNER_SECRET`, `CHECKER_TOKEN`, 팀 토큰이 설정되어 있다.
- [ ] `OPENROUTER_API_KEY`는 coordinator에만 있고 팀 서비스/agent 소스에 하드코딩되어 있지 않다.
- [ ] `docker compose config --quiet`가 통과한다.
- [ ] `curl -fsS http://localhost:42000/health`가 성공한다.
- [ ] `python scripts/gitctf.py admin preflight --repeat 3`가 통과한다.
- [ ] `RULEBOOK.md`의 요청 제한과 실제 `.env` 값이 일치한다.
- [ ] 참가자 배포 번들을 갱신했다: `python scripts/gitctf.py admin bundle`
