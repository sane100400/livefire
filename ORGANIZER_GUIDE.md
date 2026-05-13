# 주최측 운영 가이드 — HSPACE LiveFire A&D

---

## 전체 타임라인 요약

| 시점 | 작업 |
|---|---|
| D-7 | 인프라 구성, Docker 설치, repo 설정 |
| D-1 | 팀 토큰 생성, `.env` 작성, 팀에게 배포 |
| D-0 20:00 | 팀 서비스 제출 마감, vuln_spec 잠금 |
| D-0 20:00–21:00 | `gitctf.py admin preflight` 실행, 미통과 팀 지원 |
| D-0 21:00 | 라운드 1 시작 (cron 자동 또는 수동) |
| D-1 07:00 | 라운드 20 종료, 최종 스코어보드 캡처 |

---

## 1. 서버 요구사항

| 항목 | 최소 | 권장 |
|---|---|---|
| CPU | 4코어 | 8코어 |
| RAM | 8 GB | 16 GB |
| 디스크 | 40 GB | 80 GB |
| OS | Ubuntu 22.04 | Ubuntu 22.04 |
| 네트워크 | 팀 서버와 내부망 통신 가능 | 전용 스위치 |

필수 설치:
```bash
# Docker + Compose
curl -fsSL https://get.docker.com | sh
sudo apt-get install -y docker-compose-plugin git python3-pip
pip3 install httpx python-dotenv fastapi uvicorn slowapi
```

---

## 2. 초기 셋업 (D-7 ~ D-1)

### 2-1. 리포지토리 클론

```bash
git clone <이 리포> /opt/hackathon
cd /opt/hackathon
```

### 2-2. 시크릿 생성 및 `.env` 작성

```bash
cd /opt/hackathon
scripts/setup_admin_env.sh

# OpenRouter key와 팀 서비스 IP를 필요에 맞게 확인
vim coordinator/.env
```

`setup_admin_env.sh`는 7팀(teamA~teamG) 기준으로 `coordinator/.env`와
`coordinator/team_tokens.tsv`를 생성한다.

> **팀에게 배포**: 각 팀에게 `TOKEN_TEAM_X` 값만 전달. `ADMIN_SECRET`은 절대 공유 금지.
> `RUNNER_SECRET`은 coordinator의 로컬 디버그/운영 보호용이다. 참가자와 agent 컨테이너에 직접 공유하지 않는다.
> `DEFENSE_TOKEN_TEAM_X`는 공식 defense agent 컨테이너에만 주입한다. 일반 참가자용 서비스 제출 토큰과 분리한다.

### 2-3. Docker 네트워크 + 서비스 기동

```bash
cd /opt/hackathon
docker compose up -d --build

# 상태 확인
docker compose ps
# coordinator가 healthy 상태인지 확인
curl http://localhost:9000/health
```

`docker-compose.yml`은 PoC runner가 host Docker daemon에 제출 파일을 마운트할 수 있도록
`POC_HOST_DATA_DIR=${PWD}/data`를 coordinator에 넘긴다. compose 밖에서 coordinator를 직접
띄우면 이 값을 host의 `DATA_DIR` 절대경로로 맞춰야 한다.

### 2-4. 팀별 git 리포 초기화

coordinator가 시작되면 `init_all_repos()`가 자동 실행된다.
수동으로 확인:

```bash
ls /opt/hackathon/repos/
# teamA/  teamB/  teamC/  teamD/  teamE/  teamF/  teamG/
```

각 팀에게 배포할 git remote URL:
```
http://<코디네이터IP>:9000/git/teamA
```
참가자는 보통 raw git 명령 대신 `scripts/gitctf.py` 제출 helper를 사용한다.

### 2-5. 참가자 배포 번들 생성

운영자 서버 코드와 시크릿 템플릿을 제외하고, 참가자에게 필요한 템플릿과 helper만 모은다.

```bash
cd /opt/hackathon
python scripts/gitctf.py admin bundle
# user_deploy/ 폴더만 압축해서 참가자에게 전달
```

coordinator는 `/tools/gitctf.py`, `/tools/validate_vulns.py`, `/tools/agent.py`로 최신 helper를 제공한다.
참가자에게는 `gitctf.py` 하나를 기본 진입점으로 안내하고, agent 작업은 `python scripts/gitctf.py agent ...`로 실행하게 한다.
내부 helper인 `agent.py`도 실행 시 `/tools/agent.py` 최신본을 확인하고 최신본으로 재실행한다.
그래도 참가자 helper는 최종 신뢰 경계가 아니므로, push 수락 여부는 서버의 pre-receive와 PoC runner 검증을 기준으로 본다.
`git-upload-pack`도 인증이 필요하므로 참가자가 다른 팀 repo를 raw git clone으로 가져갈 수 없다.

---

## 3. 팀 서비스 제출 안내 (D-0 ~21:00까지)

팀에게 배포할 내용:

```
팀 ID: teamA
토큰: <TOKEN_TEAM_A 값>
coordinator: http://<IP>:9000

# 제출 순서
# 1. 서비스 코드 작성
# 2. vuln1~vuln4 취약점 4개 구현
# 3. vuln_spec.json 작성
# 4. 서비스 실행 후 check PASS 확인
# 5. push

# 최초 제출
cd <서비스_폴더>
python ../scripts/gitctf.py login teamA --token <TOKEN_TEAM_A> --coordinator http://<IP>:9000
python ../scripts/gitctf.py check
python ../scripts/gitctf.py push

# 패치 (대회 중)
python ../scripts/gitctf.py push --message "patch service"
```

대회 중 방어팀이 배정받은 다른 팀 repo를 push할 때는 `--repo-team`을 사용한다. 이때 커밋에는 defense agent SDK가 넣은 `Agent-Run-ID` trailer가 있어야 한다.

```bash
python scripts/gitctf.py push \
  --repo patched_teamA_service \
  --repo-team teamA \
  --team teamB \
  --token <DEFENSE_TOKEN_TEAM_B> \
  --no-commit
```

> raw git fallback: `git remote add organizer http://teamA:<TOKEN>@<IP>:9000/git/teamA && git push organizer main`

### 제출 전 팀 자가검증 (팀이 직접 실행)

```bash
# 서비스 로컬 실행. FastAPI 예시라면:
uvicorn main:app --port 8000 &

# 취약점 검증 (서비스 폴더에서 실행)
python ../scripts/gitctf.py check --repeat 3

# PoC runner 계약 디버깅이 필요할 때만 선택적으로 검증
python ../scripts/gitctf.py check --vuln 1 --poc poc.py
```

### vuln_spec 제출 방법

팀이 `vuln_spec.json`을 `vuln_specs/teamA.json`으로 저장하거나
git push 시 자동으로 복사되도록 pre-receive 훅이 설정된다.

수동 등록 (팀이 파일 전달 시):
```bash
cp <팀 제출 spec>.json /opt/hackathon/vuln_specs/teamA.json
```

---

## 4. 이벤트 직전 사전검증 (D-0 20:00–21:00)

### 4-1. 사전검증 실행

```bash
cd /opt/hackathon
python scripts/gitctf.py admin preflight \
  --coordinator http://localhost:9000 \
  --repeat 3 \
  --report /tmp/preflight_report.json
```

출력 예:
```
[1/3] Coordinator 헬스 체크: http://localhost:9000/health
  ✓ OK — round=0, active=False

[2/3] 팀 서비스 헬스 체크 (7팀)
  ✓ teamA (http://192.168.1.10:8000/health)
  ✗ teamC (http://192.168.1.12:8000/health) — 연결 오류

[3/3] 취약점 검증 (반복 3회)
  ...

사전검증 FAIL ✗
  - 팀 서비스 다운: teamC
```

### 4-2. 미통과 팀 대응

| 문제 | 조치 |
|---|---|
| 팀 서비스 DOWN | 팀에게 연락 → 서비스 재시작 → 재검증 |
| inject/retrieve 실패 | `vuln_spec.json`의 `checker.inject/retrieve` 요청과 서비스 구현 확인 |
| attack 실패 | `vuln_spec.json`의 `attack` 요청과 `test_payload` 반응 확인 |
| PoC 실패 | PoC가 `TARGET_HOST`, `TARGET_PORT`, `TARGET_TEAM`, `FLAG_ID`를 사용하고 stdout 마지막 non-empty line에 현재 flag를 출력하는지 확인 |
| basic_function 실패 | 패치 후 기본 기능 망가진 경우 → 팀 코드 롤백 |

### 4-3. 강제 시작 (일부 팀 미준비 시)

```bash
python scripts/gitctf.py admin round start --force
```

---

## 5. 이벤트 진행 (21:00 → 07:00)

### 5-1. cron 등록 (라운드 자동 전환)

```bash
# 30분마다 end-round → start-round 자동 실행
crontab -e
```

추가 내용:
```
0,30 21-23 * * * COORDINATOR_URL=http://localhost:9000 ADMIN_SECRET=<값> python3 /opt/hackathon/scripts/gitctf.py admin round next >> /tmp/and_round.log 2>&1
0,30 0-7 * * * COORDINATOR_URL=http://localhost:9000 ADMIN_SECRET=<값> python3 /opt/hackathon/scripts/gitctf.py admin round next >> /tmp/and_round.log 2>&1
```

또는 `.env`에 값이 있으면 스크립트가 자동으로 읽는다:
```
0,30 20-23,0-7 * * * cd /opt/hackathon && python3 scripts/gitctf.py admin round next >> /tmp/and_round.log 2>&1
```

### 5-2. 라운드 수동 조작 (cron 장애 시)

```bash
# 현재 상태 확인
python scripts/gitctf.py admin status

# 라운드 종료
python scripts/gitctf.py admin round end

# 다음 라운드 시작
python scripts/gitctf.py admin round start
```

### 5-3. 실시간 모니터링

```bash
# 스코어보드 API (10초 갱신)
watch -n 10 'curl -s http://localhost:9000/scoreboard | python3 -m json.tool'

# 라운드 로그
tail -f /tmp/and_round.log

# 공격 감사 로그 (특정 팀)
curl "http://localhost:9000/admin/audit-log?attacker=teamA" \
  -H "X-Admin-Secret: $ADMIN_SECRET" | python3 -m json.tool

# 스코어보드 UI
# scoreboard/index.html을 nginx 등으로 서빙하면 자동 갱신
```

### 5-4. 팀 서비스 패치 처리

대회 중 공식 defense agent 컨테이너가 SDK로 패치를 커밋하고 push하면 자동으로:
1. Dockerfile 빌드 검증
2. `vuln_spec.json` 수정 시 **거부** (21:00 이후 잠금)
3. Docker 이미지 빌드 → 컨테이너 재시작
4. 현재 라운드 flag 재주입

수동 push는 운영 모드에서 허용하지 않는다. 빌드 실패 시 defense agent의 git push가 거절된다.

---

## 6. 긴급 상황 대응

### coordinator 크래시

```bash
docker compose restart coordinator
# DB(SQLite WAL)는 크래시 안전 — 재시작 후 자동 복구
curl http://localhost:9000/health
```

### 특정 팀 서비스 강제 재시작

```bash
docker restart and-service-teama
# flag는 다음 /admin/inject 호출 시 재주입됨
# 또는 수동 재주입:
curl -X POST http://localhost:9000/admin/service-deployed \
  -H "X-Admin-Secret: $ADMIN_SECRET" \
  -H "Content-Type: application/json" \
  -d '{"team_id": "teamA", "commit": "manual"}'
```

### 라운드 로그 크래시로 건너뜀

```bash
# 현재 라운드 확인
python scripts/gitctf.py admin status

# 라운드가 active=false이고 번호가 멈춰 있으면 강제 시작
python scripts/gitctf.py admin round start --force
```

### 부정 행위 의심

```bash
# 특정 팀의 모든 공격 기록 추출
curl "http://localhost:9000/admin/audit-log?attacker=teamA&limit=2000" \
  -H "X-Admin-Secret: $ADMIN_SECRET" > /tmp/audit_teamA.json

# PoC 재실행 성공 내역 확인 (DB 직접)
sqlite3 coordinator/game_state.db \
  "SELECT * FROM poc_results WHERE attacker_team='teamA' ORDER BY created_at DESC LIMIT 50;"
```

---

## 7. 이벤트 종료 (07:00)

### 7-1. 마지막 라운드 채점

```bash
# 마지막 라운드가 아직 active이면 종료
python scripts/gitctf.py admin round end
```

### 7-2. 최종 스코어보드 캡처

```bash
curl http://localhost:9000/scoreboard | python3 -m json.tool > /tmp/final_scoreboard.json
curl http://localhost:9000/history | python3 -m json.tool > /tmp/full_history.json
```

### 7-3. 감사 리포트 생성

```bash
curl "http://localhost:9000/admin/audit-log?limit=2000" \
  -H "X-Admin-Secret: $ADMIN_SECRET" > /tmp/audit_full.json

# 팀별 PoC flag 탈취 집계
sqlite3 coordinator/game_state.db "
SELECT attacker_team, defender_team, flag_id, COUNT(*) as cnt
FROM poc_results
WHERE status='success' AND scored=1
GROUP BY attacker_team, defender_team, flag_id
ORDER BY attacker_team, cnt DESC;
"
```

### 7-4. DB 백업

```bash
cp coordinator/game_state.db /tmp/game_state_final_$(date +%Y%m%d_%H%M%S).db
```

---

## 8. 디렉토리 구조 참고

```
hackathon/
├── coordinator/           coordinator 서버
│   ├── app.py             FastAPI 메인
│   ├── flag_manager.py    flag 생성·주입·검증
│   ├── checker.py         FAUST-style checker
│   ├── db.py              SQLite WAL 레이어
│   ├── scorer.py          점수 계산
│   ├── git_handler.py     git smart HTTP
│   ├── agent_runner.py    공격 에이전트 컨테이너 실행
│   ├── config.py          전체 설정 (env vars)
│   ├── state.py           게임 상태 (DB 연동)
│   ├── .env.example       시크릿 템플릿
│   └── requirements.txt
├── vuln_specs/            팀별 취약점 명세
│   ├── example.json       작성 예시
│   └── teamA.json         (팀 제출 후 배치)
├── web_service/          자유 웹 서비스 개발용 예시 템플릿
│   ├── main.py
│   ├── vuln_spec.json
│   └── Dockerfile
├── attack_agent/          팀 공격 에이전트 템플릿
│   ├── main.py
│   └── Dockerfile
├── scripts/
│   └── gitctf.py          참가자/관리자 단일 CLI
├── scoreboard/
│   └── index.html         실시간 스코어보드 UI
├── docker-compose.yml
├── RULEBOOK.md            참가팀 배포용 규칙서
└── ORGANIZER_GUIDE.md     이 파일
```

---

## 9. 체크리스트

### D-1 체크리스트
- [ ] Docker, python3, git 설치 확인
- [ ] `coordinator/.env` 작성 완료 (모든 토큰 실제 값으로 교체)
- [ ] `docker compose up -d --build` 및 coordinator `/health` 응답 확인
- [ ] 팀별 토큰 배포 완료
- [ ] git remote URL 배포 완료

### D-0 20:00 체크리스트
- [ ] 모든 팀 `git push` 완료 확인 (`ls /opt/hackathon/repos/teamX/`)
- [ ] 모든 팀 `vuln_specs/teamX.json` 존재 확인
- [ ] `docker compose ps`에서 팀 서비스 컨테이너 확인
- [ ] vuln_spec 잠금 (21:00 이후 git push 시 spec 수정 자동 거부됨)

### D-0 21:00 직전 체크리스트
- [ ] `python scripts/gitctf.py admin preflight --repeat 3` PASS 확인
- [ ] 스코어보드 UI 팀 화면에 표시
- [ ] cron 등록 확인 (`crontab -l`)
- [ ] 비상 연락 채널(Slack/Discord) 개설
- [ ] `/tmp/and_round.log` tail 터미널 열어놓기
