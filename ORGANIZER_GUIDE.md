# 주최측 운영 가이드 — HSPACE AI A&D CTF

---

## 전체 타임라인 요약

| 시점 | 작업 |
|---|---|
| D-7 | 인프라 구성, Docker 설치, repo 설정 |
| D-1 | 팀 토큰 생성, `.env` 작성, 팀에게 배포 |
| D-0 20:00 | 팀 서비스 제출 마감, vuln_spec 잠금 |
| D-0 20:00–21:00 | preflight_check 실행, 미통과 팀 지원 |
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
cd coordinator
cp .env.example .env

# 무작위 토큰 생성 (Python)
python3 -c "
import secrets
print('ADMIN_SECRET=' + secrets.token_hex(24))
for t in 'ABCDEF':
    print(f'TOKEN_TEAM_{t}=' + secrets.token_hex(16))
" >> .env

# 팀 서비스 IP 채우기 (네트워크 배정 후)
vim .env
# IP_TEAM_A=192.168.1.10
# IP_TEAM_B=192.168.1.11
# ...
```

> **팀에게 배포**: 각 팀에게 `TOKEN_TEAM_X` 값만 전달. `ADMIN_SECRET`은 절대 공유 금지.

### 2-3. Docker 네트워크 + 서비스 기동

```bash
cd /opt/hackathon
docker compose up -d

# 상태 확인
docker compose ps
# coordinator가 healthy 상태인지 확인
curl http://localhost:9000/health
```

### 2-4. 팀별 git 리포 초기화

coordinator가 시작되면 `init_all_repos()`가 자동 실행된다.
수동으로 확인:

```bash
ls /opt/hackathon/repos/
# teamA/  teamB/  teamC/  teamD/  teamE/  teamF/
```

각 팀에게 배포할 git remote URL:
```
http://<코디네이터IP>:9000/git/teamA
```

---

## 3. 팀 서비스 제출 안내 (D-0 ~21:00까지)

팀에게 배포할 내용:

```
팀 ID: teamA
토큰: <TOKEN_TEAM_A 값>
git remote: http://teamA:<TOKEN>@<IP>:9000/git/teamA

# 최초 제출
cd agent_service/
git init
git remote add organizer http://teamA:<TOKEN_TEAM_A>@<IP>:9000/git/teamA
git add .
git commit -m "initial submit"
git push organizer main

# 패치 (대회 중)
git add .
git commit -m "patch vuln2"
git push organizer main
```

> credential 저장: `git config credential.helper store` → 첫 push 후 자동 저장

### 제출 전 팀 자가검증 (팀이 직접 실행)

```bash
# 서비스 로컬 실행
uvicorn main:app --port 8000 &

# 취약점 검증 (3회 반복)
python scripts/verify.py --repeat 3

# 또는 validate_vulns.py (더 상세)
python scripts/validate_vulns.py \
  --spec vuln_spec.json \
  --host localhost --port 8000 \
  --repeat 3 --checker-token validate-test-token
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

### 4-1. preflight_check 실행

```bash
cd /opt/hackathon
ADMIN_SECRET=$(grep ADMIN_SECRET coordinator/.env | cut -d= -f2) \
  python scripts/preflight_check.py \
    --coordinator http://localhost:9000 \
    --repeat 3 \
    --report /tmp/preflight_report.json
```

출력 예:
```
[1/3] Coordinator 헬스 체크: http://localhost:9000/health
  ✓ OK — round=0, active=False

[2/3] 팀 서비스 헬스 체크 (6팀)
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
| inject/retrieve 실패 | `/admin/inject` `/admin/check` 구현 확인 |
| attack 실패 | 취약점이 test_payload에 반응하는지 팀이 수정 |
| basic_function 실패 | 패치 후 기본 기능 망가진 경우 → 팀 코드 롤백 |

### 4-3. 강제 시작 (일부 팀 미준비 시)

```bash
# preflight 체크 없이 강제 시작
curl -X POST http://localhost:9000/admin/start-round \
  -H "X-Admin-Secret: $ADMIN_SECRET" \
  "?force=true"
```

---

## 5. 이벤트 진행 (21:00 → 07:00)

### 5-1. cron 등록 (라운드 자동 전환)

```bash
# advance_round.py: 30분마다 end-round → start-round 자동 실행
crontab -e
```

추가 내용:
```
0,30 21-23 * * * COORDINATOR_URL=http://localhost:9000 ADMIN_SECRET=<값> python3 /opt/hackathon/scripts/advance_round.py >> /tmp/and_round.log 2>&1
0,30 0-7 * * * COORDINATOR_URL=http://localhost:9000 ADMIN_SECRET=<값> python3 /opt/hackathon/scripts/advance_round.py >> /tmp/and_round.log 2>&1
```

또는 `.env`에 값이 있으면 스크립트가 자동으로 읽는다:
```
0,30 20-23,0-7 * * * cd /opt/hackathon && python3 scripts/advance_round.py >> /tmp/and_round.log 2>&1
```

### 5-2. 라운드 수동 조작 (cron 장애 시)

```bash
export ADMIN_SECRET=$(grep ADMIN_SECRET coordinator/.env | cut -d= -f2)

# 현재 상태 확인
curl http://localhost:9000/status | python3 -m json.tool

# 라운드 종료
curl -X POST http://localhost:9000/admin/end-round \
  -H "X-Admin-Secret: $ADMIN_SECRET" | python3 -m json.tool

# 다음 라운드 시작
curl -X POST http://localhost:9000/admin/start-round \
  -H "X-Admin-Secret: $ADMIN_SECRET" | python3 -m json.tool
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

대회 중 팀이 `git push organizer main`하면 자동으로:
1. Dockerfile 빌드 검증
2. `vuln_spec.json` 수정 시 **거부** (21:00 이후 잠금)
3. Docker 이미지 빌드 → 컨테이너 재시작
4. 현재 라운드 flag 재주입

별도 조작 불필요. 빌드 실패 시 팀 git push가 거절된다.

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
docker restart and-service-teamA
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
curl http://localhost:9000/status

# 라운드가 active=false이고 번호가 멈춰 있으면 강제 시작
curl -X POST "http://localhost:9000/admin/start-round?force=true" \
  -H "X-Admin-Secret: $ADMIN_SECRET"
```

### 부정 행위 의심

```bash
# 특정 팀의 모든 공격 기록 추출
curl "http://localhost:9000/admin/audit-log?attacker=teamA&limit=2000" \
  -H "X-Admin-Secret: $ADMIN_SECRET" > /tmp/audit_teamA.json

# flag 제출 내역 확인 (DB 직접)
sqlite3 coordinator/game_state.db \
  "SELECT * FROM flag_submissions WHERE attacker='teamA' ORDER BY ts DESC LIMIT 50;"
```

---

## 7. 이벤트 종료 (07:00)

### 7-1. 마지막 라운드 채점

```bash
# 마지막 라운드가 아직 active이면 종료
curl -X POST http://localhost:9000/admin/end-round \
  -H "X-Admin-Secret: $ADMIN_SECRET" | python3 -m json.tool
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

# 팀별 flag 탈취 집계
sqlite3 coordinator/game_state.db "
SELECT attacker, defender, vuln_id, COUNT(*) as cnt
FROM flag_submissions
WHERE valid=1
GROUP BY attacker, defender, vuln_id
ORDER BY attacker, cnt DESC;
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
├── agent_service/         팀 방어 서비스 템플릿
│   ├── main.py
│   ├── vuln_spec.json
│   └── Dockerfile
├── attack_agent/          팀 공격 에이전트 템플릿
│   ├── main.py
│   └── Dockerfile
├── scripts/
│   ├── verify.py          팀 자가검증 (신규)
│   ├── validate_vulns.py  주최측 일괄 검증
│   ├── preflight_check.py 이벤트 전 사전검증
│   └── advance_round.py   cron 라운드 전환
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
- [ ] `docker compose up -d` 및 `/health` 응답 확인
- [ ] 팀별 토큰 배포 완료
- [ ] git remote URL 배포 완료

### D-0 20:00 체크리스트
- [ ] 모든 팀 `git push` 완료 확인 (`ls /opt/hackathon/repos/teamX/`)
- [ ] 모든 팀 `vuln_specs/teamX.json` 존재 확인
- [ ] `docker compose ps`에서 팀 서비스 컨테이너 확인
- [ ] vuln_spec 잠금 (21:00 이후 git push 시 spec 수정 자동 거부됨)

### D-0 21:00 직전 체크리스트
- [ ] `python scripts/preflight_check.py --repeat 3` PASS 확인
- [ ] 스코어보드 UI 팀 화면에 표시
- [ ] cron 등록 확인 (`crontab -l`)
- [ ] 비상 연락 채널(Slack/Discord) 개설
- [ ] `/tmp/and_round.log` tail 터미널 열어놓기
