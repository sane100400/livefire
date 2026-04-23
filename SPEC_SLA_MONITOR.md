# SLA 모니터 명세 (SPEC_SLA_MONITOR)

> 상태: 명세 완료 / 구현 대기  
> 관련 파일: `coordinator/checker.py`, `coordinator/db.py`, `coordinator/app.py`

---

## 1. 현재 구현의 한계

| 문제 | 위치 | 영향 |
|---|---|---|
| 라운드 시작 시 **1회만** 체크 | `app.py:start_round()` | 라운드 중 DOWN 서비스에 계속 공격 허용 |
| 라운드 종료 시 `check_availability()`가 **health만** 체크 | `scorer.py:check_availability()` | FAULTY 서비스도 가용성 보너스 받을 수 있음 |
| `service_status` 테이블에 **현재 상태만** 저장 (히스토리 없음) | `db.py` | 라운드 중 상태 변화 추적 불가, 분쟁 해결 불가 |
| 공격 게이팅이 **최신화되지 않은 캐시** 기반 | `app.py:attack()` | 라운드 시작 후 DOWN된 서비스 공격 허용 |

---

## 2. 설계 원칙

1. **공정성**: 같은 라운드 내 UP/DOWN을 반복하는 서비스도 측정 시점 기준으로 일관되게 채점
2. **낮은 오탐율**: 일시적 네트워크 지연으로 FAULTY/DOWN 오판 방지 → 2회 연속 실패 시 상태 강등
3. **빠른 DOWN 감지**: 공격 차단은 즉각, 보너스 회수는 신중 → 비대칭 hysteresis
4. **감사 가능성**: 모든 체크 결과를 append-only 테이블에 기록 → 사후 분쟁 해결
5. **가용성 보너스 비례 지급**: 라운드 내 OK 비율로 계산 → 30분 중 20분만 OK여도 ~6.7점

---

## 3. 상태 머신

```
                 health 실패 (즉시)
    ┌─────────────────────────────────────────────────────┐
    ▼                                                     │
  DOWN ──────── health 성공 + 전체 체크 통과 ──────────▶ OK
    ▲                                                     │
    │           health 실패 (즉시)                         │ inject/retrieve/
    │         ┌──────────────────────────────────────┐    │ basic 중 실패
    │         │                                      │    ▼
    └─────────┘                                   FAULTY
                                                      │
                                              전체 체크 통과 (즉시)
                                                      │
                                                      ▼
                                                     OK
```

### 상태 정의

| 상태 | 정의 | 가용성 보너스 | 공격 허용 | 방어 패널티 |
|---|---|---|---|---|
| **OK** | health ✓ + inject ✓ + retrieve ✓ + basic_func ✓ | 체크 시점 기여 | ✓ | ✓ |
| **FAULTY** | health ✓ + 나머지 중 하나 이상 실패 | 기여 없음 | ✓ | ✓ |
| **DOWN** | health ✗ (무응답 또는 non-200) | 기여 없음 | ✗ | **✗** |
| **UNKNOWN** | 라운드 미시작 또는 첫 체크 전 | 기여 없음 | ✗ | ✗ |

### Hysteresis 규칙 (오탐 방지)

```
DOWN 강등: OK/FAULTY → DOWN     → 즉시 (공격 차단 우선)
FAULTY 강등: OK → FAULTY        → 즉시
OK 복구: DOWN/FAULTY → OK       → 2회 연속 OK 체크 필요
```

> **비대칭 이유**: 공격 중단(DOWN 강등)은 즉시 해야 공격자 혼란을 줄이고,  
> 가용성 보너스 회복(OK 복구)은 신중하게 해야 "잠깐 살아났다 죽기" 어뷰징 방지.

---

## 4. 체크 주기 및 타이밍

### 라운드당 체크 횟수

라운드 = 30분. 체크 간격 = **10분** → 라운드당 **3회** 체크 (T+0, T+10, T+20).

```
라운드 시작                                             라운드 종료
    │                                                       │
    T+0    ──── 10분 ────  T+10   ──── 10분 ────  T+20     │  (가용성 보너스 집계)
  체크 #0                체크 #1                 체크 #2
(flag 주입 포함)        (재주입 포함)            (재주입 포함)
```

> **체크 시작 타이밍**: T+0은 라운드 시작 직후, T+10은 10분 후. 정확한 시각은 DB의  
> `round_start_ts` 기준. cron과 독립적으로 coordinator 내부 asyncio task가 관리.

### 체크 절차 (4단계)

```
단계              타임아웃    실패 시 상태
───────────────────────────────────────────────────────
1. GET /health      5초       → DOWN (즉시, 이후 단계 생략)
2. POST /admin/inject  10초   → FAULTY (이후 단계 계속)
3. GET /admin/check    10초   → FAULTY (이후 단계 계속)
4. POST /chat (basic)  15초   → FAULTY
───────────────────────────────────────────────────────
모두 통과                     → OK
```

**취약점별 독립 판정**: 3개 취약점 중 하나만 inject 실패 → FAULTY. 나머지 두 취약점이 공격 가능해도 서비스 전체가 FAULTY.

**flag 재주입**: T+10, T+20 체크에서도 inject 단계에 현재 라운드 flag를 다시 주입.  
이유: 팀이 서비스를 재시작(git push)하면 메모리 상태가 초기화될 수 있으므로.

---

## 5. 가용성 보너스 계산

### 현행 방식 (문제 있음)

```python
# scorer.py:compute_round_scores() — 라운드 종료 시 현재 service_status만 봄
if availability.get(team, False):   # ← check_availability()는 health만 체크
    status = service_statuses.get(team, "UNKNOWN")
    if status == "OK":
        score_changes[team] += availability_bonus  # 10점 전부 or 0점
```

### 개선된 방식: 체크 결과 기반 비례 지급

```
가용성 보너스 = AVAILABILITY_BONUS × (라운드 내 OK 체크 수 / 전체 체크 수)
             = 10 × (ok_checks / total_checks)
             → 반올림하여 정수 포인트
```

예시:
| 체크 #0 | 체크 #1 | 체크 #2 | 보너스 |
|---|---|---|---|
| OK | OK | OK | **10점** |
| OK | OK | DOWN | **7점** (6.67 반올림) |
| OK | FAULTY | OK | **7점** |
| DOWN | DOWN | OK | **3점** |
| DOWN | DOWN | DOWN | **0점** |
| FAULTY | FAULTY | FAULTY | **0점** |

> FAULTY는 0점 기여. DOWN은 공격도 못 받으므로 패널티 없음 + 보너스도 없음.

### 계산 로직 위치

`scorer.py:compute_round_scores()` 에서:
```python
# checker_log에서 해당 라운드 각 팀의 OK 체크 수 집계
ok_counts = db.get_ok_check_counts(round_num)   # {team_id: ok_count}
total_checks = db.get_total_check_counts(round_num)  # {team_id: total}

for team in team_ids:
    ok = ok_counts.get(team, 0)
    total = total_checks.get(team, 1)
    bonus = round(AVAILABILITY_BONUS * ok / total)
    if bonus > 0:
        score_changes[team] += bonus
```

---

## 6. 공격 게이팅

### 현행

```python
# app.py:attack()
statuses = db.get_service_statuses()
if statuses.get(req.target_team, "UNKNOWN") == "DOWN":
    raise HTTPException(503, ...)
```

`service_status` 테이블은 마지막 체크 결과만 저장 → 체크 간격 사이에 DOWN돼도 DB가 갱신 안 되면 공격 허용.

### 개선된 게이팅

```python
# 캐시 없이 DB에서 직접 조회 (체크 간격 중 최신 상태 반영)
# service_status 테이블은 checker가 실행될 때마다 즉시 업데이트됨
# → 별도 캐시 불필요 (SQLite 읽기는 빠름)

status = db.get_service_status(req.target_team)   # 단일 팀 조회
if status in ("DOWN", "UNKNOWN"):
    raise HTTPException(503, f"타겟 서비스({req.target_team}) {status} — 공격 불가")
```

**FAULTY 서비스는 공격 허용**: FAULTY = health는 살아있음. 공격 에이전트가 /chat에 직접 접근하는 게 아니라 coordinator가 프록시하므로, FAULTY 서비스도 /chat 응답은 가능.

---

## 7. DB 스키마 변경

### 추가: `checker_log` 테이블

```sql
CREATE TABLE IF NOT EXISTS checker_log (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    ts           TEXT NOT NULL,          -- ISO8601 UTC
    round_num    INTEGER NOT NULL,
    check_idx    INTEGER NOT NULL,       -- 0=T+0, 1=T+10, 2=T+20
    team_id      TEXT NOT NULL,
    status       TEXT NOT NULL,          -- OK / FAULTY / DOWN
    health_ok    INTEGER NOT NULL,       -- 0/1
    inject_ok    INTEGER NOT NULL,       -- 0/1 (취약점 전체 AND)
    retrieve_ok  INTEGER NOT NULL,       -- 0/1
    basic_ok     INTEGER NOT NULL,       -- 0/1
    detail       TEXT                    -- 실패 원인 상세
);

CREATE INDEX IF NOT EXISTS idx_checker_log_round ON checker_log(round_num, team_id);
```

### 변경: `service_status` 테이블

```sql
-- 기존 컬럼 유지 + consecutive_ok 추가 (hysteresis 계산용)
ALTER TABLE service_status ADD COLUMN consecutive_ok INTEGER NOT NULL DEFAULT 0;
-- consecutive_ok: OK 체크 연속 횟수. OK 복구 조건(≥2)에 사용.
```

### 추가 함수 (`db.py`)

```python
def append_checker_log(
    round_num: int, check_idx: int, team_id: str,
    status: str, health_ok: bool, inject_ok: bool,
    retrieve_ok: bool, basic_ok: bool, detail: str
) -> None: ...

def get_ok_check_counts(round_num: int) -> dict[str, int]:
    """팀별 OK 체크 횟수 반환. {team_id: ok_count}"""
    ...

def get_total_check_counts(round_num: int) -> dict[str, int]:
    """팀별 전체 체크 횟수 반환."""
    ...

def get_checker_log(
    round_num: int | None = None,
    team_id: str | None = None,
    limit: int = 200,
) -> list[dict]: ...

def get_service_status(team_id: str) -> str:
    """단일 팀의 현재 상태 반환. 없으면 'UNKNOWN'."""
    ...
```

---

## 8. 백그라운드 체크 태스크

### 구현 위치: `coordinator/checker.py` + `coordinator/app.py`

```python
# checker.py에 추가
import asyncio

CHECK_INTERVAL_MINUTES = 10
RECOVERY_CONSECUTIVE_REQUIRED = 2  # OK 복구에 연속 성공 필요 횟수


async def periodic_checker_loop(
    teams: dict,
    vuln_specs_ref: dict,       # mutable reference (라운드 중 갱신 가능)
    get_meta_fn,                # db.get_meta 함수 참조
    checker_token: str,
):
    """
    라운드 활성 중 10분마다 전 팀 SLA 체크.
    coordinator lifespan에서 asyncio.create_task()로 실행.
    """
    check_idx = 0
    while True:
        await asyncio.sleep(CHECK_INTERVAL_MINUTES * 60)

        meta = get_meta_fn()
        if not meta.round_active:
            check_idx = 0
            continue

        check_idx += 1
        round_num = meta.current_round

        # 현재 라운드 flag 조회 (재주입용)
        flags_in_db = db.get_flags_for_round(round_num)
        round_flags_by_team = _group_flags_by_team(flags_in_db)

        results = await run_all_checkers(
            teams, vuln_specs_ref, round_flags_by_team, checker_token,
        )

        for team_id, result in results.items():
            _apply_hysteresis(team_id, result.status)
            db.append_checker_log(
                round_num=round_num,
                check_idx=check_idx,
                team_id=team_id,
                status=result.status,
                health_ok=result.health_ok,
                inject_ok=result.inject_ok,
                retrieve_ok=result.retrieve_ok,
                basic_ok=result.basic_func_ok,
                detail=result.detail,
            )


def _apply_hysteresis(team_id: str, new_status: str) -> None:
    """
    hysteresis 규칙 적용 후 service_status 업데이트.

    - DOWN: 즉시 강등
    - FAULTY: 즉시 강등
    - OK: consecutive_ok가 RECOVERY_CONSECUTIVE_REQUIRED 이상일 때 OK로 상향
    """
    row = db.get_service_status_row(team_id)  # {status, consecutive_ok}
    current = row["status"] if row else "UNKNOWN"
    consec = row["consecutive_ok"] if row else 0

    if new_status == "DOWN":
        db.set_service_status(team_id, "DOWN", consecutive_ok=0)
    elif new_status == "FAULTY":
        db.set_service_status(team_id, "FAULTY", consecutive_ok=0)
    elif new_status == "OK":
        new_consec = consec + 1
        if current != "OK" and new_consec < RECOVERY_CONSECUTIVE_REQUIRED:
            # 아직 회복 기준 미달 — FAULTY/DOWN 유지
            db.set_service_status(team_id, current, consecutive_ok=new_consec)
        else:
            db.set_service_status(team_id, "OK", consecutive_ok=new_consec)
```

### `app.py` 수정 (lifespan)

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    state.load(DB_PATH)
    vuln_specs.update(load_vuln_specs(VULN_SPEC_DIR))
    init_all_repos(list(TEAMS.keys()))

    # 백그라운드 SLA 모니터 시작
    checker_task = asyncio.create_task(
        chk.periodic_checker_loop(
            TEAMS, vuln_specs, db.get_meta, CHECKER_TOKEN
        )
    )

    yield

    checker_task.cancel()
    try:
        await checker_task
    except asyncio.CancelledError:
        pass
```

---

## 9. API 변경

### 신규 엔드포인트

```
GET /admin/checker-log
  Query params: round_num, team_id, limit (기본 200)
  Auth: X-Admin-Secret
  Response: {
    "entries": [
      {
        "id": 42,
        "ts": "2026-04-23T21:10:00Z",
        "round_num": 1,
        "check_idx": 1,
        "team_id": "teamA",
        "status": "OK",
        "health_ok": true,
        "inject_ok": true,
        "retrieve_ok": true,
        "basic_ok": true,
        "detail": ""
      }, ...
    ]
  }

GET /admin/availability-summary?round_num=1
  Auth: X-Admin-Secret
  Response: {
    "round": 1,
    "teams": {
      "teamA": {
        "ok_checks": 3,
        "total_checks": 3,
        "availability_pct": 100.0,
        "projected_bonus": 10
      },
      "teamB": {
        "ok_checks": 1,
        "total_checks": 3,
        "availability_pct": 33.3,
        "projected_bonus": 3
      }
    }
  }
```

### 변경: `/scoreboard` 응답

```json
{
  "scores": [
    {
      "team_id": "teamA",
      "service_status": "OK",
      "service_status_since": "2026-04-23T21:10:00Z",
      "availability_this_round": {
        "ok_checks": 2,
        "total_checks": 2,
        "projected_bonus": 10
      }
    }
  ]
}
```

### 변경: `/admin/end-round` 로직

```python
# 기존: check_availability() (health만)
# 변경: checker_log 집계로 가용성 보너스 계산
ok_counts = db.get_ok_check_counts(round_num)
total_counts = db.get_total_check_counts(round_num)

# compute_round_scores()에 전달
round_result = compute_round_scores(
    ...,
    ok_check_counts=ok_counts,
    total_check_counts=total_counts,
)
```

---

## 10. 에지 케이스

| 상황 | 처리 방식 |
|---|---|
| 라운드 시작 직후 첫 체크 전 공격 | 라운드 시작 체크(T+0)가 완료돼야 공격 허용. `UNKNOWN` 상태 = 공격 차단 |
| 체크 도중 coordinator 재시작 | `asyncio.create_task`가 재생성됨. `checker_log`에서 `check_idx` 최댓값 조회해 재개 |
| 팀이 git push로 재배포 | `handle_service_deployed()` 호출 시 즉시 단발 체크 실행 → 상태 갱신 (체크 주기와 독립) |
| 6팀 동시 체크 시간 | 팀당 최대 40초(5+10+10+15) × 6팀 = 순차 4분. asyncio 병렬화 시 40초 이내 |
| `checker_token` 불일치 | inject 실패 → FAULTY. 팀이 CHECKER_TOKEN을 잘못 설정한 경우 |
| 네트워크 파티션 (coordinator↔팀) | health 타임아웃 5초 → DOWN. 재연결되면 다음 체크에서 상태 복구 |
| 체크 중 라운드 종료 | 체크 완료 후 `round_active` 재확인. 비활성이면 checker_log 저장 안 함 |

---

## 11. 구현 우선순위 및 의존성

```
① db.py
   - checker_log 테이블 추가
   - service_status에 consecutive_ok 컬럼 추가
   - append_checker_log(), get_ok_check_counts() 등 함수 추가

② checker.py
   - _apply_hysteresis() 추가
   - periodic_checker_loop() 추가
   - run_all_checkers()에 check_idx 파라미터 추가

③ scorer.py
   - compute_round_scores()에 ok/total 체크 카운트 파라미터 추가
   - 비례 보너스 계산 로직 교체

④ app.py
   - lifespan에 asyncio.create_task() 추가
   - attack()에서 get_service_status() 단건 조회로 변경
   - end_round()에서 checker_log 집계 로직 추가
   - /admin/checker-log, /admin/availability-summary 엔드포인트 추가

⑤ scoreboard/index.html
   - SLA 상태 배지 추가
   - 이번 라운드 projected_bonus 표시
```

---

## 12. git 인증 방식 검토 노트

> git push 기반 팀 서비스 제출에 HTTP Basic Auth(토큰)를 추가하는 방식이  
> 복잡해질 수 있다는 우려가 있음. 아래 두 가지 대안을 비교.

### 현행 (git smart HTTP, 인증 없음)

- 장점: 팀이 git 워크플로우 그대로 사용 가능
- 단점: 누구나 어느 팀 repo에 push 가능 → 팀 간 서비스 덮어쓰기 위험

### 대안 A: HTTP Basic Auth 추가 (git credential)

```bash
git remote add organizer http://teamA:<TOKEN>@coordinator:9000/git/teamA
git push organizer main
```

- `git_handler.py`에서 `Authorization: Basic base64(teamA:<TOKEN>)` 검증
- 팀 토큰(`TEAM_TOKENS`) 재사용 가능
- 단점: 팀이 credential 저장을 별도로 설정해야 함

### 대안 B: 단순 ZIP 업로드 (HTTP multipart)

```
POST /admin/submit-service
Header: X-Team-Token: <팀 토큰>
Body: multipart/form-data, file=service.zip
```

- git 불필요, 팀이 `zip -r service.zip ./ && curl ...` 한 줄로 제출
- 서버가 ZIP을 해제해 Docker 빌드
- 단점: git 히스토리 없음, 패치 추적 어려움

### 대안 C: SSH 키 기반 git

- 팀별 SSH 키 등록 → `authorized_keys` 관리
- 가장 표준적이지만 사전 키 배포 절차 필요

### 권장

이벤트 규모(6팀, 단일 서버)에서는 **대안 A**(HTTP Basic Auth)가 최소 변경으로 인증 추가 가능.  
구현 포인트: `git_handler.py`의 `git_service()` 핸들러에서 `request.headers.get("Authorization")` 파싱.

```python
import base64

def _verify_git_auth(team_id: str, auth_header: str | None) -> bool:
    if not auth_header or not auth_header.startswith("Basic "):
        return False
    decoded = base64.b64decode(auth_header[6:]).decode()
    user, _, token = decoded.partition(":")
    expected = TEAM_TOKENS.get(team_id, "")
    return user == team_id and token == expected and expected != ""
```
