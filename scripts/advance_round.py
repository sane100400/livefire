"""
cron 스크립트: 30분마다 실행.
- 라운드 진행 중이면: 채점(가용성 + 익스플로잇) → 다음 라운드 시작
- 라운드 없으면: 첫 라운드 시작
- 모든 라운드 완료면: 종료 로그만 남김

crontab 등록:
  */30 20-23,0-9 * * * /usr/bin/python3 /path/to/advance_round.py >> /tmp/and_round.log 2>&1
  (20:00 ~ 09:00 사이 30분 간격 실행)
"""
import httpx
import os
import sys
from datetime import datetime
from pathlib import Path

COORDINATOR = os.getenv("COORDINATOR_URL", "http://localhost:9000")

# .env에서 로드 (cron 환경에서는 환경변수가 없을 수 있음)
_env_file = Path(__file__).parent.parent / "coordinator" / ".env"
if _env_file.exists() and not os.getenv("ADMIN_SECRET"):
    for _line in _env_file.read_text().splitlines():
        if _line.startswith("ADMIN_SECRET="):
            os.environ["ADMIN_SECRET"] = _line.split("=", 1)[1].strip()
            break

ADMIN_SECRET = os.environ.get("ADMIN_SECRET", "")
if not ADMIN_SECRET:
    print("ERROR: ADMIN_SECRET 환경변수 없음. coordinator/.env 확인")
    sys.exit(1)

HEADERS = {"x-admin-secret": ADMIN_SECRET}

def log(msg: str):
    print(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}", flush=True)


def get_status() -> dict | None:
    try:
        r = httpx.get(f"{COORDINATOR}/status", timeout=5)
        return r.json()
    except Exception as e:
        log(f"ERROR: 코디네이터 연결 실패 - {e}")
        return None


def end_round() -> dict | None:
    try:
        r = httpx.post(f"{COORDINATOR}/admin/end-round", headers=HEADERS, timeout=30)
        if r.status_code == 200:
            return r.json()
        log(f"ERROR: end-round 실패 {r.status_code} - {r.text}")
        return None
    except Exception as e:
        log(f"ERROR: end-round 예외 - {e}")
        return None


def start_round() -> dict | None:
    try:
        r = httpx.post(f"{COORDINATOR}/admin/start-round", headers=HEADERS, timeout=10)
        if r.status_code == 200:
            return r.json()
        if r.status_code == 400 and "완료" in r.text:
            log("모든 라운드 완료. 대회 종료.")
            return None
        log(f"ERROR: start-round 실패 {r.status_code} - {r.text}")
        return None
    except Exception as e:
        log(f"ERROR: start-round 예외 - {e}")
        return None


def main():
    status = get_status()
    if status is None:
        sys.exit(1)

    # 진행 중인 라운드 → 채점 후 다음 라운드
    if status.get("round_active"):
        log(f"라운드 {status['round']} 채점 시작...")
        summary = end_round()
        if summary is None:
            sys.exit(1)

        log(f"라운드 {summary['round']} 채점 완료")
        log(f"  가용성: {summary['availability']}")
        log(f"  익스플로잇: {summary['exploits']}")
        log(f"  점수 변동: {summary['score_changes']}")
        log(f"  현재 점수: {summary['scores_after']}")

        result = start_round()
        if result:
            log(f"→ {result['message']}")

    # 라운드 없음 → 첫 시작 또는 대기
    else:
        current = status.get("round", 0)
        total = status.get("total_rounds", 22)
        if current >= total:
            log("모든 라운드 완료. 추가 실행 없음.")
            return
        result = start_round()
        if result:
            log(f"→ {result['message']}")


if __name__ == "__main__":
    main()
