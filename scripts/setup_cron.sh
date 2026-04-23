#!/bin/bash
# 대회 당일 주최측 노트북에서 실행. cron 등록 + 코디네이터 서버 시작.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
COORDINATOR_DIR="$SCRIPT_DIR/../coordinator"
LOG_FILE="/tmp/and_round.log"

echo "[1/4] 코디네이터 서버 시작..."
cd "$COORDINATOR_DIR"
if [ ! -f .env ]; then
    echo "  오류: $COORDINATOR_DIR/.env 파일 없음. .env.example 참고해서 생성하세요."
    exit 1
fi
pip install -q -r requirements.txt
nohup python app.py > /tmp/coordinator.log 2>&1 &
COORDINATOR_PID=$!
echo "  PID: $COORDINATOR_PID (로그: /tmp/coordinator.log)"

echo "  서버 기동 대기 중..."
for i in $(seq 1 10); do
    sleep 1
    if curl -sf http://localhost:9000/health > /dev/null 2>&1; then
        echo "  ✓ 서버 응답 확인"
        break
    fi
    if [ $i -eq 10 ]; then
        echo "  오류: 코디네이터 서버가 10초 내 응답하지 않음"
        exit 1
    fi
done

echo "[2/4] 사전검증 실행..."
python "$SCRIPT_DIR/preflight_check.py" --repeat 3 || {
    echo "  사전검증 실패. 위 오류를 해결 후 다시 실행하세요."
    exit 1
}

echo "[3/4] cron 등록..."
# 20:00 ~ 익일 09:00, 30분마다 실행
CRON_JOB="*/30 20-23,0-9 * * * /usr/bin/python3 $SCRIPT_DIR/advance_round.py >> $LOG_FILE 2>&1"
(crontab -l 2>/dev/null | grep -v advance_round; echo "$CRON_JOB") | crontab -
echo "  등록된 cron:"
crontab -l | grep advance_round

echo "[4/4] 라운드 1 수동 시작..."
python "$SCRIPT_DIR/advance_round.py"

echo ""
echo "완료. 스코어보드: scoreboard/index.html 브라우저로 열기"
echo "라운드 로그: tail -f $LOG_FILE"
