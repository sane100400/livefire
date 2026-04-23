FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# flag는 /admin/inject 엔드포인트로 런타임에 주입된다 (main.py 참고).
# 시작 시 flags.env가 있으면 env var로 선로드 (선택적 보조 수단).
CMD ["sh", "-c", "if [ -f /app/flags.env ]; then export $(grep -v '^#' /app/flags.env | xargs); fi; exec uvicorn main:app --host 0.0.0.0 --port 8000"]

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')"
