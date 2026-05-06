FROM python:3.11-slim

WORKDIR /app

COPY attack_agent/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY agent_sdk ./agent_sdk
COPY attack_agent ./attack_agent

CMD ["python", "attack_agent/main.py"]
