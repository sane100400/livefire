FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*

COPY defense_agent/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY agent_sdk ./agent_sdk
COPY defense_agent ./defense_agent

CMD ["python", "defense_agent/main.py"]
