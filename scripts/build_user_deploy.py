#!/usr/bin/env python3
"""Build the participant-facing deployment bundle."""
from __future__ import annotations

import json
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "user_deploy"

COPY_PATHS = [
    ".dockerignore",
    "RULEBOOK.md",
    "docs/demo",
    "agent_sdk",
    "agent_service",
    "attack_agent",
    "defense_agent",
    "scripts/gitctf.py",
    "scripts/verify.py",
    "scripts/validate_vulns.py",
]

EXCLUDE_DIRS = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
}
EXCLUDE_SUFFIXES = {".pyc", ".pyo"}


README = """# HSPACE LiveFire A&D Participant Package

이 폴더는 참가자 배포용 파일만 모은 패키지입니다. coordinator, scoreboard, 진행 문서, 시크릿 템플릿, 런타임 데이터는 포함하지 않습니다.

## 포함 파일

| 경로 | 용도 |
|---|---|
| `agent_service/` | 자유 웹 서비스 개발용 예시 템플릿. `Dockerfile`, `main.py`, `vuln_spec.json` 예시 포함 |
| `attack_agent/` | 공격 에이전트 템플릿 |
| `defense_agent/` | 방어 에이전트 템플릿 |
| `agent_sdk/` | coordinator 연동 SDK |
| `scripts/gitctf.py` | 서비스 제출 및 검증 helper |
| `scripts/verify.py` | 로컬 서비스 자가검증 |
| `scripts/validate_vulns.py` | 상세 취약점 검증 |
| `RULEBOOK.md` | 참가팀 규칙서 |

## 서비스 개발

주제는 **"쓰기 싫은 사이트 만들기"**입니다. 쓸데없고 귀찮지만 실제로 실행되는 웹 서비스를 만들고, 의도된 취약점 4개를 심습니다.
고정 필수 API는 없습니다. `agent_service/`는 참고용 템플릿이고, 실제 서비스 API는 `vuln_spec.json`에 맞춰 자유롭게 만들면 됩니다.

```bash
cd agent_service
make run
make verify
```

PoC별 검증:

```bash
python ../scripts/gitctf.py check --vuln 1 --poc poc1.py
python ../scripts/gitctf.py check --poc1 poc1.py --poc2 poc2.py --poc3 poc3.py --poc4 poc4.py
```

## 서비스 제출

```bash
python scripts/gitctf.py login teamA --token "$TEAM_TOKEN" --coordinator http://<COORDINATOR_IP>:9000
cd <서비스_폴더>
python ../scripts/gitctf.py push
```

## 공격 에이전트 이미지

패키지 루트에서 빌드합니다.

```bash
docker build -f attack_agent/Dockerfile -t and-attack-teama:latest .
```

## Agent SDK 최소 사용 예

공식 라운드에서는 실행 컨테이너에 필요한 환경변수가 주입됩니다.

```python
from agent_sdk import AgentContext

ctx = AgentContext.from_env()
repo = ctx.fetch_target_repo()
scan = ctx.llm(
    model="openai/gpt-4o-mini",
    messages=[{"role": "user", "content": "scan target"}],
    purpose="scan",
)
result = ctx.attack("payload", llm_call_id=scan["llm_call_id"])
```

## 방어 에이전트 이미지

패키지 루트에서 빌드합니다.

```bash
docker build -f defense_agent/Dockerfile -t and-defense-teama:latest .
```
"""


def _ignore(_dir: str, names: list[str]) -> set[str]:
    ignored: set[str] = set()
    for name in names:
        path = Path(name)
        if name in EXCLUDE_DIRS or path.suffix in EXCLUDE_SUFFIXES:
            ignored.add(name)
    return ignored


def _copy_path(relative: str) -> None:
    source = ROOT / relative
    target = DEST / relative
    if source.is_dir():
        shutil.copytree(source, target, ignore=_ignore)
    else:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)


def main() -> int:
    if DEST.exists():
        shutil.rmtree(DEST)
    DEST.mkdir(parents=True)

    for relative in COPY_PATHS:
        _copy_path(relative)

    (DEST / "README.md").write_text(README, encoding="utf-8")
    (DEST / "bundle_manifest.json").write_text(
        json.dumps({"included": COPY_PATHS}, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"Built participant bundle: {DEST}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
