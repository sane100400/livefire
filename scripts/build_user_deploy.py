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
    "RULE_SUMMARY.txt",
    "AGENT_USAGE.txt",
    "SCRIPT_USAGE.txt",
    "agent_manifest.json",
    "docs/demo",
    "agent_sdk",
    "web_service",
    "attack_agent",
    "defense_agent",
    "scripts/agent.py",
    "scripts/gitctf.py",
    "scripts/setup_admin_env.sh",
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
| `web_service/` | 자유 웹 서비스 개발용 예시 템플릿. `Dockerfile`, `main.py`, `vuln_spec.json` 예시 포함 |
| `attack_agent/` | 공격 에이전트 템플릿 |
| `defense_agent/` | 방어 에이전트 템플릿 |
| `agent_sdk/` | coordinator 연동 SDK |
| `agent_manifest.json` | runner가 attack/defense entrypoint를 찾는 호환 manifest |
| `scripts/gitctf.py` | 로그인, 서비스 검증, 제출, agent 빌드를 처리하는 단일 helper |
| `scripts/agent.py` | `gitctf.py agent`가 호출하는 호환용 agent helper |
| `scripts/setup_admin_env.sh` | 운영자가 7팀용 `.env`와 토큰 표를 만드는 helper |
| `scripts/validate_vulns.py` | `gitctf.py check`가 내부에서 사용하는 검증 엔진 |
| `RULE_SUMMARY.txt` | 전체 규칙 최소 요약 |
| `RULEBOOK.md` | 참가팀 규칙서 |
| `AGENT_USAGE.txt` | agent 빌드와 디버그 사용법 |
| `SCRIPT_USAGE.txt` | 관리자/참가자 기본 스크립트 사용법 |

## 서비스 개발

주제는 **"쓰기 싫은 사이트 만들기"**입니다. 쓸데없고 귀찮지만 실제로 실행되는 웹 서비스를 만들고, 의도된 취약점 4개를 심습니다.
고정 필수 API는 없습니다. `web_service/`는 참고용 템플릿이고, 실제 서비스 API는 `vuln_spec.json`에 맞춰 자유롭게 만들면 됩니다.
제출 순서는 서비스 구현, 취약점 4개 심기, `vuln_spec.json` 작성, 서비스 실행, `check` PASS, `push`입니다.

터미널 1:

```bash
cd web_service
make run
```

터미널 2:

```bash
cd web_service
make check
```

## 서비스 제출

```bash
cd <서비스_폴더>
python ../scripts/gitctf.py login teamA --token "$TEAM_TOKEN" --coordinator http://<COORDINATOR_IP>:9000
python ../scripts/gitctf.py check
python ../scripts/gitctf.py push
```

`gitctf.py`는 실행 시 coordinator에서 최신 공식 helper를 확인하고 다른 버전이면 최신본으로 재실행합니다.
최종 제출 판정은 coordinator 서버 검증을 기준으로 합니다.
`gitctf.py agent`가 내부적으로 호출하는 `agent.py`도 coordinator 주소를 알 수 있으면 `/tools/agent.py` 최신 공식본을 확인한 뒤 실행합니다.
공식 라운드의 agent run 생성은 운영자가 가진 `RUNNER_SECRET` 없이는 서버가 거부합니다.
코드 구조를 바꾸면 `agent_manifest.json`의 `attack.path` 또는 `defense.path`만 맞추면 runner가 같은 방식으로 실행합니다.

## 공격 에이전트 이미지

패키지 루트에서 빌드합니다.

```bash
python scripts/gitctf.py agent build teamA --mode attack
```

## Agent SDK 최소 사용 예

공식 라운드에서는 실행 컨테이너에 필요한 환경변수가 주입됩니다.
참가자 로컬에서 직접 만든 run은 점수 산출물로 인정되지 않습니다.
agent 오케스트레이션은 자유입니다. OpenAI/OpenRouter 호환 client는 주입된
`OPENAI_BASE_URL`/`OPENAI_API_KEY`를 그대로 쓰면 coordinator wrapper를 거칩니다.
서비스 탐색과 PoC 제출은 `HSPACE_AGENT_BASE_URL`의 `/attack`, `/pocs` wrapper를 호출하면 됩니다.

```python
import os, httpx

auth = {"Authorization": "Bearer " + os.environ["OPENAI_API_KEY"]}
httpx.post(
    os.environ["OPENAI_BASE_URL"] + "/chat/completions",
    headers=auth,
    json={
        "model": "openai/gpt-4o-mini",
        "messages": [{"role": "user", "content": "scan target"}],
    },
)

auth = {"Authorization": "Bearer " + os.environ["AGENT_RUN_TOKEN"]}
httpx.post(os.environ["HSPACE_AGENT_BASE_URL"] + "/attack", headers=auth, json={"payload": "test"})
```

## 방어 에이전트 이미지

패키지 루트에서 빌드합니다.

```bash
python scripts/gitctf.py agent build teamA --mode defense
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
