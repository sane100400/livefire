#!/usr/bin/env python3
"""Build the participant-facing deployment bundle."""
from __future__ import annotations

import json
import shutil
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DEST = ROOT / "user_deploy"
DIST = ROOT / "dist"
BUNDLE_ARCHIVE = DIST / "hspace-livefire-user-deploy.tar.gz"

COPY_PATHS = [
    ".dockerignore",
    "DISCORD_NOTICE.txt",
    "DISCORD_AGENT_NOTICE.txt",
    "USER_DEPLOY_GUIDE.md",
    "RULEBOOK.md",
    "RULE_SUMMARY.txt",
    "SERVER_AVAILABILITY_GUIDE.md",
    "AGENT_USAGE.txt",
    "OPENROUTER_AGENT_ENVIRONMENT.md",
    "SCRIPT_USAGE.txt",
    "docs/pdf/agent_guide.pdf",
    "agent_manifest.json",
    "agent_sdk",
    "web_service",
    "attack_agent",
    "defense_agent",
    "scripts/agent.py",
    "scripts/gitctf.py",
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


README = """# HSPACE LiveFire A&D 일반 사용자 배포 패키지

이 폴더는 일반 사용자/참가자 배포용 파일만 모은 패키지입니다. coordinator, 운영자 시크릿, 런타임 데이터는 포함하지 않습니다.

서버 기준 주소:

- 공개 점수판 및 CLI 제출 endpoint: http://knights.hspace.io:42000
- 참가자 배포 파일: 운영진이 Discord 첨부 또는 DM으로 직접 전달합니다.

42000 포트는 점수판과 인증된 `gitctf.py` 제출 endpoint만 제공합니다. 공지, 가이드 PDF, 전체 번들은 42000에서 내려받지 않습니다.
운영진이 전달한 번들은 아래처럼 풉니다.

```bash
tar -xzf hspace-livefire-user-deploy.tar.gz
cd user_deploy
```

## 포함 파일

| 경로 | 용도 |
|---|---|
| `USER_DEPLOY_GUIDE.md` | 일반 사용자 CLI 배포 가이드 |
| `DISCORD_NOTICE.txt` | Discord 공지사항 복붙용 서버/배포 안내 |
| `DISCORD_AGENT_NOTICE.txt` | Discord 공지사항 복붙용 agent 구현 안내 |
| `docs/pdf/agent_guide.pdf` | Discord 첨부용 agent 구현 가이드 |
| `web_service/` | 자유 웹 서비스 개발용 예시 템플릿. `Dockerfile`, `main.py`, `vuln_spec.json` 예시 포함 |
| `attack_agent/` | 공격 에이전트 템플릿 |
| `defense_agent/` | 방어 에이전트 템플릿 |
| `agent_manifest.json` | runner가 attack/defense entrypoint를 찾는 호환 manifest |
| `scripts/gitctf.py` | 로그인, 서비스 검증, 제출, agent 빌드를 처리하는 단일 helper |
| `scripts/agent.py` | `gitctf.py agent`가 호출하는 호환용 agent helper |
| `scripts/validate_vulns.py` | `gitctf.py check`가 내부에서 사용하는 검증 엔진 |
| `RULE_SUMMARY.txt` | 전체 규칙 최소 요약 |
| `RULEBOOK.md` | 참가팀 규칙서 |
| `SERVER_AVAILABILITY_GUIDE.md` | 서버 가용성 점검과 agent 요청 제한 |
| `AGENT_USAGE.txt` | agent 빌드와 디버그 사용법 |
| `OPENROUTER_AGENT_ENVIRONMENT.md` | OpenRouter wrapper 기반 agent 구현 환경 가이드 |
| `SCRIPT_USAGE.txt` | 관리자/참가자 기본 스크립트 사용법 |

## 서비스 개발

각 팀은 **사전에 제공된 기획서를 바탕으로 서비스를 구현**하고, 의도된 취약점 4개를 심습니다.
고정 필수 API는 없습니다. `web_service/`는 참고용 템플릿이고, 실제 서비스 API는 `vuln_spec.json`에 맞춰 자유롭게 만들면 됩니다.
로컬 실행과 `check`는 제출 전 자가검증용입니다. 공식 제출, 대회 당일 실행, 채점은 주최 측이 제공하는 대회 서버와 coordinator 기준으로 진행됩니다.
대회 서버 접속 방법과 앱 배포 절차는 `USER_DEPLOY_GUIDE.md`를 기준으로 합니다.
제출 순서는 서비스 구현, 취약점 4개 심기, `vuln_spec.json` 작성, 자가검증, 대회 서버 배포 안내 확인, `check` PASS, `push`입니다.

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
python ../scripts/gitctf.py login team1 --token "$TEAM_TOKEN" --coordinator http://knights.hspace.io:42000
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
python scripts/gitctf.py agent build team1 --mode attack
```

## Agent 오케스트레이션

자세한 규칙은 `AGENT_USAGE.txt`를 먼저 읽고, OpenRouter wrapper 환경은 `OPENROUTER_AGENT_ENVIRONMENT.md`를 봅니다.

핵심은 아래와 같습니다.

- 오케스트레이션 방식은 자유입니다.
- 기본은 Python `attack_agent/main.py`, `defense_agent/main.py` 템플릿을 고쳐서 시작합니다.
- LangChain, AutoGen, 직접 만든 planner 등 어떤 구조든 가능합니다.
- 공식 라운드에서는 주입된 `OPENAI_BASE_URL` 또는 `OPENROUTER_BASE_URL`만 사용합니다.
- 주입된 `OPENAI_API_KEY` 또는 `OPENROUTER_API_KEY`는 실제 외부 API key가 아니라 `AGENT_RUN_TOKEN`입니다.
- 외부 AI API URL을 코드에 직접 넣지 않습니다.
- wrapper가 OpenRouter 호출과 모델 허용 여부를 검사합니다.
- 서비스 탐색과 PoC 제출은 `HSPACE_AGENT_BASE_URL`의 `/attack`, `/pocs` wrapper를 호출합니다.

```python
import os, httpx

auth = {"Authorization": "Bearer " + os.environ["OPENAI_API_KEY"]}
llm = httpx.post(
    os.environ["OPENAI_BASE_URL"] + "/chat/completions",
    headers=auth,
    json={
        "model": "openai/gpt-4o-mini",
        "messages": [{"role": "user", "content": "scan target"}],
    },
)
llm.raise_for_status()
llm_call_id = int(llm.headers["X-LLM-Call-ID"])

auth = {"Authorization": "Bearer " + os.environ["AGENT_RUN_TOKEN"]}
httpx.post(
    os.environ["HSPACE_AGENT_BASE_URL"] + "/attack",
    headers=auth,
    json={"llm_call_id": llm_call_id, "path": "/probe", "method": "POST"},
)
```

## 방어 에이전트 이미지

패키지 루트에서 빌드합니다.

```bash
python scripts/gitctf.py agent build team1 --mode defense
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


def _clear_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True)
    for child in path.iterdir():
        if child.is_dir() and not child.is_symlink():
            shutil.rmtree(child)
        else:
            child.unlink()


def main() -> int:
    _clear_directory(DEST)
    DIST.mkdir(parents=True, exist_ok=True)

    for relative in COPY_PATHS:
        _copy_path(relative)

    (DEST / "README.md").write_text(README, encoding="utf-8")
    (DEST / "bundle_manifest.json").write_text(
        json.dumps({
            "scoreboard": "http://knights.hspace.io:42000",
            "distribution": "discord_attachment_or_direct_file",
            "public_file_serving": False,
            "cli_only": True,
            "included": COPY_PATHS,
        }, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    if BUNDLE_ARCHIVE.exists():
        BUNDLE_ARCHIVE.unlink()
    shutil.make_archive(
        str(BUNDLE_ARCHIVE.with_suffix("").with_suffix("")),
        "gztar",
        root_dir=ROOT,
        base_dir=DEST.name,
    )
    print(f"Built participant bundle: {DEST}")
    print(f"Built archive: {BUNDLE_ARCHIVE}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
