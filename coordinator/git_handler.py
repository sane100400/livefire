"""
Git Smart HTTP 핸들러 + pre/post-receive 훅 로직.

팀은 서비스 코드를 git push로 제출/패치한다:
  git remote add organizer http://teamA:<TEAM_TOKEN>@coordinator:9000/git/teamA
  git push organizer main

인증: HTTP Basic Auth — username=team_id, password=TEAM_TOKEN
  - git-receive-pack (push): 팀 자신의 토큰만 허용
  - git-upload-pack (clone/fetch): 인증 필요 없음 (공개 읽기)

FastAPI에 /git/{team_id}/* 로 마운트.

pre-receive 로직 (push 수신 시):
  1. Dockerfile 빌드 테스트 (docker build --no-cache)
  2. 대회 시작(round_active) 후 vuln_spec.json 변경 시 거부

post-receive 로직 (push 수락 후):
  1. docker build 최종 빌드
  2. 기존 컨테이너 중지
  3. 새 컨테이너 실행 (SLA 타이머 시작)
  4. 현재 라운드 flag 재주입

Git bare repo 위치: REPOS_DIR/{team_id}.git
  기본: hackathon/repos/
"""
import asyncio
import base64
import hashlib
import json
import logging
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Header, Request, Response

import db
import flag_manager as fm

logger = logging.getLogger(__name__)

REPOS_DIR = Path(os.getenv("REPOS_DIR", Path(__file__).parent.parent / "repos"))
CHECKER_TOKEN = os.getenv("CHECKER_TOKEN", "checker-token-changeme")

# 팀별 target-net 내부 IP + 호스트 외부 노출 포트
# docker-compose.yml의 static IP / port 배정과 반드시 일치해야 한다.
_TEAM_NET = {
    "teamA": {"ip": "172.21.0.10", "host_port": 8001},
    "teamB": {"ip": "172.21.0.11", "host_port": 8002},
    "teamC": {"ip": "172.21.0.12", "host_port": 8003},
    "teamD": {"ip": "172.21.0.13", "host_port": 8004},
    "teamE": {"ip": "172.21.0.14", "host_port": 8005},
    "teamF": {"ip": "172.21.0.15", "host_port": 8006},
}

router = APIRouter(prefix="/git")


# ── 인증 헬퍼 ─────────────────────────────────────────────────────────

def _require_push_auth(team_id: str, authorization: str | None) -> None:
    """
    git push(git-receive-pack) 전용 인증.

    HTTP Basic Auth: username=team_id, password=TEAM_TOKEN
    실패 시 401 + WWW-Authenticate 헤더 반환 (git 클라이언트가 credential 재요청)
    """
    from config import TEAM_TOKENS

    _UNAUTHORIZED = HTTPException(
        status_code=401,
        detail="Git push 인증 실패",
        headers={"WWW-Authenticate": f'Basic realm="HSPACE CTF git — {team_id}"'},
    )

    if not authorization or not authorization.startswith("Basic "):
        raise _UNAUTHORIZED

    try:
        decoded = base64.b64decode(authorization[6:]).decode("utf-8")
    except Exception:
        raise _UNAUTHORIZED

    username, _, password = decoded.partition(":")
    expected_token = TEAM_TOKENS.get(team_id, "")

    if not expected_token or username != team_id or password != expected_token:
        raise _UNAUTHORIZED


# ── bare repo 초기화 ───────────────────────────────────────────────────

def init_team_repo(team_id: str) -> Path:
    """팀 bare repo가 없으면 생성."""
    repo_path = REPOS_DIR / f"{team_id}.git"
    REPOS_DIR.mkdir(parents=True, exist_ok=True)
    if not repo_path.exists():
        subprocess.run(["git", "init", "--bare", str(repo_path)], check=True)
        _install_hooks(repo_path, team_id)
        logger.info("Bare repo 생성: %s", repo_path)
    return repo_path


def init_all_repos(team_ids: list[str]) -> None:
    for tid in team_ids:
        init_team_repo(tid)


def _install_hooks(repo_path: Path, team_id: str) -> None:
    """pre-receive / post-receive 훅 스크립트 설치."""
    hooks_dir = repo_path / "hooks"
    net_cfg = _TEAM_NET.get(team_id, {"ip": "0.0.0.0", "host_port": 8000})
    team_ip = net_cfg["ip"]
    host_port = net_cfg["host_port"]

    # pre-receive: Dockerfile 빌드 검증 + vuln_spec 잠금
    pre_receive = hooks_dir / "pre-receive"
    pre_receive.write_text(f"""#!/bin/bash
# pre-receive hook for team {team_id}
TEAM_ID="{team_id}"
COORDINATOR_URL="${{COORDINATOR_URL:-http://localhost:9000}}"

while read oldrev newrev refname; do
    # vuln_spec.json 변경 감지
    if git diff --name-only "$oldrev" "$newrev" 2>/dev/null | grep -q "vuln_spec.json"; then
        # 라운드 진행 중이면 거부
        STATUS=$(curl -sf "$COORDINATOR_URL/status" 2>/dev/null)
        ACTIVE=$(echo "$STATUS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('round_active',False))" 2>/dev/null)
        if [ "$ACTIVE" = "True" ]; then
            echo "ERROR: 대회 진행 중에는 vuln_spec.json 변경 불가"
            exit 1
        fi
    fi

    # Dockerfile 빌드 테스트
    TMPDIR=$(mktemp -d)
    git archive "$newrev" | tar -x -C "$TMPDIR" 2>/dev/null
    if [ -f "$TMPDIR/Dockerfile" ]; then
        echo "Dockerfile 빌드 검증 중..."
        docker build --no-cache -t "and-service-{team_id}-test:pre" "$TMPDIR" >/dev/null 2>&1
        BUILD_RESULT=$?
        rm -rf "$TMPDIR"
        docker rmi "and-service-{team_id}-test:pre" >/dev/null 2>&1
        if [ $BUILD_RESULT -ne 0 ]; then
            echo "ERROR: Dockerfile 빌드 실패. push 거부됩니다."
            exit 1
        fi
        echo "Dockerfile 빌드 검증 통과"
    else
        rm -rf "$TMPDIR"
        echo "ERROR: Dockerfile 없음"
        exit 1
    fi
done
exit 0
""")
    pre_receive.chmod(0o755)

    # post-receive: docker rebuild + flag 재주입
    post_receive = hooks_dir / "post-receive"
    post_receive.write_text(f"""#!/bin/bash
# post-receive hook for team {team_id}
TEAM_ID="{team_id}"
COORDINATOR_URL="${{COORDINATOR_URL:-http://localhost:9000}}"
ADMIN_SECRET="${{ADMIN_SECRET:-changeme}}"

while read oldrev newrev refname; do
    echo "[$TEAM_ID] 서비스 빌드/배포 시작..."

    # 소스 추출
    DEPLOY_DIR="/tmp/and-deploy-{team_id}"
    rm -rf "$DEPLOY_DIR"
    mkdir -p "$DEPLOY_DIR"
    git archive "$newrev" | tar -x -C "$DEPLOY_DIR"

    # docker build
    docker build -t "and-service-{team_id}:latest" "$DEPLOY_DIR"
    if [ $? -ne 0 ]; then
        echo "ERROR: 빌드 실패"
        rm -rf "$DEPLOY_DIR"
        exit 1
    fi
    rm -rf "$DEPLOY_DIR"

    # 기존 컨테이너 중지 + 새 컨테이너 시작
    docker stop "and-service-{team_id}" 2>/dev/null
    docker rm "and-service-{team_id}" 2>/dev/null
    docker run -d \\
        --name "and-service-{team_id}" \\
        --network hackathon_target-net \\
        --ip "{team_ip}" \\
        --cpus 0.5 --memory 1g \\
        -p "{host_port}:8000" \\
        -e "CHECKER_TOKEN=$CHECKER_TOKEN" \\
        "and-service-{team_id}:latest"

    if [ $? -ne 0 ]; then
        echo "ERROR: 컨테이너 시작 실패"
        exit 1
    fi

    # coordinator에 deploy 이벤트 알림 (flag 재주입 트리거)
    curl -sf -X POST "$COORDINATOR_URL/admin/service-deployed" \\
        -H "X-Admin-Secret: $ADMIN_SECRET" \\
        -H "Content-Type: application/json" \\
        -d '{{"team_id": "{team_id}", "commit": "'"$newrev"'"}}'

    echo "[$TEAM_ID] 배포 완료 (commit: ${{newrev:0:8}})"
done
exit 0
""")
    post_receive.chmod(0o755)


# ── FastAPI git smart HTTP 프록시 ──────────────────────────────────────

@router.get("/{team_id}/info/refs")
async def git_info_refs(
    team_id: str,
    request: Request,
    service: str = "",
):
    repo_path = _get_repo_or_404(team_id)
    if not service:
        raise HTTPException(400, "dumb HTTP not supported")

    # push advertisement는 인증 필요 (git 클라이언트가 먼저 refs를 요청)
    if service == "git-receive-pack":
        _require_push_auth(team_id, request.headers.get("Authorization"))

    cmd = [service, "--stateless-rpc", "--advertise-refs", str(repo_path)]
    result = subprocess.run(cmd, capture_output=True, timeout=30)
    if result.returncode != 0:
        raise HTTPException(500, result.stderr.decode())

    pkt_line = _pkt_line(f"# service={service}\n") + b"0000"
    content_type = f"application/x-{service}-advertisement"
    return Response(
        content=pkt_line + result.stdout,
        media_type=content_type,
        headers={"Cache-Control": "no-cache"},
    )


@router.post("/{team_id}/{service}")
async def git_service(team_id: str, service: str, request: Request):
    if service not in ("git-upload-pack", "git-receive-pack"):
        raise HTTPException(400, "unknown service")

    # push는 팀 토큰 인증 필수
    if service == "git-receive-pack":
        _require_push_auth(team_id, request.headers.get("Authorization"))

    repo_path = _get_repo_or_404(team_id)
    body = await request.body()

    env = os.environ.copy()
    env["COORDINATOR_URL"] = os.getenv("COORDINATOR_URL", "http://localhost:9000")
    env["ADMIN_SECRET"] = os.getenv("ADMIN_SECRET", "changeme")
    env["CHECKER_TOKEN"] = CHECKER_TOKEN

    cmd = [service, "--stateless-rpc", str(repo_path)]
    result = subprocess.run(
        cmd,
        input=body,
        capture_output=True,
        timeout=120,
        env=env,
    )

    content_type = f"application/x-{service}-result"
    return Response(
        content=result.stdout,
        media_type=content_type,
        headers={"Cache-Control": "no-cache"},
    )


# ── admin: service-deployed 알림 처리 (app.py에서 호출) ───────────────

async def handle_service_deployed(team_id: str, commit: str, current_round: int, vuln_specs: dict) -> bool:
    """
    post-receive hook에서 coordinator로 알림이 오면:
    1. DB에 배포 기록
    2. 현재 라운드 flag 재주입
    """
    logger.info("서비스 배포 알림: team=%s commit=%s", team_id, commit[:8])

    if current_round > 0:
        # 현재 라운드 flag 다시 주입
        flags_in_db = db.get_flags_for_round(current_round)
        team_flags = {r["vuln_id"]: r["flag"] for r in flags_in_db if r["team_id"] == team_id}
        if team_flags:
            vulns = vuln_specs.get(team_id, [])
            fm.inject_flags_to_container(team_id, team_flags, vulns)
            logger.info("배포 후 flag 재주입: team=%s round=%d", team_id, current_round)

    return True


# ── 유틸 ──────────────────────────────────────────────────────────────

def _get_repo_or_404(team_id: str) -> Path:
    repo_path = REPOS_DIR / f"{team_id}.git"
    if not repo_path.exists():
        raise HTTPException(404, f"팀 {team_id} 저장소 없음")
    return repo_path


def _pkt_line(s: str) -> bytes:
    data = s.encode()
    length = len(data) + 4
    return f"{length:04x}".encode() + data
