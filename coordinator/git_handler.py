"""
Git Smart HTTP 핸들러 + pre/post-receive 훅 로직.

팀은 서비스 코드를 git push로 제출/패치한다:
  python scripts/gitctf.py submit --repo agent_service --team teamA --token "$TEAM_TOKEN" --coordinator http://coordinator:9000

raw git도 지원한다:
  git remote add organizer http://teamA:<TEAM_TOKEN>@coordinator:9000/git/teamA && git push organizer main

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
from rotation import get_defender

logger = logging.getLogger(__name__)

REPOS_DIR = Path(os.getenv("REPOS_DIR", Path(__file__).parent.parent / "repos"))
CHECKER_TOKEN = os.getenv("CHECKER_TOKEN", "checker-token-changeme")

# 팀별 target-net 내부 IP + 호스트 외부 노출 포트
# docker-compose.yml의 static IP / port 배정과 반드시 일치해야 한다.
_TEAM_NET = {
    "teamA": {"ip": "10.89.21.10", "host_port": 8001},
    "teamB": {"ip": "10.89.21.11", "host_port": 8002},
    "teamC": {"ip": "10.89.21.12", "host_port": 8003},
    "teamD": {"ip": "10.89.21.13", "host_port": 8004},
    "teamE": {"ip": "10.89.21.14", "host_port": 8005},
    "teamF": {"ip": "10.89.21.15", "host_port": 8006},
}

router = APIRouter(prefix="/git")


# ── 인증 헬퍼 ─────────────────────────────────────────────────────────

def _require_push_auth(repo_team_id: str, authorization: str | None) -> str:
    """
    git push(git-receive-pack) 전용 인증.

    HTTP Basic Auth: username=team_id, password=TEAM_TOKEN
    실패 시 401 + WWW-Authenticate 헤더 반환 (git 클라이언트가 credential 재요청)
    """
    from config import TEAM_TOKENS, DEFENSE_TOKENS

    _UNAUTHORIZED = HTTPException(
        status_code=401,
        detail="Git push 인증 실패",
        headers={"WWW-Authenticate": f'Basic realm="HSPACE CTF git — {repo_team_id}"'},
    )

    if not authorization or not authorization.startswith("Basic "):
        raise _UNAUTHORIZED

    try:
        decoded = base64.b64decode(authorization[6:]).decode("utf-8")
    except Exception:
        raise _UNAUTHORIZED

    username, _, password = decoded.partition(":")
    defender = get_defender(repo_team_id)
    allowed_users = {repo_team_id, defender}
    if username == repo_team_id:
        expected_token = TEAM_TOKENS.get(username, "")
    elif username == defender:
        expected_token = DEFENSE_TOKENS.get(username, "")
    else:
        expected_token = ""

    if not expected_token or username not in allowed_users or password != expected_token:
        raise _UNAUTHORIZED
    return username


# ── bare repo 초기화 ───────────────────────────────────────────────────

def init_team_repo(team_id: str) -> Path:
    """팀 bare repo가 없으면 생성."""
    repo_path = REPOS_DIR / f"{team_id}.git"
    REPOS_DIR.mkdir(parents=True, exist_ok=True)
    if not repo_path.exists():
        result = subprocess.run(["git", "init", "--bare", "-b", "main", str(repo_path)], check=False)
        if result.returncode != 0:
            subprocess.run(["git", "init", "--bare", str(repo_path)], check=True)
        logger.info("Bare repo 생성: %s", repo_path)
    _install_hooks(repo_path, team_id)
    return repo_path


def init_all_repos(team_ids: list[str]) -> None:
    for tid in team_ids:
        init_team_repo(tid)


def _install_hooks(repo_path: Path, team_id: str) -> None:
    """pre-receive / post-receive 훅 스크립트 설치."""
    hooks_dir = repo_path / "hooks"
    docker_team = team_id.lower()
    net_cfg = _TEAM_NET.get(team_id, {"ip": "0.0.0.0", "host_port": 8000})
    team_ip = net_cfg["ip"]
    host_port = net_cfg["host_port"]

    # pre-receive: Dockerfile 빌드 검증 + vuln_spec 잠금
    pre_receive = hooks_dir / "pre-receive"
    pre_receive.write_text(f"""#!/bin/bash
# pre-receive hook for team {team_id}
TEAM_ID="{team_id}"
COORDINATOR_URL="${{COORDINATOR_URL:-http://localhost:9000}}"
ADMIN_SECRET="${{ADMIN_SECRET:-changeme}}"
PUSH_USER="${{PUSH_USER:-$TEAM_ID}}"
VULN_SPEC_DIR="${{VULN_SPEC_DIR:-/app/vuln_specs}}"
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

while read oldrev newrev refname; do
    STATUS=$(curl -sf "$COORDINATOR_URL/status" 2>/dev/null)
    ACTIVE=$(echo "$STATUS" | python3 -c "import sys,json; print(json.load(sys.stdin).get('round_active',False))" 2>/dev/null)

    # vuln_spec.json 변경 감지
    if git diff --name-only "$oldrev" "$newrev" 2>/dev/null | grep -q "vuln_spec.json"; then
        # 라운드 진행 중이면 거부
        if [ "$ACTIVE" = "True" ]; then
            echo "ERROR: 대회 진행 중에는 vuln_spec.json 변경 불가"
            exit 1
        fi
    fi

    if [ "$ACTIVE" = "True" ]; then
        if [ "$PUSH_USER" = "$TEAM_ID" ]; then
            echo "ERROR: 라운드 중에는 사이트 소유자가 직접 패치 push 불가. 방어 에이전트 run을 사용하세요."
            exit 1
        fi
        AGENT_RUN_ID=$(git log -1 --format=%B "$newrev" | awk '/^Agent-Run-ID:/ {{print $2}}' | tail -n 1)
        if [ -z "$AGENT_RUN_ID" ]; then
            echo "ERROR: defense patch commit에는 Agent-Run-ID trailer가 필요합니다."
            exit 1
        fi
        curl -sf -X POST "$COORDINATOR_URL/admin/validate-defense-push" \\
            -H "X-Admin-Secret: $ADMIN_SECRET" \\
            -H "Content-Type: application/json" \\
            -d '{{"repo_team_id":"{team_id}","pusher_team_id":"'"$PUSH_USER"'","commit":"'"$newrev"'","agent_run_id":"'"$AGENT_RUN_ID"'"}}' >/dev/null
        if [ $? -ne 0 ]; then
            echo "ERROR: Agent-Run-ID provenance 검증 실패"
            exit 1
        fi
    else
        if [ "$PUSH_USER" != "$TEAM_ID" ]; then
            echo "ERROR: 대회 시작 전에는 사이트 소유자만 push 가능"
            exit 1
        fi
    fi

    # Dockerfile 빌드 테스트
    TMPDIR=$(mktemp -d)
    git archive "$newrev" | tar -x -C "$TMPDIR" 2>/dev/null
    if [ -f "$TMPDIR/Dockerfile" ]; then
        echo "Dockerfile 빌드 검증 중..."
        BUILD_LOG=$(mktemp)
        docker build --no-cache -t "and-service-{docker_team}-test:pre" "$TMPDIR" >"$BUILD_LOG" 2>&1
        BUILD_RESULT=$?
        rm -rf "$TMPDIR"
        docker rmi "and-service-{docker_team}-test:pre" >/dev/null 2>&1
        if [ $BUILD_RESULT -ne 0 ]; then
            echo "ERROR: Dockerfile 빌드 실패. push 거부됩니다."
            tail -n 80 "$BUILD_LOG"
            rm -f "$BUILD_LOG"
            exit 1
        fi
        rm -f "$BUILD_LOG"
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
PUSH_USER="${{PUSH_USER:-$TEAM_ID}}"
VULN_SPEC_DIR="${{VULN_SPEC_DIR:-/app/vuln_specs}}"
PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:$PATH"

while read oldrev newrev refname; do
    echo "[$TEAM_ID] 서비스 빌드/배포 시작..."

    # 소스 추출
    DEPLOY_DIR="/tmp/and-deploy-{team_id}"
    rm -rf "$DEPLOY_DIR"
    mkdir -p "$DEPLOY_DIR"
    git archive "$newrev" | tar -x -C "$DEPLOY_DIR"

    # docker build
    docker build -t "and-service-{docker_team}:latest" "$DEPLOY_DIR"
    if [ $? -ne 0 ]; then
        echo "ERROR: 빌드 실패"
        rm -rf "$DEPLOY_DIR"
        exit 1
    fi
    rm -rf "$DEPLOY_DIR"

    # 기존 컨테이너 중지 + 새 컨테이너 시작
    docker stop "and-service-{docker_team}" 2>/dev/null
    docker rm "and-service-{docker_team}" 2>/dev/null
    docker run -d \\
        --name "and-service-{docker_team}" \\
        --restart unless-stopped \\
        --network hackathon_target-net \\
        --ip "{team_ip}" \\
        --cpus 0.5 --memory 1g \\
        -p "{host_port}:8000" \\
        -e "CHECKER_TOKEN=$CHECKER_TOKEN" \\
        "and-service-{docker_team}:latest"

    if [ $? -ne 0 ]; then
        echo "ERROR: 컨테이너 시작 실패"
        exit 1
    fi

    if git cat-file -e "$newrev:vuln_spec.json" 2>/dev/null; then
        mkdir -p "$VULN_SPEC_DIR"
        TMP_SPEC=$(mktemp)
        git show "$newrev:vuln_spec.json" > "$TMP_SPEC"
        python3 -m json.tool "$TMP_SPEC" >/dev/null
        if [ $? -ne 0 ]; then
            echo "ERROR: vuln_spec.json이 유효한 JSON이 아닙니다"
            rm -f "$TMP_SPEC"
            exit 1
        fi
        chmod 0644 "$TMP_SPEC"
        mv "$TMP_SPEC" "$VULN_SPEC_DIR/{team_id}.json"
        echo "[$TEAM_ID] vuln_spec 추출 완료: $VULN_SPEC_DIR/{team_id}.json"
    fi

    AGENT_RUN_ID=""
    if [ "$PUSH_USER" != "$TEAM_ID" ]; then
        AGENT_RUN_ID=$(git log -1 --format=%B "$newrev" | awk '/^Agent-Run-ID:/ {{print $2}}' | tail -n 1)
    fi

    # coordinator에 deploy 이벤트 알림 (flag 재주입 트리거)
    curl -sf -X POST "$COORDINATOR_URL/admin/service-deployed" \\
        -H "X-Admin-Secret: $ADMIN_SECRET" \\
        -H "Content-Type: application/json" \\
        -d '{{"team_id": "{team_id}", "commit": "'"$newrev"'", "pusher_team_id": "'"$PUSH_USER"'", "agent_run_id": "'"$AGENT_RUN_ID"'"}}'

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
    result = await asyncio.to_thread(subprocess.run, cmd, capture_output=True, timeout=30)
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
    push_user = None
    if service == "git-receive-pack":
        push_user = _require_push_auth(team_id, request.headers.get("Authorization"))

    repo_path = _get_repo_or_404(team_id)
    body = await request.body()

    env = os.environ.copy()
    # Hooks run inside the coordinator process/container. Use loopback here;
    # agent-facing COORDINATOR_URL may point at the scoring-net address and can
    # hang when a container tries to call itself through the bridge IP.
    env["COORDINATOR_URL"] = os.getenv("HOOK_COORDINATOR_URL", "http://127.0.0.1:9000")
    env["ADMIN_SECRET"] = os.getenv("ADMIN_SECRET", "changeme")
    env["CHECKER_TOKEN"] = CHECKER_TOKEN
    env["VULN_SPEC_DIR"] = os.getenv("VULN_SPEC_DIR", str(Path(__file__).parent.parent / "vuln_specs"))
    if push_user:
        env["PUSH_USER"] = push_user

    cmd = [service, "--stateless-rpc", str(repo_path)]
    result = await asyncio.to_thread(
        subprocess.run,
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

async def handle_service_deployed(
    team_id: str,
    commit: str,
    current_round: int,
    vuln_specs: dict,
    team_info: dict | None = None,
    checker_token: str | None = None,
    pusher_team_id: str | None = None,
    agent_run_id: str | None = None,
) -> bool:
    """
    post-receive hook에서 coordinator로 알림이 오면:
    1. DB에 배포 기록
    2. 현재 라운드 flag 재주입
    """
    logger.info("서비스 배포 알림: team=%s pusher=%s commit=%s", team_id, pusher_team_id or team_id, commit[:8])
    db.record_service_deployment(
        team_id=team_id,
        commit_sha=commit,
        agent_run_id=agent_run_id or None,
        mode="defense_patch" if agent_run_id else "service",
    )

    if current_round > 0:
        # 현재 라운드 flag 다시 주입
        flags_in_db = db.get_flags_for_round(current_round)
        team_flags = {r["vuln_id"]: r["flag"] for r in flags_in_db if r["team_id"] == team_id}
        if team_flags:
            vulns = vuln_specs.get(team_id, [])
            if team_info and checker_token:
                injected = await fm.inject_flags_via_checker(team_info, team_flags, vulns, checker_token)
                if not injected:
                    logger.error("배포 후 checker flag 재주입 실패: team=%s round=%d", team_id, current_round)
            else:
                logger.warning("team_info/checker_token 없음 — 배포 후 checker flag 재주입 생략: team=%s", team_id)
            logger.info("배포 후 flag 재주입 시도: team=%s round=%d", team_id, current_round)

    return True


# ── 유틸 ──────────────────────────────────────────────────────────────

def _get_repo_or_404(team_id: str) -> Path:
    repo_path = REPOS_DIR / f"{team_id}.git"
    if not repo_path.exists():
        raise HTTPException(404, f"팀 {team_id} 저장소 없음")
    return repo_path


def archive_team_repo(team_id: str) -> tuple[bytes, str]:
    """Return a tar archive of the team's current HEAD and its commit SHA."""
    repo_path = _get_repo_or_404(team_id)
    rev = subprocess.run(
        ["git", f"--git-dir={repo_path}", "rev-parse", "--verify", "HEAD^{commit}"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    if rev.returncode != 0:
        raise HTTPException(404, f"팀 {team_id} 저장소에 커밋 없음")

    commit = rev.stdout.strip()
    result = subprocess.run(
        [
            "git",
            f"--git-dir={repo_path}",
            "archive",
            "--format=tar",
            "--prefix",
            f"{team_id}/",
            commit,
        ],
        capture_output=True,
        timeout=30,
    )
    if result.returncode != 0:
        stderr = result.stderr.decode("utf-8", errors="replace")[:300]
        raise HTTPException(500, f"repo archive 생성 실패: {stderr}")
    return result.stdout, commit


def _pkt_line(s: str) -> bytes:
    data = s.encode()
    length = len(data) + 4
    return f"{length:04x}".encode() + data
