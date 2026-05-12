#!/usr/bin/env python3
"""Participant-facing LiveFire A&D service CLI."""
from __future__ import annotations

import argparse
import base64
import getpass
import json
import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import urlparse


REMOTE_NAME = "organizer"
CONFIG_PATH = Path(os.getenv("GITCTF_CONFIG", "~/.config/hspace-gitctf/config.json")).expanduser()
COMMON_FLOW = """처음 쓰는 순서:
  1. 로그인 저장
     python scripts/gitctf.py login teamA --token <TEAM_TOKEN> --coordinator http://HOST:9000

  2. 서비스 폴더로 이동
     cd agent_service

  3. 제출 전 검증
     python ../scripts/gitctf.py check

  4. 제출
     python ../scripts/gitctf.py push
"""


def _run(cmd: list[str], cwd: Path, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    env = os.environ.copy()
    env["GIT_TERMINAL_PROMPT"] = "0"
    return subprocess.run(
        cmd,
        cwd=cwd,
        check=check,
        env=env,
        text=True,
        capture_output=capture,
    )


def _git(cwd: Path, *args: str, check: bool = True, capture: bool = False) -> subprocess.CompletedProcess:
    return _run(["git", *args], cwd=cwd, check=check, capture=capture)


def _has_git_repo(repo: Path) -> bool:
    if not (repo / ".git").exists():
        return False
    result = _git(repo, "rev-parse", "--is-inside-work-tree", check=False, capture=True)
    if result.returncode != 0 or result.stdout.strip() != "true":
        return False
    top = _git(repo, "rev-parse", "--show-toplevel", check=False, capture=True)
    return top.returncode == 0 and Path(top.stdout.strip()).resolve() == repo.resolve()


def _has_head(repo: Path) -> bool:
    return _git(repo, "rev-parse", "--verify", "HEAD", check=False, capture=True).returncode == 0


def _require_file(repo: Path, name: str) -> None:
    if not (repo / name).exists():
        raise SystemExit(
            f"필수 파일이 없습니다: {name}\n"
            f"확인 위치: {repo}\n"
            "서비스 repo 루트에서 실행했는지 확인하거나 --repo로 서비스 폴더를 지정하세요."
        )


def _print_section(title: str) -> None:
    print(f"\n[{title}]", flush=True)


def _print_kv(label: str, value: object) -> None:
    print(f"  {label:<12} {value}", flush=True)


def _mask_token(token: str | None) -> str:
    if not token:
        return "(없음)"
    if len(token) <= 8:
        return "<hidden>"
    return f"{token[:4]}...{token[-4:]}"


def _load_config() -> dict:
    if not CONFIG_PATH.exists():
        return {}
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise SystemExit(f"ERROR: invalid config file: {CONFIG_PATH}: {exc}") from exc


def _write_config(config: dict) -> None:
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(json.dumps(config, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    CONFIG_PATH.chmod(0o600)


def _load_env_file(path: Path) -> None:
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key:
            os.environ.setdefault(key, value)


def _load_local_env(repo: Path) -> None:
    seen: set[Path] = set()
    for path in (Path.cwd() / ".env", repo / ".env"):
        resolved = path.resolve()
        if resolved not in seen:
            _load_env_file(resolved)
            seen.add(resolved)


def _resolve_setting(
    name: str,
    cli_value: str | None,
    env_name: str,
    config_key: str,
    config: dict,
    default: str | None = None,
    required: bool = True,
) -> str | None:
    value = cli_value or os.getenv(env_name) or config.get(config_key) or default
    if required and not value:
        raise SystemExit(
            f"{name} 값이 필요합니다.\n"
            f"해결: `python scripts/gitctf.py login teamA --token <TEAM_TOKEN> "
            f"--coordinator http://HOST:9000`을 먼저 실행하거나 {env_name} 환경변수를 설정하세요."
        )
    return value


def _init_repo(repo: Path) -> None:
    if _has_git_repo(repo):
        return
    result = _git(repo, "init", "-b", "main", check=False)
    if result.returncode != 0:
        _git(repo, "init")
        _git(repo, "checkout", "-B", "main")


def _ensure_identity(repo: Path) -> None:
    if _git(repo, "config", "user.email", check=False, capture=True).returncode != 0:
        _git(repo, "config", "user.email", "hspace-team@example.invalid")
    if _git(repo, "config", "user.name", check=False, capture=True).returncode != 0:
        _git(repo, "config", "user.name", "HSPACE Team")


def _ensure_main_branch(repo: Path) -> None:
    branch = _git(repo, "branch", "--show-current", check=False, capture=True).stdout.strip()
    if branch != "main":
        _git(repo, "checkout", "-B", "main")


def _stage_and_commit(repo: Path, message: str) -> None:
    _git(repo, "add", "-A")
    staged = _git(repo, "diff", "--cached", "--quiet", check=False)
    if staged.returncode == 0:
        if not _has_head(repo):
            raise SystemExit("커밋할 파일이 없고 기존 커밋도 없습니다. 서비스 파일을 먼저 추가하세요.")
        print("변경된 파일이 없습니다. 현재 HEAD를 그대로 제출합니다.", flush=True)
        return
    print(f"커밋 생성: {message}", flush=True)
    _git(repo, "commit", "-m", message)


def _set_remote(repo: Path, coordinator: str, repo_team: str) -> str:
    base = coordinator.rstrip("/")
    remote_url = f"{base}/git/{repo_team}"
    existing = _git(repo, "remote", "get-url", REMOTE_NAME, check=False, capture=True)
    if existing.returncode == 0:
        _git(repo, "remote", "set-url", REMOTE_NAME, remote_url)
    else:
        _git(repo, "remote", "add", REMOTE_NAME, remote_url)
    return remote_url


def _basic_auth_header(team: str, token: str) -> str:
    raw = f"{team}:{token}".encode("utf-8")
    return "Authorization: Basic " + base64.b64encode(raw).decode("ascii")


def _validate_coordinator(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise SystemExit("--coordinator는 http://HOST:9000 같은 주소여야 합니다.")


def login(args: argparse.Namespace) -> int:
    config = _load_config()
    team = args.team or os.getenv("TEAM_ID") or config.get("team")
    if not team:
        raise SystemExit("ERROR: team is required, for example: python scripts/gitctf.py login teamA")
    coordinator = args.coordinator or os.getenv("COORDINATOR_URL") or config.get("coordinator") or "http://localhost:9000"
    _validate_coordinator(coordinator)

    token = args.token or os.getenv("TEAM_TOKEN")
    if not token:
        if not sys.stdin.isatty():
            raise SystemExit("ERROR: token is required in non-interactive mode. Use --token or TEAM_TOKEN.")
        token = getpass.getpass("Team token: ")
    if not token:
        raise SystemExit("ERROR: empty token")

    config.update({"team": team, "token": token, "coordinator": coordinator})
    _write_config(config)
    _print_section("로그인 저장 완료")
    _print_kv("팀", team)
    _print_kv("coordinator", coordinator)
    _print_kv("토큰", _mask_token(token))
    _print_kv("설정 파일", CONFIG_PATH)
    _print_section("다음 단계")
    print("  cd <서비스_폴더>")
    print("  python ../scripts/gitctf.py check")
    print("  python ../scripts/gitctf.py push")
    return 0


def submit(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    if not repo.exists():
        raise SystemExit(f"서비스 폴더가 없습니다: {repo}")
    _load_local_env(repo)
    config = _load_config()
    team = _resolve_setting("team", args.team, "TEAM_ID", "team", config)
    token = _resolve_setting("token", args.token, "TEAM_TOKEN", "token", config)
    coordinator = _resolve_setting(
        "coordinator",
        args.coordinator,
        "COORDINATOR_URL",
        "coordinator",
        config,
        default="http://localhost:9000",
    )
    assert team is not None and token is not None and coordinator is not None
    _validate_coordinator(coordinator)
    _require_file(repo, "Dockerfile")
    _require_file(repo, "vuln_spec.json")

    repo_team = args.repo_team or os.getenv("REPO_TEAM") or config.get("repo_team") or team
    _print_section("제출 준비")
    _print_kv("서비스 폴더", repo)
    _print_kv("제출 대상", repo_team)
    _print_kv("제출 팀", team)
    _print_kv("coordinator", coordinator)
    _print_kv("커밋 방식", "기존 HEAD 사용" if args.no_commit else "변경분 자동 커밋")

    _init_repo(repo)
    _ensure_identity(repo)
    _ensure_main_branch(repo)
    if not args.no_commit:
        _stage_and_commit(repo, args.message)
    elif not _has_head(repo):
        raise SystemExit("ERROR: --no-commit requires an existing HEAD commit")

    remote_url = _set_remote(repo, coordinator, repo_team)

    _print_section("git remote")
    _print_kv("이름", REMOTE_NAME)
    _print_kv("주소", remote_url)
    if args.dry_run:
        _print_section("dry run 완료")
        print("  여기까지 준비만 확인했습니다. 실제 push는 하지 않았습니다.")
        return 0

    _print_section("push 시작")
    header = _basic_auth_header(team, token)
    _git(repo, "-c", f"http.extraHeader={header}", "push", REMOTE_NAME, "HEAD:main")
    _print_section("제출 완료")
    print("  coordinator가 Dockerfile 빌드와 vuln_spec.json 검사를 통과하면 서비스가 반영됩니다.")
    return 0


def verify(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    if not repo.exists():
        raise SystemExit(f"서비스 폴더가 없습니다: {repo}")
    _load_local_env(repo)
    _require_file(repo, "Dockerfile")
    spec = Path(args.spec).resolve() if args.spec else repo / "vuln_spec.json"
    if not spec.exists():
        raise SystemExit(f"vuln_spec.json을 찾을 수 없습니다: {spec}")

    _print_section("서비스 검증")
    _print_kv("서비스 폴더", repo)
    _print_kv("spec", spec)
    _print_kv("대상", f"http://{args.host}:{args.port}")
    _print_kv("반복", f"{args.repeat}회")

    cmd = [
        sys.executable,
        str(Path(__file__).with_name("validate_vulns.py")),
        "--spec",
        str(spec),
        "--host",
        args.host,
        "--port",
        str(args.port),
        "--repeat",
        str(args.repeat),
        "--checker-token",
        args.checker_token,
    ]
    if args.save_report:
        cmd.extend(["--save-report", args.save_report])
    result = _run(cmd, cwd=repo, check=False)
    if result.returncode != 0:
        _print_section("검증 실패")
        print("  vuln_spec.json에 선언된 4개 취약점이 모두 flag를 노출해야 제출 준비가 됩니다.", file=sys.stderr)
        print("  서비스를 실행 중인지, --host/--port가 맞는지, checker 요청이 서비스 구현과 맞는지 확인하세요.", file=sys.stderr)
    else:
        _print_section("검증 완료")
        print("  이제 `python ../scripts/gitctf.py push`로 제출할 수 있습니다.")
    return result.returncode


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="HSPACE LiveFire A&D 참가자 CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=COMMON_FLOW,
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")

    login_parser = sub.add_parser(
        "login",
        help="팀 토큰과 coordinator 주소를 저장",
        description="팀 토큰과 coordinator 주소를 저장합니다. 이후 check/push에서 반복 입력하지 않아도 됩니다.",
    )
    login_parser.add_argument("team", nargs="?", help="팀 ID, 예: teamA")
    login_parser.add_argument("--token", help="팀 토큰. 생략하면 터미널에서 숨김 입력으로 받습니다.")
    login_parser.add_argument(
        "--coordinator",
        default=os.getenv("COORDINATOR_URL"),
        help="coordinator 주소. 기본값: COORDINATOR_URL, 저장된 설정, 또는 http://localhost:9000",
    )
    login_parser.set_defaults(func=login)

    check_parser = sub.add_parser(
        "check",
        aliases=["verify"],
        help="제출 전 서비스와 vuln_spec.json 검증",
        description=(
            "로컬에서 실행 중인 서비스를 vuln_spec.json 기준으로 검증합니다.\n"
            "기본값은 현재 폴더의 vuln_spec.json, localhost:8000, 취약점당 3회 반복입니다."
        ),
    )
    check_parser.add_argument("--repo", default=".", help="서비스 repo 경로. 기본값: 현재 폴더")
    check_parser.add_argument("--spec", help="vuln_spec.json 경로. 기본값: <repo>/vuln_spec.json")
    check_parser.add_argument("--host", default="localhost", help="실행 중인 서비스 host. 기본값: localhost")
    check_parser.add_argument("--port", type=int, default=8000, help="실행 중인 서비스 port. 기본값: 8000")
    check_parser.add_argument("--repeat", type=int, default=3, help="취약점당 반복 횟수. 모든 시도가 성공해야 PASS")
    check_parser.add_argument(
        "--checker-token",
        default=os.getenv("CHECKER_TOKEN", "validate-test-token"),
        help="checker 인증 토큰. 기본값: CHECKER_TOKEN 또는 validate-test-token",
    )
    check_parser.add_argument("--save-report", help="검증 결과 JSON 저장 경로")
    check_parser.set_defaults(func=verify)

    push_parser = sub.add_parser(
        "push",
        aliases=["submit"],
        help="서비스 repo를 commit 후 coordinator에 제출",
        description=(
            "서비스 repo를 main 브랜치로 정리한 뒤 coordinator git remote에 push합니다.\n"
            "팀 토큰은 git config에 저장하지 않고 push 명령에만 임시로 붙입니다."
        ),
    )
    push_parser.add_argument("--repo", default=".", help="서비스 repo 경로. 기본값: 현재 폴더")
    push_parser.add_argument("--team", default=None, help="제출 팀 ID. 기본값: TEAM_ID 또는 login 저장값")
    push_parser.add_argument(
        "--repo-team",
        default=None,
        help="push할 repo 소유 팀. 기본값: --team. 방어 패치 제출 때 사용합니다.",
    )
    push_parser.add_argument("--token", default=None, help="팀 토큰. 기본값: TEAM_TOKEN 또는 login 저장값")
    push_parser.add_argument(
        "--coordinator",
        default=None,
        help="coordinator 주소. 기본값: COORDINATOR_URL 또는 login 저장값",
    )
    push_parser.add_argument("--message", default="Submit service", help="자동 커밋 메시지")
    push_parser.add_argument("--no-commit", action="store_true", help="자동 커밋 없이 현재 HEAD를 제출")
    push_parser.add_argument("--dry-run", action="store_true", help="커밋/remote 준비만 하고 실제 push는 하지 않음")
    push_parser.set_defaults(func=submit)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        return 0
    return args.func(args)


def _safe_cmd(cmd: object) -> str:
    if not isinstance(cmd, list):
        return str(cmd)
    masked: list[str] = []
    for item in cmd:
        if isinstance(item, str) and item.startswith("http.extraHeader=Authorization:"):
            masked.append("http.extraHeader=Authorization: <redacted>")
        else:
            masked.append(str(item))
    return " ".join(masked)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.CalledProcessError as exc:
        print(f"ERROR: command failed: {_safe_cmd(exc.cmd)}", file=sys.stderr)
        if exc.stderr:
            print(exc.stderr, file=sys.stderr)
        raise SystemExit(exc.returncode)
