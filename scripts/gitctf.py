#!/usr/bin/env python3
"""
Small LiveFire A&D service submit helper.

Participants use this instead of memorizing the raw git remote/push commands:

  python scripts/gitctf.py login teamA --token TOKEN --coordinator http://HOST:9000
  cd agent_service && python ../scripts/gitctf.py check
  cd agent_service && python ../scripts/gitctf.py push

Legacy explicit commands still work:

  python scripts/gitctf.py verify --repo agent_service --host localhost --port 8000 --repeat 3
  python scripts/gitctf.py submit --repo agent_service --team teamA --token TOKEN --coordinator http://HOST:9000
  python scripts/gitctf.py submit --repo patched_service --repo-team teamA --team teamB --token DEFENSE_TOKEN --coordinator http://HOST:9000

The helper keeps the team token out of .git/config by sending it as a temporary
HTTP Basic Auth header only for the push command.
"""
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
        raise SystemExit(f"ERROR: {repo / name} not found")


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
            f"ERROR: {name} is required. Run `python scripts/gitctf.py login <team> --token <token> "
            f"--coordinator http://HOST:9000` or set {env_name}."
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
            raise SystemExit("ERROR: no files staged and repository has no commits")
        print("No service changes to commit; pushing current HEAD.")
        return
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
        raise SystemExit("ERROR: --coordinator must look like http://host:9000")


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
    print(f"Saved gitctf login for {team} at {coordinator}")
    print(f"Config: {CONFIG_PATH}")
    return 0


def submit(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    if not repo.exists():
        raise SystemExit(f"ERROR: repo path does not exist: {repo}")
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

    _init_repo(repo)
    _ensure_identity(repo)
    _ensure_main_branch(repo)
    if not args.no_commit:
        _stage_and_commit(repo, args.message)
    elif not _has_head(repo):
        raise SystemExit("ERROR: --no-commit requires an existing HEAD commit")

    repo_team = args.repo_team or os.getenv("REPO_TEAM") or config.get("repo_team") or team
    remote_url = _set_remote(repo, coordinator, repo_team)

    print(f"Submitting {repo} to {repo_team} as {team}")
    print(f"Remote: {remote_url}")
    if args.dry_run:
        print("Dry run: commit/remote prepared, push skipped.")
        return 0

    header = _basic_auth_header(team, token)
    _git(repo, "-c", f"http.extraHeader={header}", "push", REMOTE_NAME, "HEAD:main")
    print("Submit complete.")
    return 0


def verify(args: argparse.Namespace) -> int:
    repo = Path(args.repo).resolve()
    if not repo.exists():
        raise SystemExit(f"ERROR: repo path does not exist: {repo}")
    _load_local_env(repo)
    _require_file(repo, "Dockerfile")
    spec = Path(args.spec).resolve() if args.spec else repo / "vuln_spec.json"
    if not spec.exists():
        raise SystemExit(f"ERROR: {spec} not found")

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
        print("Verify failed: service must expose all four flags through the vuln_spec attack checks.", file=sys.stderr)
    return result.returncode


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="HSPACE LiveFire A&D submit helper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Common flow:
  python scripts/gitctf.py login teamA --token TOKEN --coordinator http://HOST:9000
  cd agent_service
  python ../scripts/gitctf.py check
  python ../scripts/gitctf.py push
""",
    )
    sub = parser.add_subparsers(dest="command")

    login_parser = sub.add_parser("login", help="save team/coordinator/token for short commands")
    login_parser.add_argument("team", nargs="?", help="team id, for example teamA")
    login_parser.add_argument("--token", help="team token; prompts if omitted on a TTY")
    login_parser.add_argument(
        "--coordinator",
        default=os.getenv("COORDINATOR_URL"),
        help="coordinator base URL, default: COORDINATOR_URL, saved config, or http://localhost:9000",
    )
    login_parser.set_defaults(func=login)

    verify_parser = sub.add_parser("verify", help="validate a local service before submit")
    verify_parser.add_argument("--repo", default=".", help="service repo path, default: current directory")
    verify_parser.add_argument("--spec", help="vuln_spec.json path, default: <repo>/vuln_spec.json")
    verify_parser.add_argument("--host", default="localhost", help="running service host, default: localhost")
    verify_parser.add_argument("--port", type=int, default=8000, help="running service port, default: 8000")
    verify_parser.add_argument("--repeat", type=int, default=3, help="repeat count per vuln; all attempts must pass")
    verify_parser.add_argument(
        "--checker-token",
        default=os.getenv("CHECKER_TOKEN", "validate-test-token"),
        help="checker token, default: CHECKER_TOKEN or validate-test-token",
    )
    verify_parser.add_argument("--save-report", help="write validation JSON report")
    verify_parser.set_defaults(func=verify)

    check_parser = sub.add_parser("check", help="short alias for verify")
    check_parser.add_argument("--repo", default=".", help="service repo path, default: current directory")
    check_parser.add_argument("--spec", help="vuln_spec.json path, default: <repo>/vuln_spec.json")
    check_parser.add_argument("--host", default="localhost", help="running service host, default: localhost")
    check_parser.add_argument("--port", type=int, default=8000, help="running service port, default: 8000")
    check_parser.add_argument("--repeat", type=int, default=3, help="repeat count per vuln; all attempts must pass")
    check_parser.add_argument(
        "--checker-token",
        default=os.getenv("CHECKER_TOKEN", "validate-test-token"),
        help="checker token, default: CHECKER_TOKEN or validate-test-token",
    )
    check_parser.add_argument("--save-report", help="write validation JSON report")
    check_parser.set_defaults(func=verify)

    submit_parser = sub.add_parser("submit", help="commit and push a service repo")
    submit_parser.add_argument("--repo", default=".", help="service repo path, default: current directory")
    submit_parser.add_argument("--team", default=None, help="team id, default: TEAM_ID or gitctf login")
    submit_parser.add_argument(
        "--repo-team",
        default=None,
        help="repository owner team to push to; defaults to --team. Use this for defense pushes.",
    )
    submit_parser.add_argument("--token", default=None, help="team token, default: TEAM_TOKEN or gitctf login")
    submit_parser.add_argument(
        "--coordinator",
        default=None,
        help="coordinator base URL, default: COORDINATOR_URL or http://localhost:9000",
    )
    submit_parser.add_argument("--message", default="Submit service", help="git commit message")
    submit_parser.add_argument("--no-commit", action="store_true", help="push existing HEAD without staging or committing")
    submit_parser.add_argument("--dry-run", action="store_true", help="prepare commit/remote but skip push")
    submit_parser.set_defaults(func=submit)

    push_parser = sub.add_parser("push", help="short alias for submit")
    push_parser.add_argument("--repo", default=".", help="service repo path, default: current directory")
    push_parser.add_argument("--team", default=None, help="team id, default: TEAM_ID or gitctf login")
    push_parser.add_argument(
        "--repo-team",
        default=None,
        help="repository owner team to push to; defaults to --team. Use this for defense pushes.",
    )
    push_parser.add_argument("--token", default=None, help="team token, default: TEAM_TOKEN or gitctf login")
    push_parser.add_argument(
        "--coordinator",
        default=None,
        help="coordinator base URL, default: COORDINATOR_URL or saved login",
    )
    push_parser.add_argument("--message", default="Submit service", help="git commit message")
    push_parser.add_argument("--no-commit", action="store_true", help="push existing HEAD without staging or committing")
    push_parser.add_argument("--dry-run", action="store_true", help="prepare commit/remote but skip push")
    push_parser.set_defaults(func=submit)
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()
    if not hasattr(args, "func"):
        parser.print_help()
        return 2
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
