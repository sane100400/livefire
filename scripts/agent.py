#!/usr/bin/env python3
"""Unified helper for attack/defense agent images and local debug runs."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path


AGENT_HELPER_TRUSTED_BOOTSTRAP = True
SDK_NAME = "hspace-agent-sdk/1"
CONFIG_PATH = Path(os.getenv("GITCTF_CONFIG", "~/.config/hspace-gitctf/config.json")).expanduser()
UPDATE_CACHE_DIR = Path(os.getenv("AGENT_HELPER_CACHE_DIR", "~/.cache/hspace-agent-helper")).expanduser()


def _project_root() -> Path:
    source_root = os.getenv("AGENT_HELPER_SOURCE_ROOT")
    if source_root:
        return Path(source_root).expanduser().resolve()
    return Path(__file__).resolve().parents[1]


ROOT = _project_root()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _fetch_url(url: str, timeout: float = 5.0) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "hspace-agent-helper/1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _extract_cli_option(argv: list[str], name: str) -> str | None:
    prefix = f"{name}="
    for idx, item in enumerate(argv):
        if item == name and idx + 1 < len(argv):
            return argv[idx + 1]
        if item.startswith(prefix):
            return item[len(prefix):]
    return None


def _load_config_quietly() -> dict:
    if not CONFIG_PATH.exists():
        return {}
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
    except Exception:
        return {}


def _coordinator_from_argv(argv: list[str]) -> str | None:
    return (
        _extract_cli_option(argv, "--coordinator")
        or os.getenv("COORDINATOR_URL")
        or _load_config_quietly().get("coordinator")
        or ("http://localhost:42000" if argv and argv[0] == "run" else None)
    )


def _update_url_from_context(argv: list[str]) -> str | None:
    explicit = os.getenv("AGENT_HELPER_UPDATE_URL")
    if explicit:
        return explicit
    coordinator = _coordinator_from_argv(argv)
    if coordinator:
        return f"{coordinator.rstrip('/')}/tools/agent.py"
    return None


def _looks_like_agent_script(source: bytes) -> bool:
    return (
        b"AGENT_HELPER_TRUSTED_BOOTSTRAP = True" in source
        and b"def main()" in source
        and b"HSPACE attack/defense agent" in source
    )


def _cache_tool(source: bytes, digest: str) -> Path:
    target_dir = UPDATE_CACHE_DIR / digest
    target_dir.mkdir(parents=True, exist_ok=True)
    target = target_dir / "agent.py"
    with tempfile.NamedTemporaryFile("wb", delete=False, dir=target_dir) as fh:
        fh.write(source)
        tmp = Path(fh.name)
    tmp.replace(target)
    return target


def _self_update(argv: list[str]) -> None:
    if os.getenv("AGENT_HELPER_SELF_UPDATED") == "1":
        return
    if os.getenv("AGENT_HELPER_NO_SELF_UPDATE") == "1":
        if argv and argv[0] == "run" and os.getenv("AGENT_HELPER_ALLOW_STALE") != "1":
            raise SystemExit("agent run은 공식 agent.py 최신본 확인을 건너뛸 수 없습니다.")
        return
    if not argv or "-h" in argv or "--help" in argv:
        return

    update_url = _update_url_from_context(argv)
    if not update_url:
        return

    subcommand = argv[0]
    require_update = os.getenv("AGENT_HELPER_REQUIRE_SELF_UPDATE") == "1" or subcommand == "run"
    try:
        source = _fetch_url(update_url, timeout=5.0)
        if not _looks_like_agent_script(source):
            raise RuntimeError(f"공식 agent.py 형식이 아닙니다: {update_url}")
        current = Path(__file__).read_bytes()
        remote_hash = _sha256(source)
        if _sha256(current) == remote_hash:
            return
        cached = _cache_tool(source, remote_hash)
        env = os.environ.copy()
        env["AGENT_HELPER_SELF_UPDATED"] = "1"
        env["AGENT_HELPER_SOURCE_ROOT"] = str(ROOT)
        env["AGENT_HELPER_ORIGINAL"] = str(Path(__file__).resolve())
        print(f"[agent.py] 최신 공식 helper로 재실행합니다 ({remote_hash[:12]}).", flush=True)
        os.execve(sys.executable, [sys.executable, str(cached), *argv], env)
    except Exception as exc:
        if require_update and os.getenv("AGENT_HELPER_ALLOW_STALE") != "1":
            raise SystemExit(
                "공식 agent.py 최신본 확인에 실패했습니다.\n"
                f"업데이트 URL: {update_url}\n"
                f"오류: {exc}\n"
                "coordinator 주소와 네트워크를 확인하세요. 긴급 로컬 디버그만 AGENT_HELPER_ALLOW_STALE=1로 우회할 수 있습니다."
            ) from exc
        print(f"[agent.py] 최신본 확인 실패, 현재 파일로 계속합니다: {exc}", file=sys.stderr)


def _team_suffix(team: str) -> str:
    raw = team.strip()
    if raw.lower().startswith("team"):
        raw = raw[4:]
    if raw not in {"1", "2", "3", "4", "5", "6"}:
        raise SystemExit("team은 team1~team6 중 하나여야 합니다.")
    return raw


def _image_name(mode: str, team: str) -> str:
    return f"and-{mode}-team{_team_suffix(team)}:latest"


def _run(cmd: list[str], *, cwd: Path = ROOT, env: dict[str, str] | None = None) -> int:
    print("+ " + " ".join(cmd), flush=True)
    return subprocess.run(cmd, cwd=cwd, env=env).returncode


def _json_request(method: str, url: str, *, headers: dict[str, str], body: object) -> dict:
    raw = json.dumps(body).encode("utf-8")
    request_headers = {"Content-Type": "application/json", **headers}
    req = urllib.request.Request(url, data=raw, headers=request_headers, method=method.upper())
    try:
        with urllib.request.urlopen(req, timeout=20.0) as resp:
            data = resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise SystemExit(f"HTTP {exc.code}: {detail[:500]}") from exc
    if not data:
        return {}
    return json.loads(data)


def _create_local_agent_run(args: argparse.Namespace) -> dict:
    headers = {"X-Team-Token": args.token, "X-Agent-SDK": SDK_NAME}
    if args.runner_secret:
        headers["X-Runner-Secret"] = args.runner_secret
    return _json_request(
        "POST",
        f"{args.coordinator.rstrip('/')}/agent-runs",
        headers=headers,
        body={
            "team_id": args.team,
            "mode": args.mode,
            "target_team": args.target,
            "round_num": args.round,
            "agent_image": "local-debug",
            "agent_commit": "local",
        },
    )


def _finish_local_agent_run(coordinator: str, run_token: str, status: str, error: str = "") -> None:
    try:
        _json_request(
            "POST",
            f"{coordinator.rstrip('/')}/agent/finish",
            headers={"Authorization": f"Bearer {run_token}"},
            body={"status": status, "error": error},
        )
    except Exception as exc:
        print(f"[agent.py] finish 전송 실패: {exc}", file=sys.stderr)


def build(args: argparse.Namespace) -> int:
    modes = ["attack", "defense"] if args.mode == "all" else [args.mode]
    if args.entrypoint and args.mode == "all":
        raise SystemExit("--entrypoint는 --mode attack 또는 --mode defense와 함께 사용하세요.")
    for mode in modes:
        dockerfile = ROOT / f"{mode}_agent" / "Dockerfile"
        image = args.image or _image_name(mode, args.team)
        cmd = ["docker", "build", "-f", str(dockerfile), "-t", image]
        if args.entrypoint:
            cmd.extend(["--build-arg", f"AGENT_ENTRYPOINT={args.entrypoint}"])
        cmd.append(".")
        code = _run(cmd)
        if code != 0:
            return code
        print(f"{mode} image: {image}", flush=True)
    return 0


def run_local(args: argparse.Namespace) -> int:
    run_data = _create_local_agent_run(args)
    run_id = run_data["agent_run_id"]
    run_token = run_data["agent_run_token"]
    wrapper_base = f"{args.coordinator.rstrip('/')}/openrouter/api/v1"
    env = os.environ.copy()
    env.update({
        "COORDINATOR_URL": args.coordinator,
        "TEAM_ID": args.team,
        "TEAM_TOKEN": args.token,
        "MODE": args.mode,
        "TARGET_TEAM": args.target,
        "ROUND": str(args.round),
        "AGENT_RUN_ID": run_id,
        "AGENT_RUN_TOKEN": run_token,
        "OPENAI_BASE_URL": wrapper_base,
        "OPENAI_API_KEY": run_token,
        "OPENROUTER_BASE_URL": wrapper_base,
        "OPENROUTER_API_KEY": run_token,
        "HSPACE_AGENT_BASE_URL": f"{args.coordinator.rstrip('/')}/agent",
        "TARGET_REPO_URL": f"{args.coordinator.rstrip('/')}/git/{args.target}",
    })
    if args.runner_secret:
        env["RUNNER_SECRET"] = args.runner_secret
    if args.entrypoint:
        env[f"{args.mode.upper()}_AGENT_ENTRYPOINT"] = args.entrypoint
    code = _run([sys.executable, "-m", "agent_sdk.runner"], env=env)
    _finish_local_agent_run(args.coordinator, run_token, "completed" if code == 0 else "failed")
    return code


def doctor(args: argparse.Namespace) -> int:
    env = os.environ.copy()
    env["MODE"] = args.mode
    if args.entrypoint:
        env[f"{args.mode.upper()}_AGENT_ENTRYPOINT"] = args.entrypoint
    return _run([sys.executable, "-m", "agent_sdk.runner", "--print-plan"], env=env)


def print_config(args: argparse.Namespace) -> int:
    attack = _image_name("attack", args.team)
    defense = _image_name("defense", args.team)
    print("coordinator/config.py에 아래 image 이름이 맞는지 확인하세요.\n")
    print(f'"{args.team}": "{attack}",   # ATTACK_AGENT_IMAGES')
    print(f'"{args.team}": "{defense}",  # DEFENSE_AGENT_IMAGES')
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="HSPACE attack/defense agent 단일 helper",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "자주 쓰는 명령:\n"
            "  python scripts/agent.py build team1\n"
            "  python scripts/agent.py config team1\n"
            "  python scripts/agent.py doctor --mode attack\n"
            "  python scripts/agent.py run attack --team team1 --target team3 --token <TOKEN> --runner-secret <RUNNER_SECRET>\n"
        ),
    )
    sub = parser.add_subparsers(dest="command", metavar="<command>")
    sub.required = True

    build_parser = sub.add_parser("build", help="팀 attack/defense agent 이미지 빌드")
    build_parser.add_argument("team", help="team1~team6")
    build_parser.add_argument("--mode", choices=["all", "attack", "defense"], default="all")
    build_parser.add_argument("--image", help="단일 mode 빌드 때 사용할 image 이름")
    build_parser.add_argument("--entrypoint", help="단일 mode 이미지에 고정할 agent entrypoint")
    build_parser.set_defaults(func=build)

    config_parser = sub.add_parser("config", help="coordinator/config.py에 넣을 image 이름 출력")
    config_parser.add_argument("team", help="team1~team6")
    config_parser.set_defaults(func=print_config)

    run_parser = sub.add_parser("run", help="agent를 로컬에서 디버그 실행")
    run_parser.add_argument("mode", choices=["attack", "defense"])
    run_parser.add_argument("--team", required=True, help="실행 팀, 예: team1")
    run_parser.add_argument("--target", required=True, help="대상 팀, 예: team3")
    run_parser.add_argument("--token", required=True, help="TEAM_TOKEN 또는 DEFENSE_TOKEN")
    run_parser.add_argument("--round", type=int, default=1)
    run_parser.add_argument("--coordinator", default="http://localhost:42000")
    run_parser.add_argument("--runner-secret", default=os.getenv("RUNNER_SECRET", ""))
    run_parser.add_argument("--entrypoint", help="로컬 디버그 때 사용할 agent entrypoint")
    run_parser.set_defaults(func=run_local)

    doctor_parser = sub.add_parser("doctor", help="runner가 어떤 agent entrypoint를 실행할지 확인")
    doctor_parser.add_argument("--mode", choices=["attack", "defense"], default="attack")
    doctor_parser.add_argument("--entrypoint", help="검사할 agent entrypoint override")
    doctor_parser.set_defaults(func=doctor)
    return parser


def main() -> int:
    _self_update(sys.argv[1:])
    parser = build_parser()
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
