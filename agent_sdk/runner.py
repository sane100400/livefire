"""Compatibility runner for attack/defense agent entrypoints.

The coordinator and local helper both invoke this module. It resolves the
participant's actual agent code from environment variables, a small manifest,
or the default template paths, then execs it with the runner-provided env.
"""
from __future__ import annotations

import argparse
import json
import os
import shlex
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


MANIFEST_NAMES = ("agent_manifest.json", "agent.json")


class AgentRunnerError(RuntimeError):
    pass


@dataclass
class Entrypoint:
    mode: str
    command: list[str]
    cwd: Path
    source: str


def _repo_root() -> Path:
    return Path(os.getenv("AGENT_WORKDIR", os.getcwd())).resolve()


def _mode() -> str:
    mode = os.getenv("MODE", "attack").strip().lower()
    if mode not in {"attack", "defense"}:
        raise AgentRunnerError("MODE는 attack 또는 defense만 허용")
    return mode


def _safe_cwd(root: Path, raw: str | None) -> Path:
    cwd = (root / (raw or ".")).resolve()
    try:
        cwd.relative_to(root)
    except ValueError as exc:
        raise AgentRunnerError(f"agent cwd가 작업 디렉터리 밖입니다: {raw}") from exc
    if not cwd.exists():
        raise AgentRunnerError(f"agent cwd가 없습니다: {cwd}")
    return cwd


def _command_from_value(value: str, root: Path) -> list[str]:
    parts = shlex.split(value)
    if not parts:
        raise AgentRunnerError("빈 agent entrypoint")
    if len(parts) == 1:
        item = parts[0]
        candidate = (root / item).resolve()
        if item.endswith(".py") or candidate.exists():
            if not candidate.exists():
                raise AgentRunnerError(f"agent script가 없습니다: {candidate}")
            return [sys.executable, item]
        return [sys.executable, "-m", item]
    return parts


def _script_command(cwd: Path, raw_path: str) -> list[str]:
    candidate = (cwd / raw_path).resolve()
    try:
        candidate.relative_to(cwd)
    except ValueError as exc:
        raise AgentRunnerError(f"agent script가 cwd 밖입니다: {raw_path}") from exc
    if not candidate.exists():
        raise AgentRunnerError(f"agent script가 없습니다: {candidate}")
    return [sys.executable, raw_path]


def _load_manifest(root: Path) -> tuple[Path, dict[str, Any]] | None:
    for name in MANIFEST_NAMES:
        path = root / name
        if path.exists():
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise AgentRunnerError(f"{name}은 JSON object여야 합니다")
            return path, data
    return None


def _entry_from_manifest(root: Path, mode: str) -> Entrypoint | None:
    loaded = _load_manifest(root)
    if not loaded:
        return None
    manifest_path, manifest = loaded
    spec = manifest.get(mode)
    if spec is None:
        return None
    if isinstance(spec, str):
        return Entrypoint(mode, _command_from_value(spec, root), root, str(manifest_path))
    if not isinstance(spec, dict):
        raise AgentRunnerError(f"{manifest_path.name}.{mode}는 string 또는 object여야 합니다")

    cwd = _safe_cwd(root, spec.get("cwd"))
    if "cmd" in spec:
        raw = spec["cmd"]
        if isinstance(raw, list):
            command = [str(item) for item in raw]
        elif isinstance(raw, str):
            command = _command_from_value(raw, cwd)
        else:
            raise AgentRunnerError("cmd는 string 또는 list여야 합니다")
    elif "module" in spec:
        command = [sys.executable, "-m", str(spec["module"])]
    elif "path" in spec:
        command = _script_command(cwd, str(spec["path"]))
    else:
        raise AgentRunnerError(f"{manifest_path.name}.{mode}에 cmd/module/path 중 하나가 필요합니다")
    return Entrypoint(mode, command, cwd, str(manifest_path))


def resolve_entrypoint(mode: str | None = None, root: Path | None = None) -> Entrypoint:
    root = (root or _repo_root()).resolve()
    mode = mode or _mode()

    env_value = os.getenv(f"{mode.upper()}_AGENT_ENTRYPOINT") or os.getenv("AGENT_ENTRYPOINT")
    if env_value:
        return Entrypoint(mode, _command_from_value(env_value, root), root, "environment")

    manifest_entry = _entry_from_manifest(root, mode)
    if manifest_entry:
        return manifest_entry

    script = root / f"{mode}_agent" / "main.py"
    if script.exists():
        return Entrypoint(mode, [sys.executable, str(script.relative_to(root))], root, "default")

    module_dir = root / f"{mode}_agent"
    if (module_dir / "__main__.py").exists():
        return Entrypoint(mode, [sys.executable, "-m", f"{mode}_agent"], root, "default")

    raise AgentRunnerError(
        f"{mode} agent entrypoint를 찾을 수 없습니다. "
        "agent_manifest.json 또는 AGENT_ENTRYPOINT를 설정하세요."
    )


def _print_plan(entry: Entrypoint) -> None:
    print(json.dumps({
        "mode": entry.mode,
        "cwd": str(entry.cwd),
        "command": entry.command,
        "source": entry.source,
    }, indent=2, ensure_ascii=False))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Resolve and run HSPACE attack/defense agent entrypoints")
    parser.add_argument("--print-plan", action="store_true", help="entrypoint 해석 결과만 출력")
    args = parser.parse_args(argv)

    try:
        entry = resolve_entrypoint()
    except Exception as exc:
        print(f"[agent-runner] {exc}", file=sys.stderr)
        return 2

    if args.print_plan:
        _print_plan(entry)
        return 0

    print(
        f"[agent-runner] mode={entry.mode} source={entry.source} cwd={entry.cwd} cmd={' '.join(entry.command)}",
        flush=True,
    )
    return subprocess.run(entry.command, cwd=entry.cwd, env=os.environ.copy()).returncode


if __name__ == "__main__":
    raise SystemExit(main())
