"""
PoC execution and scoring.

Submitted Python PoCs run once per round after static validation. The production
path executes them in a restricted Docker container attached only to target-net;
local mode remains for unit tests and offline development.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Optional

import db
from flag_manager import extract_flags_from_text


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _decode(data: bytes) -> str:
    return data.decode("utf-8", errors="replace")


def _last_non_empty_line(text: str) -> str:
    for line in reversed(text.splitlines()):
        stripped = line.strip()
        if stripped:
            return stripped
    return ""


def _result_dir(data_dir: str, round_num: int, poc_id: str) -> Path:
    path = Path(data_dir) / "poc_runs" / str(round_num) / poc_id
    path.mkdir(parents=True, exist_ok=True)
    return path


def _validate_flag(flag: str, round_num: int, target_team: str, flag_id: str) -> bool:
    record = db.lookup_flag(flag)
    if not record:
        return False
    return (
        record["round_num"] == round_num
        and record["team_id"] == target_team
        and record["vuln_id"] == flag_id
    )


def run_pocs_for_round(
    round_num: int,
    teams: dict,
    data_dir: str,
    timeout_sec: int,
    output_max_bytes: int,
    attack_reward: int,
    attack_penalty: int,
    poc_timeout_overrides: Optional[dict[str, dict[str, int]]] = None,
    only_poc_id: Optional[str] = None,
    runner_mode: str = "auto",
    docker_network: str = "hackathon_target-net",
    docker_image: str = "python:3.11-slim",
    host_data_dir: str = "",
) -> list[dict]:
    results: list[dict] = []
    service_statuses = db.get_service_statuses()
    successful_keys = db.get_successful_poc_keys(round_num)

    for poc in db.get_runnable_pocs(round_num, only_poc_id):
        existing = db.get_poc_result(round_num, poc["id"])
        if existing:
            existing = dict(existing)
            existing["already_ran"] = True
            results.append(existing)
            continue

        success_key = (poc["attacker_team"], poc["target_team"], poc["flag_id"])
        if success_key in successful_keys:
            _record_result(
                round_num,
                poc,
                "skipped_already_scored",
                [],
                False,
                0,
                0,
                detail="a PoC already scored for this attacker/target/vuln in this round",
            )
            results.append(db.get_poc_result(round_num, poc["id"]) or {})
            continue

        target_team = poc["target_team"]
        target_info = teams.get(target_team)
        if not target_info:
            _record_result(round_num, poc, "runner_error", [], False, 0, 0, detail="unknown target team")
            results.append(db.get_poc_result(round_num, poc["id"]) or {})
            continue

        if service_statuses.get(target_team, "UNKNOWN") == "DOWN":
            _record_result(round_num, poc, "skipped_down", [], False, 0, 0, detail="target service is DOWN")
            results.append(db.get_poc_result(round_num, poc["id"]) or {})
            continue

        started = time.monotonic()
        stdout = b""
        stderr = b""
        exit_code: Optional[int] = None
        status = "failed"
        detail = ""

        env = {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "PYTHONUNBUFFERED": "1",
            "TARGET_HOST": str(target_info["ip"]),
            "TARGET_PORT": str(target_info["port"]),
            "TARGET_TEAM": target_team,
            "FLAG_ID": poc["flag_id"],
        }
        poc_timeout_sec = (
            (poc_timeout_overrides or {})
            .get(target_team, {})
            .get(poc["flag_id"], timeout_sec)
        )

        try:
            completed = _execute_poc(
                poc_path=Path(poc["storage_path"]),
                env=env,
                timeout_sec=poc_timeout_sec,
                runner_mode=runner_mode,
                docker_network=docker_network,
                docker_image=docker_image,
                container_data_dir=data_dir,
                host_data_dir=host_data_dir,
            )
            stdout = completed.stdout[:output_max_bytes]
            stderr = completed.stderr[:output_max_bytes]
            exit_code = completed.returncode
        except subprocess.TimeoutExpired as exc:
            stdout = (exc.stdout or b"")[:output_max_bytes]
            stderr = (exc.stderr or b"")[:output_max_bytes]
            status = "timeout"
            detail = f"timeout after {poc_timeout_sec}s"
        except Exception as exc:
            status = "runner_error"
            detail = str(exc)

        duration_ms = int((time.monotonic() - started) * 1000)
        stdout_text = _decode(stdout)
        stderr_text = _decode(stderr)
        combined = stdout_text + "\n" + stderr_text
        final_stdout_line = _last_non_empty_line(stdout_text)
        flags = extract_flags_from_text(final_stdout_line)
        valid_flags = [
            flag
            for flag in flags
            if _validate_flag(flag, round_num, target_team, poc["flag_id"])
        ]

        scored = bool(valid_flags) and status not in {"timeout", "runner_error"}
        if scored:
            status = "success"
            attacker_delta = attack_reward
            defender_delta = -attack_penalty
        else:
            attacker_delta = 0
            defender_delta = 0
            if status not in {"timeout", "runner_error"}:
                status = "failed"
                if extract_flags_from_text(combined) and not valid_flags:
                    detail = "valid flag must be printed on the final non-empty stdout line"

        run_dir = _result_dir(data_dir, round_num, poc["id"])
        (run_dir / "stdout.txt").write_bytes(stdout)
        (run_dir / "stderr.txt").write_bytes(stderr)

        inserted = _record_result(
            round_num,
            poc,
            status,
            valid_flags,
            scored,
            attacker_delta,
            defender_delta,
            exit_code=exit_code,
            duration_ms=duration_ms,
            stdout_hash=_sha256(stdout),
            stderr_hash=_sha256(stderr),
            detail=detail,
        )

        if inserted and scored:
            db.update_score(poc["attacker_team"], attacker_delta)
            db.update_score(poc["defender_team"], defender_delta)
            db.record_exploit(poc["attacker_team"], poc["defender_team"], round_num)
            successful_keys.add(success_key)

        results.append(db.get_poc_result(round_num, poc["id"]) or {})

    return results


def _execute_poc(
    poc_path: Path,
    env: dict[str, str],
    timeout_sec: int,
    runner_mode: str,
    docker_network: str,
    docker_image: str,
    container_data_dir: str,
    host_data_dir: str,
) -> subprocess.CompletedProcess:
    mode = runner_mode.lower()
    if mode not in {"auto", "docker", "local"}:
        raise RuntimeError(f"invalid POC_RUNNER_MODE: {runner_mode}")
    if mode in {"auto", "docker"} and shutil.which("docker"):
        try:
            return _execute_poc_docker(
                poc_path,
                env,
                timeout_sec,
                docker_network,
                docker_image,
                container_data_dir,
                host_data_dir,
            )
        except Exception:
            if mode == "docker":
                raise
    if mode == "docker":
        raise RuntimeError("docker runner requested but docker is unavailable")
    return _execute_poc_local(poc_path, env, timeout_sec)


def _execute_poc_local(
    poc_path: Path,
    env: dict[str, str],
    timeout_sec: int,
) -> subprocess.CompletedProcess:
    with tempfile.TemporaryDirectory(prefix=f"poc-local-") as workdir:
        return subprocess.run(
            ["python3", str(poc_path)],
            cwd=workdir,
            env=env,
            capture_output=True,
            timeout=timeout_sec,
        )


def _execute_poc_docker(
    poc_path: Path,
    env: dict[str, str],
    timeout_sec: int,
    docker_network: str,
    docker_image: str,
    container_data_dir: str,
    host_data_dir: str,
) -> subprocess.CompletedProcess:
    abs_poc = poc_path.resolve()
    mount_poc = _host_mount_path(abs_poc, Path(container_data_dir).resolve(), host_data_dir)
    cmd = [
        "docker", "run", "--rm",
        "--network", docker_network,
        "--cpus", "0.5",
        "--memory", "256m",
        "--pids-limit", "64",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--read-only",
        "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m",
        "-v", f"{mount_poc}:/poc/poc.py:ro",
    ]
    for key, value in env.items():
        if key in {"TARGET_HOST", "TARGET_PORT", "TARGET_TEAM", "FLAG_ID", "PYTHONUNBUFFERED"}:
            cmd.extend(["-e", f"{key}={value}"])
    cmd.extend([docker_image, "python", "/poc/poc.py"])
    return subprocess.run(
        cmd,
        capture_output=True,
        timeout=timeout_sec + 5,
    )


def _host_mount_path(abs_poc: Path, container_data_dir: Path, host_data_dir: str) -> Path:
    if not host_data_dir:
        return abs_poc
    try:
        relative = abs_poc.relative_to(container_data_dir)
    except ValueError:
        return abs_poc
    return Path(host_data_dir).resolve() / relative


def _record_result(
    round_num: int,
    poc: dict,
    status: str,
    flags: list[str],
    scored: bool,
    attacker_delta: int,
    defender_delta: int,
    exit_code: Optional[int] = None,
    duration_ms: Optional[int] = None,
    stdout_hash: Optional[str] = None,
    stderr_hash: Optional[str] = None,
    detail: str = "",
) -> bool:
    return db.insert_poc_result(
        round_num=round_num,
        poc_id=poc["id"],
        attacker_team=poc["attacker_team"],
        target_team=poc["target_team"],
        defender_team=poc["defender_team"],
        flag_id=poc["flag_id"],
        status=status,
        flags=flags,
        scored=scored,
        attacker_delta=attacker_delta,
        defender_delta=defender_delta,
        exit_code=exit_code,
        duration_ms=duration_ms,
        stdout_hash=stdout_hash,
        stderr_hash=stderr_hash,
        detail=detail,
    )
