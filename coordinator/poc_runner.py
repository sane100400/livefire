"""
PoC execution and scoring.

MVP runner executes accepted Python PoCs with a constrained environment and
per-run working directory. Production deployment should wrap this command in
a network-restricted container attached only to target-net.
"""
from __future__ import annotations

import hashlib
import os
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
    only_poc_id: Optional[str] = None,
) -> list[dict]:
    results: list[dict] = []
    service_statuses = db.get_service_statuses()

    for poc in db.get_accepted_pocs(only_poc_id):
        existing = db.get_poc_result(round_num, poc["id"])
        if existing:
            existing = dict(existing)
            existing["already_ran"] = True
            results.append(existing)
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

        try:
            with tempfile.TemporaryDirectory(prefix=f"poc-{poc['id']}-") as workdir:
                completed = subprocess.run(
                    ["python3", poc["storage_path"]],
                    cwd=workdir,
                    env=env,
                    capture_output=True,
                    timeout=timeout_sec,
                )
            stdout = completed.stdout[:output_max_bytes]
            stderr = completed.stderr[:output_max_bytes]
            exit_code = completed.returncode
        except subprocess.TimeoutExpired as exc:
            stdout = (exc.stdout or b"")[:output_max_bytes]
            stderr = (exc.stderr or b"")[:output_max_bytes]
            status = "timeout"
            detail = f"timeout after {timeout_sec}s"
        except Exception as exc:
            status = "runner_error"
            detail = str(exc)

        duration_ms = int((time.monotonic() - started) * 1000)
        combined = _decode(stdout) + "\n" + _decode(stderr)
        flags = extract_flags_from_text(combined)
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

        results.append(db.get_poc_result(round_num, poc["id"]) or {})

    return results


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
