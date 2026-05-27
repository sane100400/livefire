"""Round-end scoring snapshots for team service containers."""
from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class ScoringSnapshot:
    round_num: int
    teams: dict[str, dict]
    containers: list[str]
    image_tags: dict[str, str]


def _run_docker(args: list[str], *, check: bool = True) -> subprocess.CompletedProcess:
    result = subprocess.run(
        ["docker", *args],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    if check and result.returncode != 0:
        stderr = (result.stderr or result.stdout or "").strip()
        raise RuntimeError(f"docker {' '.join(args)} failed: {stderr[:500]}")
    return result


def _snapshot_ip(ip_prefix: str, ip_start: int, index: int) -> str:
    return f"{ip_prefix}{ip_start + index}"


def create_round_snapshot(
    *,
    round_num: int,
    teams: dict[str, dict],
    checker_token: str,
    network: str,
    ip_prefix: str,
    ip_start: int,
) -> ScoringSnapshot:
    snapshot_teams: dict[str, dict] = {}
    containers: list[str] = []
    image_tags: dict[str, str] = {}

    try:
        for index, (team_id, info) in enumerate(teams.items()):
            docker_team = team_id.lower()
            source_image = f"and-service-{docker_team}:latest"
            snapshot_image = f"and-service-{docker_team}:round{round_num}-snapshot"
            container = f"and-score-r{round_num}-{docker_team}"
            ip = _snapshot_ip(ip_prefix, ip_start, index)

            _run_docker(["image", "inspect", source_image])
            _run_docker(["tag", source_image, snapshot_image])
            _run_docker(["rm", "-f", container], check=False)
            _run_docker([
                "run",
                "-d",
                "--name", container,
                "--network", network,
                "--ip", ip,
                "--cpus", "0.5",
                "--memory", "1g",
                "-e", f"CHECKER_TOKEN={checker_token}",
                snapshot_image,
            ])

            containers.append(container)
            image_tags[team_id] = snapshot_image
            snapshot_teams[team_id] = {
                **info,
                "ip": ip,
                "snapshot_container": container,
                "snapshot_image": snapshot_image,
            }
            logger.info(
                "scoring snapshot started: round=%d team=%s image=%s ip=%s",
                round_num,
                team_id,
                snapshot_image,
                ip,
            )
    except Exception:
        cleanup_round_snapshot(ScoringSnapshot(round_num, snapshot_teams, containers, image_tags))
        raise

    return ScoringSnapshot(round_num, snapshot_teams, containers, image_tags)


def cleanup_round_snapshot(snapshot: ScoringSnapshot) -> None:
    for container in snapshot.containers:
        try:
            _run_docker(["rm", "-f", container], check=False)
        except Exception as exc:
            logger.warning("scoring snapshot cleanup failed: container=%s error=%s", container, exc)
