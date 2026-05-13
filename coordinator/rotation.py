"""
Team rotation helpers.

The clockwise order is fixed in config.TEAM_ORDER:
site owner teamA is defended by teamB, teamB by teamC, and so on.
The default event uses teamA through teamG.
"""
from __future__ import annotations

from config import TEAM_ORDER


def _index(team_id: str) -> int:
    try:
        return TEAM_ORDER.index(team_id)
    except ValueError as exc:
        raise ValueError(f"unknown team: {team_id}") from exc


def get_defender(site_owner: str) -> str:
    """Return the team that defends a site owner's service."""
    idx = _index(site_owner)
    return TEAM_ORDER[(idx + 1) % len(TEAM_ORDER)]


def get_defense_target(defender: str) -> str:
    """Return the site owner defended by the given defender."""
    idx = _index(defender)
    return TEAM_ORDER[(idx - 1) % len(TEAM_ORDER)]


def get_attack_targets(attacker: str) -> list[str]:
    """Return legal attack target site owners for an attacker."""
    defense_target = get_defense_target(attacker)
    return [
        team_id
        for team_id in TEAM_ORDER
        if team_id not in {attacker, defense_target}
    ]


def assert_attack_allowed(attacker: str, target: str) -> None:
    if target not in get_attack_targets(attacker):
        raise ValueError(
            f"{attacker} cannot attack {target}; allowed targets: "
            f"{', '.join(get_attack_targets(attacker))}"
        )


def assert_defense_allowed(defender: str, target: str) -> None:
    expected = get_defense_target(defender)
    if target != expected:
        raise ValueError(f"{defender} can only defend {expected}, not {target}")
