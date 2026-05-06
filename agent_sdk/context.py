"""
Small SDK used by team attack/defense agents.

The SDK owns coordinator provenance fields: agent run creation, run id reuse,
LLM gateway calls, PoC upload metadata, and defense commit trailers.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

import httpx


class AgentSDKError(RuntimeError):
    pass


@dataclass
class AgentContext:
    coordinator_url: str
    team_id: str
    team_token: str
    mode: str
    target_team: str
    round_num: int
    agent_run_id: str
    allowed_models: list[str]

    @classmethod
    def from_env(cls) -> "AgentContext":
        coordinator_url = os.environ["COORDINATOR_URL"].rstrip("/")
        team_id = os.environ.get("TEAM_ID") or os.environ.get("ATTACKER_TEAM")
        if not team_id:
            raise AgentSDKError("TEAM_ID env is required")
        team_token = os.environ["TEAM_TOKEN"]
        mode = os.environ.get("MODE", "attack")
        target_team = os.environ["TARGET_TEAM"]
        round_num = int(os.environ["ROUND"])

        existing_run = os.environ.get("AGENT_RUN_ID")
        if existing_run:
            return cls(
                coordinator_url=coordinator_url,
                team_id=team_id,
                team_token=team_token,
                mode=mode,
                target_team=target_team,
                round_num=round_num,
                agent_run_id=existing_run,
                allowed_models=[],
            )

        resp = httpx.post(
            f"{coordinator_url}/agent-runs",
            headers={"X-Team-Token": team_token},
            json={
                "team_id": team_id,
                "mode": mode,
                "target_team": target_team,
                "round_num": round_num,
                "agent_image": os.environ.get("AGENT_IMAGE"),
                "agent_image_digest": os.environ.get("AGENT_IMAGE_DIGEST"),
                "agent_commit": os.environ.get("AGENT_COMMIT"),
            },
            timeout=15.0,
        )
        if resp.status_code >= 400:
            raise AgentSDKError(f"/agent-runs failed: HTTP {resp.status_code} {resp.text[:300]}")
        data = resp.json()
        return cls(
            coordinator_url=coordinator_url,
            team_id=team_id,
            team_token=team_token,
            mode=mode,
            target_team=target_team,
            round_num=round_num,
            agent_run_id=data["agent_run_id"],
            allowed_models=data.get("allowed_models", []),
        )

    def finish(self, status: str = "completed", error: str = "") -> None:
        resp = httpx.post(
            f"{self.coordinator_url}/agent-runs/{self.agent_run_id}/finish",
            headers={"X-Team-Token": self.team_token},
            json={"status": status, "error": error},
            timeout=10.0,
        )
        if resp.status_code >= 400:
            raise AgentSDKError(f"finish failed: HTTP {resp.status_code} {resp.text[:300]}")

    def llm(
        self,
        model: str,
        messages: list[dict[str, Any]],
        temperature: float = 0.2,
        max_tokens: int = 2048,
        purpose: str = "general",
    ) -> dict:
        resp = httpx.post(
            f"{self.coordinator_url}/llm",
            headers={"X-Team-Token": self.team_token},
            json={
                "agent_run_id": self.agent_run_id,
                "model": model,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
                "purpose": purpose,
            },
            timeout=75.0,
        )
        if resp.status_code >= 400:
            raise AgentSDKError(f"/llm failed: HTTP {resp.status_code} {resp.text[:300]}")
        return resp.json()

    def attack(
        self,
        payload: str,
        llm_call_id: int,
        target_team: Optional[str] = None,
        session_id: Optional[str] = None,
        history: Optional[list[dict[str, Any]]] = None,
    ) -> dict:
        target = target_team or self.target_team
        resp = httpx.post(
            f"{self.coordinator_url}/attack",
            headers={"X-Team-Token": self.team_token},
            json={
                "agent_run_id": self.agent_run_id,
                "llm_call_id": llm_call_id,
                "attacker_team": self.team_id,
                "target_team": target,
                "payload": payload,
                "session_id": session_id,
                "history": history,
            },
            timeout=40.0,
        )
        if resp.status_code >= 400:
            raise AgentSDKError(f"/attack failed: HTTP {resp.status_code} {resp.text[:300]}")
        return resp.json()

    def submit_poc(
        self,
        path: str | Path,
        llm_call_id: int,
        target_team: Optional[str] = None,
        flag_id: str = "vuln1",
    ) -> dict:
        poc_path = Path(path)
        data = poc_path.read_bytes()
        sha256 = hashlib.sha256(data).hexdigest()
        target = target_team or self.target_team
        with poc_path.open("rb") as fh:
            resp = httpx.post(
                f"{self.coordinator_url}/pocs",
                headers={"X-Team-Token": self.team_token},
                data={
                    "agent_run_id": self.agent_run_id,
                    "llm_call_id": str(llm_call_id),
                    "attacker_team": self.team_id,
                    "target_team": target,
                    "flag_id": flag_id,
                    "sha256": sha256,
                },
                files={"file": (poc_path.name, fh, "text/x-python")},
                timeout=30.0,
            )
        if resp.status_code >= 400:
            raise AgentSDKError(f"/pocs failed: HTTP {resp.status_code} {resp.text[:300]}")
        return resp.json()

    def commit_patch(self, message: str, repo_dir: str | Path = ".") -> str:
        if self.mode != "defense":
            raise AgentSDKError("commit_patch is only available in defense mode")
        repo = Path(repo_dir)
        full_message = f"{message.rstrip()}\n\nAgent-Run-ID: {self.agent_run_id}"
        subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
        subprocess.run(["git", "commit", "-m", full_message], cwd=repo, check=True)
        result = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=repo,
            check=True,
            capture_output=True,
            text=True,
        )
        return result.stdout.strip()


def write_json(path: str | Path, data: object) -> None:
    Path(path).write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
