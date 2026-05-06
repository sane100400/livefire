"""
Defense agent template using agent_sdk.

This is a minimal provenance-safe wrapper. Team implementations should inspect
the checked-out target repo, patch it, then call ctx.commit_patch().
"""
from __future__ import annotations

import os
from pathlib import Path

from agent_sdk import AgentContext

MODEL = os.getenv("MODEL", "openai/gpt-4o-mini")
REPO_DIR = Path(os.getenv("REPO_DIR", "."))


def main() -> None:
    ctx = AgentContext.from_env()
    print(f"[{ctx.team_id}] defense run {ctx.agent_run_id} target={ctx.target_team} round={ctx.round_num}")
    try:
        ctx.llm(
            model=MODEL,
            messages=[
                {
                    "role": "user",
                    "content": (
                        f"Review the checked-out repo for {ctx.target_team}. "
                        "Patch vulnerabilities while preserving /health, /chat, /admin/inject, /admin/check."
                    ),
                }
            ],
            max_tokens=1024,
            purpose="defense",
        )
        if (REPO_DIR / ".git").exists():
            print("repo detected; call ctx.commit_patch('message') after applying changes")
        ctx.finish("completed")
    except Exception as exc:
        try:
            ctx.finish("failed", str(exc))
        finally:
            raise


if __name__ == "__main__":
    main()
