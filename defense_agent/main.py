"""Defense agent template using agent_sdk.

The template performs a full provenance-safe loop:
  1. clone assigned target repo from coordinator git HTTP
  2. ask the whitelisted LLM for a machine-applicable patch
  3. apply the patch, commit with Agent-Run-ID trailer, and push
"""
from __future__ import annotations

import json
import os
import re
import subprocess
from pathlib import Path

from agent_sdk import AgentContext, AgentSDKError

MODEL = os.getenv("MODEL", "openai/gpt-4o-mini")
REPO_DIR = Path(os.getenv("REPO_DIR", "target_repo"))
MAX_REPO_FILES = int(os.getenv("MAX_REPO_FILES", "28"))
MAX_REPO_PROMPT_BYTES = int(os.getenv("MAX_REPO_PROMPT_BYTES", str(64 * 1024)))
MAX_REPO_FILE_BYTES = int(os.getenv("MAX_REPO_FILE_BYTES", str(10 * 1024)))
TEXT_SUFFIXES = {".py", ".js", ".ts", ".tsx", ".jsx", ".json", ".yaml", ".yml", ".toml", ".md", ".txt", ".html", ".css", ".sh"}
IMPORTANT_NAMES = {"dockerfile", "requirements.txt", "pyproject.toml", "package.json", "vuln_spec.json", "app.py", "main.py", "server.py"}
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", ".mypy_cache", ".venv", "venv", "node_modules", "dist", "build"}


def _json_from_text(text: str) -> dict:
    match = re.search(r"```(?:json)?\s*(.*?)```", text, flags=re.S)
    raw = match.group(1) if match else text
    data = json.loads(raw)
    if not isinstance(data, dict):
        raise ValueError("defense LLM response must be a JSON object")
    return data


def _candidate_file(path: Path) -> bool:
    name = path.name.lower()
    return name in IMPORTANT_NAMES or path.suffix.lower() in TEXT_SUFFIXES


def _priority(path: Path) -> tuple[int, str]:
    name = path.name.lower()
    if name == "vuln_spec.json":
        return 0, str(path)
    if name in {"main.py", "app.py", "server.py"}:
        return 1, str(path)
    if name in IMPORTANT_NAMES:
        return 2, str(path)
    if path.suffix.lower() == ".py":
        return 3, str(path)
    return 4, str(path)


def load_repo_context(root: Path, commit: str) -> str:
    chunks = [f"Target commit: {commit}"]
    total = sum(len(c.encode("utf-8")) for c in chunks)
    included = 0
    files = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        rel_parts = path.relative_to(root).parts
        if any(part in SKIP_DIRS for part in rel_parts):
            continue
        if _candidate_file(path):
            files.append(path)
    for path in sorted(files, key=_priority):
        if included >= MAX_REPO_FILES or total >= MAX_REPO_PROMPT_BYTES:
            break
        raw = path.read_bytes()
        if b"\x00" in raw:
            continue
        text = raw[:MAX_REPO_FILE_BYTES].decode("utf-8", errors="replace")
        chunk = f"\n\n### {path.relative_to(root)}\n```\n{text}\n```"
        size = len(chunk.encode("utf-8"))
        if total + size > MAX_REPO_PROMPT_BYTES:
            break
        chunks.append(chunk)
        total += size
        included += 1
    return "".join(chunks)


def apply_llm_patch(repo: Path, data: dict) -> int:
    changed = 0
    patch = data.get("patch")
    if isinstance(patch, str) and patch.strip():
        proc = subprocess.run(["git", "apply", "--whitespace=fix", "-"], cwd=repo, input=patch, text=True)
        if proc.returncode != 0:
            raise AgentSDKError("git apply failed for LLM patch")
        changed += 1

    files = data.get("files", [])
    if files:
        if not isinstance(files, list):
            raise ValueError("'files' must be a list")
        root = repo.resolve()
        for item in files:
            if not isinstance(item, dict):
                continue
            rel = str(item.get("path") or "")
            content = item.get("content")
            if not rel or not isinstance(content, str):
                continue
            target = (root / rel).resolve()
            target.relative_to(root)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            changed += 1
    return changed


def syntax_check(repo: Path) -> None:
    py_files = [str(p.relative_to(repo)) for p in repo.rglob("*.py") if ".git" not in p.parts]
    if py_files:
        subprocess.run(["python", "-m", "py_compile", *py_files], cwd=repo, check=True)


def main() -> None:
    ctx = AgentContext.from_env()
    print(f"[{ctx.team_id}] defense run {ctx.agent_run_id} target={ctx.target_team} round={ctx.round_num}")
    try:
        repo_info = ctx.clone_target_repo(REPO_DIR)
        repo = Path(repo_info["path"])
        context = load_repo_context(repo, repo_info["commit"])
        resp = ctx.llm(
            model=MODEL,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are an autonomous CTF defense agent. Return only JSON. "
                        "Patch the target service vulnerabilities while preserving /health, /chat, "
                        "/admin/inject, /admin/check and the documented checker behavior. "
                        "Prefer minimal edits. Output either {'patch': '<unified diff>'} or "
                        "{'files': [{'path': 'relative/path', 'content': 'full file content'}], 'summary': '...'}."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(
                        {
                            "target_team": ctx.target_team,
                            "repo_commit": repo_info["commit"],
                            "repo_snapshot": context,
                        },
                        ensure_ascii=False,
                    ),
                }
            ],
            max_tokens=4096,
            purpose="defense",
        )
        patch_data = _json_from_text(resp["content"])
        changed = apply_llm_patch(repo, patch_data)
        if not changed:
            raise AgentSDKError("defense LLM returned no applicable changes")
        syntax_check(repo)
        summary = str(patch_data.get("summary") or f"defense patch for {ctx.target_team}")[:120]
        commit = ctx.commit_patch(summary, repo_dir=repo)
        ctx.push_repo(repo_dir=repo, repo_team=ctx.target_team)
        print(f"  pushed defense commit {commit[:12]}")
        ctx.finish("completed")
    except Exception as exc:
        try:
            ctx.finish("failed", str(exc))
        finally:
            raise


if __name__ == "__main__":
    main()
