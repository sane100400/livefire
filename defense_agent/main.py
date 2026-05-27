"""
Defense agent template.

Participants may replace everything in this file. The only required contract is
to use the injected coordinator wrapper URLs and tokens, then push a patch
commit that contains the current Agent-Run-ID.
"""
from __future__ import annotations

import base64
import json
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

MODEL = os.getenv("MODEL", "openai/gpt-4o-mini")
REPO_DIR = Path(os.getenv("REPO_DIR", "target_repo"))
MAX_REPO_FILES = int(os.getenv("MAX_REPO_FILES", "28"))
MAX_REPO_PROMPT_BYTES = int(os.getenv("MAX_REPO_PROMPT_BYTES", str(64 * 1024)))
MAX_REPO_FILE_BYTES = int(os.getenv("MAX_REPO_FILE_BYTES", str(10 * 1024)))
TEXT_SUFFIXES = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".json",
    ".yaml",
    ".yml",
    ".toml",
    ".md",
    ".txt",
    ".html",
    ".css",
    ".sh",
}
IMPORTANT_NAMES = {
    "dockerfile",
    "requirements.txt",
    "pyproject.toml",
    "package.json",
    "vuln_spec.json",
    "app.py",
    "main.py",
    "server.py",
}
SKIP_DIRS = {".git", "__pycache__", ".pytest_cache", ".mypy_cache", ".venv", "venv", "node_modules", "dist", "build"}


@dataclass(frozen=True)
class AgentEnv:
    team_id: str
    team_token: str
    target_team: str
    round_num: int
    run_id: str
    run_token: str
    openrouter_base_url: str
    agent_base_url: str
    target_repo_url: str

    @classmethod
    def from_env(cls) -> "AgentEnv":
        coordinator_url = os.environ["COORDINATOR_URL"].rstrip("/")
        target_team = os.environ["TARGET_TEAM"]
        return cls(
            team_id=os.environ["TEAM_ID"],
            team_token=os.environ["TEAM_TOKEN"],
            target_team=target_team,
            round_num=int(os.environ["ROUND"]),
            run_id=os.environ["AGENT_RUN_ID"],
            run_token=os.environ["AGENT_RUN_TOKEN"],
            openrouter_base_url=os.environ["OPENROUTER_BASE_URL"].rstrip("/"),
            agent_base_url=os.environ["HSPACE_AGENT_BASE_URL"].rstrip("/"),
            target_repo_url=os.getenv("TARGET_REPO_URL") or f"{coordinator_url}/git/{target_team}",
        )

    @property
    def auth(self) -> dict[str, str]:
        return {"Authorization": f"Bearer {self.run_token}"}


def _check_response(resp: httpx.Response, label: str) -> None:
    if resp.status_code >= 400:
        raise RuntimeError(f"{label} failed: HTTP {resp.status_code} {resp.text[:300]}")


def call_llm(
    env: AgentEnv,
    *,
    messages: list[dict[str, Any]],
    max_tokens: int,
    temperature: float = 0.2,
) -> tuple[int, str]:
    resp = httpx.post(
        f"{env.openrouter_base_url}/chat/completions",
        headers={**env.auth, "X-Agent-Purpose": "defense"},
        json={
            "model": MODEL,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        },
        timeout=75.0,
    )
    _check_response(resp, "LLM wrapper")
    data = resp.json()
    llm_call_id = resp.headers.get("X-LLM-Call-ID") or (data.get("hspace") or {}).get("llm_call_id")
    if not llm_call_id:
        raise RuntimeError("LLM wrapper response did not include X-LLM-Call-ID")
    choices = data.get("choices") or []
    content = ((choices[0] if choices else {}).get("message") or {}).get("content") or ""
    return int(llm_call_id), content


def finish(env: AgentEnv, status: str, error: str = "") -> None:
    try:
        httpx.post(
            f"{env.agent_base_url}/finish",
            headers=env.auth,
            json={"status": status, "error": error},
            timeout=10.0,
        )
    except Exception as exc:
        print(f"finish failed: {exc}")


def _git_auth_header(env: AgentEnv) -> str:
    raw = f"{env.team_id}:{env.team_token}".encode("utf-8")
    return "Authorization: Basic " + base64.b64encode(raw).decode("ascii")


def clone_target_repo(env: AgentEnv, dest: Path) -> dict[str, str]:
    if dest.exists() and any(dest.iterdir()):
        raise RuntimeError(f"destination is not empty: {dest}")
    dest.parent.mkdir(parents=True, exist_ok=True)
    result = subprocess.run(
        [
            "git",
            "-c",
            f"http.extraHeader={_git_auth_header(env)}",
            "clone",
            "--depth",
            "1",
            env.target_repo_url,
            str(dest),
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git clone failed: {result.stderr[-500:]}")
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"],
        cwd=dest,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.strip()
    return {"path": str(dest), "team": env.target_team, "commit": commit, "url": env.target_repo_url}


def push_repo(env: AgentEnv, repo: Path, branch: str = "main") -> None:
    result = subprocess.run(
        ["git", "-c", f"http.extraHeader={_git_auth_header(env)}", "push", env.target_repo_url, f"HEAD:{branch}"],
        cwd=repo,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"git push failed: {result.stderr[-800:]}")


def commit_patch(env: AgentEnv, repo: Path, message: str) -> str:
    full_message = f"{message.rstrip()}\n\nAgent-Run-ID: {env.run_id}"
    subprocess.run(["git", "add", "-A"], cwd=repo, check=True)
    staged = subprocess.run(["git", "diff", "--cached", "--quiet"], cwd=repo)
    if staged.returncode == 0:
        raise RuntimeError("no staged defense patch changes to commit")
    subprocess.run(["git", "commit", "-m", full_message], cwd=repo, check=True)
    result = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, check=True, capture_output=True, text=True)
    return result.stdout.strip()


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
            raise RuntimeError("git apply failed for LLM patch")
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
    env = AgentEnv.from_env()
    print(f"[{env.team_id}] defense run {env.run_id} target={env.target_team} round={env.round_num}")
    try:
        repo_info = clone_target_repo(env, REPO_DIR)
        repo = Path(repo_info["path"])
        context = load_repo_context(repo, repo_info["commit"])
        _, content = call_llm(
            env,
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
                            "target_team": env.target_team,
                            "repo_commit": repo_info["commit"],
                            "repo_snapshot": context,
                        },
                        ensure_ascii=False,
                    ),
                },
            ],
            max_tokens=4096,
        )
        patch_data = _json_from_text(content)
        changed = apply_llm_patch(repo, patch_data)
        if not changed:
            raise RuntimeError("defense LLM returned no applicable changes")
        syntax_check(repo)
        summary = str(patch_data.get("summary") or f"defense patch for {env.target_team}")[:120]
        commit = commit_patch(env, repo, summary)
        push_repo(env, repo)
        print(f"  pushed defense commit {commit[:12]}")
        finish(env, "completed")
    except Exception as exc:
        finish(env, "failed", str(exc))
        raise


if __name__ == "__main__":
    main()
