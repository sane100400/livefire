"""
Attack agent template.

Participants may replace everything in this file. The only required contract is
to call the coordinator-provided wrapper APIs with the injected environment
variables. Do not call external AI providers or target services directly.
"""
from __future__ import annotations

import io
import json
import os
import re
import tarfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx

MODEL = os.getenv("MODEL", "openai/gpt-4o-mini")
MAX_REPO_FILES = int(os.getenv("MAX_REPO_FILES", "24"))
MAX_REPO_PROMPT_BYTES = int(os.getenv("MAX_REPO_PROMPT_BYTES", str(48 * 1024)))
MAX_REPO_FILE_BYTES = int(os.getenv("MAX_REPO_FILE_BYTES", str(8 * 1024)))
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
    ".ini",
    ".cfg",
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
SKIP_DIRS = {
    ".git",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
}


@dataclass(frozen=True)
class AgentEnv:
    team_id: str
    target_team: str
    round_num: int
    run_id: str
    run_token: str
    openrouter_base_url: str
    agent_base_url: str

    @classmethod
    def from_env(cls) -> "AgentEnv":
        return cls(
            team_id=os.environ["TEAM_ID"],
            target_team=os.environ["TARGET_TEAM"],
            round_num=int(os.environ["ROUND"]),
            run_id=os.environ["AGENT_RUN_ID"],
            run_token=os.environ["AGENT_RUN_TOKEN"],
            openrouter_base_url=os.environ["OPENROUTER_BASE_URL"].rstrip("/"),
            agent_base_url=os.environ["HSPACE_AGENT_BASE_URL"].rstrip("/"),
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
    purpose: str,
    messages: list[dict[str, Any]],
    max_tokens: int,
    temperature: float = 0.2,
) -> tuple[int, str]:
    resp = httpx.post(
        f"{env.openrouter_base_url}/chat/completions",
        headers={**env.auth, "X-Agent-Purpose": purpose},
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


def fetch_target_repo(env: AgentEnv, dest: str | Path = "target_repo") -> dict[str, str]:
    resp = httpx.get(f"{env.agent_base_url}/target-repo.tar", headers=env.auth, timeout=30.0)
    _check_response(resp, "target repo fetch")

    repo_team = resp.headers.get("X-Repo-Team") or env.target_team
    commit = resp.headers.get("X-Repo-Commit") or ""
    dest_root = (Path(dest) / env.run_id).resolve()
    dest_root.mkdir(parents=True, exist_ok=True)

    with tarfile.open(fileobj=io.BytesIO(resp.content), mode="r:*") as archive:
        for member in archive.getmembers():
            member_path = (dest_root / member.name).resolve()
            member_path.relative_to(dest_root)
            if member.isdir():
                member_path.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                continue
            member_path.parent.mkdir(parents=True, exist_ok=True)
            extracted = archive.extractfile(member)
            if extracted is not None:
                member_path.write_bytes(extracted.read())

    return {"path": str(dest_root / repo_team), "team": repo_team, "commit": commit}


def attack_target(env: AgentEnv, probe: dict, llm_call_id: int) -> dict:
    resp = httpx.post(
        f"{env.agent_base_url}/attack",
        headers=env.auth,
        json={
            "llm_call_id": llm_call_id,
            "payload": probe.get("payload") or "",
            "path": probe.get("path"),
            "method": probe.get("method") or "POST",
            "json_body": probe.get("json_body"),
            "query": probe.get("query"),
            "headers": probe.get("headers"),
            "data": probe.get("data"),
        },
        timeout=40.0,
    )
    _check_response(resp, "attack wrapper")
    return resp.json()


def submit_poc(env: AgentEnv, *, flag_id: str, llm_call_id: int, source: str) -> dict:
    resp = httpx.post(
        f"{env.agent_base_url}/pocs",
        headers=env.auth,
        data={"flag_id": flag_id, "llm_call_id": str(llm_call_id), "source": source},
        timeout=30.0,
    )
    _check_response(resp, "PoC submit wrapper")
    return resp.json()


def _json_from_text(text: str) -> object:
    match = re.search(r"```(?:json)?\s*(.*?)```", text, flags=re.S)
    raw = match.group(1) if match else text
    return json.loads(raw)


def _parse_scan_plan(text: str) -> list[dict]:
    plan = _json_from_text(text)
    if isinstance(plan, dict):
        plan = plan.get("probes", [])
    if not isinstance(plan, list):
        raise ValueError("scan LLM response must be a JSON list or {'probes': [...]}")

    probes: list[dict] = []
    for item in plan:
        if not isinstance(item, dict):
            continue
        flag_id = str(item.get("flag_id") or "").strip()
        payload = str(item.get("payload") or "").strip()
        path = str(item.get("path") or "").strip()
        if flag_id and (payload or path):
            probes.append({
                "flag_id": flag_id,
                "payload": payload,
                "path": path or None,
                "method": str(item.get("method") or "POST").upper(),
                "json_body": item.get("json_body"),
                "query": item.get("query"),
                "headers": item.get("headers"),
                "data": item.get("data"),
            })

    if not probes:
        raise ValueError("scan LLM response did not contain any usable probes")
    return probes


def _is_candidate_file(path: Path) -> bool:
    name = path.name.lower()
    return name in IMPORTANT_NAMES or path.suffix.lower() in TEXT_SUFFIXES


def _repo_file_priority(path: Path) -> tuple[int, str]:
    name = path.name.lower()
    if name == "vuln_spec.json":
        rank = 0
    elif name in {"app.py", "main.py", "server.py"}:
        rank = 1
    elif name in IMPORTANT_NAMES:
        rank = 2
    elif path.suffix.lower() == ".py":
        rank = 3
    else:
        rank = 4
    return rank, str(path)


def load_target_repo_context(env: AgentEnv) -> tuple[dict, str]:
    info = fetch_target_repo(env)
    root = Path(info["path"])
    if not root.exists():
        raise RuntimeError(f"target repo snapshot missing: {root}")

    candidates: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative_parts = path.relative_to(root).parts
        if any(part in SKIP_DIRS for part in relative_parts):
            continue
        if _is_candidate_file(path):
            candidates.append(path)

    chunks: list[str] = [
        f"Target repo team: {info.get('team')}",
        f"Target repo commit: {info.get('commit')}",
    ]
    total_bytes = sum(len(chunk.encode("utf-8")) for chunk in chunks)
    included = 0

    for path in sorted(candidates, key=_repo_file_priority):
        if included >= MAX_REPO_FILES or total_bytes >= MAX_REPO_PROMPT_BYTES:
            break
        try:
            raw = path.read_bytes()
        except OSError:
            continue
        if b"\x00" in raw:
            continue
        text = raw[:MAX_REPO_FILE_BYTES].decode("utf-8", errors="replace")
        relative = path.relative_to(root)
        chunk = f"\n\n### {relative}\n```\n{text}\n```"
        chunk_bytes = len(chunk.encode("utf-8"))
        if total_bytes + chunk_bytes > MAX_REPO_PROMPT_BYTES:
            break
        chunks.append(chunk)
        total_bytes += chunk_bytes
        included += 1

    if included == 0:
        raise RuntimeError(f"no readable target repo files found under {root}")

    return info, "".join(chunks)


def plan_scan(env: AgentEnv, repo_info: dict, repo_context: str) -> tuple[int, list[dict]]:
    llm_call_id, content = call_llm(
        env,
        purpose="scan",
        messages=[
            {
                "role": "system",
                "content": (
                    "You are an autonomous CTF attack agent. Return only JSON. "
                    "Analyze the provided target git repository snapshot, infer likely "
                    "service vulnerabilities, and create reproducible HTTP scan probes for "
                    "the live target service. Return path/method/json_body when the service "
                    "does not use the template /chat API."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "target_team": env.target_team,
                        "repo_commit": repo_info.get("commit"),
                        "known_possible_vuln_ids": ["vuln1", "vuln2", "vuln3", "vuln4"],
                        "required_output_shape": {
                            "probes": [
                                {
                                    "flag_id": "vuln1",
                                    "payload": "message or search text",
                                    "path": "/target/path",
                                    "method": "POST",
                                    "json_body": {"message": "message or search text"},
                                }
                            ]
                        },
                        "target_repo_snapshot": repo_context,
                    },
                    ensure_ascii=False,
                ),
            },
        ],
        max_tokens=700,
    )
    return llm_call_id, _parse_scan_plan(content)


def build_poc(
    env: AgentEnv,
    flag_id: str,
    probe: dict,
    observation: dict,
    repo_info: dict,
    repo_context: str,
) -> tuple[int, str]:
    llm_call_id, content = call_llm(
        env,
        purpose="poc",
        messages=[
            {
                "role": "system",
                "content": (
                    "You are an autonomous CTF exploit developer. Return only a single Python file. "
                    "The script must read TARGET_HOST and TARGET_PORT, and may use TARGET_TEAM and FLAG_ID. "
                    "It must send the reproducing request to the target service and print the extracted "
                    "HSPACE{...} flag as the final non-empty stdout line. "
                    "Use only the Python standard library."
                ),
            },
            {
                "role": "user",
                "content": json.dumps(
                    {
                        "target_team": env.target_team,
                        "repo_commit": repo_info.get("commit"),
                        "flag_id": flag_id,
                        "successful_probe": probe,
                        "observation": {
                            "flags_found": observation.get("flags_found", []),
                            "tool_calls": observation.get("tool_calls", []),
                        },
                        "target_repo_snapshot": repo_context[:20000],
                    },
                    ensure_ascii=False,
                ),
            },
        ],
        max_tokens=1200,
    )
    source = content.strip()
    match = re.search(r"```(?:python)?\s*(.*?)```", source, flags=re.S)
    if match:
        source = match.group(1).strip()
    compile(source, f"poc_{env.target_team}_{flag_id}.py", "exec")
    return llm_call_id, source + "\n"


def main() -> None:
    env = AgentEnv.from_env()
    print(f"[{env.team_id}] attack run {env.run_id} target={env.target_team} round={env.round_num}")
    try:
        repo_info, repo_context = load_target_repo_context(env)
        print(f"  repo {repo_info.get('team')}@{str(repo_info.get('commit', ''))[:12]} loaded")
        scan_llm_call_id, probes = plan_scan(env, repo_info, repo_context)

        for item in probes:
            flag_id = item["flag_id"]
            try:
                result = attack_target(env, item, scan_llm_call_id)
                flags_found = result.get("flags_found", [])
                print(f"  probe {flag_id}: flags={len(flags_found)} turns={result.get('turns_remaining')}")
                if not flags_found:
                    continue

                poc_llm_call_id, source = build_poc(env, flag_id, item, result, repo_info, repo_context)
                submitted = submit_poc(env, flag_id=flag_id, llm_call_id=poc_llm_call_id, source=source)
                print(f"  submitted agent-generated poc.py for {flag_id}: {submitted}")
            except (RuntimeError, ValueError, SyntaxError) as exc:
                print(f"  probe {flag_id} failed: {exc}")

        finish(env, "completed")
    except Exception as exc:
        finish(env, "failed", str(exc))
        raise


if __name__ == "__main__":
    main()
