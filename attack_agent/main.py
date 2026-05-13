"""
Attack agent template using the compatibility agent_sdk path.

Participants may replace this with any orchestration they want. Official runs
must still use the coordinator-provided LLM wrapper and agent PoC/attack APIs.
"""
from __future__ import annotations

import json
import os
import re
from pathlib import Path

from agent_sdk import AgentContext, AgentSDKError

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


def load_target_repo_context(ctx: AgentContext) -> tuple[dict, str]:
    info = ctx.fetch_target_repo()
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


def plan_scan(ctx: AgentContext, repo_info: dict, repo_context: str) -> tuple[int, list[dict]]:
    resp = ctx.llm(
        model=MODEL,
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
                        "target_team": ctx.target_team,
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
        purpose="scan",
    )
    return int(resp["llm_call_id"]), _parse_scan_plan(resp["content"])


def build_poc(
    ctx: AgentContext,
    flag_id: str,
    probe: dict,
    observation: dict,
    repo_info: dict,
    repo_context: str,
) -> tuple[int, str]:
    resp = ctx.llm(
        model=MODEL,
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
                        "target_team": ctx.target_team,
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
        purpose="poc",
    )
    source = resp["content"].strip()
    match = re.search(r"```(?:python)?\s*(.*?)```", source, flags=re.S)
    if match:
        source = match.group(1).strip()
    compile(source, f"poc_{ctx.target_team}_{flag_id}.py", "exec")
    return int(resp["llm_call_id"]), source + "\n"


def main() -> None:
    ctx = AgentContext.from_env()
    print(f"[{ctx.team_id}] attack run {ctx.agent_run_id} target={ctx.target_team} round={ctx.round_num}")
    try:
        repo_info, repo_context = load_target_repo_context(ctx)
        print(f"  repo {repo_info.get('team')}@{str(repo_info.get('commit', ''))[:12]} loaded")
        scan_llm_call_id, probes = plan_scan(ctx, repo_info, repo_context)

        for item in probes:
            flag_id = item["flag_id"]
            payload = item["payload"]
            try:
                result = ctx.attack(
                    payload,
                    llm_call_id=scan_llm_call_id,
                    path=item.get("path"),
                    method=item.get("method") or "POST",
                    json_body=item.get("json_body"),
                    query=item.get("query"),
                    headers=item.get("headers"),
                    data=item.get("data"),
                )
                flags_found = result.get("flags_found", [])
                print(f"  probe {flag_id}: flags={len(flags_found)} turns={result.get('turns_remaining')}")
                if not flags_found:
                    continue

                poc_llm_call_id, source = build_poc(ctx, flag_id, item, result, repo_info, repo_context)
                submitted = ctx.submit_poc_source(
                    source,
                    llm_call_id=poc_llm_call_id,
                    flag_id=flag_id,
                    file_name="poc.py",
                )
                print(f"  submitted agent-generated poc.py for {flag_id}: {submitted}")
            except (AgentSDKError, ValueError, SyntaxError) as exc:
                print(f"  probe {flag_id} failed: {exc}")

        ctx.finish("completed")
    except Exception as exc:
        try:
            ctx.finish("failed", str(exc))
        finally:
            raise


if __name__ == "__main__":
    main()
