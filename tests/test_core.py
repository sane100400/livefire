import io
import asyncio
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import textwrap
import threading
import unittest
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COORDINATOR = ROOT / "coordinator"
SCRIPTS = ROOT / "scripts"
os.environ.setdefault("ADMIN_SECRET", "test-admin")
for suffix in "ABCDEFG":
    os.environ.setdefault(f"TOKEN_TEAM_{suffix}", f"tok{suffix}")
    os.environ.setdefault(f"DEFENSE_TOKEN_TEAM_{suffix}", f"dtok{suffix}")
sys.path.insert(0, str(COORDINATOR))
sys.path.insert(0, str(SCRIPTS))

import db  # noqa: E402
import checker  # noqa: E402
import poc_runner  # noqa: E402
import scorer  # noqa: E402
from validate_vulns import validate_poc_single, validate_single  # noqa: E402
from rotation import get_attack_targets, get_defender, get_defense_target  # noqa: E402
from config import TEAM_ORDER, TEAMS, TEAM_TOKENS, ATTACK_AGENT_IMAGES, DEFENSE_AGENT_IMAGES  # noqa: E402


TEAM_IDS = ["teamA", "teamB", "teamC", "teamD", "teamE", "teamF", "teamG"]


def reset_db(path: Path) -> None:
    conn = getattr(db, "_conn", None)
    if conn is not None:
        conn.close()
    db._conn = None
    db.init_db(str(path))
    db.init_scores({team_id: 1000 for team_id in TEAM_IDS})


class CoreFlowTests(unittest.TestCase):
    def test_default_event_has_seven_teams(self):
        self.assertEqual(TEAM_ORDER, TEAM_IDS)
        self.assertIn("teamG", TEAMS)
        self.assertIn("teamG", TEAM_TOKENS)
        self.assertEqual(ATTACK_AGENT_IMAGES["teamG"], "and-attack-teamg:latest")
        self.assertEqual(DEFENSE_AGENT_IMAGES["teamG"], "and-defense-teamg:latest")

    def test_rotation_rules(self):
        self.assertEqual(get_defender("teamA"), "teamB")
        self.assertEqual(get_defense_target("teamB"), "teamA")
        self.assertNotIn("teamA", get_attack_targets("teamA"))
        self.assertNotIn("teamG", get_attack_targets("teamA"))
        self.assertEqual(set(get_attack_targets("teamA")), {"teamB", "teamC", "teamD", "teamE", "teamF"})
        self.assertEqual(get_defender("teamG"), "teamA")
        self.assertEqual(get_defense_target("teamA"), "teamG")

    def test_submitted_poc_scores_once_per_round_without_manual_accept(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            reset_db(root / "game.db")
            db.set_service_status("teamB", "OK")
            flag = "HSPACE{0123456789abcdef0123456789abcdef}"
            db.upsert_flag(1, "teamB", "vuln1", flag)
            run = db.create_agent_run("run-1", "teamA", "attack", "teamB", 1)
            llm_id = db.append_llm_call(
                agent_run_id=run["id"],
                model="openai/gpt-4o-mini",
                allowed=True,
                prompt_hash="prompt",
                response_hash="response",
                purpose="poc",
                status="completed",
            )
            poc_path = root / "poc_teamB_vuln1.py"
            poc_path.write_text(f"print('{flag}')\n", encoding="utf-8")
            poc = db.create_poc_submission(
                poc_id="poc-1",
                agent_run_id=run["id"],
                llm_call_id=llm_id,
                attacker_team="teamA",
                target_team="teamB",
                defender_team="teamC",
                flag_id="vuln1",
                submitted_round=1,
                file_name=poc_path.name,
                sha256="sha",
                storage_path=str(poc_path),
            )
            self.assertEqual(poc["status"], "submitted")

            teams = {"teamB": {"ip": "127.0.0.1", "port": 8000, "name": "Team B"}}
            first = poc_runner.run_pocs_for_round(
                round_num=1,
                teams=teams,
                data_dir=str(root / "data"),
                timeout_sec=5,
                output_max_bytes=4096,
                attack_reward=10,
                attack_penalty=10,
                runner_mode="local",
            )
            second = poc_runner.run_pocs_for_round(
                round_num=1,
                teams=teams,
                data_dir=str(root / "data"),
                timeout_sec=5,
                output_max_bytes=4096,
                attack_reward=10,
                attack_penalty=10,
                runner_mode="local",
            )

            self.assertEqual(first[0]["status"], "success")
            self.assertEqual(first[0]["scored"], 1)
            self.assertTrue(second[0]["already_ran"])
            scores = db.get_all_scores()
            self.assertEqual(scores["teamA"]["score"], 1010)
            self.assertEqual(scores["teamC"]["score"], 990)
            self.assertEqual(db.count_successful_pocs_by_attacker(), {"teamA": 1})

    def test_poc_runner_requires_flag_on_final_stdout_line(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            reset_db(root / "game.db")
            db.set_service_status("teamB", "OK")
            flag = "HSPACE{fedcba9876543210fedcba9876543210}"
            db.upsert_flag(1, "teamB", "vuln1", flag)
            run = db.create_agent_run("run-final-line", "teamA", "attack", "teamB", 1)
            llm_id = db.append_llm_call(
                agent_run_id=run["id"],
                model="openai/gpt-4o-mini",
                allowed=True,
                prompt_hash="prompt",
                response_hash="response",
                purpose="poc",
                status="completed",
            )
            poc_path = root / "poc_bad_final_line.py"
            poc_path.write_text(f"print('{flag}')\nprint('done')\n", encoding="utf-8")
            db.create_poc_submission(
                poc_id="poc-final-line",
                agent_run_id=run["id"],
                llm_call_id=llm_id,
                attacker_team="teamA",
                target_team="teamB",
                defender_team="teamC",
                flag_id="vuln1",
                submitted_round=1,
                file_name=poc_path.name,
                sha256="sha",
                storage_path=str(poc_path),
            )

            result = poc_runner.run_pocs_for_round(
                round_num=1,
                teams={"teamB": {"ip": "127.0.0.1", "port": 8000, "name": "Team B"}},
                data_dir=str(root / "data"),
                timeout_sec=5,
                output_max_bytes=4096,
                attack_reward=10,
                attack_penalty=10,
                runner_mode="local",
            )

            self.assertEqual(result[0]["status"], "failed")
            self.assertEqual(result[0]["scored"], 0)
            self.assertIn("final non-empty stdout line", result[0]["detail"])

    def test_round_score_report_separates_availability_from_poc_deltas(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            reset_db(root / "game.db")
            db.set_service_status("teamA", "OK")
            db.set_service_status("teamB", "OK")
            run = db.create_agent_run("run-1", "teamA", "attack", "teamB", 1)
            llm_id = db.append_llm_call(
                agent_run_id=run["id"],
                model="openai/gpt-4o-mini",
                allowed=True,
                prompt_hash="prompt",
                purpose="poc",
                status="completed",
            )
            db.create_poc_submission(
                poc_id="poc-1",
                agent_run_id=run["id"],
                llm_call_id=llm_id,
                attacker_team="teamA",
                target_team="teamB",
                defender_team="teamC",
                flag_id="vuln1",
                submitted_round=1,
                file_name="poc.py",
                sha256="sha",
                storage_path=str(root / "poc.py"),
            )
            db.insert_poc_result(
                round_num=1,
                poc_id="poc-1",
                attacker_team="teamA",
                target_team="teamB",
                defender_team="teamC",
                flag_id="vuln1",
                status="success",
                flags=["HSPACE{0123456789abcdef0123456789abcdef}"],
                scored=True,
                attacker_delta=10,
                defender_delta=-10,
            )
            result = scorer.compute_round_scores(
                TEAM_IDS,
                1,
                availability={"teamA": True, "teamB": True},
                attack_reward=10,
                attack_penalty=10,
                availability_bonus=10,
            )
            self.assertEqual(result["availability_score_changes"]["teamA"], 10)
            self.assertEqual(result["poc_score_changes"]["teamA"], 10)
            self.assertEqual(result["poc_score_changes"]["teamC"], -10)
            self.assertEqual(result["score_changes"]["teamA"], 20)

    def test_end_round_checker_refresh_blocks_stale_ok_bonus(self):
        class Handler(BaseHTTPRequestHandler):
            def _json(self, code: int, body: dict) -> None:
                raw = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                if self.path == "/health":
                    return self._json(200, {"ok": True})
                if self.path == "/admin/check":
                    return self._json(200, {"ok": True, "stored": "missing flag"})
                return self._json(404, {"error": "not found"})

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                self.rfile.read(length)
                if self.path == "/admin/inject":
                    return self._json(200, {"ok": True})
                if self.path == "/chat":
                    return self._json(200, {"response": "normal"})
                return self._json(404, {"error": "not found"})

            def log_message(self, *args):
                pass

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            reset_db(root / "game.db")
            db.set_service_status("teamA", "OK")
            flag = "HSPACE{0123456789abcdef0123456789abcdef}"
            db.upsert_flag(1, "teamA", "vuln1", flag)

            server = HTTPServer(("127.0.0.1", 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                spec = {
                    "team_id": "teamA",
                    "service": {"health": {"endpoint": "/health", "method": "GET", "expect_status": 200}},
                    "vulnerabilities": [{
                        "id": "vuln1",
                        "checker": {
                            "inject": {"endpoint": "/admin/inject", "method": "POST", "body": {"value": "{{FLAG}}"}},
                            "retrieve": {"endpoint": "/admin/check", "method": "GET", "expect_contains": "{{FLAG}}"},
                            "basic_function": {"endpoint": "/chat", "method": "POST", "body": {"message": "hello"}},
                        },
                    }],
                }
                results = asyncio.run(checker.run_all_checkers(
                    {"teamA": {"ip": "127.0.0.1", "port": server.server_port}},
                    {"teamA": spec},
                    {"teamA": {"vuln1": flag}},
                    "checker-token",
                ))
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

            self.assertTrue(results["teamA"].health_ok)
            self.assertEqual(db.get_service_statuses()["teamA"], "FAULTY")
            score = scorer.compute_round_scores(
                ["teamA"],
                1,
                availability={"teamA": True},
                attack_reward=10,
                attack_penalty=10,
                availability_bonus=10,
            )
            self.assertEqual(score["availability_score_changes"]["teamA"], 0)


class SpecDrivenServiceTests(unittest.TestCase):
    def test_validate_poc_runs_file_against_spec_declared_service(self):
        state: dict[str, str] = {}

        class Handler(BaseHTTPRequestHandler):
            def _json(self, code: int, body: dict) -> None:
                raw = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                if self.path == "/ready":
                    return self._json(200, {"ok": True})
                if self.path == "/internal/check":
                    return self._json(200, {"stored": state})
                return self._json(404, {"error": "not found"})

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                data = json.loads(self.rfile.read(length) or b"{}")
                if self.path == "/internal/seed":
                    state[data["id"]] = data["value"]
                    return self._json(200, {"ok": True})
                if self.path == "/api/leak":
                    return self._json(200, {"leak": state.get(data["id"], "")})
                if self.path == "/api/ping":
                    return self._json(200, {"ok": True})
                return self._json(404, {"error": "not found"})

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            spec = {
                "team_id": "teamX",
                "service": {"health": {"endpoint": "/ready", "method": "GET", "expect_status": 200}},
                "vulnerabilities": [{
                    "id": "vuln1",
                    "checker": {
                        "inject": {
                            "endpoint": "/internal/seed",
                            "method": "POST",
                            "body": {"id": "vuln1", "value": "{{FLAG}}"},
                        },
                        "retrieve": {
                            "endpoint": "/internal/check",
                            "method": "GET",
                            "expect_contains": "{{FLAG}}",
                        },
                        "basic_function": {
                            "endpoint": "/api/ping",
                            "method": "POST",
                            "body": {"ok": True},
                            "expect_status": 200,
                        },
                    },
                }],
            }
            with tempfile.TemporaryDirectory() as td:
                poc = Path(td) / "poc1.py"
                poc.write_text(textwrap.dedent("""
                    import json
                    import os
                    import re
                    import urllib.request

                    body = json.dumps({"id": os.environ["FLAG_ID"]}).encode()
                    req = urllib.request.Request(
                        f"http://{os.environ['TARGET_HOST']}:{os.environ['TARGET_PORT']}/api/leak",
                        data=body,
                        headers={"Content-Type": "application/json"},
                    )
                    with urllib.request.urlopen(req, timeout=5) as response:
                        text = response.read().decode()
                    print("debug line")
                    print(re.search(r"HSPACE\\{[a-f0-9]{32}\\}", text).group(0))
                """))
                with redirect_stdout(io.StringIO()):
                    result = validate_poc_single(
                        spec,
                        "127.0.0.1",
                        server.server_port,
                        "1",
                        poc,
                        timeout=5,
                    )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertTrue(result["passed"])
        self.assertTrue(result["poc_flag_match"])

    def test_validate_vulns_uses_spec_declared_endpoints(self):
        state: dict[str, str] = {}

        class Handler(BaseHTTPRequestHandler):
            def _json(self, code: int, body: dict) -> None:
                raw = json.dumps(body).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                if self.path == "/ready":
                    return self._json(200, {"ok": True})
                if self.path == "/internal/check":
                    return self._json(200, {"stored": state})
                return self._json(404, {"error": "not found"})

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                data = json.loads(self.rfile.read(length) or b"{}")
                if self.path == "/internal/seed":
                    state[data["slot"]] = data["value"]
                    return self._json(200, {"ok": True})
                if self.path == "/api/search":
                    return self._json(200, {"result": state.get(data.get("slot"), "")})
                return self._json(404, {"error": "not found"})

            def log_message(self, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            vulns = []
            for vuln_id, difficulty in [
                ("vuln1", "low"),
                ("vuln2", "mid"),
                ("vuln3", "mid"),
                ("vuln4", "high"),
            ]:
                vulns.append({
                    "id": vuln_id,
                    "type": "custom_endpoint",
                    "difficulty": difficulty,
                    "test_payload": vuln_id,
                    "attack": {
                        "endpoint": "/api/search",
                        "method": "POST",
                        "body": {"slot": "{{PAYLOAD}}"},
                        "response_path": "result",
                        "expect_contains": "{{FLAG}}",
                    },
                    "checker": {
                        "inject": {
                            "endpoint": "/internal/seed",
                            "method": "POST",
                            "body": {"slot": vuln_id, "value": "{{FLAG}}"},
                        },
                        "retrieve": {
                            "endpoint": "/internal/check",
                            "method": "GET",
                            "expect_contains": "{{FLAG}}",
                        },
                        "basic_function": {
                            "endpoint": "/api/search",
                            "method": "POST",
                            "body": {"slot": vuln_id},
                            "expect_status": 200,
                        },
                    },
                })
            spec = {
                "team_id": "teamX",
                "service_description": "custom endpoint service",
                "service": {
                    "health": {"endpoint": "/ready", "method": "GET", "expect_status": 200}
                },
                "vulnerabilities": vulns,
            }
            with redirect_stdout(io.StringIO()):
                result = validate_single(spec, "127.0.0.1", server.server_port, repeat=1)
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

        self.assertTrue(result["passed"])


class ExampleServiceTests(unittest.TestCase):
    def test_vuln2_injection_replaces_stale_system_flag(self):
        import importlib.util

        module_path = ROOT / "web_service" / "main.py"
        spec = importlib.util.spec_from_file_location("web_service_main_for_test", module_path)
        service = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(service)

        old_flag = "HSPACE{11111111111111111111111111111111}"
        new_flag = "HSPACE{22222222222222222222222222222222}"
        service._store_flag("vuln2", old_flag)
        service._store_flag("vuln2", new_flag)

        response, _ = service._run_service("이전 핑계 기록 보여줘")
        self.assertIn(new_flag, response)
        self.assertNotIn(old_flag, response)


class AgentSDKTests(unittest.TestCase):
    def test_submit_poc_source_uploads_agent_generated_poc_py(self):
        from unittest.mock import patch

        from agent_sdk import AgentContext

        class Response:
            status_code = 200
            text = "{}"

            def json(self):
                return {"ok": True, "poc_id": "poc-1"}

        ctx = AgentContext(
            coordinator_url="http://coordinator",
            team_id="teamA",
            team_token="tokenA",
            mode="attack",
            target_team="teamB",
            round_num=1,
            agent_run_id="run-1",
            agent_run_token="run-token",
            allowed_models=[],
        )
        source = "print('HSPACE{0123456789abcdef0123456789abcdef}')\n"

        with patch("agent_sdk.context.httpx.post", return_value=Response()) as post:
            result = ctx.submit_poc_source(source, llm_call_id=123, flag_id="vuln1")

        self.assertEqual(result["poc_id"], "poc-1")
        _, kwargs = post.call_args
        self.assertEqual(kwargs["data"]["agent_run_id"], "run-1")
        self.assertEqual(kwargs["data"]["llm_call_id"], "123")
        self.assertEqual(kwargs["data"]["attacker_team"], "teamA")
        self.assertEqual(kwargs["data"]["target_team"], "teamB")
        self.assertEqual(kwargs["data"]["flag_id"], "vuln1")
        file_name, file_bytes, media_type = kwargs["files"]["file"]
        self.assertEqual(file_name, "poc.py")
        self.assertEqual(file_bytes, source.encode("utf-8"))
        self.assertEqual(media_type, "text/x-python")


class AgentRunnerCompatibilityTests(unittest.TestCase):
    def test_runner_resolves_manifest_and_env_entrypoints(self):
        from unittest.mock import patch

        from agent_sdk.runner import resolve_entrypoint

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            custom = root / "custom_agents"
            custom.mkdir()
            (custom / "attack.py").write_text("print('attack')\n", encoding="utf-8")
            (root / "agent_manifest.json").write_text(
                json.dumps({"attack": {"path": "custom_agents/attack.py"}}),
                encoding="utf-8",
            )

            manifest_entry = resolve_entrypoint("attack", root)
            self.assertEqual(manifest_entry.source, str(root / "agent_manifest.json"))
            self.assertEqual(manifest_entry.command[-1], "custom_agents/attack.py")

            (custom / "alt_attack.py").write_text("print('alt')\n", encoding="utf-8")
            with patch.dict(os.environ, {"ATTACK_AGENT_ENTRYPOINT": "custom_agents/alt_attack.py"}):
                env_entry = resolve_entrypoint("attack", root)
            self.assertEqual(env_entry.source, "environment")
            self.assertEqual(env_entry.command[-1], "custom_agents/alt_attack.py")

    def test_runner_rejects_missing_manifest_path(self):
        from agent_sdk.runner import AgentRunnerError, resolve_entrypoint

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "agent_manifest.json").write_text(
                json.dumps({"attack": {"path": "missing.py"}}),
                encoding="utf-8",
            )
            with self.assertRaises(AgentRunnerError):
                resolve_entrypoint("attack", root)


class AgentOrchestrationPolicyTests(unittest.TestCase):
    def test_agent_templates_use_coordinator_llm_gateway(self):
        for relative in ["attack_agent/main.py", "defense_agent/main.py"]:
            source = (ROOT / relative).read_text(encoding="utf-8")
            self.assertIn("ctx.llm(", source, relative)
            self.assertNotIn("OPENROUTER_API_KEY", source, relative)
            self.assertNotIn("openrouter.ai", source.lower(), relative)
            self.assertNotIn("/chat/completions", source, relative)

    def test_unified_agent_helper_has_trusted_bootstrap_marker(self):
        source = (ROOT / "scripts" / "agent.py").read_text(encoding="utf-8")
        self.assertIn("AGENT_HELPER_TRUSTED_BOOTSTRAP = True", source)
        self.assertIn("AGENT_HELPER_SELF_UPDATED", source)
        self.assertIn("/agent-runs", source)
        self.assertIn("OPENAI_BASE_URL", source)
        self.assertIn("/agent/finish", source)

    def test_gitctf_exposes_agent_helper_as_subcommand(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "gitctf.py"), "agent", "doctor", "--mode", "attack"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("agent_sdk.runner", result.stdout)
        self.assertIn("attack_agent/main.py", result.stdout)

        help_result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "gitctf.py"), "agent"],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(help_result.returncode, 0, help_result.stderr + help_result.stdout)
        self.assertIn("gitctf.py agent build teamA", help_result.stdout)

    def test_admin_env_setup_script_targets_seven_team_event(self):
        script = ROOT / "scripts" / "setup_admin_env.sh"
        result = subprocess.run(["bash", "-n", str(script)], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        source = script.read_text(encoding="utf-8")
        self.assertIn("A,B,C,D,E,F,G", source)
        self.assertIn("team_tokens.tsv", source)
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            (tmp / "scripts").mkdir()
            copied = tmp / "scripts" / "setup_admin_env.sh"
            copied.write_text(source, encoding="utf-8")
            copied.chmod(0o755)
            run = subprocess.run(
                [str(copied), "--openrouter-api-key", "test-key"],
                cwd=tmp,
                capture_output=True,
                text=True,
            )
            self.assertEqual(run.returncode, 0, run.stderr + run.stdout)
            env_text = (tmp / "coordinator" / ".env").read_text(encoding="utf-8")
            tokens_text = (tmp / "coordinator" / "team_tokens.tsv").read_text(encoding="utf-8")
            self.assertIn("TOKEN_TEAM_G=", env_text)
            self.assertIn("HOST_PORT_TEAM_G=8007", env_text)
            self.assertIn("teamG\t", tokens_text)

    def test_user_docs_point_to_single_cli_for_agent_work(self):
        for relative in ["README.md", "SCRIPT_USAGE.txt", "AGENT_USAGE.txt"]:
            source = (ROOT / relative).read_text(encoding="utf-8")
            self.assertIn("gitctf.py agent", source, relative)
            self.assertNotIn("python scripts/agent.py", source, relative)

    def test_agent_dockerfiles_use_compatibility_runner(self):
        for relative in ["attack_agent/Dockerfile", "defense_agent/Dockerfile"]:
            source = (ROOT / relative).read_text(encoding="utf-8")
            self.assertIn("agent_sdk.runner", source, relative)
            self.assertNotIn('CMD ["python", "attack_agent/main.py"]', source, relative)
            self.assertNotIn('CMD ["python", "defense_agent/main.py"]', source, relative)

    def test_official_agent_runner_does_not_expose_runner_secret(self):
        source = (ROOT / "coordinator" / "agent_runner.py").read_text(encoding="utf-8")
        self.assertIn("AGENT_RUN_TOKEN", source)
        self.assertIn("OPENAI_BASE_URL", source)
        self.assertIn("HSPACE_AGENT_BASE_URL", source)
        self.assertNotIn("RUNNER_SECRET=", source)

    def test_git_hook_locks_push_after_preflight(self):
        source = (ROOT / "coordinator" / "git_handler.py").read_text(encoding="utf-8")
        self.assertIn("PREFLIGHT_DONE", source)
        self.assertIn("사전검증 이후에는 추가 push 불가", source)

    def test_protected_script_commands_cannot_skip_self_update(self):
        env = os.environ.copy()
        env["GITCTF_NO_SELF_UPDATE"] = "1"
        gitctf = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "gitctf.py"), "push", "--repo", str(ROOT / "web_service"), "--dry-run"],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(gitctf.returncode, 0)
        self.assertIn("최신본 확인을 건너뛸 수 없습니다", gitctf.stderr + gitctf.stdout)

        env = os.environ.copy()
        env["AGENT_HELPER_NO_SELF_UPDATE"] = "1"
        agent = subprocess.run(
            [
                sys.executable,
                str(ROOT / "scripts" / "agent.py"),
                "run",
                "attack",
                "--team",
                "teamA",
                "--target",
                "teamB",
                "--token",
                "token",
            ],
            cwd=ROOT,
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(agent.returncode, 0)
        self.assertIn("최신본 확인을 건너뛸 수 없습니다", agent.stderr + agent.stdout)


class OpenRouterGatewayTests(unittest.TestCase):
    def test_llm_gateway_uses_openrouter_compatible_api(self):
        script = textwrap.dedent(
            f"""
            import json
            import hashlib
            import hmac
            import os
            import tempfile
            import threading
            import time
            from http.server import BaseHTTPRequestHandler, HTTPServer
            from pathlib import Path

            root = Path({str(ROOT)!r})
            os.environ.update({{
                "ADMIN_SECRET": "admin",
                "TOKEN_TEAM_A": "tokA",
                "TOKEN_TEAM_B": "tokB",
                "TOKEN_TEAM_C": "tokC",
                "TOKEN_TEAM_D": "tokD",
                "TOKEN_TEAM_E": "tokE",
                "TOKEN_TEAM_F": "tokF",
                "TOKEN_TEAM_G": "tokG",
                "DEFENSE_TOKEN_TEAM_A": "dtokA",
                "DEFENSE_TOKEN_TEAM_B": "dtokB",
                "DEFENSE_TOKEN_TEAM_C": "dtokC",
                "DEFENSE_TOKEN_TEAM_D": "dtokD",
                "DEFENSE_TOKEN_TEAM_E": "dtokE",
                "DEFENSE_TOKEN_TEAM_F": "dtokF",
                "DEFENSE_TOKEN_TEAM_G": "dtokG",
                "RUNNER_SECRET": "runner-secret",
                "OPENROUTER_API_KEY": "test-openrouter-key",
                "DB_PATH": str(Path(tempfile.mkdtemp()) / "game.db"),
                "VULN_SPEC_DIR": tempfile.mkdtemp(),
                "REPOS_DIR": tempfile.mkdtemp(),
            }})

            class Handler(BaseHTTPRequestHandler):
                def do_POST(self):
                    length = int(self.headers.get("Content-Length", "0"))
                    self.rfile.read(length)
                    body = {{
                        "id": "mock-request",
                        "choices": [{{"message": {{"content": "mock llm response"}}}}],
                        "usage": {{"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3}},
                    }}
                    raw = json.dumps(body).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.send_header("x-request-id", "mock-request-header")
                    self.end_headers()
                    self.wfile.write(raw)
                def log_message(self, *args):
                    pass

            server = HTTPServer(("127.0.0.1", 0), Handler)
            threading.Thread(target=server.serve_forever, daemon=True).start()
            os.environ["OPENROUTER_BASE_URL"] = f"http://127.0.0.1:{{server.server_port}}"

            import sys
            sys.path.insert(0, str(root / "coordinator"))
            from fastapi.testclient import TestClient
            import app

            def sdk_headers(team_token, run_id, run_token, method, path):
                timestamp = str(int(time.time()))
                token_hash = hashlib.sha256(run_token.encode()).hexdigest()
                payload = "\\n".join([method, path, run_id, timestamp]).encode()
                signature = hmac.new(token_hash.encode(), payload, hashlib.sha256).hexdigest()
                return {{
                    "X-Team-Token": team_token,
                    "X-Agent-Run-Token": run_token,
                    "X-Agent-SDK": "hspace-agent-sdk/1",
                    "X-Agent-SDK-Timestamp": timestamp,
                    "X-Agent-SDK-Signature": signature,
                }}

            with TestClient(app.app) as client:
                tool = client.get("/tools/gitctf.py")
                assert tool.status_code == 200, tool.text
                assert "GITCTF_TRUSTED_BOOTSTRAP = True" in tool.text
                assert tool.headers.get("x-content-sha256")

                validate_tool = client.get("/tools/validate_vulns.py")
                assert validate_tool.status_code == 200, validate_tool.text
                assert "def validate_single" in validate_tool.text

                agent_tool = client.get("/tools/agent.py")
                assert agent_tool.status_code == 200, agent_tool.text
                assert "AGENT_HELPER_TRUSTED_BOOTSTRAP = True" in agent_tool.text
                assert agent_tool.headers.get("x-content-sha256")

                bad_run = client.post(
                    "/agent-runs",
                    headers={{"X-Team-Token": "tokA", "X-Agent-SDK": "hspace-agent-sdk/1"}},
                    json={{"team_id": "teamA", "mode": "attack", "target_team": "teamC", "round_num": 0}},
                )
                assert bad_run.status_code == 403, bad_run.text
                student_run = client.post(
                    "/student/agent-runs",
                    headers={{"X-Team-Token": "tokA"}},
                    json={{"team_id": "teamA", "mode": "attack", "target_team": "teamC", "round_num": 0}},
                )
                assert student_run.status_code == 404, student_run.text
                run = client.post(
                    "/agent-runs",
                    headers={{
                        "X-Team-Token": "tokA",
                        "X-Runner-Secret": "runner-secret",
                        "X-Agent-SDK": "hspace-agent-sdk/1",
                    }},
                    json={{"team_id": "teamA", "mode": "attack", "target_team": "teamC", "round_num": 0}},
                )
                assert run.status_code == 200, run.text
                run_data = run.json()
                run_id = run_data["agent_run_id"]
                run_token = run_data["agent_run_token"]
                missing_token = client.post(
                    "/llm",
                    headers={{"X-Team-Token": "tokA"}},
                    json={{
                        "agent_run_id": run_id,
                        "model": "openai/gpt-4o-mini",
                        "messages": [{{"role": "user", "content": "hello"}}],
                        "purpose": "scan",
                    }},
                )
                assert missing_token.status_code == 403, missing_token.text
                rejected_model = client.post(
                    "/llm",
                    headers=sdk_headers("tokA", run_id, run_token, "POST", "/llm"),
                    json={{
                        "agent_run_id": run_id,
                        "model": "meta-llama/llama-3.1-70b",
                        "messages": [{{"role": "user", "content": "hello"}}],
                        "purpose": "scan",
                    }},
                )
                assert rejected_model.status_code == 403, rejected_model.text
                resp = client.post(
                    "/llm",
                    headers=sdk_headers("tokA", run_id, run_token, "POST", "/llm"),
                    json={{
                        "agent_run_id": run_id,
                        "model": "openai/gpt-4o-mini",
                        "messages": [{{"role": "user", "content": "hello"}}],
                        "purpose": "scan",
                    }},
                )
                assert resp.status_code == 200, resp.text
                data = resp.json()
                assert data["content"] == "mock llm response"
                assert data["usage"]["total_tokens"] == 3

                oversized = client.post(
                    "/llm",
                    headers=sdk_headers("tokA", run_id, run_token, "POST", "/llm"),
                    json={{
                        "agent_run_id": run_id,
                        "model": "openai/gpt-4o-mini",
                        "messages": [{{"role": "user", "content": "x"}} for _ in range(33)],
                        "purpose": "scan",
                    }},
                )
                assert oversized.status_code == 413, oversized.text
            server.shutdown()
            """
        )
        result = subprocess.run([sys.executable, "-c", script], cwd=ROOT, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            self.fail(result.stdout + result.stderr)

    def test_openrouter_wrapper_links_free_agent_attack_and_poc_submission(self):
        script = textwrap.dedent(
            f"""
            import json
            import os
            import tempfile
            import threading
            from http.server import BaseHTTPRequestHandler, HTTPServer
            from pathlib import Path

            root = Path({str(ROOT)!r})
            workdir = Path(tempfile.mkdtemp())
            flag = "HSPACE" + chr(123) + "11111111111111111111111111111111" + chr(125)
            os.environ.update({{
                "ADMIN_SECRET": "admin",
                "TOKEN_TEAM_A": "tokA",
                "TOKEN_TEAM_B": "tokB",
                "TOKEN_TEAM_C": "tokC",
                "TOKEN_TEAM_D": "tokD",
                "TOKEN_TEAM_E": "tokE",
                "TOKEN_TEAM_F": "tokF",
                "TOKEN_TEAM_G": "tokG",
                "DEFENSE_TOKEN_TEAM_A": "dtokA",
                "DEFENSE_TOKEN_TEAM_B": "dtokB",
                "DEFENSE_TOKEN_TEAM_C": "dtokC",
                "DEFENSE_TOKEN_TEAM_D": "dtokD",
                "DEFENSE_TOKEN_TEAM_E": "dtokE",
                "DEFENSE_TOKEN_TEAM_F": "dtokF",
                "DEFENSE_TOKEN_TEAM_G": "dtokG",
                "RUNNER_SECRET": "runner-secret",
                "DB_PATH": str(workdir / "game.db"),
                "DATA_DIR": str(workdir / "data"),
                "VULN_SPEC_DIR": str(workdir / "vuln_specs"),
                "REPOS_DIR": str(workdir / "repos"),
                "POC_RUNNER_MODE": "local",
                "POC_TIMEOUT_SEC": "5",
            }})
            (workdir / "vuln_specs").mkdir()
            (workdir / "repos").mkdir()

            class OpenRouterHandler(BaseHTTPRequestHandler):
                def do_POST(self):
                    length = int(self.headers.get("Content-Length", "0"))
                    self.rfile.read(length)
                    body = {{
                        "id": "mock-openrouter-free-agent",
                        "object": "chat.completion",
                        "choices": [{{"message": {{"role": "assistant", "content": "probe /probe then submit poc"}}}}],
                        "usage": {{"prompt_tokens": 1, "completion_tokens": 2, "total_tokens": 3}},
                    }}
                    raw = json.dumps(body).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                def log_message(self, *args):
                    pass

            class TargetHandler(BaseHTTPRequestHandler):
                def do_POST(self):
                    length = int(self.headers.get("Content-Length", "0"))
                    self.rfile.read(length)
                    raw = json.dumps({{"response": flag}}).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)
                def log_message(self, *args):
                    pass

            openrouter_server = HTTPServer(("127.0.0.1", 0), OpenRouterHandler)
            target_server = HTTPServer(("127.0.0.1", 0), TargetHandler)
            threading.Thread(target=openrouter_server.serve_forever, daemon=True).start()
            threading.Thread(target=target_server.serve_forever, daemon=True).start()
            os.environ["OPENROUTER_BASE_URL"] = f"http://127.0.0.1:{{openrouter_server.server_port}}"

            import sys
            sys.path.insert(0, str(root / "coordinator"))
            from fastapi.testclient import TestClient
            import app

            app.TEAMS["teamB"] = {{"ip": "127.0.0.1", "port": target_server.server_port, "name": "Team B"}}

            with TestClient(app.app) as client:
                app.state.start_round(1)
                app.db.set_service_status("teamB", "OK")
                app.db.upsert_flag(1, "teamB", "vuln1", flag)
                run = client.post(
                    "/agent-runs",
                    headers={{
                        "X-Team-Token": "tokA",
                        "X-Runner-Secret": "runner-secret",
                        "X-Agent-SDK": "hspace-agent-sdk/1",
                    }},
                    json={{"team_id": "teamA", "mode": "attack", "target_team": "teamB", "round_num": 1}},
                )
                assert run.status_code == 200, run.text
                run_token = run.json()["agent_run_token"]
                auth = {{"Authorization": "Bearer " + run_token}}

                chat = client.post(
                    "/openrouter/api/v1/chat/completions",
                    headers=auth,
                    json={{
                        "model": "openai/gpt-4o-mini",
                        "messages": [{{"role": "user", "content": "find exploit"}}],
                    }},
                )
                assert chat.status_code == 200, chat.text
                assert chat.headers.get("x-llm-call-id"), chat.headers
                assert chat.json()["hspace"]["llm_call_id"] == int(chat.headers["x-llm-call-id"])

                attack = client.post(
                    "/agent/attack",
                    headers=auth,
                    json={{"path": "/probe", "method": "POST", "json_body": {{"q": "x"}}}},
                )
                assert attack.status_code == 200, attack.text
                assert flag in attack.json()["flags_found"], attack.json()

                poc = client.post(
                    "/agent/pocs",
                    headers=auth,
                    data={{"flag_id": "vuln1", "source": "print(" + repr(flag) + ")\\n"}},
                )
                assert poc.status_code == 200, poc.text
                body = poc.json()
                assert body["run_result"]["status"] == "success", body
                assert body["run_result"]["scored"] == 1, body
            openrouter_server.shutdown()
            target_server.shutdown()
            """
        )
        result = subprocess.run([sys.executable, "-c", script], cwd=ROOT, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            self.fail(result.stdout + result.stderr)

    def test_agent_run_and_git_security_gates(self):
        script = textwrap.dedent(
            f"""
            import base64
            import os
            import tempfile
            from pathlib import Path

            root = Path({str(ROOT)!r})
            workdir = Path(tempfile.mkdtemp())
            os.environ.update({{
                "ADMIN_SECRET": "admin",
                "TOKEN_TEAM_A": "tokA",
                "TOKEN_TEAM_B": "tokB",
                "TOKEN_TEAM_C": "tokC",
                "TOKEN_TEAM_D": "tokD",
                "TOKEN_TEAM_E": "tokE",
                "TOKEN_TEAM_F": "tokF",
                "TOKEN_TEAM_G": "tokG",
                "DEFENSE_TOKEN_TEAM_A": "dtokA",
                "DEFENSE_TOKEN_TEAM_B": "dtokB",
                "DEFENSE_TOKEN_TEAM_C": "dtokC",
                "DEFENSE_TOKEN_TEAM_D": "dtokD",
                "DEFENSE_TOKEN_TEAM_E": "dtokE",
                "DEFENSE_TOKEN_TEAM_F": "dtokF",
                "DEFENSE_TOKEN_TEAM_G": "dtokG",
                "DB_PATH": str(workdir / "game.db"),
                "DATA_DIR": str(workdir / "data"),
                "VULN_SPEC_DIR": str(workdir / "vuln_specs"),
                "REPOS_DIR": str(workdir / "repos"),
            }})
            os.environ["RUNNER_SECRET"] = ""
            (workdir / "vuln_specs").mkdir()
            (workdir / "repos").mkdir()

            import sys
            sys.path.insert(0, str(root / "coordinator"))
            from fastapi.testclient import TestClient
            import app

            with TestClient(app.app) as client:
                run = client.post(
                    "/agent-runs",
                    headers={{"X-Team-Token": "tokA", "X-Agent-SDK": "hspace-agent-sdk/1"}},
                    json={{"team_id": "teamA", "mode": "attack", "target_team": "teamB", "round_num": 1}},
                )
                assert run.status_code == 503, run.text

                invalid_service = client.get("/git/teamA/info/refs?service=sh")
                assert invalid_service.status_code == 400, invalid_service.text

                unauth_read = client.get("/git/teamA/info/refs?service=git-upload-pack")
                assert unauth_read.status_code == 401, unauth_read.text

                raw = base64.b64encode(b"teamA:tokA").decode()
                auth_read = client.get(
                    "/git/teamA/info/refs?service=git-upload-pack",
                    headers={{"Authorization": "Basic " + raw}},
                )
                assert auth_read.status_code == 200, auth_read.text
            """
        )
        result = subprocess.run([sys.executable, "-c", script], cwd=ROOT, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            self.fail(result.stdout + result.stderr)

    def test_poc_submission_runs_and_scores_immediately(self):
        script = textwrap.dedent(
            f"""
            import hashlib
            import hmac
            import os
            import tempfile
            import time
            from pathlib import Path

            root = Path({str(ROOT)!r})
            workdir = Path(tempfile.mkdtemp())
            os.environ.update({{
                "ADMIN_SECRET": "admin",
                "TOKEN_TEAM_A": "tokA",
                "TOKEN_TEAM_B": "tokB",
                "TOKEN_TEAM_C": "tokC",
                "TOKEN_TEAM_D": "tokD",
                "TOKEN_TEAM_E": "tokE",
                "TOKEN_TEAM_F": "tokF",
                "TOKEN_TEAM_G": "tokG",
                "DEFENSE_TOKEN_TEAM_A": "dtokA",
                "DEFENSE_TOKEN_TEAM_B": "dtokB",
                "DEFENSE_TOKEN_TEAM_C": "dtokC",
                "DEFENSE_TOKEN_TEAM_D": "dtokD",
                "DEFENSE_TOKEN_TEAM_E": "dtokE",
                "DEFENSE_TOKEN_TEAM_F": "dtokF",
                "DEFENSE_TOKEN_TEAM_G": "dtokG",
                "RUNNER_SECRET": "runner-secret",
                "DB_PATH": str(workdir / "game.db"),
                "DATA_DIR": str(workdir / "data"),
                "VULN_SPEC_DIR": str(workdir / "vuln_specs"),
                "REPOS_DIR": str(workdir / "repos"),
                "POC_RUNNER_MODE": "local",
                "POC_TIMEOUT_SEC": "5",
            }})
            (workdir / "vuln_specs").mkdir()
            (workdir / "repos").mkdir()

            import sys
            sys.path.insert(0, str(root / "coordinator"))
            from fastapi.testclient import TestClient
            import app

            def sdk_headers(team_token, run_id, run_token, method, path):
                timestamp = str(int(time.time()))
                token_hash = hashlib.sha256(run_token.encode()).hexdigest()
                payload = "\\n".join([method, path, run_id, timestamp]).encode()
                signature = hmac.new(token_hash.encode(), payload, hashlib.sha256).hexdigest()
                return {{
                    "X-Team-Token": team_token,
                    "X-Agent-Run-Token": run_token,
                    "X-Agent-SDK": "hspace-agent-sdk/1",
                    "X-Agent-SDK-Timestamp": timestamp,
                    "X-Agent-SDK-Signature": signature,
                }}

            with TestClient(app.app) as client:
                app.state.start_round(1)
                app.db.set_service_status("teamB", "OK")
                flag = "HSPACE" + chr(123) + "0123456789abcdef0123456789abcdef" + chr(125)
                app.db.upsert_flag(1, "teamB", "vuln1", flag)

                run = client.post(
                    "/agent-runs",
                    headers={{
                        "X-Team-Token": "tokA",
                        "X-Runner-Secret": "runner-secret",
                        "X-Agent-SDK": "hspace-agent-sdk/1",
                    }},
                    json={{"team_id": "teamA", "mode": "attack", "target_team": "teamB", "round_num": 1}},
                )
                assert run.status_code == 200, run.text
                run_data = run.json()
                run_id = run_data["agent_run_id"]
                run_token = run_data["agent_run_token"]
                llm_call_id = app.db.append_llm_call(
                    agent_run_id=run_id,
                    model="openai/gpt-4o-mini",
                    allowed=True,
                    prompt_hash="prompt",
                    response_hash="response",
                    purpose="poc",
                    status="completed",
                )
                poc_source = ("print(" + repr(flag) + ")\\n").encode()
                poc_sha = hashlib.sha256(poc_source).hexdigest()

                resp = client.post(
                    "/pocs",
                    headers=sdk_headers("tokA", run_id, run_token, "POST", "/pocs"),
                    data={{
                        "agent_run_id": run_id,
                        "llm_call_id": str(llm_call_id),
                        "attacker_team": "teamA",
                        "target_team": "teamB",
                        "flag_id": "vuln1",
                        "sha256": poc_sha,
                    }},
                    files={{"file": ("poc1.py", poc_source, "text/x-python")}},
                )
                assert resp.status_code == 200, resp.text
                body = resp.json()
                assert body["status"] == "submitted", body
                assert body["run_result"]["status"] == "success", body
                assert body["run_result"]["scored"] == 1, body
                scores = app.db.get_all_scores()
                assert scores["teamA"]["score"] == 1010, scores
                assert scores["teamC"]["score"] == 990, scores
                scoreboard = client.get("/scoreboard")
                assert scoreboard.status_code == 200, scoreboard.text
                public_result = scoreboard.json()["poc_results"][0]
                assert "flags" not in public_result, public_result
                assert public_result["flags_found"] == 1, public_result
                assert flag not in scoreboard.text, scoreboard.text
            """
        )
        result = subprocess.run([sys.executable, "-c", script], cwd=ROOT, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            self.fail(result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
