import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COORDINATOR = ROOT / "coordinator"
sys.path.insert(0, str(COORDINATOR))

import db  # noqa: E402
import poc_runner  # noqa: E402
import scorer  # noqa: E402
from rotation import get_attack_targets, get_defender, get_defense_target  # noqa: E402


TEAM_IDS = ["teamA", "teamB", "teamC", "teamD", "teamE", "teamF"]


def reset_db(path: Path) -> None:
    conn = getattr(db, "_conn", None)
    if conn is not None:
        conn.close()
    db._conn = None
    db.init_db(str(path))
    db.init_scores({team_id: 1000 for team_id in TEAM_IDS})


class CoreFlowTests(unittest.TestCase):
    def test_rotation_rules(self):
        self.assertEqual(get_defender("teamA"), "teamB")
        self.assertEqual(get_defense_target("teamB"), "teamA")
        self.assertNotIn("teamA", get_attack_targets("teamA"))
        self.assertNotIn("teamF", get_attack_targets("teamA"))
        self.assertEqual(set(get_attack_targets("teamA")), {"teamB", "teamC", "teamD", "teamE"})

    def test_poc_runner_scores_once_per_round(self):
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
                status="accepted",
            )
            db.update_poc_status(poc["id"], "accepted", "test")

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
                status="accepted",
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
                status="accepted",
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


class OpenRouterGatewayTests(unittest.TestCase):
    def test_llm_gateway_uses_openrouter_compatible_api(self):
        script = textwrap.dedent(
            f"""
            import json
            import os
            import tempfile
            import threading
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
                "DEFENSE_TOKEN_TEAM_A": "dtokA",
                "DEFENSE_TOKEN_TEAM_B": "dtokB",
                "DEFENSE_TOKEN_TEAM_C": "dtokC",
                "DEFENSE_TOKEN_TEAM_D": "dtokD",
                "DEFENSE_TOKEN_TEAM_E": "dtokE",
                "DEFENSE_TOKEN_TEAM_F": "dtokF",
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

            with TestClient(app.app) as client:
                run = client.post(
                    "/agent-runs",
                    headers={{"X-Team-Token": "tokA"}},
                    json={{"team_id": "teamA", "mode": "attack", "target_team": "teamC", "round_num": 0}},
                )
                assert run.status_code == 200, run.text
                run_id = run.json()["agent_run_id"]
                resp = client.post(
                    "/llm",
                    headers={{"X-Team-Token": "tokA"}},
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
            server.shutdown()
            """
        )
        result = subprocess.run([sys.executable, "-c", script], cwd=ROOT, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            self.fail(result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
