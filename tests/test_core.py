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
from types import SimpleNamespace
from contextlib import redirect_stdout
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
COORDINATOR = ROOT / "coordinator"
SCRIPTS = ROOT / "scripts"
os.environ.setdefault("ADMIN_SECRET", "test-admin")
os.environ["TEAM_SUFFIXES"] = "1,2,3,4,5,6"
for suffix in "1234567":
    os.environ.setdefault(f"TOKEN_TEAM_{suffix}", f"tok{suffix}")
    os.environ.setdefault(f"DEFENSE_TOKEN_TEAM_{suffix}", f"dtok{suffix}")
sys.path.insert(0, str(COORDINATOR))
sys.path.insert(0, str(SCRIPTS))

import db  # noqa: E402
import checker  # noqa: E402
import poc_runner  # noqa: E402
import scorer  # noqa: E402
from validate_vulns import validate_poc_single, validate_single  # noqa: E402
from preflight_check import _missing_team_specs  # noqa: E402
from rotation import get_attack_targets, get_defender, get_defense_target  # noqa: E402
from config import TEAM_ORDER, TEAMS, TEAM_TOKENS, ATTACK_AGENT_IMAGES, DEFENSE_AGENT_IMAGES  # noqa: E402


TEAM_IDS = ["team1", "team2", "team3", "team4", "team5", "team6"]


def reset_db(path: Path) -> None:
    conn = getattr(db, "_conn", None)
    if conn is not None:
        conn.close()
    db._conn = None
    db.init_db(str(path))
    db.init_scores({team_id: 1000 for team_id in TEAM_IDS})


class CoreFlowTests(unittest.TestCase):
    def test_default_event_has_six_teams(self):
        self.assertEqual(TEAM_ORDER, TEAM_IDS)
        self.assertIn("team6", TEAMS)
        self.assertIn("team6", TEAM_TOKENS)
        self.assertEqual(ATTACK_AGENT_IMAGES["team6"], "and-attack-team6:latest")
        self.assertEqual(DEFENSE_AGENT_IMAGES["team6"], "and-defense-team6:latest")

    def test_preflight_requires_team_specs_for_all_teams(self):
        teams = {team_id: {"ip": f"10.0.0.{idx}", "port": 8000} for idx, team_id in enumerate(TEAM_IDS, start=1)}
        specs = {team_id: {"team_id": team_id} for team_id in TEAM_IDS[:-1]}
        self.assertEqual(_missing_team_specs(teams, specs), ["team6"])

    def test_rotation_rules(self):
        self.assertEqual(get_defender("team1"), "team2")
        self.assertEqual(get_defense_target("team2"), "team1")
        self.assertNotIn("team1", get_attack_targets("team1"))
        self.assertNotIn("team6", get_attack_targets("team1"))
        self.assertEqual(set(get_attack_targets("team1")), {"team2", "team3", "team4", "team5"})
        self.assertEqual(get_defender("team6"), "team1")
        self.assertEqual(get_defense_target("team1"), "team6")

    def test_submitted_poc_scores_once_per_round_without_manual_accept(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            reset_db(root / "game.db")
            db.set_service_status("team2", "OK")
            flag = "HSPACE{0123456789abcdef0123456789abcdef}"
            db.upsert_flag(1, "team2", "vuln1", flag)
            run = db.create_agent_run("run-1", "team1", "attack", "team2", 1)
            llm_id = db.append_llm_call(
                agent_run_id=run["id"],
                model="openai/gpt-4o-mini",
                allowed=True,
                prompt_hash="prompt",
                response_hash="response",
                purpose="poc",
                status="completed",
            )
            poc_path = root / "poc_team2_vuln1.py"
            poc_path.write_text(f"print('{flag}')\n", encoding="utf-8")
            poc = db.create_poc_submission(
                poc_id="poc-1",
                agent_run_id=run["id"],
                llm_call_id=llm_id,
                attacker_team="team1",
                target_team="team2",
                defender_team="team3",
                flag_id="vuln1",
                submitted_round=1,
                file_name=poc_path.name,
                sha256="sha",
                storage_path=str(poc_path),
            )
            self.assertEqual(poc["status"], "submitted")

            teams = {"team2": {"ip": "127.0.0.1", "port": 8000, "name": "Team 2"}}
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
            self.assertEqual(scores["team1"]["score"], 1010)
            self.assertEqual(scores["team3"]["score"], 990)
            self.assertEqual(db.count_successful_pocs_by_attacker(), {"team1": 1})

    def test_poc_runner_requires_flag_on_final_stdout_line(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            reset_db(root / "game.db")
            db.set_service_status("team2", "OK")
            flag = "HSPACE{fedcba9876543210fedcba9876543210}"
            db.upsert_flag(1, "team2", "vuln1", flag)
            run = db.create_agent_run("run-final-line", "team1", "attack", "team2", 1)
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
                attacker_team="team1",
                target_team="team2",
                defender_team="team3",
                flag_id="vuln1",
                submitted_round=1,
                file_name=poc_path.name,
                sha256="sha",
                storage_path=str(poc_path),
            )

            result = poc_runner.run_pocs_for_round(
                round_num=1,
                teams={"team2": {"ip": "127.0.0.1", "port": 8000, "name": "Team 2"}},
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

    def test_poc_runner_only_runs_pocs_submitted_for_that_round(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            reset_db(root / "game.db")
            db.set_service_status("team2", "OK")
            flag = "HSPACE{aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"
            db.upsert_flag(2, "team2", "vuln1", flag)
            run1 = db.create_agent_run("run-old", "team1", "attack", "team2", 1)
            run2 = db.create_agent_run("run-new", "team1", "attack", "team2", 2)
            old_path = root / "poc_old.py"
            new_path = root / "poc_new.py"
            old_path.write_text("print('old')\n", encoding="utf-8")
            new_path.write_text(f"print('{flag}')\n", encoding="utf-8")
            db.create_poc_submission(
                poc_id="poc-old",
                agent_run_id=run1["id"],
                llm_call_id=1,
                attacker_team="team1",
                target_team="team2",
                defender_team="team3",
                flag_id="vuln1",
                submitted_round=1,
                file_name=old_path.name,
                sha256="old-sha",
                storage_path=str(old_path),
            )
            db.create_poc_submission(
                poc_id="poc-new",
                agent_run_id=run2["id"],
                llm_call_id=2,
                attacker_team="team1",
                target_team="team2",
                defender_team="team3",
                flag_id="vuln1",
                submitted_round=2,
                file_name=new_path.name,
                sha256="new-sha",
                storage_path=str(new_path),
            )

            result = poc_runner.run_pocs_for_round(
                round_num=2,
                teams={"team2": {"ip": "127.0.0.1", "port": 8000, "name": "Team 2"}},
                data_dir=str(root / "data"),
                timeout_sec=5,
                output_max_bytes=4096,
                attack_reward=10,
                attack_penalty=10,
                runner_mode="local",
            )

            self.assertEqual([row["poc_id"] for row in result], ["poc-new"])
            self.assertIsNone(db.get_poc_result(2, "poc-old"))
            self.assertEqual(result[0]["status"], "success")

    def test_poc_runner_scores_only_once_per_vuln_per_round(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            reset_db(root / "game.db")
            db.set_service_status("team2", "OK")
            flag = "HSPACE{bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb}"
            db.upsert_flag(1, "team2", "vuln1", flag)
            run = db.create_agent_run("run-once-vuln", "team1", "attack", "team2", 1)
            for idx in range(2):
                path = root / f"poc_success_{idx}.py"
                path.write_text(f"print('{flag}')\n", encoding="utf-8")
                db.create_poc_submission(
                    poc_id=f"poc-success-{idx}",
                    agent_run_id=run["id"],
                    llm_call_id=idx + 1,
                    attacker_team="team1",
                    target_team="team2",
                    defender_team="team3",
                    flag_id="vuln1",
                    submitted_round=1,
                    file_name=path.name,
                    sha256=f"sha-{idx}",
                    storage_path=str(path),
                )

            result = poc_runner.run_pocs_for_round(
                round_num=1,
                teams={"team2": {"ip": "127.0.0.1", "port": 8000, "name": "Team 2"}},
                data_dir=str(root / "data"),
                timeout_sec=5,
                output_max_bytes=4096,
                attack_reward=10,
                attack_penalty=10,
                runner_mode="local",
            )

            self.assertEqual(result[0]["status"], "success")
            self.assertEqual(result[0]["scored"], 1)
            self.assertEqual(result[1]["status"], "skipped_already_scored")
            self.assertEqual(result[1]["scored"], 0)
            scores = db.get_all_scores()
            self.assertEqual(scores["team1"]["score"], 1010)
            self.assertEqual(scores["team3"]["score"], 990)

    def test_poc_submission_replaces_oldest_after_two_per_vuln_per_round(self):
        import app as coordinator_app

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            reset_db(root / "game.db")
            coordinator_app.state.start_round(1)
            run = db.create_agent_run("run-quota", "team1", "attack", "team2", 1)
            llm_id = db.append_llm_call(
                agent_run_id=run["id"],
                model="openai/gpt-4o-mini",
                allowed=True,
                prompt_hash="prompt",
                response_hash="response",
                purpose="poc",
                status="completed",
            )

            old_data_dir = coordinator_app.DATA_DIR
            old_run_pocs = coordinator_app._run_pocs
            coordinator_app.DATA_DIR = str(root / "data")
            coordinator_app._run_pocs = lambda round_num, only_poc_id=None: []
            try:
                poc_ids = []
                for idx in range(2):
                    result = coordinator_app._submit_poc_content(
                        run=run,
                        llm_call={"id": llm_id},
                        attacker_team="team1",
                        target_team="team2",
                        flag_id="vuln1",
                        file_name=f"poc{idx}.py",
                        content=f"print('attempt {idx}')\n".encode(),
                    )
                    self.assertEqual(result["status"], "submitted")
                    self.assertIsNone(result["replaced_poc_id"])
                    poc_ids.append(result["poc_id"])

                result = coordinator_app._submit_poc_content(
                    run=run,
                    llm_call={"id": llm_id},
                    attacker_team="team1",
                    target_team="team2",
                    flag_id="vuln1",
                    file_name="poc2.py",
                    content=b"print('attempt 2')\n",
                )

                self.assertEqual(result["status"], "submitted")
                self.assertEqual(result["replaced_poc_id"], poc_ids[0])
                self.assertEqual(db.get_poc_submission(poc_ids[0])["status"], "replaced")
                self.assertEqual(
                    db.count_active_poc_submissions_for_vuln("team1", "team2", "vuln1", 1),
                    2,
                )
                runnable_ids = [poc["id"] for poc in db.get_runnable_pocs(1)]
                self.assertNotIn(poc_ids[0], runnable_ids)
                self.assertIn(poc_ids[1], runnable_ids)
                self.assertIn(result["poc_id"], runnable_ids)
            finally:
                coordinator_app.DATA_DIR = old_data_dir
                coordinator_app._run_pocs = old_run_pocs

    def test_poc_timeout_overrides_are_capped_per_vuln(self):
        import app as coordinator_app

        old_max = coordinator_app.POC_MAX_TIMEOUT_SEC
        coordinator_app.POC_MAX_TIMEOUT_SEC = 120
        try:
            overrides = coordinator_app._poc_timeout_overrides({
                "team2": {
                    "vulnerabilities": [
                        {"id": "vuln1", "poc_timeout_sec": 60},
                        {"id": "vuln2", "checker": {"poc_timeout_sec": 999}},
                        {"id": "vuln3", "poc_timeout_sec": "bad"},
                    ],
                }
            })
        finally:
            coordinator_app.POC_MAX_TIMEOUT_SEC = old_max

        self.assertEqual(overrides["team2"]["vuln1"], 60)
        self.assertEqual(overrides["team2"]["vuln2"], 120)
        self.assertNotIn("vuln3", overrides["team2"])

    def test_round_score_report_separates_availability_from_poc_deltas(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            reset_db(root / "game.db")
            db.set_service_status("team1", "OK")
            db.set_service_status("team2", "OK")
            run = db.create_agent_run("run-1", "team1", "attack", "team2", 1)
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
                attacker_team="team1",
                target_team="team2",
                defender_team="team3",
                flag_id="vuln1",
                submitted_round=1,
                file_name="poc.py",
                sha256="sha",
                storage_path=str(root / "poc.py"),
            )
            db.insert_poc_result(
                round_num=1,
                poc_id="poc-1",
                attacker_team="team1",
                target_team="team2",
                defender_team="team3",
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
                availability={"team1": True, "team2": True},
                attack_reward=10,
                attack_penalty=10,
                availability_bonus=10,
            )
            self.assertEqual(result["availability_score_changes"]["team1"], 10)
            self.assertEqual(result["poc_score_changes"]["team1"], 10)
            self.assertEqual(result["poc_score_changes"]["team3"], -10)
            self.assertEqual(result["score_changes"]["team1"], 20)

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
            db.set_service_status("team1", "OK")
            flag = "HSPACE{0123456789abcdef0123456789abcdef}"
            db.upsert_flag(1, "team1", "vuln1", flag)

            server = HTTPServer(("127.0.0.1", 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                spec = {
                    "team_id": "team1",
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
                    {"team1": {"ip": "127.0.0.1", "port": server.server_port}},
                    {"team1": spec},
                    {"team1": {"vuln1": flag}},
                    "checker-token",
                ))
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

            self.assertTrue(results["team1"].health_ok)
            self.assertEqual(db.get_service_statuses()["team1"], "FAULTY")
            score = scorer.compute_round_scores(
                ["team1"],
                1,
                availability={"team1": True},
                attack_reward=10,
                attack_penalty=10,
                availability_bonus=10,
            )
            self.assertEqual(score["availability_score_changes"]["team1"], 0)

    def test_checker_runs_basic_function_for_each_vulnerability(self):
        stored: dict[str, str] = {}

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
                    return self._json(200, {"stored": list(stored.values())})
                if self.path == "/basic/v1":
                    return self._json(200, {"response": "vuln1 basic ok"})
                if self.path == "/basic/v2":
                    return self._json(404, {"error": "removed"})
                return self._json(404, {"error": "not found"})

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length)
                if self.path == "/admin/inject":
                    body = json.loads(raw.decode() or "{}")
                    stored[body["vuln_id"]] = body["value"]
                    return self._json(200, {"ok": True})
                return self._json(404, {"error": "not found"})

            def log_message(self, *args):
                pass

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            reset_db(root / "game.db")
            flags = {
                "vuln1": "HSPACE{11111111111111111111111111111111}",
                "vuln2": "HSPACE{22222222222222222222222222222222}",
            }
            spec = {
                "team_id": "team1",
                "service": {"health": {"endpoint": "/health", "method": "GET", "expect_status": 200}},
                "vulnerabilities": [
                    {
                        "id": "vuln1",
                        "checker": {
                            "inject": {"endpoint": "/admin/inject", "method": "POST", "body": {"vuln_id": "vuln1", "value": "{{FLAG}}"}},
                            "retrieve": {"endpoint": "/admin/check", "method": "GET", "expect_contains": "{{FLAG}}"},
                            "basic_function": {"endpoint": "/basic/v1", "method": "GET", "expect_status": 200},
                        },
                    },
                    {
                        "id": "vuln2",
                        "checker": {
                            "inject": {"endpoint": "/admin/inject", "method": "POST", "body": {"vuln_id": "vuln2", "value": "{{FLAG}}"}},
                            "retrieve": {"endpoint": "/admin/check", "method": "GET", "expect_contains": "{{FLAG}}"},
                            "basic_function": {"endpoint": "/basic/v2", "method": "GET", "expect_status": 200},
                        },
                    },
                ],
            }

            server = HTTPServer(("127.0.0.1", 0), Handler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                results = asyncio.run(checker.run_all_checkers(
                    {"team1": {"ip": "127.0.0.1", "port": server.server_port}},
                    {"team1": spec},
                    {"team1": flags},
                    "checker-token",
                ))
            finally:
                server.shutdown()
                server.server_close()
                thread.join(timeout=2)

            result = results["team1"]
            self.assertEqual(result.status, "FAULTY")
            self.assertFalse(result.basic_func_ok)
            self.assertTrue(result.vuln_results["vuln1"]["basic_function"])
            self.assertFalse(result.vuln_results["vuln2"]["basic_function"])
            self.assertEqual(db.get_service_statuses()["team1"], "FAULTY")

    def test_end_round_scores_against_scoring_snapshot(self):
        import app as coordinator_app

        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            reset_db(root / "game.db")
            coordinator_app.state.start_round(1)
            calls: list[tuple[str, object]] = []
            snapshot_teams = {
                team_id: {**info, "ip": f"10.89.21.{110 + idx}"}
                for idx, (team_id, info) in enumerate(coordinator_app.TEAMS.items())
            }

            def fake_snapshot(**kwargs):
                calls.append(("snapshot", kwargs["round_num"]))
                return SimpleNamespace(
                    teams=snapshot_teams,
                    image_tags={team_id: f"and-service-{team_id}:round1-snapshot" for team_id in snapshot_teams},
                    containers=[],
                )

            async def fake_checkers(teams, vuln_specs, round_flags_by_team, checker_token):
                calls.append(("checker", teams))
                for team_id in teams:
                    db.set_service_status(team_id, "OK")
                return {
                    team_id: SimpleNamespace(health_ok=True, status="OK")
                    for team_id in teams
                }

            def fake_run_pocs(round_num, only_poc_id=None, teams_override=None):
                calls.append(("pocs", teams_override))
                return [{"status": "success"}]

            old_snapshot = coordinator_app.create_round_snapshot
            old_cleanup = coordinator_app.cleanup_round_snapshot
            old_checkers = coordinator_app.chk.run_all_checkers
            old_run_pocs = coordinator_app._run_pocs
            old_stop_agents = coordinator_app.stop_round_agents
            old_grace = coordinator_app.SCORING_SNAPSHOT_STARTUP_GRACE_SEC
            cleanup_calls: list[object] = []
            coordinator_app.create_round_snapshot = fake_snapshot
            coordinator_app.cleanup_round_snapshot = lambda snapshot: cleanup_calls.append(snapshot)
            coordinator_app.chk.run_all_checkers = fake_checkers
            coordinator_app._run_pocs = fake_run_pocs
            coordinator_app.stop_round_agents = lambda round_num: calls.append(("stop", round_num))
            coordinator_app.SCORING_SNAPSHOT_STARTUP_GRACE_SEC = 0
            try:
                result = asyncio.run(coordinator_app.end_round(x_admin_secret="test-admin"))
            finally:
                coordinator_app.create_round_snapshot = old_snapshot
                coordinator_app.cleanup_round_snapshot = old_cleanup
                coordinator_app.chk.run_all_checkers = old_checkers
                coordinator_app._run_pocs = old_run_pocs
                coordinator_app.stop_round_agents = old_stop_agents
                coordinator_app.SCORING_SNAPSHOT_STARTUP_GRACE_SEC = old_grace

            self.assertFalse(coordinator_app.state.round_active)
            self.assertEqual(result["pocs_run"], 1)
            self.assertTrue(result["scoring_snapshot"]["enabled"])
            self.assertEqual(calls[0], ("stop", 1))
            self.assertEqual(calls[1], ("snapshot", 1))
            self.assertEqual(calls[2][0], "checker")
            self.assertEqual(calls[2][1], snapshot_teams)
            self.assertEqual(calls[3], ("pocs", snapshot_teams))
            self.assertEqual(len(cleanup_calls), 1)


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
            team_id="team1",
            team_token="tokenA",
            mode="attack",
            target_team="team2",
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
        self.assertEqual(kwargs["data"]["attacker_team"], "team1")
        self.assertEqual(kwargs["data"]["target_team"], "team2")
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
            self.assertIn("OPENROUTER_BASE_URL", source, relative)
            self.assertIn("AGENT_RUN_TOKEN", source, relative)
            self.assertIn("HSPACE_AGENT_BASE_URL", source, relative)
            self.assertIn("/chat/completions", source, relative)
            self.assertIn("/finish", source, relative)
            self.assertNotIn("AgentContext", source, relative)
            self.assertNotIn("agent_sdk", source, relative)
            for forbidden in [
                "openrouter.ai",
                "api.openai.com",
                "api.anthropic.com",
                "generativelanguage.googleapis.com",
            ]:
                self.assertNotIn(forbidden, source.lower(), relative)
        attack_source = (ROOT / "attack_agent/main.py").read_text(encoding="utf-8")
        self.assertIn("/attack", attack_source)
        self.assertIn("/pocs", attack_source)

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
        self.assertIn("gitctf.py agent build team1", help_result.stdout)

    def test_admin_env_setup_script_targets_six_team_event(self):
        script = ROOT / "scripts" / "setup_admin_env.sh"
        result = subprocess.run(["bash", "-n", str(script)], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        source = script.read_text(encoding="utf-8")
        self.assertIn("1,2,3,4,5,6", source)
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
            self.assertIn("CHECKER_TOKEN=", env_text)
            self.assertIn("TOKEN_TEAM_6=", env_text)
            self.assertIn("HOST_PORT_TEAM_6=42006", env_text)
            self.assertIn("team6\t", tokens_text)
            self.assertNotIn("CHECKER_TOKEN", tokens_text)
            self.assertNotIn("TOKEN_TEAM_G=", env_text)
            self.assertNotIn("teamG\t", tokens_text)

    def test_user_docs_point_to_single_cli_for_agent_work(self):
        for relative in ["README.md", "SCRIPT_USAGE.txt", "AGENT_USAGE.txt", "OPENROUTER_AGENT_ENVIRONMENT.md"]:
            source = (ROOT / relative).read_text(encoding="utf-8")
            self.assertIn("gitctf.py agent", source, relative)
            self.assertNotIn("python scripts/agent.py", source, relative)
        agent_usage = (ROOT / "AGENT_USAGE.txt").read_text(encoding="utf-8")
        self.assertIn("오케스트레이션 방식은 자유입니다", agent_usage)
        self.assertIn("OPENAI_BASE_URL", agent_usage)
        self.assertIn("OPENROUTER_BASE_URL", agent_usage)
        self.assertIn("api.openai.com", agent_usage)
        self.assertIn("/agent/attack", agent_usage)
        self.assertIn("/agent/pocs", agent_usage)
        self.assertIn("허용 모델", agent_usage)
        self.assertIn("하면 안 되는 것", agent_usage)
        self.assertIn("Python main.py 템플릿", agent_usage)
        self.assertNotIn("AgentContext", agent_usage)
        self.assertNotIn("SDK", agent_usage)
        openrouter_guide = (ROOT / "OPENROUTER_AGENT_ENVIRONMENT.md").read_text(encoding="utf-8")
        self.assertIn("OPENROUTER_BASE_URL", openrouter_guide)
        self.assertIn("OPENROUTER_API_KEY", openrouter_guide)
        self.assertIn("openai/gpt-5.5", openrouter_guide)
        self.assertIn("/agent/attack", openrouter_guide)
        self.assertIn("test_disallowed_gpt55_model_cannot_unlock_agent_attack", openrouter_guide)
        self.assertIn("하면 안 되는 것", openrouter_guide)
        self.assertIn("wrapper는 OpenRouter 사용 여부와 모델 허용 여부를 검사", openrouter_guide)
        self.assertNotIn("AgentContext", openrouter_guide)
        self.assertNotIn("SDK", openrouter_guide)

    def test_user_deploy_bundle_is_participant_facing(self):
        source = (ROOT / "scripts" / "build_user_deploy.py").read_text(encoding="utf-8")
        self.assertIn("USER_DEPLOY_GUIDE.md", source)
        self.assertIn("DISCORD_NOTICE.txt", source)
        self.assertIn("DISCORD_AGENT_NOTICE.txt", source)
        self.assertIn("OPENROUTER_AGENT_ENVIRONMENT.md", source)
        self.assertIn("docs/pdf/agent_guide.pdf", source)
        self.assertIn("hspace-livefire-user-deploy.tar.gz", source)
        self.assertIn("42000 포트는 점수판과 인증된 `gitctf.py` 제출 endpoint만 제공", source)
        self.assertIn('"public_file_serving": False', source)
        self.assertNotIn("42000/deploy", source)
        self.assertNotIn("deploy-bundle.tar.gz", source)
        self.assertNotIn("deploy-guide.pdf", source)
        self.assertNotIn("USER_DEPLOY_GUIDE.pdf", source)
        self.assertNotIn('"scripts/setup_admin_env.sh"', source)
        notice = (ROOT / "DISCORD_NOTICE.txt").read_text(encoding="utf-8")
        self.assertIn("팀 토큰 및 서버 안내", notice)
        self.assertIn("<TEAM_TOKEN>", notice)
        self.assertIn("<DEFENSE_TOKEN>", notice)
        self.assertIn("gitctf.py login", notice)
        self.assertIn("GitHub에 올리지 말고", notice)
        self.assertIn("gitctf.py push", notice)
        self.assertIn("make push", notice)
        self.assertIn("http://knights.hspace.io:42001", notice)
        self.assertIn("http://knights.hspace.io:42006", notice)
        self.assertNotIn("Agent 오케스트레이션", notice)
        self.assertNotIn("허용 모델 prefix", notice)
        agent_notice = (ROOT / "DISCORD_AGENT_NOTICE.txt").read_text(encoding="utf-8")
        self.assertIn("Agent 구현 안내", agent_notice)
        self.assertIn("API key는 참가자가 관리하지 않습니다", agent_notice)
        self.assertIn("main.py", agent_notice)
        self.assertIn("OPENROUTER_BASE_URL", agent_notice)
        self.assertIn("wrapper가 OpenRouter 사용 여부", agent_notice)
        self.assertIn("하지 말아야 할 것", agent_notice)
        self.assertIn("agent_guide.pdf", agent_notice)
        self.assertLess(len(agent_notice.splitlines()), 40)
        self.assertNotIn("AgentContext", agent_notice)
        self.assertNotIn("SDK", agent_notice)
        guide_html = (ROOT / "docs" / "pdf" / "agent_guide.html").read_text(encoding="utf-8")
        self.assertIn("HSPACE LiveFire Agent Guide", guide_html)
        self.assertIn("개인 API key는 필요 없습니다", guide_html)
        self.assertIn("wrapper가 하는 일", guide_html)
        self.assertIn("하면 안 되는 것", guide_html)
        self.assertTrue((ROOT / "docs" / "pdf" / "agent_guide.pdf").exists())

    def test_public_runtime_serves_scoreboard_site(self):
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        gateway = (ROOT / "gateway" / "nginx.conf").read_text(encoding="utf-8")
        scoreboard = (ROOT / "scoreboard" / "index.html").read_text(encoding="utf-8")
        self.assertIn("./scoreboard:/srv/scoreboard:ro", compose)
        self.assertTrue((ROOT / "scoreboard" / "index.html").exists())
        self.assertIn("HSPACE LiveFire", scoreboard)
        self.assertIn("행사 시간표", scoreboard)
        self.assertIn("팀별 점수 현황", scoreboard)
        self.assertIn("대기 PoC", scoreboard)
        self.assertIn("2026년 5월 29일(금) KST 기준", scoreboard)
        self.assertIn("A&amp;D 5/29 20:00 KST 시작", scoreboard)
        self.assertIn("const EVENT_DAY = 29;", scoreboard)
        self.assertIn('fetch("/scoreboard"', scoreboard)
        self.assertIn('fetch("/status"', scoreboard)
        self.assertIn("queued_poc_count", scoreboard)
        self.assertIn("queued_pocs", scoreboard)
        self.assertNotIn("공격 대상", scoreboard)
        self.assertNotIn("attack_targets", scoreboard)
        self.assertNotIn("target_team", scoreboard)
        self.assertNotIn("defender_team", scoreboard)
        self.assertIn("types { }", gateway)
        self.assertIn("default_type text/plain", gateway)
        self.assertIn("location = / {", gateway)
        self.assertIn("root /srv/scoreboard;", gateway)
        self.assertIn("try_files /index.html =404;", gateway)
        self.assertIn("default_type text/html;", gateway)
        self.assertNotIn("HSPACE LiveFire CLI/API gateway", gateway)
        self.assertIn('return 404 "not found\\n"', gateway)
        self.assertIn("location = /health", gateway)
        self.assertIn("location /tools/", gateway)
        self.assertIn("location /git/", gateway)
        self.assertIn("proxy_request_buffering off", gateway)
        self.assertNotIn("./user_deploy:/srv/user_deploy:ro", compose)
        self.assertNotIn("./dist:/srv/dist:ro", compose)
        self.assertNotIn("/deploy", gateway)
        self.assertNotIn("alias /srv/user_deploy", gateway)
        self.assertNotIn("alias /srv/dist", gateway)
        self.assertNotIn("DISCORD_AGENT_NOTICE.txt", gateway)
        self.assertNotIn("agent_guide.pdf", gateway)
        self.assertNotIn("location /admin/", gateway)
        self.assertNotIn("location /agent/", gateway)
        self.assertNotIn("location /openrouter/", gateway)
        self.assertNotIn("location /v1/", gateway)
        self.assertNotIn("autoindex on", gateway)
        self.assertNotIn("deploy-guide.pdf", gateway)

    def test_agent_dockerfiles_use_compatibility_runner(self):
        for relative in ["attack_agent/Dockerfile", "defense_agent/Dockerfile"]:
            source = (ROOT / relative).read_text(encoding="utf-8")
            self.assertIn("agent_sdk.runner", source, relative)
            self.assertNotIn('CMD ["python", "attack_agent/main.py"]', source, relative)
            self.assertNotIn('CMD ["python", "defense_agent/main.py"]', source, relative)

    def test_official_agent_runner_does_not_expose_runner_secret(self):
        source = (ROOT / "coordinator" / "agent_runner.py").read_text(encoding="utf-8")
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        self.assertIn("COORDINATOR_URL=http://10.89.20.2:9000", compose)
        self.assertIn('ATTACK_DOCKER_NETWORK=hackathon_scoring-net', compose)
        self.assertIn("--network", source)
        self.assertIn("ATTACK_DOCKER_NETWORK", source)
        self.assertIn("AGENT_RUN_TOKEN", source)
        self.assertIn("OPENAI_BASE_URL", source)
        self.assertIn("OPENROUTER_BASE_URL", source)
        self.assertIn("OPENROUTER_API_KEY={run_token}", source)
        self.assertIn("HSPACE_AGENT_BASE_URL", source)
        self.assertIn("TARGET_REPO_URL", source)
        self.assertNotIn("RUNNER_SECRET=", source)

    def test_git_hook_locks_push_after_preflight(self):
        source = (ROOT / "coordinator" / "git_handler.py").read_text(encoding="utf-8")
        self.assertIn("PREFLIGHT_DONE", source)
        self.assertIn("사전검증 이후에는 추가 push 불가", source)

    def test_git_deploy_uses_gateway_owned_team_ports(self):
        compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
        gateway = (ROOT / "gateway" / "nginx.conf").read_text(encoding="utf-8")
        git_handler_source = (ROOT / "coordinator" / "git_handler.py").read_text(encoding="utf-8")
        self.assertIn('"42001:42001"', compose)
        self.assertIn('"42006:42006"', compose)
        self.assertIn("profiles:", compose)
        self.assertIn("- mock", compose)
        self.assertIn("proxy_pass http://10.89.21.10:8000;", gateway)
        self.assertIn("--network hackathon_target-net", git_handler_source)
        self.assertIn('--ip "{team_ip}"', git_handler_source)
        self.assertIn('"hackathon-{docker_team}-service-1"', git_handler_source)
        self.assertNotIn('-p "{host_port}:8000"', git_handler_source)

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
                "team1",
                "--target",
                "team2",
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
    def test_agent_run_rate_limit_returns_429(self):
        script = textwrap.dedent(
            f"""
            import os
            import tempfile
            from pathlib import Path

            root = Path({str(ROOT)!r})
            workdir = Path(tempfile.mkdtemp())
            os.environ.update({{
                "ADMIN_SECRET": "admin",
                "TOKEN_TEAM_1": "tokA",
                "TOKEN_TEAM_2": "tokB",
                "TOKEN_TEAM_3": "tokC",
                "TOKEN_TEAM_4": "tokD",
                "TOKEN_TEAM_5": "tokE",
                "TOKEN_TEAM_6": "tokF",
                "DEFENSE_TOKEN_TEAM_1": "dtokA",
                "DEFENSE_TOKEN_TEAM_2": "dtokB",
                "DEFENSE_TOKEN_TEAM_3": "dtokC",
                "DEFENSE_TOKEN_TEAM_4": "dtokD",
                "DEFENSE_TOKEN_TEAM_5": "dtokE",
                "DEFENSE_TOKEN_TEAM_6": "dtokF",
                "RUNNER_SECRET": "runner-secret",
                "DB_PATH": str(workdir / "game.db"),
                "DATA_DIR": str(workdir / "data"),
                "VULN_SPEC_DIR": str(workdir / "vuln_specs"),
                "REPOS_DIR": str(workdir / "repos"),
                "RATE_LIMIT_AGENT_RUNS": "2/minute",
            }})
            (workdir / "vuln_specs").mkdir()
            (workdir / "repos").mkdir()

            import sys
            sys.path.insert(0, str(root / "coordinator"))
            from fastapi.testclient import TestClient
            import app

            with TestClient(app.app) as client:
                headers = {{
                    "X-Team-Token": "tokA",
                    "X-Runner-Secret": "runner-secret",
                    "X-Agent-SDK": "hspace-agent-sdk/1",
                }}
                payload = {{"team_id": "team1", "mode": "attack", "target_team": "team2", "round_num": 0}}
                first = client.post("/agent-runs", headers=headers, json=payload)
                second = client.post("/agent-runs", headers=headers, json=payload)
                third = client.post("/agent-runs", headers=headers, json=payload)
                assert first.status_code == 200, first.text
                assert second.status_code == 200, second.text
                assert third.status_code == 429, third.text
            """
        )
        result = subprocess.run([sys.executable, "-c", script], cwd=ROOT, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            self.fail(result.stdout + result.stderr)

    def test_agent_run_rate_limit_is_split_by_mode(self):
        script = textwrap.dedent(
            f"""
            import os
            import tempfile
            from pathlib import Path

            root = Path({str(ROOT)!r})
            workdir = Path(tempfile.mkdtemp())
            os.environ.pop("RATE_LIMIT_AGENT_RUNS", None)
            os.environ.update({{
                "ADMIN_SECRET": "admin",
                "TOKEN_TEAM_1": "tokA",
                "TOKEN_TEAM_2": "tokB",
                "TOKEN_TEAM_3": "tokC",
                "TOKEN_TEAM_4": "tokD",
                "TOKEN_TEAM_5": "tokE",
                "TOKEN_TEAM_6": "tokF",
                "DEFENSE_TOKEN_TEAM_1": "dtokA",
                "DEFENSE_TOKEN_TEAM_2": "dtokB",
                "DEFENSE_TOKEN_TEAM_3": "dtokC",
                "DEFENSE_TOKEN_TEAM_4": "dtokD",
                "DEFENSE_TOKEN_TEAM_5": "dtokE",
                "DEFENSE_TOKEN_TEAM_6": "dtokF",
                "RUNNER_SECRET": "runner-secret",
                "DB_PATH": str(workdir / "game.db"),
                "DATA_DIR": str(workdir / "data"),
                "VULN_SPEC_DIR": str(workdir / "vuln_specs"),
                "REPOS_DIR": str(workdir / "repos"),
                "RATE_LIMIT_ATTACK_AGENT_RUNS": "2/minute",
                "RATE_LIMIT_DEFENSE_AGENT_RUNS": "1/minute",
            }})
            (workdir / "vuln_specs").mkdir()
            (workdir / "repos").mkdir()

            import sys
            sys.path.insert(0, str(root / "coordinator"))
            from fastapi.testclient import TestClient
            import app

            with TestClient(app.app) as client:
                headers = {{
                    "X-Team-Token": "tokA",
                    "X-Runner-Secret": "runner-secret",
                    "X-Agent-SDK": "hspace-agent-sdk/1",
                }}
                attack_payload = {{"team_id": "team1", "mode": "attack", "target_team": "team2", "round_num": 0}}
                assert client.post("/agent-runs", headers=headers, json=attack_payload).status_code == 200
                assert client.post("/agent-runs", headers=headers, json=attack_payload).status_code == 200
                attack_blocked = client.post("/agent-runs", headers=headers, json=attack_payload)
                assert attack_blocked.status_code == 429, attack_blocked.text

                defense_headers = {{
                    "X-Team-Token": "dtokB",
                    "X-Runner-Secret": "runner-secret",
                    "X-Agent-SDK": "hspace-agent-sdk/1",
                }}
                defense_payload = {{"team_id": "team2", "mode": "defense", "target_team": "team1", "round_num": 0}}
                assert client.post("/agent-runs", headers=defense_headers, json=defense_payload).status_code == 200
                defense_blocked = client.post("/agent-runs", headers=defense_headers, json=defense_payload)
                assert defense_blocked.status_code == 429, defense_blocked.text
            """
        )
        result = subprocess.run([sys.executable, "-c", script], cwd=ROOT, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            self.fail(result.stdout + result.stderr)

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
                "TOKEN_TEAM_1": "tokA",
                "TOKEN_TEAM_2": "tokB",
                "TOKEN_TEAM_3": "tokC",
                "TOKEN_TEAM_4": "tokD",
                "TOKEN_TEAM_5": "tokE",
                "TOKEN_TEAM_6": "tokF",
                "DEFENSE_TOKEN_TEAM_1": "dtokA",
                "DEFENSE_TOKEN_TEAM_2": "dtokB",
                "DEFENSE_TOKEN_TEAM_3": "dtokC",
                "DEFENSE_TOKEN_TEAM_4": "dtokD",
                "DEFENSE_TOKEN_TEAM_5": "dtokE",
                "DEFENSE_TOKEN_TEAM_6": "dtokF",
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
                    json={{"team_id": "team1", "mode": "attack", "target_team": "team3", "round_num": 0}},
                )
                assert bad_run.status_code == 403, bad_run.text
                student_run = client.post(
                    "/student/agent-runs",
                    headers={{"X-Team-Token": "tokA"}},
                    json={{"team_id": "team1", "mode": "attack", "target_team": "team3", "round_num": 0}},
                )
                assert student_run.status_code == 404, student_run.text
                run = client.post(
                    "/agent-runs",
                    headers={{
                        "X-Team-Token": "tokA",
                        "X-Runner-Secret": "runner-secret",
                        "X-Agent-SDK": "hspace-agent-sdk/1",
                    }},
                    json={{"team_id": "team1", "mode": "attack", "target_team": "team3", "round_num": 0}},
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

    def test_disallowed_gpt55_model_cannot_unlock_agent_attack(self):
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
            os.environ.update({{
                "ADMIN_SECRET": "admin",
                "TOKEN_TEAM_1": "tokA",
                "TOKEN_TEAM_2": "tokB",
                "TOKEN_TEAM_3": "tokC",
                "TOKEN_TEAM_4": "tokD",
                "TOKEN_TEAM_5": "tokE",
                "TOKEN_TEAM_6": "tokF",
                "DEFENSE_TOKEN_TEAM_1": "dtokA",
                "DEFENSE_TOKEN_TEAM_2": "dtokB",
                "DEFENSE_TOKEN_TEAM_3": "dtokC",
                "DEFENSE_TOKEN_TEAM_4": "dtokD",
                "DEFENSE_TOKEN_TEAM_5": "dtokE",
                "DEFENSE_TOKEN_TEAM_6": "dtokF",
                "RUNNER_SECRET": "runner-secret",
                "OPENROUTER_API_KEY": "test-openrouter-key",
                "DB_PATH": str(workdir / "game.db"),
                "DATA_DIR": str(workdir / "data"),
                "VULN_SPEC_DIR": str(workdir / "vuln_specs"),
                "REPOS_DIR": str(workdir / "repos"),
            }})
            (workdir / "vuln_specs").mkdir()
            (workdir / "repos").mkdir()

            class OpenRouterHandler(BaseHTTPRequestHandler):
                request_count = 0

                def do_POST(self):
                    type(self).request_count += 1
                    raw = json.dumps({{"error": "should not be called"}}).encode()
                    self.send_response(500)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(raw)))
                    self.end_headers()
                    self.wfile.write(raw)

                def log_message(self, *args):
                    pass

            openrouter_server = HTTPServer(("127.0.0.1", 0), OpenRouterHandler)
            threading.Thread(target=openrouter_server.serve_forever, daemon=True).start()
            os.environ["OPENROUTER_BASE_URL"] = f"http://127.0.0.1:{{openrouter_server.server_port}}"

            import sys
            sys.path.insert(0, str(root / "coordinator"))
            from fastapi.testclient import TestClient
            import app

            with TestClient(app.app) as client:
                app.state.start_round(1)
                app.db.set_service_status("team2", "OK")
                run = client.post(
                    "/agent-runs",
                    headers={{
                        "X-Team-Token": "tokA",
                        "X-Runner-Secret": "runner-secret",
                        "X-Agent-SDK": "hspace-agent-sdk/1",
                    }},
                    json={{"team_id": "team1", "mode": "attack", "target_team": "team2", "round_num": 1}},
                )
                assert run.status_code == 200, run.text
                run_data = run.json()
                run_id = run_data["agent_run_id"]
                run_token = run_data["agent_run_token"]
                auth = {{"Authorization": "Bearer " + run_token}}

                rejected = client.post(
                    "/v1/chat/completions",
                    headers=auth,
                    json={{
                        "model": "openai/gpt-5.5",
                        "messages": [{{"role": "user", "content": "find and exploit the service"}}],
                        "metadata": {{"purpose": "scan"}},
                    }},
                )
                assert rejected.status_code == 403, rejected.text
                assert "허용되지 않은 모델" in rejected.text, rejected.text
                assert OpenRouterHandler.request_count == 0

                calls = app.db.list_llm_calls(run_id)
                assert len(calls) == 1, calls
                assert calls[0]["model"] == "openai/gpt-5.5", calls
                assert calls[0]["allowed"] == 0, calls
                assert calls[0]["status"] == "rejected", calls
                assert app.db.get_latest_llm_call(run_id, allowed_only=True, successful_only=True) is None

                attack = client.post(
                    "/agent/attack",
                    headers=auth,
                    json={{"path": "/probe", "method": "POST", "json_body": {{"q": "x"}}}},
                )
                assert attack.status_code == 403, attack.text
                assert "OpenRouter wrapper LLM 호출 기록이 없습니다" in attack.text, attack.text
            openrouter_server.shutdown()
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
                "TOKEN_TEAM_1": "tokA",
                "TOKEN_TEAM_2": "tokB",
                "TOKEN_TEAM_3": "tokC",
                "TOKEN_TEAM_4": "tokD",
                "TOKEN_TEAM_5": "tokE",
                "TOKEN_TEAM_6": "tokF",
                "DEFENSE_TOKEN_TEAM_1": "dtokA",
                "DEFENSE_TOKEN_TEAM_2": "dtokB",
                "DEFENSE_TOKEN_TEAM_3": "dtokC",
                "DEFENSE_TOKEN_TEAM_4": "dtokD",
                "DEFENSE_TOKEN_TEAM_5": "dtokE",
                "DEFENSE_TOKEN_TEAM_6": "dtokF",
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

            app.TEAMS["team2"] = {{"ip": "127.0.0.1", "port": target_server.server_port, "name": "Team 2"}}

            with TestClient(app.app) as client:
                app.state.start_round(1)
                app.db.set_service_status("team2", "OK")
                app.db.upsert_flag(1, "team2", "vuln1", flag)
                run = client.post(
                    "/agent-runs",
                    headers={{
                        "X-Team-Token": "tokA",
                        "X-Runner-Secret": "runner-secret",
                        "X-Agent-SDK": "hspace-agent-sdk/1",
                    }},
                    json={{"team_id": "team1", "mode": "attack", "target_team": "team2", "round_num": 1}},
                )
                assert run.status_code == 200, run.text
                run_data = run.json()
                run_id = run_data["agent_run_id"]
                run_token = run_data["agent_run_token"]
                auth = {{"Authorization": "Bearer " + run_token}}

                rejected_chat = client.post(
                    "/v1/chat/completions",
                    headers=auth,
                    json={{
                        "model": "meta-llama/llama-3.1-70b",
                        "messages": [{{"role": "user", "content": "use a stronger model"}}],
                    }},
                )
                assert rejected_chat.status_code == 403, rejected_chat.text
                rejected_calls = app.db.list_llm_calls(run_id)
                assert rejected_calls[0]["model"] == "meta-llama/llama-3.1-70b", rejected_calls
                assert rejected_calls[0]["allowed"] == 0, rejected_calls
                assert rejected_calls[0]["status"] == "rejected", rejected_calls

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

                app.db.set_service_status("team2", "DOWN")
                down_attack = client.post(
                    "/agent/attack",
                    headers=auth,
                    json={{"path": "/probe", "method": "POST", "json_body": {{"q": "x"}}}},
                )
                assert down_attack.status_code == 503, down_attack.text

                app.db.set_service_status("team2", "FAULTY")
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
                assert body["queued"] is True, body
                assert "run_result" not in body, body
                batch = client.post(
                    "/admin/run-pocs",
                    headers={{"X-Admin-Secret": "admin"}},
                    json={{"round_num": 1}},
                )
                assert batch.status_code == 200, batch.text
                assert batch.json()["results"][0]["status"] == "success", batch.text
                assert batch.json()["results"][0]["scored"] == 1, batch.text
            openrouter_server.shutdown()
            target_server.shutdown()
            """
        )
        result = subprocess.run([sys.executable, "-c", script], cwd=ROOT, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            self.fail(result.stdout + result.stderr)

    def test_defense_push_requires_whitelisted_defense_llm_call(self):
        script = textwrap.dedent(
            f"""
            import os
            import tempfile
            from pathlib import Path

            root = Path({str(ROOT)!r})
            workdir = Path(tempfile.mkdtemp())
            os.environ.update({{
                "ADMIN_SECRET": "admin",
                "TOKEN_TEAM_1": "tokA",
                "TOKEN_TEAM_2": "tokB",
                "TOKEN_TEAM_3": "tokC",
                "TOKEN_TEAM_4": "tokD",
                "TOKEN_TEAM_5": "tokE",
                "TOKEN_TEAM_6": "tokF",
                "DEFENSE_TOKEN_TEAM_1": "dtokA",
                "DEFENSE_TOKEN_TEAM_2": "dtokB",
                "DEFENSE_TOKEN_TEAM_3": "dtokC",
                "DEFENSE_TOKEN_TEAM_4": "dtokD",
                "DEFENSE_TOKEN_TEAM_5": "dtokE",
                "DEFENSE_TOKEN_TEAM_6": "dtokF",
                "RUNNER_SECRET": "runner-secret",
                "DB_PATH": str(workdir / "game.db"),
                "DATA_DIR": str(workdir / "data"),
                "VULN_SPEC_DIR": str(workdir / "vuln_specs"),
                "REPOS_DIR": str(workdir / "repos"),
            }})
            (workdir / "vuln_specs").mkdir()
            (workdir / "repos").mkdir()

            import sys
            sys.path.insert(0, str(root / "coordinator"))
            from fastapi.testclient import TestClient
            import app

            with TestClient(app.app) as client:
                app.state.start_round(1)
                run = client.post(
                    "/agent-runs",
                    headers={{
                        "X-Team-Token": "dtokB",
                        "X-Runner-Secret": "runner-secret",
                        "X-Agent-SDK": "hspace-agent-sdk/1",
                    }},
                    json={{"team_id": "team2", "mode": "defense", "target_team": "team1", "round_num": 1}},
                )
                assert run.status_code == 200, run.text
                run_id = run.json()["agent_run_id"]
                validation = {{
                    "repo_team_id": "team1",
                    "pusher_team_id": "team2",
                    "commit": "deadbeef",
                    "agent_run_id": run_id,
                }}

                no_llm = client.post(
                    "/admin/validate-defense-push",
                    headers={{"X-Admin-Secret": "admin"}},
                    json=validation,
                )
                assert no_llm.status_code == 403, no_llm.text

                app.db.append_llm_call(
                    agent_run_id=run_id,
                    model="openai/gpt-4o-mini",
                    allowed=True,
                    prompt_hash="scan-prompt",
                    response_hash="scan-response",
                    purpose="scan",
                    status="completed",
                )
                wrong_purpose = client.post(
                    "/admin/validate-defense-push",
                    headers={{"X-Admin-Secret": "admin"}},
                    json=validation,
                )
                assert wrong_purpose.status_code == 403, wrong_purpose.text

                app.db.append_llm_call(
                    agent_run_id=run_id,
                    model="meta-llama/llama-3.1-70b",
                    allowed=False,
                    prompt_hash="defense-prompt",
                    response_hash=None,
                    purpose="defense",
                    status="rejected",
                )
                rejected_model = client.post(
                    "/admin/validate-defense-push",
                    headers={{"X-Admin-Secret": "admin"}},
                    json=validation,
                )
                assert rejected_model.status_code == 403, rejected_model.text

                app.db.append_llm_call(
                    agent_run_id=run_id,
                    model="openai/gpt-4o-mini",
                    allowed=True,
                    prompt_hash="defense-prompt",
                    response_hash="defense-response",
                    purpose="defense",
                    status="completed",
                )
                accepted = client.post(
                    "/admin/validate-defense-push",
                    headers={{"X-Admin-Secret": "admin"}},
                    json=validation,
                )
                assert accepted.status_code == 200, accepted.text

                wrong_defender = client.post(
                    "/admin/validate-defense-push",
                    headers={{"X-Admin-Secret": "admin"}},
                    json={{**validation, "repo_team_id": "team2"}},
                )
                assert wrong_defender.status_code == 403, wrong_defender.text

                app.db.finish_agent_run(run_id, "completed")
                closed_run = client.post(
                    "/admin/validate-defense-push",
                    headers={{"X-Admin-Secret": "admin"}},
                    json=validation,
                )
                assert closed_run.status_code == 403, closed_run.text
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
                "TOKEN_TEAM_1": "tokA",
                "TOKEN_TEAM_2": "tokB",
                "TOKEN_TEAM_3": "tokC",
                "TOKEN_TEAM_4": "tokD",
                "TOKEN_TEAM_5": "tokE",
                "TOKEN_TEAM_6": "tokF",
                "DEFENSE_TOKEN_TEAM_1": "dtokA",
                "DEFENSE_TOKEN_TEAM_2": "dtokB",
                "DEFENSE_TOKEN_TEAM_3": "dtokC",
                "DEFENSE_TOKEN_TEAM_4": "dtokD",
                "DEFENSE_TOKEN_TEAM_5": "dtokE",
                "DEFENSE_TOKEN_TEAM_6": "dtokF",
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
                    json={{"team_id": "team1", "mode": "attack", "target_team": "team2", "round_num": 1}},
                )
                assert run.status_code == 503, run.text

                invalid_service = client.get("/git/team1/info/refs?service=sh")
                assert invalid_service.status_code == 400, invalid_service.text

                unauth_read = client.get("/git/team1/info/refs?service=git-upload-pack")
                assert unauth_read.status_code == 401, unauth_read.text

                raw = base64.b64encode(b"team1:tokA").decode()
                auth_read = client.get(
                    "/git/team1/info/refs?service=git-upload-pack",
                    headers={{"Authorization": "Basic " + raw}},
                )
                assert auth_read.status_code == 200, auth_read.text
            """
        )
        result = subprocess.run([sys.executable, "-c", script], cwd=ROOT, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            self.fail(result.stdout + result.stderr)

    def test_poc_submission_is_queued_then_batch_scored(self):
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
                "TOKEN_TEAM_1": "tokA",
                "TOKEN_TEAM_2": "tokB",
                "TOKEN_TEAM_3": "tokC",
                "TOKEN_TEAM_4": "tokD",
                "TOKEN_TEAM_5": "tokE",
                "TOKEN_TEAM_6": "tokF",
                "DEFENSE_TOKEN_TEAM_1": "dtokA",
                "DEFENSE_TOKEN_TEAM_2": "dtokB",
                "DEFENSE_TOKEN_TEAM_3": "dtokC",
                "DEFENSE_TOKEN_TEAM_4": "dtokD",
                "DEFENSE_TOKEN_TEAM_5": "dtokE",
                "DEFENSE_TOKEN_TEAM_6": "dtokF",
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
                app.db.set_service_status("team2", "OK")
                flag = "HSPACE" + chr(123) + "0123456789abcdef0123456789abcdef" + chr(125)
                app.db.upsert_flag(1, "team2", "vuln1", flag)

                run = client.post(
                    "/agent-runs",
                    headers={{
                        "X-Team-Token": "tokA",
                        "X-Runner-Secret": "runner-secret",
                        "X-Agent-SDK": "hspace-agent-sdk/1",
                    }},
                    json={{"team_id": "team1", "mode": "attack", "target_team": "team2", "round_num": 1}},
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
                        "attacker_team": "team1",
                        "target_team": "team2",
                        "flag_id": "vuln1",
                        "sha256": poc_sha,
                    }},
                    files={{"file": ("poc1.py", poc_source, "text/x-python")}},
                )
                assert resp.status_code == 200, resp.text
                body = resp.json()
                assert body["status"] == "submitted", body
                assert body["queued"] is True, body
                assert "run_result" not in body, body
                queued_scoreboard = client.get("/scoreboard")
                assert queued_scoreboard.status_code == 200, queued_scoreboard.text
                queued_body = queued_scoreboard.json()
                team1_row = next(row for row in queued_body["scores"] if row["team_id"] == "team1")
                assert team1_row["queued_poc_count"] == 1, queued_body
                assert queued_body["queued_pocs"][0]["status"] == "queued", queued_body
                assert "target_team" not in queued_scoreboard.text, queued_scoreboard.text
                assert "defender_team" not in queued_scoreboard.text, queued_scoreboard.text
                scores = app.db.get_all_scores()
                assert scores["team1"]["score"] == 1000, scores
                assert scores["team3"]["score"] == 1000, scores

                batch = client.post(
                    "/admin/run-pocs",
                    headers={{"X-Admin-Secret": "admin"}},
                    json={{"round_num": 1}},
                )
                assert batch.status_code == 200, batch.text
                assert batch.json()["results"][0]["status"] == "success", batch.text
                assert batch.json()["results"][0]["scored"] == 1, batch.text
                scores = app.db.get_all_scores()
                assert scores["team1"]["score"] == 1010, scores
                assert scores["team3"]["score"] == 990, scores
                scoreboard = client.get("/scoreboard")
                assert scoreboard.status_code == 200, scoreboard.text
                assert "attack_targets" not in scoreboard.text, scoreboard.text
                assert "target_team" not in scoreboard.text, scoreboard.text
                assert "defender_team" not in scoreboard.text, scoreboard.text
                assert "round_exploits" not in scoreboard.text, scoreboard.text
                for row in scoreboard.json()["scores"]:
                    assert "attack_targets" not in row, row
                team1_row = next(row for row in scoreboard.json()["scores"] if row["team_id"] == "team1")
                assert team1_row["queued_poc_count"] == 0, scoreboard.text
                public_result = scoreboard.json()["poc_results"][0]
                assert "flags" not in public_result, public_result
                assert "target_team" not in public_result, public_result
                assert "defender_team" not in public_result, public_result
                assert public_result["flags_found"] == 1, public_result
                assert flag not in scoreboard.text, scoreboard.text
            """
        )
        result = subprocess.run([sys.executable, "-c", script], cwd=ROOT, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            self.fail(result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
