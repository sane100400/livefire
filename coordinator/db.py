"""
SQLite WAL 영속성 레이어.

모든 상태 변경은 명시적 트랜잭션으로 atomic하게 처리.
game_state.json을 완전히 대체한다.
"""
import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

_conn: Optional[sqlite3.Connection] = None


def _get_conn() -> sqlite3.Connection:
    global _conn
    if _conn is None:
        raise RuntimeError("DB not initialised — call init_db() first")
    return _conn


def init_db(path: str) -> None:
    """DB 파일을 열고 스키마를 생성한다. 이미 존재하면 그대로 사용."""
    global _conn
    _conn = sqlite3.connect(path, check_same_thread=False)
    _conn.row_factory = sqlite3.Row
    _conn.execute("PRAGMA journal_mode=WAL")
    _conn.execute("PRAGMA foreign_keys=ON")
    _create_schema(_conn)
    _conn.commit()


def _create_schema(conn: sqlite3.Connection) -> None:
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS game_meta (
            id             INTEGER PRIMARY KEY CHECK(id = 1),
            current_round  INTEGER NOT NULL DEFAULT 0,
            round_active   INTEGER NOT NULL DEFAULT 0,
            round_start_ts TEXT,
            preflight_done INTEGER NOT NULL DEFAULT 0
        );

        INSERT OR IGNORE INTO game_meta(id) VALUES(1);

        CREATE TABLE IF NOT EXISTS scores (
            team_id  TEXT PRIMARY KEY,
            score    INTEGER NOT NULL DEFAULT 1000,
            credits  REAL    NOT NULL DEFAULT 2.0
        );

        CREATE TABLE IF NOT EXISTS round_attacks (
            team_id TEXT PRIMARY KEY,
            count   INTEGER NOT NULL DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS round_exploits (
            attacker  TEXT NOT NULL,
            defender  TEXT NOT NULL,
            round_num INTEGER NOT NULL,
            ts        TEXT NOT NULL,
            PRIMARY KEY (attacker, defender, round_num)
        );

        CREATE TABLE IF NOT EXISTS history (
            id                  INTEGER PRIMARY KEY AUTOINCREMENT,
            round_num           INTEGER NOT NULL,
            exploits_json       TEXT NOT NULL,
            availability_json   TEXT NOT NULL,
            score_changes_json  TEXT NOT NULL,
            scores_after_json   TEXT NOT NULL,
            ended_at            TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id            INTEGER PRIMARY KEY AUTOINCREMENT,
            ts            TEXT NOT NULL,
            round_num     INTEGER NOT NULL,
            attacker      TEXT NOT NULL,
            target        TEXT NOT NULL,
            payload_hash  TEXT NOT NULL,
            model         TEXT,
            step_cost     REAL,
            exploited     INTEGER NOT NULL,
            scored        INTEGER NOT NULL,
            response_hash TEXT NOT NULL
        );

        -- 라운드별 동적 flag (PoC 재실행 채점용)
        -- accepted PoC가 응답에서 HSPACE{ 패턴을 탈취하면 채점
        CREATE TABLE IF NOT EXISTS active_flags (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            round_num INTEGER NOT NULL,
            team_id   TEXT NOT NULL,
            vuln_id   TEXT NOT NULL,
            flag      TEXT NOT NULL UNIQUE,
            created_at TEXT NOT NULL,
            expires_at TEXT,                -- NULL = 라운드 종료 시 만료
            UNIQUE(round_num, team_id, vuln_id)
        );

        -- flag 제출 기록 (attacker → 탈취한 flag 제출)
        CREATE TABLE IF NOT EXISTS flag_submissions (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          TEXT NOT NULL,
            round_num   INTEGER NOT NULL,
            attacker    TEXT NOT NULL,
            flag        TEXT NOT NULL,
            valid       INTEGER NOT NULL,   -- 1=정답, 0=오답/만료
            defender    TEXT,               -- valid=1일 때 피해 팀
            vuln_id     TEXT,               -- valid=1일 때 해당 취약점
            UNIQUE(attacker, flag)           -- 동일 flag 중복 제출 방지
        );

        -- 팀별 서비스 상태 (checker 결과)
        CREATE TABLE IF NOT EXISTS service_status (
            team_id    TEXT PRIMARY KEY,
            status     TEXT NOT NULL DEFAULT 'UNKNOWN',  -- OK / FAULTY / DOWN
            checked_at TEXT,
            detail     TEXT   -- 실패 원인 등 디버그 메시지
        );

        CREATE TABLE IF NOT EXISTS agent_runs (
            id                 TEXT PRIMARY KEY,
            team_id            TEXT NOT NULL,
            mode               TEXT NOT NULL CHECK(mode IN ('attack','defense')),
            target_team        TEXT NOT NULL,
            round_num          INTEGER NOT NULL,
            agent_image        TEXT,
            agent_image_digest TEXT,
            agent_commit       TEXT,
            status             TEXT NOT NULL DEFAULT 'running',
            started_at         TEXT NOT NULL,
            ended_at           TEXT,
            error              TEXT
        );

        CREATE TABLE IF NOT EXISTS llm_calls (
            id                    INTEGER PRIMARY KEY AUTOINCREMENT,
            agent_run_id          TEXT NOT NULL REFERENCES agent_runs(id),
            ts                    TEXT NOT NULL,
            purpose               TEXT NOT NULL DEFAULT 'general',
            model                 TEXT NOT NULL,
            allowed               INTEGER NOT NULL,
            openrouter_request_id TEXT,
            prompt_hash           TEXT NOT NULL,
            response_hash         TEXT,
            prompt_tokens         INTEGER,
            completion_tokens     INTEGER,
            total_tokens          INTEGER,
            status                TEXT NOT NULL,
            error                 TEXT
        );

        CREATE TABLE IF NOT EXISTS poc_submissions (
            id                TEXT PRIMARY KEY,
            agent_run_id      TEXT NOT NULL REFERENCES agent_runs(id),
            attacker_team     TEXT NOT NULL,
            target_team       TEXT NOT NULL,
            defender_team     TEXT NOT NULL,
            flag_id           TEXT NOT NULL,
            submitted_round   INTEGER NOT NULL,
            file_name         TEXT NOT NULL,
            sha256            TEXT NOT NULL,
            storage_path      TEXT NOT NULL,
            status            TEXT NOT NULL DEFAULT 'pending',
            canonical_poc_id  TEXT,
            review_reason     TEXT,
            created_at        TEXT NOT NULL,
            accepted_at       TEXT,
            UNIQUE(attacker_team, target_team, sha256)
        );

        CREATE TABLE IF NOT EXISTS poc_results (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            round_num       INTEGER NOT NULL,
            poc_id          TEXT NOT NULL REFERENCES poc_submissions(id),
            attacker_team   TEXT NOT NULL,
            target_team     TEXT NOT NULL,
            defender_team   TEXT NOT NULL,
            flag_id         TEXT NOT NULL,
            status          TEXT NOT NULL,
            flags_json      TEXT NOT NULL,
            scored          INTEGER NOT NULL DEFAULT 0,
            attacker_delta  INTEGER NOT NULL DEFAULT 0,
            defender_delta  INTEGER NOT NULL DEFAULT 0,
            exit_code       INTEGER,
            duration_ms     INTEGER,
            stdout_hash     TEXT,
            stderr_hash     TEXT,
            detail          TEXT,
            created_at      TEXT NOT NULL,
            UNIQUE(round_num, poc_id)
        );

        CREATE TABLE IF NOT EXISTS service_deployments (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            team_id         TEXT NOT NULL,
            commit_sha      TEXT NOT NULL,
            agent_run_id    TEXT,
            mode            TEXT NOT NULL DEFAULT 'service',
            accepted        INTEGER NOT NULL DEFAULT 1,
            reject_reason   TEXT,
            deployed_at     TEXT NOT NULL
        );
    """)
    _ensure_column(conn, "audit_log", "agent_run_id", "TEXT")
    _ensure_column(conn, "audit_log", "llm_call_id", "INTEGER")
    _ensure_column(conn, "llm_calls", "purpose", "TEXT NOT NULL DEFAULT 'general'")
    _ensure_column(conn, "poc_submissions", "llm_call_id", "INTEGER")


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, definition: str) -> None:
    cols = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")


# ── game_meta ──────────────────────────────────────────────────────────

@dataclass
class Meta:
    current_round: int
    round_active: bool
    round_start_ts: Optional[str]
    preflight_done: bool


def get_meta() -> Meta:
    row = _get_conn().execute("SELECT * FROM game_meta WHERE id=1").fetchone()
    return Meta(
        current_round=row["current_round"],
        round_active=bool(row["round_active"]),
        round_start_ts=row["round_start_ts"],
        preflight_done=bool(row["preflight_done"]),
    )


def set_round_active(round_num: int, active: bool, start_ts: Optional[str] = None) -> None:
    with _get_conn() as conn:
        conn.execute(
            "UPDATE game_meta SET current_round=?, round_active=?, round_start_ts=? WHERE id=1",
            (round_num, int(active), start_ts),
        )


def set_preflight_done() -> None:
    with _get_conn() as conn:
        conn.execute("UPDATE game_meta SET preflight_done=1 WHERE id=1")


def ping() -> bool:
    try:
        _get_conn().execute("SELECT 1")
        return True
    except Exception:
        return False


# ── scores ─────────────────────────────────────────────────────────────

def init_scores(teams: dict[str, int]) -> None:
    """팀 점수 초기화 (이미 있으면 무시)."""
    with _get_conn() as conn:
        for team_id, score in teams.items():
            conn.execute(
                "INSERT OR IGNORE INTO scores(team_id, score) VALUES(?,?)",
                (team_id, score),
            )


def get_all_scores() -> dict[str, dict]:
    """{ team_id: {score} }"""
    rows = _get_conn().execute("SELECT team_id, score FROM scores").fetchall()
    return {r["team_id"]: {"score": r["score"]} for r in rows}


def update_score(team_id: str, delta: int) -> None:
    with _get_conn() as conn:
        conn.execute(
            "UPDATE scores SET score = MAX(0, score + ?) WHERE team_id=?",
            (delta, team_id),
        )


# ── round_attacks ──────────────────────────────────────────────────────

def reset_round_attacks(team_ids: list[str]) -> None:
    with _get_conn() as conn:
        for tid in team_ids:
            conn.execute(
                "INSERT INTO round_attacks(team_id, count) VALUES(?,0) "
                "ON CONFLICT(team_id) DO UPDATE SET count=0",
                (tid,),
            )


def get_attack_count(team_id: str) -> int:
    row = _get_conn().execute(
        "SELECT count FROM round_attacks WHERE team_id=?", (team_id,)
    ).fetchone()
    return row["count"] if row else 0


def increment_attack(team_id: str) -> None:
    with _get_conn() as conn:
        conn.execute(
            "INSERT INTO round_attacks(team_id, count) VALUES(?,1) "
            "ON CONFLICT(team_id) DO UPDATE SET count=count+1",
            (team_id,),
        )


# ── round_exploits ─────────────────────────────────────────────────────

def record_exploit(attacker: str, defender: str, round_num: int) -> bool:
    """중복 없을 때만 INSERT, 성공 시 True."""
    ts = datetime.now(timezone.utc).isoformat()
    try:
        with _get_conn() as conn:
            conn.execute(
                "INSERT INTO round_exploits(attacker, defender, round_num, ts) VALUES(?,?,?,?)",
                (attacker, defender, round_num, ts),
            )
        return True
    except sqlite3.IntegrityError:
        return False


def get_round_exploits(round_num: int) -> list[dict]:
    rows = _get_conn().execute(
        "SELECT attacker, defender FROM round_exploits WHERE round_num=?", (round_num,)
    ).fetchall()
    return [{"attacker": r["attacker"], "defender": r["defender"]} for r in rows]


def get_all_exploit_counts() -> dict[str, int]:
    """팀별 전체 라운드 익스플로잇 성공 횟수."""
    rows = _get_conn().execute(
        "SELECT attacker, COUNT(*) as cnt FROM round_exploits GROUP BY attacker"
    ).fetchall()
    return {r["attacker"]: r["cnt"] for r in rows}


# ── history ────────────────────────────────────────────────────────────

def append_history(
    round_num: int,
    exploits: list[dict],
    availability: dict[str, bool],
    score_changes: dict[str, int],
    scores_after: dict[str, int],
) -> None:
    with _get_conn() as conn:
        conn.execute(
            "INSERT INTO history(round_num, exploits_json, availability_json, "
            "score_changes_json, scores_after_json, ended_at) VALUES(?,?,?,?,?,?)",
            (
                round_num,
                json.dumps(exploits, ensure_ascii=False),
                json.dumps(availability, ensure_ascii=False),
                json.dumps(score_changes, ensure_ascii=False),
                json.dumps(scores_after, ensure_ascii=False),
                datetime.now(timezone.utc).isoformat(),
            ),
        )


def get_history() -> list[dict]:
    rows = _get_conn().execute(
        "SELECT round_num, exploits_json, availability_json, "
        "score_changes_json, scores_after_json, ended_at FROM history ORDER BY id"
    ).fetchall()
    return [
        {
            "round": r["round_num"],
            "exploits": json.loads(r["exploits_json"]),
            "availability": json.loads(r["availability_json"]),
            "score_changes": json.loads(r["score_changes_json"]),
            "scores_after": json.loads(r["scores_after_json"]),
            "ended_at": r["ended_at"],
        }
        for r in rows
    ]


# ── audit_log ──────────────────────────────────────────────────────────

def append_audit(
    round_num: int,
    attacker: str,
    target: str,
    payload_hash: str,
    model: Optional[str],
    step_cost: float,
    exploited: bool,
    scored: bool,
    response_hash: str,
    agent_run_id: Optional[str] = None,
    llm_call_id: Optional[int] = None,
) -> int:
    """INSERT 후 새 행의 id 반환."""
    ts = datetime.now(timezone.utc).isoformat()
    with _get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO audit_log(ts, round_num, attacker, target, payload_hash, "
            "model, step_cost, exploited, scored, response_hash, agent_run_id, llm_call_id) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (ts, round_num, attacker, target, payload_hash,
             model, step_cost, int(exploited), int(scored), response_hash, agent_run_id, llm_call_id),
        )
        return cur.lastrowid


def query_audit(
    attacker: Optional[str] = None,
    target: Optional[str] = None,
    round_num: Optional[int] = None,
    limit: int = 500,
) -> list[dict]:
    clauses, params = [], []
    if attacker:
        clauses.append("attacker=?"); params.append(attacker)
    if target:
        clauses.append("target=?"); params.append(target)
    if round_num is not None:
        clauses.append("round_num=?"); params.append(round_num)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(limit)
    rows = _get_conn().execute(
        f"SELECT * FROM audit_log {where} ORDER BY id DESC LIMIT ?", params
    ).fetchall()
    return [dict(r) for r in rows]


# ── migration ──────────────────────────────────────────────────────────

def import_from_json(json_path: str, team_ids: list[str], starting_score: int) -> None:
    """game_state.json이 존재할 경우 SQLite로 마이그레이션."""
    if not os.path.exists(json_path):
        return
    with open(json_path) as f:
        data = json.load(f)

    with _get_conn() as conn:
        # game_meta
        conn.execute(
            "UPDATE game_meta SET current_round=?, round_active=?, round_start_ts=? WHERE id=1",
            (data.get("current_round", 0), int(data.get("round_active", False)), None),
        )
        # scores
        scores = data.get("scores", {})
        for tid in team_ids:
            conn.execute(
                "INSERT INTO scores(team_id, score) VALUES(?,?) "
                "ON CONFLICT(team_id) DO UPDATE SET score=excluded.score",
                (tid, scores.get(tid, starting_score)),
            )
        # round_exploits
        current_round = data.get("current_round", 0)
        for pair in data.get("round_exploits", []):
            attacker, defender = pair[0], pair[1]
            ts = datetime.now(timezone.utc).isoformat()
            try:
                conn.execute(
                    "INSERT OR IGNORE INTO round_exploits(attacker, defender, round_num, ts) VALUES(?,?,?,?)",
                    (attacker, defender, current_round, ts),
                )
            except sqlite3.IntegrityError:
                pass
        # history
        for entry in data.get("history", []):
            conn.execute(
                "INSERT INTO history(round_num, exploits_json, availability_json, "
                "score_changes_json, scores_after_json, ended_at) VALUES(?,?,?,?,?,?)",
                (
                    entry.get("round", 0),
                    json.dumps(entry.get("exploits", []), ensure_ascii=False),
                    json.dumps(entry.get("availability", {}), ensure_ascii=False),
                    json.dumps(entry.get("score_changes", {}), ensure_ascii=False),
                    json.dumps(entry.get("scores_after", {}), ensure_ascii=False),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
    print(f"[db] game_state.json → game_state.db 마이그레이션 완료")


# ── active_flags ───────────────────────────────────────────────────────

def upsert_flag(round_num: int, team_id: str, vuln_id: str, flag: str) -> None:
    ts = datetime.now(timezone.utc).isoformat()
    with _get_conn() as conn:
        conn.execute(
            "INSERT INTO active_flags(round_num, team_id, vuln_id, flag, created_at) "
            "VALUES(?,?,?,?,?) "
            "ON CONFLICT(round_num, team_id, vuln_id) DO UPDATE SET flag=excluded.flag, created_at=excluded.created_at",
            (round_num, team_id, vuln_id, flag, ts),
        )


def get_flags_for_round(round_num: int) -> list[dict]:
    rows = _get_conn().execute(
        "SELECT team_id, vuln_id, flag FROM active_flags WHERE round_num=?",
        (round_num,),
    ).fetchall()
    return [{"team_id": r["team_id"], "vuln_id": r["vuln_id"], "flag": r["flag"]} for r in rows]


def lookup_flag(flag: str) -> Optional[dict]:
    """제출된 flag 문자열이 현재 active flag인지 조회. None이면 유효하지 않음."""
    row = _get_conn().execute(
        "SELECT round_num, team_id, vuln_id FROM active_flags WHERE flag=?",
        (flag,),
    ).fetchone()
    return dict(row) if row else None


def expire_flags(round_num: int) -> None:
    ts = datetime.now(timezone.utc).isoformat()
    with _get_conn() as conn:
        conn.execute(
            "UPDATE active_flags SET expires_at=? WHERE round_num=? AND expires_at IS NULL",
            (ts, round_num),
        )


# ── flag_submissions ───────────────────────────────────────────────────

def submit_flag(
    round_num: int,
    attacker: str,
    flag: str,
    valid: bool,
    defender: Optional[str] = None,
    vuln_id: Optional[str] = None,
) -> bool:
    """제출 기록 저장. 이미 제출된 동일 flag면 False 반환 (중복)."""
    ts = datetime.now(timezone.utc).isoformat()
    try:
        with _get_conn() as conn:
            conn.execute(
                "INSERT INTO flag_submissions(ts, round_num, attacker, flag, valid, defender, vuln_id) "
                "VALUES(?,?,?,?,?,?,?)",
                (ts, round_num, attacker, flag, int(valid), defender, vuln_id),
            )
        return True
    except sqlite3.IntegrityError:
        return False  # 중복 제출


def get_flag_submissions(round_num: Optional[int] = None, attacker: Optional[str] = None) -> list[dict]:
    clauses, params = [], []
    if round_num is not None:
        clauses.append("round_num=?"); params.append(round_num)
    if attacker:
        clauses.append("attacker=?"); params.append(attacker)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    rows = _get_conn().execute(
        f"SELECT * FROM flag_submissions {where} ORDER BY id DESC",
        params,
    ).fetchall()
    return [dict(r) for r in rows]


def count_valid_captures(round_num: int) -> dict[str, int]:
    """라운드 내 팀별 성공 flag 제출 수 {attacker: count}."""
    rows = _get_conn().execute(
        "SELECT attacker, COUNT(*) as cnt FROM flag_submissions "
        "WHERE round_num=? AND valid=1 GROUP BY attacker",
        (round_num,),
    ).fetchall()
    return {r["attacker"]: r["cnt"] for r in rows}


# ── service_status ─────────────────────────────────────────────────────

def set_service_status(team_id: str, status: str, detail: str = "") -> None:
    ts = datetime.now(timezone.utc).isoformat()
    with _get_conn() as conn:
        conn.execute(
            "INSERT INTO service_status(team_id, status, checked_at, detail) VALUES(?,?,?,?) "
            "ON CONFLICT(team_id) DO UPDATE SET status=excluded.status, checked_at=excluded.checked_at, detail=excluded.detail",
            (team_id, status, ts, detail),
        )


def get_service_statuses() -> dict[str, str]:
    rows = _get_conn().execute("SELECT team_id, status FROM service_status").fetchall()
    return {r["team_id"]: r["status"] for r in rows}


# ── agent_runs ────────────────────────────────────────────────────────

def create_agent_run(
    run_id: str,
    team_id: str,
    mode: str,
    target_team: str,
    round_num: int,
    agent_image: Optional[str] = None,
    agent_image_digest: Optional[str] = None,
    agent_commit: Optional[str] = None,
) -> dict:
    ts = datetime.now(timezone.utc).isoformat()
    with _get_conn() as conn:
        conn.execute(
            "INSERT INTO agent_runs(id, team_id, mode, target_team, round_num, "
            "agent_image, agent_image_digest, agent_commit, started_at) "
            "VALUES(?,?,?,?,?,?,?,?,?)",
            (
                run_id,
                team_id,
                mode,
                target_team,
                round_num,
                agent_image,
                agent_image_digest,
                agent_commit,
                ts,
            ),
        )
    return get_agent_run(run_id) or {}


def get_agent_run(run_id: str) -> Optional[dict]:
    row = _get_conn().execute("SELECT * FROM agent_runs WHERE id=?", (run_id,)).fetchone()
    return dict(row) if row else None


def finish_agent_run(run_id: str, status: str, error: str = "") -> bool:
    ts = datetime.now(timezone.utc).isoformat()
    with _get_conn() as conn:
        cur = conn.execute(
            "UPDATE agent_runs SET status=?, ended_at=?, error=? WHERE id=?",
            (status, ts, error, run_id),
        )
        return cur.rowcount > 0


def list_agent_runs(
    team_id: Optional[str] = None,
    mode: Optional[str] = None,
    round_num: Optional[int] = None,
    limit: int = 500,
) -> list[dict]:
    clauses, params = [], []
    if team_id:
        clauses.append("team_id=?"); params.append(team_id)
    if mode:
        clauses.append("mode=?"); params.append(mode)
    if round_num is not None:
        clauses.append("round_num=?"); params.append(round_num)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(limit)
    rows = _get_conn().execute(
        f"SELECT * FROM agent_runs {where} ORDER BY started_at DESC LIMIT ?",
        params,
    ).fetchall()
    return [dict(r) for r in rows]


# ── llm_calls ─────────────────────────────────────────────────────────

def append_llm_call(
    agent_run_id: str,
    model: str,
    allowed: bool,
    prompt_hash: str,
    status: str,
    purpose: str = "general",
    response_hash: Optional[str] = None,
    openrouter_request_id: Optional[str] = None,
    prompt_tokens: Optional[int] = None,
    completion_tokens: Optional[int] = None,
    total_tokens: Optional[int] = None,
    error: Optional[str] = None,
) -> int:
    ts = datetime.now(timezone.utc).isoformat()
    with _get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO llm_calls(agent_run_id, ts, purpose, model, allowed, openrouter_request_id, "
            "prompt_hash, response_hash, prompt_tokens, completion_tokens, total_tokens, status, error) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                agent_run_id,
                ts,
                purpose,
                model,
                int(allowed),
                openrouter_request_id,
                prompt_hash,
                response_hash,
                prompt_tokens,
                completion_tokens,
                total_tokens,
                status,
                error,
            ),
        )
        return cur.lastrowid


def has_llm_call(
    agent_run_id: str,
    allowed_only: bool = True,
    successful_only: bool = True,
    purpose: Optional[str] = None,
) -> bool:
    clauses = ["agent_run_id=?"]
    params: list[object] = [agent_run_id]
    if allowed_only:
        clauses.append("allowed=1")
    if successful_only:
        clauses.append("status IN ('completed', 'mock')")
    if purpose:
        clauses.append("purpose=?")
        params.append(purpose)
    where = " AND ".join(clauses)
    row = _get_conn().execute(
        f"SELECT 1 FROM llm_calls WHERE {where} LIMIT 1",
        params,
    ).fetchone()
    return row is not None


def list_llm_calls(agent_run_id: Optional[str] = None, limit: int = 500) -> list[dict]:
    params: list[object] = []
    where = ""
    if agent_run_id:
        where = "WHERE agent_run_id=?"
        params.append(agent_run_id)
    params.append(limit)
    rows = _get_conn().execute(
        f"SELECT * FROM llm_calls {where} ORDER BY id DESC LIMIT ?",
        params,
    ).fetchall()
    return [dict(r) for r in rows]


def get_llm_call(call_id: int) -> Optional[dict]:
    row = _get_conn().execute("SELECT * FROM llm_calls WHERE id=?", (call_id,)).fetchone()
    return dict(row) if row else None


# ── poc_submissions ───────────────────────────────────────────────────

def find_poc_by_sha(attacker_team: str, target_team: str, sha256: str) -> Optional[dict]:
    row = _get_conn().execute(
        "SELECT * FROM poc_submissions WHERE attacker_team=? AND target_team=? AND sha256=?",
        (attacker_team, target_team, sha256),
    ).fetchone()
    return dict(row) if row else None


def create_poc_submission(
    poc_id: str,
    agent_run_id: str,
    llm_call_id: int,
    attacker_team: str,
    target_team: str,
    defender_team: str,
    flag_id: str,
    submitted_round: int,
    file_name: str,
    sha256: str,
    storage_path: str,
    status: str = "pending",
    canonical_poc_id: Optional[str] = None,
    review_reason: Optional[str] = None,
) -> dict:
    ts = datetime.now(timezone.utc).isoformat()
    with _get_conn() as conn:
        conn.execute(
            "INSERT INTO poc_submissions(id, agent_run_id, llm_call_id, attacker_team, target_team, defender_team, "
            "flag_id, submitted_round, file_name, sha256, storage_path, status, canonical_poc_id, "
            "review_reason, created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                poc_id,
                agent_run_id,
                llm_call_id,
                attacker_team,
                target_team,
                defender_team,
                flag_id,
                submitted_round,
                file_name,
                sha256,
                storage_path,
                status,
                canonical_poc_id,
                review_reason,
                ts,
            ),
        )
    return get_poc_submission(poc_id) or {}


def get_poc_submission(poc_id: str) -> Optional[dict]:
    row = _get_conn().execute("SELECT * FROM poc_submissions WHERE id=?", (poc_id,)).fetchone()
    return dict(row) if row else None


def update_poc_status(poc_id: str, status: str, reason: str = "") -> bool:
    accepted_at = datetime.now(timezone.utc).isoformat() if status == "accepted" else None
    with _get_conn() as conn:
        if accepted_at:
            cur = conn.execute(
                "UPDATE poc_submissions SET status=?, review_reason=?, accepted_at=? WHERE id=?",
                (status, reason, accepted_at, poc_id),
            )
        else:
            cur = conn.execute(
                "UPDATE poc_submissions SET status=?, review_reason=? WHERE id=?",
                (status, reason, poc_id),
            )
        return cur.rowcount > 0


def list_poc_submissions(status: Optional[str] = None, limit: int = 500) -> list[dict]:
    params: list[object] = []
    where = ""
    if status:
        where = "WHERE status=?"
        params.append(status)
    params.append(limit)
    rows = _get_conn().execute(
        f"SELECT * FROM poc_submissions {where} ORDER BY created_at DESC LIMIT ?",
        params,
    ).fetchall()
    return [dict(r) for r in rows]


def get_accepted_pocs(only_poc_id: Optional[str] = None) -> list[dict]:
    params: list[object] = ["accepted"]
    where = "WHERE status=?"
    if only_poc_id:
        where += " AND id=?"
        params.append(only_poc_id)
    rows = _get_conn().execute(
        f"SELECT * FROM poc_submissions {where} ORDER BY accepted_at, created_at",
        params,
    ).fetchall()
    return [dict(r) for r in rows]


# ── poc_results ───────────────────────────────────────────────────────

def get_poc_result(round_num: int, poc_id: str) -> Optional[dict]:
    row = _get_conn().execute(
        "SELECT * FROM poc_results WHERE round_num=? AND poc_id=?",
        (round_num, poc_id),
    ).fetchone()
    return dict(row) if row else None


def insert_poc_result(
    round_num: int,
    poc_id: str,
    attacker_team: str,
    target_team: str,
    defender_team: str,
    flag_id: str,
    status: str,
    flags: list[str],
    scored: bool,
    attacker_delta: int,
    defender_delta: int,
    exit_code: Optional[int] = None,
    duration_ms: Optional[int] = None,
    stdout_hash: Optional[str] = None,
    stderr_hash: Optional[str] = None,
    detail: str = "",
) -> bool:
    ts = datetime.now(timezone.utc).isoformat()
    try:
        with _get_conn() as conn:
            conn.execute(
                "INSERT INTO poc_results(round_num, poc_id, attacker_team, target_team, defender_team, "
                "flag_id, status, flags_json, scored, attacker_delta, defender_delta, exit_code, "
                "duration_ms, stdout_hash, stderr_hash, detail, created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    round_num,
                    poc_id,
                    attacker_team,
                    target_team,
                    defender_team,
                    flag_id,
                    status,
                    json.dumps(flags, ensure_ascii=False),
                    int(scored),
                    attacker_delta,
                    defender_delta,
                    exit_code,
                    duration_ms,
                    stdout_hash,
                    stderr_hash,
                    detail,
                    ts,
                ),
            )
        return True
    except sqlite3.IntegrityError:
        return False


def list_poc_results(round_num: Optional[int] = None, limit: int = 500) -> list[dict]:
    clauses, params = [], []
    if round_num is not None:
        clauses.append("round_num=?"); params.append(round_num)
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    params.append(limit)
    rows = _get_conn().execute(
        f"SELECT * FROM poc_results {where} ORDER BY id DESC LIMIT ?",
        params,
    ).fetchall()
    results = []
    for row in rows:
        item = dict(row)
        item["flags"] = json.loads(item.pop("flags_json"))
        results.append(item)
    return results


def count_successful_pocs_by_attacker() -> dict[str, int]:
    rows = _get_conn().execute(
        "SELECT attacker_team, COUNT(*) as cnt FROM poc_results "
        "WHERE status='success' AND scored=1 GROUP BY attacker_team"
    ).fetchall()
    return {r["attacker_team"]: r["cnt"] for r in rows}


# ── service_deployments ───────────────────────────────────────────────

def record_service_deployment(
    team_id: str,
    commit_sha: str,
    agent_run_id: Optional[str] = None,
    mode: str = "service",
    accepted: bool = True,
    reject_reason: str = "",
) -> int:
    ts = datetime.now(timezone.utc).isoformat()
    with _get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO service_deployments(team_id, commit_sha, agent_run_id, mode, accepted, "
            "reject_reason, deployed_at) VALUES(?,?,?,?,?,?,?)",
            (team_id, commit_sha, agent_run_id, mode, int(accepted), reject_reason, ts),
        )
        return cur.lastrowid
