"""
게임 상태 관리. app.py의 퍼블릭 인터페이스를 유지하면서
내부 영속성을 db.py(SQLite WAL)로 위임한다.
"""
from datetime import datetime
from typing import Dict

import db


class GameState:
    def __init__(self, team_ids: list, starting_score: int):
        self.team_ids = team_ids
        self.starting_score = starting_score

    # ── 프로퍼티: DB에서 실시간 조회 ──────────────────────────────────

    @property
    def current_round(self) -> int:
        return db.get_meta().current_round

    @property
    def round_active(self) -> bool:
        return db.get_meta().round_active

    @property
    def round_start_time(self) -> str:
        return db.get_meta().round_start_ts or ""

    @property
    def scores(self) -> Dict[str, int]:
        return {tid: info["score"] for tid, info in db.get_all_scores().items()}

    @property
    def history(self) -> list:
        return db.get_history()

    @property
    def round_attacks(self) -> Dict[str, int]:
        return {tid: db.get_attack_count(tid) for tid in self.team_ids}

    @property
    def round_exploits(self) -> set:
        meta = db.get_meta()
        exploits = db.get_round_exploits(meta.current_round)
        return {(e["attacker"], e["defender"]) for e in exploits}

    # ── 초기화 ────────────────────────────────────────────────────────

    def load(self, db_path: str, json_path: str = "game_state.json") -> None:
        """DB 초기화 + JSON 마이그레이션(있으면) + 팀 점수 초기화."""
        db.init_db(db_path)
        db.import_from_json(json_path, self.team_ids, self.starting_score)
        db.init_scores({t: self.starting_score for t in self.team_ids})
        db.reset_round_attacks(self.team_ids)

    # ── 라운드 제어 ───────────────────────────────────────────────────

    def start_round(self, round_num: int) -> None:
        ts = datetime.now().isoformat()
        db.set_round_active(round_num, True, ts)
        db.reset_round_attacks(self.team_ids)

    def end_round(
        self,
        availability: Dict[str, bool],
        attack_reward: int,
        attack_penalty: int,
        availability_bonus: int,
    ) -> dict:
        round_num = self.current_round
        score_changes: Dict[str, int] = {t: 0 for t in self.team_ids}

        # 가용성 보너스
        for team in self.team_ids:
            if availability.get(team, False):
                db.update_score(team, availability_bonus)
                score_changes[team] += availability_bonus

        # 익스플로잇 점수 (현재 라운드 exploit 목록에서)
        exploits = db.get_round_exploits(round_num)
        for e in exploits:
            attacker, defender = e["attacker"], e["defender"]
            db.update_score(attacker, attack_reward)
            score_changes[attacker] = score_changes.get(attacker, 0) + attack_reward
            db.update_score(defender, -attack_penalty)
            score_changes[defender] = score_changes.get(defender, 0) - attack_penalty

        scores_after = {tid: info["score"] for tid, info in db.get_all_scores().items()}

        db.append_history(round_num, exploits, availability, score_changes, scores_after)
        db.set_round_active(round_num, False)

        return {
            "round": round_num,
            "exploits": exploits,
            "availability": availability,
            "score_changes": score_changes,
            "scores_after": scores_after,
        }

    # ── 공격 추적 ─────────────────────────────────────────────────────

    def get_attack_count(self, attacker: str) -> int:
        return db.get_attack_count(attacker)

    def record_attack(self, attacker: str) -> None:
        db.increment_attack(attacker)

    def record_exploit(self, attacker: str, defender: str) -> bool:
        return db.record_exploit(attacker, defender, self.current_round)
