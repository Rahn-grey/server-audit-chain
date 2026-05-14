from __future__ import annotations
"""MockES - SQLite日志存储。

在SQLite中模拟ES的索引、搜索、分页行为。
每条日志即插即存，按索引查询，不爆内存。
"""

import json
import logging
import sqlite3
from pathlib import Path

from src.config import DEBUG_DATA_DIR

logger = logging.getLogger(__name__)

_DEFAULT_DB_PATH = str(Path(DEBUG_DATA_DIR) / "audit_logs.db")

_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    log_id      TEXT NOT NULL DEFAULT '',
    batch_id    TEXT DEFAULT '',
    operator    TEXT NOT NULL DEFAULT '',
    ip          TEXT DEFAULT '',
    command     TEXT NOT NULL DEFAULT '',
    target      TEXT DEFAULT '',
    result      TEXT DEFAULT '',
    risk_level  TEXT DEFAULT 'normal',
    timestamp   TEXT NOT NULL DEFAULT '',
    raw_json    TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_log_id    ON logs(log_id);
CREATE INDEX IF NOT EXISTS idx_operator  ON logs(operator);
CREATE INDEX IF NOT EXISTS idx_batch_id  ON logs(batch_id);
CREATE INDEX IF NOT EXISTS idx_timestamp ON logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_risk      ON logs(risk_level);
"""


class SearchResult:
    """搜索结果。"""

    def __init__(self, results: list, total: int, page: int, size: int):
        self.results = results
        self.total = total
        self.page = page
        self.size = size

    def to_dict(self) -> dict:
        return {
            "results": self.results,
            "total": self.total,
            "page": self.page,
            "size": self.size,
        }


class MockES:
    """SQLite 模拟 Elasticsearch 日志存储和搜索。"""

    def __init__(self, db_path: str | None = None):
        self._db_path = db_path or _DEFAULT_DB_PATH
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self._db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA_SQL)
        self._conn.commit()

    def close(self):
        self._conn.close()

    # ------------------------------------------------------------------
    # 写入
    # ------------------------------------------------------------------

    def _insert_one(self, log: dict):
        self._conn.execute(
            """INSERT INTO logs
               (log_id, batch_id, operator, ip, command, target,
                result, risk_level, timestamp, raw_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                log.get("log_id", ""),
                log.get("batch_id", ""),
                log.get("operator", ""),
                log.get("ip", ""),
                log.get("command", ""),
                log.get("target", ""),
                log.get("result", ""),
                log.get("risk_level", "normal"),
                log.get("timestamp", ""),
                json.dumps(log, ensure_ascii=False),
            ),
        )

    def inject_logs(self, logs: list[dict]):
        for log in logs:
            self._insert_one(log)
        self._conn.commit()
        logger.debug("写入 %d 条日志到 SQLite", len(logs))

    def bulk_index(self, logs: list[dict], index_prefix: str = "server-audit"):
        self.inject_logs(logs)

    # ------------------------------------------------------------------
    # 搜索
    # ------------------------------------------------------------------

    def search_logs(self, operator: str | None = None,
                    start_time: str | None = None,
                    end_time: str | None = None,
                    keyword: str | None = None,
                    page: int = 1, size: int = 50) -> SearchResult:
        clauses = []
        params: list = []

        if operator:
            clauses.append("operator = ?")
            params.append(operator)
        if start_time:
            clauses.append("timestamp >= ?")
            params.append(start_time)
        if end_time:
            clauses.append("timestamp <= ?")
            params.append(end_time)
        if keyword:
            clauses.append("command LIKE ?")
            params.append(f"%{keyword}%")

        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""

        # 总数
        count_row = self._conn.execute(
            f"SELECT COUNT(*) FROM logs {where}", params
        ).fetchone()
        total = count_row[0] if count_row else 0

        # 分页
        offset = (page - 1) * size
        rows = self._conn.execute(
            f"SELECT raw_json FROM logs {where} "
            f"ORDER BY timestamp DESC LIMIT ? OFFSET ?",
            params + [size, offset],
        ).fetchall()

        results = [json.loads(r["raw_json"]) for r in rows]

        logger.debug("SQLite搜索: operator=%s, keyword=%s, 匹配%d条",
                     operator, keyword, total)
        return SearchResult(results=results, total=total, page=page, size=size)

    def get_log_by_id(self, log_id: str) -> dict | None:
        row = self._conn.execute(
            "SELECT raw_json FROM logs WHERE log_id = ?", (log_id,)
        ).fetchone()
        return json.loads(row["raw_json"]) if row else None

    def get_logs_by_batch(self, batch_id: str) -> list[dict]:
        rows = self._conn.execute(
            "SELECT raw_json FROM logs WHERE batch_id = ? ORDER BY timestamp",
            (batch_id,),
        ).fetchall()
        return [json.loads(r["raw_json"]) for r in rows]

    def get_all_logs(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT raw_json FROM logs ORDER BY timestamp DESC"
        ).fetchall()
        return [json.loads(r["raw_json"]) for r in rows]

    # ------------------------------------------------------------------
    # Debug 专用
    # ------------------------------------------------------------------

    def reset_logs(self):
        self._conn.execute("DELETE FROM logs")
        self._conn.commit()
        logger.debug("SQLite日志已清空")

    def tamper_log(self, log_id: str, field: str, new_value: str) -> bool:
        row = self._conn.execute(
            "SELECT id, raw_json FROM logs WHERE log_id = ?", (log_id,)
        ).fetchone()
        if not row:
            return False

        log = json.loads(row["raw_json"])
        log[field] = new_value
        # 更新 raw_json 和对应列
        self._conn.execute(
            "UPDATE logs SET raw_json = ?, command = ?, risk_level = ?, "
            "result = ? WHERE id = ?",
            (json.dumps(log, ensure_ascii=False),
             log.get("command", ""), log.get("risk_level", "normal"),
             log.get("result", ""), row["id"]),
        )
        self._conn.commit()
        logger.warning("篡改日志: log_id=%s, field=%s", log_id, field)
        return True
