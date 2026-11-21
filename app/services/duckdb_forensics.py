import logging
import time
from typing import Any

import duckdb
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.models.log_event import LogEventModel

logger = logging.getLogger(__name__)


class ColumnarQueryRequest(BaseModel):
    sql_query: str = (
        "SELECT source_ip, COUNT(*) as hit_count, COUNT(DISTINCT path) as unique_paths "
        "FROM logs GROUP BY source_ip ORDER BY hit_count DESC LIMIT 10"
    )
    time_range_hours: int = 24


class ColumnarQueryResult(BaseModel):
    columns: list[str]
    rows: list[list[Any]]
    total_rows: int
    execution_time_ms: float
    summary: str


class DuckDBForensicsEngine:
    """Embedded columnar analytics engine for sub-second aggregations across massive log sets."""

    _con: duckdb.DuckDBPyConnection | None = None

    @classmethod
    def get_connection(cls) -> duckdb.DuckDBPyConnection:
        if cls._con is None:
            cls._con = duckdb.connect(database=":memory:")
            cls._initialize_tables()
        return cls._con

    @classmethod
    def _initialize_tables(cls):
        con = cls._con
        if con is not None:
            con.execute("""
                CREATE TABLE IF NOT EXISTS logs (
                    id VARCHAR,
                    timestamp TIMESTAMP,
                    source VARCHAR,
                    source_type VARCHAR,
                    source_ip VARCHAR,
                    destination_ip VARCHAR,
                    http_method VARCHAR,
                    path VARCHAR,
                    status_code VARCHAR,
                    raw_log VARCHAR,
                    tenant_id VARCHAR
                )
            """)

    @classmethod
    def sync_from_database(cls, db: Session, limit: int = 10000):
        """Loads recent telemetry from relational DB into high-speed columnar DuckDB memory."""
        con = cls.get_connection()
        records = (
            db.query(LogEventModel)
            .order_by(LogEventModel.created_at.desc())
            .limit(limit)
            .all()
        )

        con.execute("DELETE FROM logs")

        if not records:
            return

        data = [
            (
                r.id,
                r.timestamp,
                r.source,
                r.source_type,
                r.source_ip,
                r.destination_ip,
                r.http_method,
                r.path,
                r.status_code,
                r.raw_log,
                getattr(r, "tenant_id", "default") or "default",
            )
            for r in records
        ]

        con.executemany(
            """
            INSERT INTO logs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            data,
        )

    @classmethod
    def execute_query(cls, db: Session, sql_query: str) -> ColumnarQueryResult:
        """Executes vectorized SQL query in DuckDB."""
        cls.sync_from_database(db)
        con = cls.get_connection()

        start = time.perf_counter()

        # Sanitize query: only allow SELECT queries for security
        clean_sql = sql_query.strip()
        if not clean_sql.upper().startswith("SELECT"):
            raise ValueError(
                "Only read-only SELECT analytical queries are permitted in forensics engine."
            )

        try:
            rel = con.execute(clean_sql)
            columns = [col[0] for col in rel.description] if rel.description else []
            rows = rel.fetchall()
            elapsed_ms = round((time.perf_counter() - start) * 1000, 2)

            return ColumnarQueryResult(
                columns=columns,
                rows=rows,
                total_rows=len(rows),
                execution_time_ms=elapsed_ms,
                summary=f"DuckDB executed query across columnar telemetry in {elapsed_ms}ms. Returned {len(rows)} rows.",
            )
        except Exception as e:
            logger.error(f"DuckDB query error: {e}")
            raise
