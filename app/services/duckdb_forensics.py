import logging
import re
import time
from typing import Any

import duckdb
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.models.log_event import LogEventModel

logger = logging.getLogger(__name__)

# Disallowed dangerous SQL operations & functions
DANGEROUS_SQL_PATTERNS = [
    re.compile(
        r"\b(INSERT|UPDATE|DELETE|DROP|ALTER|CREATE|TRUNCATE|REPLACE|GRANT|REVOKE)\b",
        re.I,
    ),
    re.compile(
        r"\b(ATTACH|DETACH|USE|INSTALL|LOAD|PRAGMA|COPY|EXPORT|IMPORT|CALL)\b", re.I
    ),
    re.compile(
        r"\b(READ_CSV|READ_PARQUET|READ_JSON|WRITE_PARQUET|WRITE_CSV|SCAN_CSV|HTTPFS|DUCKDB_SETTINGS|DUCKDB_SECRETS|GETENV)\b",
        re.I,
    ),
    re.compile(r"--|\/\*", re.I),  # Comments that could hide SQL injection
]

MAX_RESULT_ROWS = 500


class ColumnarQueryRequest(BaseModel):
    sql_query: str = (
        "SELECT source_ip, COUNT(*) as hit_count, COUNT(DISTINCT path) as unique_paths "
        "FROM logs GROUP BY source_ip ORDER BY hit_count DESC LIMIT 10"
    )
    time_range_hours: int = 24
    tenant_id: str = "default"


class ColumnarQueryResult(BaseModel):
    columns: list[str]
    rows: list[list[Any]]
    total_rows: int
    execution_time_ms: float
    summary: str


class DuckDBForensicsEngine:
    """Embedded columnar analytics engine with strict SQL isolation boundary and tenant scoping."""

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
    def validate_sql_security(cls, sql: str) -> str:
        """
        Validates that query is strictly a read-only single-statement analytical query.
        Blocks DDL, DML, file system operations, and external network functions.
        """
        clean_sql = sql.strip()

        # Disallow empty query
        if not clean_sql:
            raise ValueError("SQL query cannot be empty.")

        # Disallow multiple statements separated by semicolon
        # Allow trailing semicolon only
        sanitized = clean_sql.rstrip(";")
        if ";" in sanitized:
            raise ValueError(
                "Multiple SQL statements are strictly prohibited in the forensics sandbox."
            )

        # Must start with SELECT
        if not sanitized.upper().startswith("SELECT"):
            raise ValueError(
                "Only read-only SELECT analytical queries are permitted in the forensics engine."
            )

        # Check against dangerous keywords & functions
        for pattern in DANGEROUS_SQL_PATTERNS:
            match = pattern.search(sanitized)
            if match:
                raise ValueError(
                    f"Forbidden SQL operation or capability detected: '{match.group(0)}'. "
                    "Analytical sandbox permits pure aggregation and projection only."
                )

        return sanitized

    @classmethod
    def sync_from_database(
        cls, db: Session, tenant_id: str = "default", limit: int = 10000
    ):
        """Loads recent telemetry from relational DB into high-speed columnar DuckDB memory."""
        con = cls.get_connection()
        query = db.query(LogEventModel)

        if tenant_id and tenant_id not in ("default", "*", "system"):
            query = query.filter(LogEventModel.tenant_id == tenant_id)

        records = query.order_by(LogEventModel.created_at.desc()).limit(limit).all()

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
    def execute_query(
        cls, db: Session, sql_query: str, tenant_id: str = "default"
    ) -> ColumnarQueryResult:
        """Executes vectorized SQL query in DuckDB within a strictly isolated security sandbox."""
        validated_sql = cls.validate_sql_security(sql_query)
        cls.sync_from_database(db, tenant_id=tenant_id)
        con = cls.get_connection()

        start = time.perf_counter()

        try:
            rel = con.execute(validated_sql)
            columns = [col[0] for col in rel.description] if rel.description else []
            rows = rel.fetchmany(MAX_RESULT_ROWS)
            elapsed_ms = round((time.perf_counter() - start) * 1000, 2)

            return ColumnarQueryResult(
                columns=columns,
                rows=rows,
                total_rows=len(rows),
                execution_time_ms=elapsed_ms,
                summary=f"DuckDB executed query across columnar telemetry in {elapsed_ms}ms. Returned {len(rows)} rows (capped at {MAX_RESULT_ROWS}).",
            )
        except Exception as e:
            logger.error(f"DuckDB query execution error: {e}")
            raise
