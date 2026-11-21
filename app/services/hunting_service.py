import fnmatch
import logging
import re
from datetime import UTC, datetime
from typing import Any

from pydantic import BaseModel

logger = logging.getLogger(__name__)


class HuntingQueryRequest(BaseModel):
    query: str
    limit: int = 100
    time_range_hours: int | None = 24
    tenant_id: str | None = "default"


class HuntingSearchResult(BaseModel):
    query: str
    total_hits: int
    execution_time_ms: float
    results: list[dict[str, Any]]
    facets: dict[str, dict[str, int]]
    time_histogram: list[dict[str, Any]]


class ThreatHuntingEngine:
    """High-speed threat hunting search engine with Lucene / OpenSearch syntax support."""

    @classmethod
    def parse_query_tokens(cls, query_str: str) -> list[dict[str, Any]]:
        """
        Parses queries like:
        source_ip:192.168.1.* AND status_code:>=400 AND method:POST
        """
        tokens = []
        raw_parts = query_str.strip().split()
        current_op = "AND"

        for part in raw_parts:
            upper = part.upper()
            if upper in ("AND", "OR", "NOT"):
                current_op = upper
                continue

            if ":" in part:
                field, val = part.split(":", 1)
                field = field.strip().lower()
                val = val.strip().strip("\"'")

                # Check comparison operators (>=, <=, >, <)
                comp_match = re.match(r"^(>=|<=|>|<)(.*)$", val)
                if comp_match:
                    op, comp_val = comp_match.groups()
                    tokens.append(
                        {
                            "field": field,
                            "op": op,
                            "value": comp_val,
                            "bool": current_op,
                        }
                    )
                else:
                    tokens.append(
                        {
                            "field": field,
                            "op": "wildcard" if "*" in val or "?" in val else "exact",
                            "value": val,
                            "bool": current_op,
                        }
                    )
            else:
                # Free-text search term
                tokens.append(
                    {
                        "field": "raw_log",
                        "op": "contains",
                        "value": part.strip("\"'"),
                        "bool": current_op,
                    }
                )
            current_op = "AND"

        return tokens

    @classmethod
    def match_event(cls, event: dict[str, Any], tokens: list[dict[str, Any]]) -> bool:
        """Evaluate parsed query tokens against an event dictionary."""
        if not tokens:
            return True

        overall_matched = True

        for token in tokens:
            field = token["field"]
            val = str(token["value"])
            op = token["op"]
            bool_op = token.get("bool", "AND")

            event_val = event.get(field)
            if event_val is None:
                event_val_str = ""
            else:
                event_val_str = str(event_val)

            term_matched = False

            if op == "exact":
                term_matched = event_val_str.lower() == val.lower()
            elif op == "wildcard":
                term_matched = fnmatch.fnmatch(event_val_str.lower(), val.lower())
            elif op == "contains":
                term_matched = (
                    val.lower() in event_val_str.lower()
                    or val.lower() in str(event.get("raw_log", "")).lower()
                )
            elif op in (">=", "<=", ">", "<"):
                try:
                    num_event = float(event_val_str)
                    num_target = float(val)
                    if op == ">=":
                        term_matched = num_event >= num_target
                    elif op == "<=":
                        term_matched = num_event <= num_target
                    elif op == ">":
                        term_matched = num_event > num_target
                    elif op == "<":
                        term_matched = num_event < num_target
                except ValueError:
                    term_matched = False

            if bool_op == "NOT":
                term_matched = not term_matched

            if bool_op == "OR":
                overall_matched = overall_matched or term_matched
            else:
                overall_matched = overall_matched and term_matched

        return overall_matched

    @classmethod
    def search(
        cls,
        query_str: str,
        events: list[dict[str, Any]],
        limit: int = 100,
    ) -> HuntingSearchResult:
        """Execute a threat hunting search against an in-memory or database log set."""
        start_time = datetime.now(UTC)
        tokens = cls.parse_query_tokens(query_str)

        matched_events: list[dict[str, Any]] = []
        facets: dict[str, dict[str, int]] = {
            "status_code": {},
            "method": {},
            "source_ip": {},
        }

        for ev in events:
            if cls.match_event(ev, tokens):
                matched_events.append(ev)

                # Collect facets
                sc = str(ev.get("status_code", "unknown"))
                facets["status_code"][sc] = facets["status_code"].get(sc, 0) + 1

                method = str(ev.get("method", "GET"))
                facets["method"][method] = facets["method"].get(method, 0) + 1

                sip = str(ev.get("source_ip", "unknown"))
                facets["source_ip"][sip] = facets["source_ip"].get(sip, 0) + 1

        duration_ms = (datetime.now(UTC) - start_time).total_seconds() * 1000

        # Build hourly histogram
        histogram_buckets: dict[str, int] = {}
        for ev in matched_events:
            ts = ev.get("timestamp") or datetime.now(UTC).isoformat()
            bucket_key = str(ts)[:13] + ":00:00"  # group by hour
            histogram_buckets[bucket_key] = histogram_buckets.get(bucket_key, 0) + 1

        histogram = [
            {"bucket": k, "count": v} for k, v in sorted(histogram_buckets.items())
        ]

        return HuntingSearchResult(
            query=query_str,
            total_hits=len(matched_events),
            execution_time_ms=round(duration_ms, 2),
            results=matched_events[:limit],
            facets=facets,
            time_histogram=histogram,
        )
