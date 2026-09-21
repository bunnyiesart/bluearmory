"""Graylog MCP Server.

Wraps the Graylog REST API and exposes search, streams, and alert endpoints
as MCP tools for SOC workflows.
"""

import os

import httpx
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("graylog")

GRAYLOG_URL = os.environ.get("GRAYLOG_URL", "http://localhost:9000")
GRAYLOG_API_TOKEN = os.environ.get("GRAYLOG_API_TOKEN", "")


def _client() -> httpx.Client:
    return httpx.Client(
        base_url=f"{GRAYLOG_URL}/api",
        auth=(GRAYLOG_API_TOKEN, "token"),
        headers={
            "Accept": "application/json",
            "X-Requested-By": "graylog-mcp",
            "User-Agent": "graylog-mcp/1.0",
        },
        verify=False,
        timeout=30,
    )


# ── Internals ──────────────────────────────────────────────────────────────


def _check(r: httpx.Response) -> None:
    """Raise with the Graylog error body attached.

    httpx's raise_for_status() discards the response body, which is where
    Graylog explains itself (missing permission, validation failure). Losing
    it turns every failure into a bare status code.
    """
    if r.is_error:
        raise RuntimeError(
            f"Graylog {r.status_code} on {r.request.method} "
            f"{r.request.url.path}: {r.text[:600]}"
        )


def _rows_to_messages(payload: dict) -> dict:
    """Flatten a Scripting API result into a list of message dicts.

    /search/messages answers with a column schema plus positional rows:
        {"schema": [{"field": "timestamp"}, ...], "datarows": [[v1, v2], ...]}
    Callers want records, so zip the two back together.
    """
    schema = payload.get("schema") or []
    names = [s.get("field") or s.get("name") for s in schema]
    rows = payload.get("datarows") or []
    messages = [dict(zip(names, row)) for row in rows]
    return {
        "messages": messages,
        "fields": names,
        # The Scripting API reports no grand total for message queries, so this
        # is the size of THIS page, never the number of matches. When it equals
        # the requested limit the result is probably truncated -- say so rather
        # than let a caller read a page size as a population count.
        "returned": len(messages),
        "effective_timerange": (payload.get("metadata") or {}).get(
            "effective_timerange", {}
        ),
    }


# Legacy /search/universal/* returned every field when none were named. The
# Scripting API instead defaults to source+timestamp, which silently drops the
# payload. `message` carries the raw log line, so this default keeps the whole
# event reachable when a caller names no fields.
_DEFAULT_FIELDS = ["timestamp", "source", "message"]


def _search_messages(
    query: str,
    timerange: dict,
    limit: int,
    fields: str,
    stream_id: str,
) -> dict:
    """Run one message search against the Scripting API.

    Replaces /search/universal/*, which exists on Graylog 7.x but is authorized
    by searches:{relative,absolute,keyword} -- permissions no default role
    grants, so it answers 403. This route authorizes by streams:read plus
    messages:read instead.
    """
    named = [f.strip() for f in fields.split(",") if f.strip()] if fields else []
    body: dict = {
        "query": query or "*",
        "timerange": timerange,
        "fields": named or _DEFAULT_FIELDS,
        "size": limit,
        "sort": "timestamp",
        "sort_order": "Descending",
    }
    if stream_id:
        body["streams"] = [stream_id]
    with _client() as c:
        r = c.post("/search/messages", json=body)
        _check(r)
        return _rows_to_messages(r.json())


# ── Search ─────────────────────────────────────────────────────────────────


@mcp.tool()
def search_relative(
    query: str,
    range_seconds: int = 300,
    limit: int = 50,
    fields: str = "",
    stream_id: str = "",
) -> dict:
    """Search Graylog messages with a relative time range.

    Args:
        query: Graylog search query (Lucene syntax)
        range_seconds: How far back to search in seconds (default: 300 = 5 minutes)
        limit: Maximum number of results (default: 50)
        fields: Comma-separated list of fields to return (empty = timestamp, source, message)
        stream_id: Limit search to a specific stream ID (optional)
    """
    return _search_messages(
        query, {"type": "relative", "range": range_seconds}, limit, fields, stream_id
    )


@mcp.tool()
def search_absolute(
    query: str,
    from_time: str,
    to_time: str,
    limit: int = 50,
    fields: str = "",
    stream_id: str = "",
) -> dict:
    """Search Graylog messages with an absolute time range.

    Args:
        query: Graylog search query (Lucene syntax)
        from_time: Start time (ISO 8601, e.g. 2024-01-15T10:00:00.000Z)
        to_time: End time (ISO 8601)
        limit: Maximum number of results (default: 50)
        fields: Comma-separated list of fields to return (empty = timestamp, source, message)
        stream_id: Limit search to a specific stream ID (optional)
    """
    return _search_messages(
        query,
        {"type": "absolute", "from": from_time, "to": to_time},
        limit,
        fields,
        stream_id,
    )


@mcp.tool()
def search_keyword(
    query: str,
    keyword: str = "last 1 hour",
    limit: int = 50,
    fields: str = "",
    stream_id: str = "",
) -> dict:
    """Search Graylog messages with a keyword time range.

    Args:
        query: Graylog search query (Lucene syntax)
        keyword: Natural language time range (e.g. "last 1 hour", "yesterday")
        limit: Maximum number of results (default: 50)
        fields: Comma-separated list of fields to return (empty = timestamp, source, message)
        stream_id: Limit search to a specific stream ID (optional)
    """
    return _search_messages(
        query, {"type": "keyword", "keyword": keyword}, limit, fields, stream_id
    )


@mcp.tool()
def get_message(message_id: str, index: str) -> dict:
    """Retrieve a specific message by ID.

    Args:
        message_id: The message ID
        index: The Elasticsearch index containing the message
    """
    with _client() as c:
        r = c.get(f"/messages/{index}/{message_id}")
        r.raise_for_status()
        return r.json()


@mcp.tool()
def search_aggregate(
    query: str,
    group_by: str,
    range_seconds: int = 3600,
    from_time: str = "",
    to_time: str = "",
    stream_id: str = "",
) -> dict:
    """Count messages grouped by one or more fields.

    Use this instead of search_relative when the question is "how many", not
    "show me". /search/messages reports no grand total, so counting by hand from
    a capped page silently undercounts.

    Args:
        query: Graylog search query (Lucene syntax)
        group_by: Comma-separated fields to group by (e.g. "host,response_http_code")
        range_seconds: How far back to search in seconds (default: 3600); ignored when from_time is given
        from_time: Absolute start (ISO 8601). Overrides range_seconds when set, requires to_time
        to_time: Absolute end (ISO 8601)
        stream_id: Limit to a specific stream ID (optional)
    """
    groups = [g.strip() for g in group_by.split(",") if g.strip()]
    if not groups:
        raise ValueError("group_by needs at least one field name")
    if from_time and to_time:
        timerange = {"type": "absolute", "from": from_time, "to": to_time}
    else:
        timerange = {"type": "relative", "range": range_seconds}
    body: dict = {
        "query": query or "*",
        "timerange": timerange,
        "group_by": [{"field": g} for g in groups],
        "metrics": [{"function": "count"}],
    }
    if stream_id:
        body["streams"] = [stream_id]
    with _client() as c:
        # This endpoint rejects unknown properties (no `size`, no `limit`) and
        # names the ones it knows in the 400 body, which _check now surfaces.
        r = c.post("/search/aggregate", json=body)
        _check(r)
        payload = r.json()
    schema = payload.get("schema") or []
    names = [s.get("field") or s.get("function") or s.get("name") for s in schema]
    rows = payload.get("datarows") or []
    return {
        "columns": names,
        "rows": [dict(zip(names, row)) for row in rows],
        "groups": len(rows),
        "effective_timerange": (payload.get("metadata") or {}).get(
            "effective_timerange", {}
        ),
    }


# ── Streams ────────────────────────────────────────────────────────────────


@mcp.tool()
def list_streams() -> dict:
    """List all streams configured in Graylog."""
    with _client() as c:
        r = c.get("/streams")
        r.raise_for_status()
        return r.json()


@mcp.tool()
def get_stream(stream_id: str) -> dict:
    """Get details for a specific stream.

    Args:
        stream_id: The stream ID
    """
    with _client() as c:
        r = c.get(f"/streams/{stream_id}")
        r.raise_for_status()
        return r.json()


# ── Alerts / Events ───────────────────────────────────────────────────────


@mcp.tool()
def search_events(
    query: str = "",
    timerange_from: int = 3600,
    page: int = 1,
    per_page: int = 50,
) -> dict:
    """Search alert events in Graylog.

    Args:
        query: Filter query (optional)
        timerange_from: How far back in seconds (default: 3600 = 1 hour)
        page: Page number (default: 1)
        per_page: Results per page (default: 50)
    """
    with _client() as c:
        r = c.post(
            "/events/search",
            json={
                "query": query,
                "timerange": {"type": "relative", "range": timerange_from},
                "page": page,
                "per_page": per_page,
            },
        )
        r.raise_for_status()
        return r.json()


@mcp.tool()
def list_event_definitions() -> dict:
    """List all event/alert definitions configured in Graylog."""
    with _client() as c:
        r = c.get("/events/definitions")
        r.raise_for_status()
        return r.json()


# ── System ─────────────────────────────────────────────────────────────────


@mcp.tool()
def system_overview() -> dict:
    """Get Graylog system overview (version, cluster, status)."""
    with _client() as c:
        r = c.get("/system")
        r.raise_for_status()
        return r.json()


@mcp.tool()
def list_inputs() -> dict:
    """List all configured inputs in Graylog."""
    with _client() as c:
        r = c.get("/system/inputs")
        r.raise_for_status()
        return r.json()


if __name__ == "__main__":
    mcp.run(transport="stdio")
