#!/usr/bin/env python3
"""
Google Ads MCP Server (FastMCP) – simple keyword planner / GAQL tools.

Env vars required:
- GOOGLE_ADS_DEVELOPER_TOKEN
- GOOGLE_ADS_OAUTH_TOKENS_BASE64  (base64-encoded JSON: {"client_id","client_secret","refresh_token"})
- GOOGLE_ADS_LOGIN_CUSTOMER_ID    (optional; MCC login customer id, digits)
- GOOGLE_ADS_KEYWORD_CUSTOMER_ID  (optional; customer id used for keyword planner endpoints)
"""

import os
import json
import base64
import asyncio
from typing import Any

import httpx

from fastmcp import FastMCP
from pydantic import Field

# --------------------------------------------------
# Config
# --------------------------------------------------

API_VERSION = os.environ.get("GOOGLE_ADS_API_VERSION", "v16")

mcp = FastMCP("google-ads-mcp")

# --------------------------------------------------
# Errors
# --------------------------------------------------


class ToolError(Exception):
    pass


# --------------------------------------------------
# Auth helpers
# --------------------------------------------------


def _load_oauth_tokens() -> dict[str, str]:
    b64 = os.environ.get("GOOGLE_ADS_OAUTH_TOKENS_BASE64")
    if not b64:
        raise ValueError("GOOGLE_ADS_OAUTH_TOKENS_BASE64 not set")

    try:
        raw = base64.b64decode(b64).decode("utf-8")
        data = json.loads(raw)
    except Exception as e:
        raise ValueError(f"Failed to decode GOOGLE_ADS_OAUTH_TOKENS_BASE64: {e}")

    for k in ("client_id", "client_secret", "refresh_token"):
        if not data.get(k):
            raise ValueError(f"Missing '{k}' in GOOGLE_ADS_OAUTH_TOKENS_BASE64 JSON")

    return data


class Credentials:
    def __init__(self, token: str):
        self.token = token


async def _refresh_access_token() -> str:
    data = _load_oauth_tokens()
    token_url = "https://oauth2.googleapis.com/token"

    payload = {
        "client_id": data["client_id"],
        "client_secret": data["client_secret"],
        "refresh_token": data["refresh_token"],
        "grant_type": "refresh_token",
    }

    async with httpx.AsyncClient(timeout=30) as client:
        r = await client.post(token_url, data=payload)
        if r.status_code != 200:
            raise ValueError(f"Token refresh failed: {r.status_code} {r.text}")
        j = r.json()

    token = j.get("access_token")
    if not token:
        raise ValueError("No access_token in OAuth response")

    return token


def get_credentials() -> Credentials:
    token = asyncio.get_event_loop().run_until_complete(_refresh_access_token())
    return Credentials(token)


def format_customer_id(cid: str) -> str:
    cid = str(cid).replace('"', "")
    digits = "".join(c for c in cid if c.isdigit())
    return digits.zfill(10)


def _to_int(v):
    """Best-effort conversion to int (handles numeric strings); returns None if not convertible."""
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def get_headers(creds: Credentials) -> dict[str, str]:
    developer_token = os.environ.get("GOOGLE_ADS_DEVELOPER_TOKEN")
    if not developer_token:
        raise ValueError("GOOGLE_ADS_DEVELOPER_TOKEN not set")

    # Refresh access token in case creds were created earlier.
    headers = {
        "authorization": f"Bearer {creds.token}",
        "developer-token": developer_token,
        "content-type": "application/json",
    }

    login_cid = os.environ.get("GOOGLE_ADS_LOGIN_CUSTOMER_ID")
    if login_cid:
        headers["login-customer-id"] = format_customer_id(login_cid)

    return headers


def get_keyword_customer_id() -> str:
    """
    Customer ID used internally for keyword planner endpoints.
    Not exposed to Agent as parameter.
    """
    cid = os.environ.get("GOOGLE_ADS_KEYWORD_CUSTOMER_ID") or os.environ.get("GOOGLE_ADS_LOGIN_CUSTOMER_ID")
    if not cid:
        raise ValueError("Set GOOGLE_ADS_KEYWORD_CUSTOMER_ID or GOOGLE_ADS_LOGIN_CUSTOMER_ID")
    return format_customer_id(cid)


# --------------------------------------------------
# Google Ads API helpers
# --------------------------------------------------


async def _post_json(url: str, headers: dict[str, str], body: dict[str, Any]) -> dict[str, Any]:
    async with httpx.AsyncClient(timeout=60) as client:
        r = await client.post(url, headers=headers, json=body)

    if r.status_code >= 400:
        raise ToolError(f"Google Ads API error {r.status_code}: {r.text}")

    try:
        return r.json()
    except Exception:
        raise ToolError(f"Invalid JSON response from Google Ads API: {r.text}")


async def _search_stream(customer_id: str, headers: dict[str, str], query: str) -> list[dict[str, Any]]:
    url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{customer_id}/googleAds:searchStream"
    body = {"query": query}

    resp = await _post_json(url, headers, body)

    # searchStream returns a list of batches, each has results
    out: list[dict[str, Any]] = []
    if isinstance(resp, list):
        for batch in resp:
            out.extend(batch.get("results", []) or [])
    elif isinstance(resp, dict):
        out.extend(resp.get("results", []) or [])
    return out


# --------------------------------------------------
# Tools
# --------------------------------------------------


@mcp.tool()
async def generate_keyword_ideas(
    seed_keywords: list[str] = Field(description="Seed keywords (list)."),
    language_id: str = Field(default="1000", description="Language Constant ID (1000 = German)."),
    location_ids: list[str] = Field(default=["2276"], description="GeoTarget IDs (2276 = Germany)."),
    min_avg_monthly_searches: int = Field(default=10, description="Filter out low-volume ideas."),
    max_results: int = Field(default=50, description="Maximum number of ideas to return."),
) -> str:
    """
    Generate keyword ideas + basic metrics for given seed keywords.

    Notes:
    - Uses Keyword Plan Idea Service (generateKeywordIdeas endpoint).
    - Returns a readable text response.
    """
    if not seed_keywords or not any(k.strip() for k in seed_keywords):
        raise ToolError("seed_keywords must be a non-empty list of strings")

    try:
        creds = get_credentials()
        headers = get_headers(creds)
        cid = get_keyword_customer_id()

        endpoint = f"https://googleads.googleapis.com/{API_VERSION}/customers/{cid}:generateKeywordIdeas"

        # Prepare request body
        seed = [k.strip() for k in seed_keywords if k and k.strip()]
        seed_set = {k.lower() for k in seed}

        body = {
            "language": f"languageConstants/{language_id}",
            "geoTargetConstants": [f"geoTargetConstants/{lid}" for lid in location_ids],
            "includeAdultKeywords": False,
            "keywordSeed": {"keywords": seed},
        }

        resp = await _post_json(endpoint, headers, body)
        results = resp.get("results") or []
        ideas: list[dict] = []

        for item in results:
            text = (item.get("text") or "").strip()
            if not text:
                continue

            metrics = item.get("keywordIdeaMetrics", {}) or {}
            avg = _to_int(metrics.get("avgMonthlySearches"))

            # remove exact seeds
            if text.lower() in seed_set:
                continue

            # volume filter
            if avg is None or avg < int(min_avg_monthly_searches):
                continue

            ideas.append(
                {
                    "text": text,
                    "avg": avg,
                    "competition": metrics.get("competition"),
                    "low_bid": _to_int(metrics.get("lowTopOfPageBidMicros")),
                    "high_bid": _to_int(metrics.get("highTopOfPageBidMicros")),
                }
            )

        ideas.sort(key=lambda x: x["avg"], reverse=True)
        ideas = ideas[: int(max_results)]

        if not ideas:
            return "Keine Keyword-Ideen gefunden (oder alle wurden durch Filter entfernt)."

        out = []
        for i, it in enumerate(ideas, start=1):
            out.append(
                f"{i}. {it['text']}\n"
                f"   Avg. monthly searches: {it['avg']}\n"
                f"   Competition: {it.get('competition')}\n"
                f"   Low bid (micros): {it.get('low_bid')}\n"
                f"   High bid (micros): {it.get('high_bid')}\n"
            )

        return "\n".join(out)

    except Exception as e:
        raise ToolError(str(e))


@mcp.tool()
async def get_keyword_search_volume(
    keywords: list[str] = Field(description="Exact keyword list to evaluate."),
    language_id: str = Field(default="1000", description="Language Constant ID (1000 = German)."),
    location_ids: list[str] = Field(default=["2276"], description="GeoTarget IDs (2276 = Germany)."),
) -> str:
    """
    Returns search volume + metrics for an exact keyword list.

    Implementation uses the same generateKeywordIdeas endpoint and then filters results
    to the exact keyword list.
    """
    if not keywords or not any(k.strip() for k in keywords):
        raise ToolError("keywords must be a non-empty list of strings")

    try:
        creds = get_credentials()
        headers = get_headers(creds)
        cid = get_keyword_customer_id()

        endpoint = f"https://googleads.googleapis.com/{API_VERSION}/customers/{cid}:generateKeywordIdeas"

        wanted = {k.lower().strip() for k in keywords if k and k.strip()}

        body = {
            "language": f"languageConstants/{language_id}",
            "geoTargetConstants": [f"geoTargetConstants/{lid}" for lid in location_ids],
            "includeAdultKeywords": False,
            "keywordSeed": {"keywords": list(wanted)},
        }

        resp = await _post_json(endpoint, headers, body)
        results = resp.get("results") or []

        out = []

        for item in results:
            text = (item.get("text") or "").strip()
            if not text or text.lower() not in wanted:
                continue

            metrics = item.get("keywordIdeaMetrics", {}) or {}
            out.append(
                f"Keyword: {text}\n"
                f"  Avg. monthly searches: {metrics.get('avgMonthlySearches')}\n"
                f"  Competition: {metrics.get('competition')}\n"
                f"  Low bid (micros): {metrics.get('lowTopOfPageBidMicros')}\n"
                f"  High bid (micros): {metrics.get('highTopOfPageBidMicros')}\n"
            )

        return "\n".join(out) if out else "Keine Daten gefunden (für diese Keywords keine Metriken)."

    except Exception as e:
        raise ToolError(str(e))


@mcp.tool()
async def gaql_search_stream(
    customer_id: str = Field(description="Google Ads Customer ID (digits or formatted)."),
    query: str = Field(description="GAQL query string."),
) -> str:
    """
    Run a GAQL searchStream query. Useful for optional tools and debugging.

    Example query:
      SELECT campaign.id, campaign.name FROM campaign LIMIT 10
    """
    if not query or not query.strip():
        raise ToolError("query must be non-empty")

    try:
        creds = get_credentials()
        headers = get_headers(creds)
        cid = format_customer_id(customer_id)

        results = await _search_stream(cid, headers, query.strip())
        if not results:
            return "No results."

        # Pretty print the first N results
        N = 20
        shown = results[:N]
        return json.dumps(shown, indent=2, ensure_ascii=False)

    except Exception as e:
        raise ToolError(str(e))


# --------------------------------------------------
# Run
# --------------------------------------------------

if __name__ == "__main__":
    # FastMCP will serve by default on 127.0.0.1:8000 unless configured otherwise
    mcp.run()
