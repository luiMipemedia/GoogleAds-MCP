#!/usr/bin/env python3
"""
Google Ads MCP Server (FastMCP) – Keyword Ideas + Search Volume
- No external MCP auth (trusted env only)
- Credentials loaded from GOOGLE_ADS_OAUTH_TOKENS_BASE64 (base64-encoded JSON)
- Uses Google Ads REST endpoints:
  - customers:listAccessibleCustomers
  - customers/{cid}:generateKeywordIdeas
  - googleAds:search (GAQL) for optional tools
"""

import os
import json
import base64
import logging
import warnings
from datetime import datetime, timezone

import requests
from dateutil import parser
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as AuthRequest

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from pydantic import Field

warnings.filterwarnings("ignore")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("google_ads_mcp")

SCOPES = ["https://www.googleapis.com/auth/adwords"]
API_VERSION = "v20"

# --------------------------------------------------
# Robust credentials init
# --------------------------------------------------

def initialize_credentials() -> Credentials:
    b64 = os.environ.get("GOOGLE_ADS_OAUTH_TOKENS_BASE64")
    if not b64:
        raise ValueError("GOOGLE_ADS_OAUTH_TOKENS_BASE64 not set")

    try:
        decoded = base64.b64decode(b64).decode("utf-8", errors="strict")
    except Exception as e:
        raise ValueError(f"Base64 decode failed: {e}")

    # Common pitfall: RTF accidentally encoded
    if decoded.lstrip().startswith("{\\rtf"):
        raise ValueError(
            "Decoded content is RTF, not JSON. Your base64 encodes an RTF file."
        )

    try:
        data = json.loads(decoded)
    except Exception as e:
        raise ValueError(f"JSON parse failed: {e}")

    missing = [k for k in ["refresh_token", "client_id", "client_secret"] if not data.get(k)]
    if missing:
        raise ValueError(f"Missing required OAuth fields in JSON: {', '.join(missing)}")

    creds = Credentials(
        token=data.get("token"),  # optional
        refresh_token=data.get("refresh_token"),
        client_id=data.get("client_id"),
        client_secret=data.get("client_secret"),
        token_uri=data.get("token_uri", "https://oauth2.googleapis.com/token"),
        scopes=data.get("scopes", SCOPES),
    )

    if data.get("expiry"):
        creds.expiry = parser.parse(data["expiry"])

    return creds


try:
    _credentials = initialize_credentials()
    logger.info("✅ Google Ads credentials initialized successfully")
except Exception as e:
    logger.error(f"❌ Failed to initialize Google Ads credentials: {e}")
    _credentials = None


def get_credentials() -> Credentials:
    if not _credentials:
        raise ValueError("Google Ads credentials not initialized")
    return _credentials


def format_customer_id(cid: str) -> str:
    cid = str(cid).replace('"', "")
    digits = "".join(c for c in cid if c.isdigit())
    return digits.zfill(10)


def get_headers(creds: Credentials) -> dict[str, str]:
    developer_token = os.environ.get("GOOGLE_ADS_DEVELOPER_TOKEN")
    if not developer_token:
        raise ValueError("GOOGLE_ADS_DEVELOPER_TOKEN not set")

    # Refresh access token each call (safe + simple)
    creds.refresh(AuthRequest())

    headers: dict[str, str] = {
        "Authorization": f"Bearer {creds.token}",
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
        raise ValueError("Missing GOOGLE_ADS_KEYWORD_CUSTOMER_ID (or GOOGLE_ADS_LOGIN_CUSTOMER_ID)")
    return format_customer_id(cid)


def _execute_gaql_query_internal(customer_id: str, query: str) -> str:
    """
    Optional GAQL helper used by get_search_terms / get_search_keywords.
    """
    try:
        creds = get_credentials()
        headers = get_headers(creds)

        cid = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{cid}/googleAds:search"

        resp = requests.post(url, headers=headers, json={"query": query})
        if resp.status_code != 200:
            return f"Error executing query: {resp.text}"

        data = resp.json()
        results = data.get("results") or []
        if not results:
            return "No results found for the query."

        out = [f"Query Results for Account {cid}:", "-" * 80]
        for i, r in enumerate(results[:50], 1):
            out.append(f"\nResult {i}:")
            out.append(json.dumps(r, indent=2))
        return "\n".join(out)

    except Exception as e:
        return f"Error executing GAQL query: {e}"


# --------------------------------------------------
# MCP server
# --------------------------------------------------

mcp = FastMCP(name="Google Ads MCP")


@mcp.resource("health://status")
def health_status() -> str:
    return json.dumps(
        {
            "status": "ok",
            "google_ads_connected": _credentials is not None,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        indent=2,
    )


# --------------------------------------------------
# Tools (accounts + optional GAQL + keyword planner)
# --------------------------------------------------

@mcp.tool()
async def list_accounts() -> str:
    """Lists accessible Google Ads accounts for the current OAuth identity."""
    try:
        creds = get_credentials()
        headers = get_headers(creds)

        url = f"https://googleads.googleapis.com/{API_VERSION}/customers:listAccessibleCustomers"
        resp = requests.get(url, headers=headers)

        if resp.status_code != 200:
            raise ToolError(f"Error accessing accounts: {resp.text}")

        data = resp.json()
        names = data.get("resourceNames") or []
        if not names:
            return "No accessible accounts found."

        lines = ["Accessible Google Ads Accounts:", "-" * 50]
        for rn in names:
            cid = rn.split("/")[-1]
            lines.append(f"Account ID: {format_customer_id(cid)}")
        return "\n".join(lines)

    except Exception as e:
        raise ToolError(str(e))


@mcp.tool()
async def get_search_keywords(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes)."),
    days: int = Field(default=7, description="Number of days to look back (LAST_N_DAYS)."),
) -> str:
    """Reads existing keyword performance from the account (GAQL keyword_view)."""
    query = f"""
        SELECT
            ad_group_criterion.keyword.text,
            campaign.name,
            ad_group.name,
            ad_group_criterion.keyword.match_type,
            metrics.clicks,
            metrics.impressions,
            metrics.ctr,
            metrics.average_cpc,
            metrics.cost_micros
        FROM keyword_view
        WHERE segments.date DURING LAST_{days}_DAYS
          AND ad_group_criterion.status != 'REMOVED'
        ORDER BY metrics.impressions DESC
        LIMIT 100
    """
    return _execute_gaql_query_internal(customer_id, query)


@mcp.tool()
async def get_search_terms(
    customer_id: str = Field(description="Google Ads customer ID (10 digits, no dashes)."),
    days: int = Field(default=7, description="Number of days to look back (LAST_N_DAYS)."),
) -> str:
    """Reads actual search terms (queries) that triggered ads (GAQL search_term_view)."""
    query = f"""
        SELECT
            search_term_view.search_term,
            segments.keyword.info.match_type,
            campaign.name,
            ad_group.name,
            metrics.clicks,
            metrics.impressions,
            metrics.ctr,
            metrics.average_cpc,
            metrics.cost_micros
        FROM search_term_view
        WHERE segments.date DURING LAST_{days}_DAYS
        ORDER BY metrics.impressions DESC
        LIMIT 100
    """
    return _execute_gaql_query_internal(customer_id, query)


@mcp.tool()
async def generate_keyword_ideas(
    seed_keywords: list[str] = Field(description="Seed keywords (list)."),
    language_id: str = Field(default="1000", description="Language Constant ID (1000 = German)."),
    location_ids: list[str] = Field(default=["2276"], description="GeoTarget IDs (2276 = Germany)."),
    min_avg_monthly_searches: int = Field(default=10, description="Filter out low-volume ideas."),
    max_results: int = Field(default=50, description="Max number of ideas returned."),
) -> str:
    """
    Generates NEW keyword ideas based on seed keywords (no URL).
    Filters out the seed keywords from the result set.
    """
    if not seed_keywords or not any(s.strip() for s in seed_keywords):
        raise ToolError("seed_keywords must be a non-empty list of strings")

    try:
        creds = get_credentials()
        headers = get_headers(creds)
        cid = get_keyword_customer_id()

        endpoint = f"https://googleads.googleapis.com/{API_VERSION}/customers/{cid}:generateKeywordIdeas"

        seed_set = {s.lower().strip() for s in seed_keywords if s and s.strip()}

        body = {
            "language": f"languageConstants/{language_id}",
            "geoTargetConstants": [f"geoTargetConstants/{l}" for l in location_ids],
            "keywordPlanNetwork": "GOOGLE_SEARCH_AND_PARTNERS",
            "keywordSeed": {"keywords": seed_keywords},
        }

        resp = requests.post(endpoint, headers=headers, json=body)
        if resp.status_code != 200:
            raise ToolError(resp.text)

        results = resp.json().get("results") or []
        ideas: list[dict] = []

        for item in results:
            text = (item.get("text") or "").strip()
            if not text:
                continue

            metrics = item.get("keywordIdeaMetrics", {}) or {}
            avg = metrics.get("avgMonthlySearches")

            # remove exact seeds
            if text.lower() in seed_set:
                continue

            # volume filter
            if avg is None or avg < min_avg_monthly_searches:
                continue

            ideas.append(
                {
                    "text": text,
                    "avg": avg,
                    "competition": metrics.get("competition"),
                    "low_bid": metrics.get("lowTopOfPageBidMicros"),
                    "high_bid": metrics.get("highTopOfPageBidMicros"),
                }
            )

        ideas.sort(key=lambda x: x["avg"], reverse=True)

        if not ideas:
            return "Keine neuen Keyword-Ideen gefunden (nur Seeds oder zu wenig Volumen)."

        out = []
        for i in ideas[:max_results]:
            out.append(
                f"Keyword: {i['text']}\n"
                f"  Avg. monthly searches: {i['avg']}\n"
                f"  Competition: {i['competition']}\n"
                f"  Low bid (micros): {i['low_bid']}\n"
                f"  High bid (micros): {i['high_bid']}\n"
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
    (Uses generateKeywordIdeas under the hood and filters to requested keywords.)
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
            "geoTargetConstants": [f"geoTargetConstants/{l}" for l in location_ids],
            "keywordSeed": {"keywords": keywords},
        }

        resp = requests.post(endpoint, headers=headers, json=body)
        if resp.status_code != 200:
            raise ToolError(resp.text)

        results = resp.json().get("results") or []
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


# --------------------------------------------------
# Run
# --------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    mcp.run(transport="streamable-http", host="0.0.0.0", port=port)
