#!/usr/bin/env python3

import os
import json
import base64
import logging
import warnings
from datetime import datetime, timezone
from dateutil import parser

import requests
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
# Credentials
# --------------------------------------------------

def initialize_credentials() -> Credentials:
    b64 = os.environ.get("GOOGLE_ADS_OAUTH_TOKENS_BASE64")
    if not b64:
        raise ValueError("GOOGLE_ADS_OAUTH_TOKENS_BASE64 not set")

    data = json.loads(base64.b64decode(b64).decode("utf-8"))

    creds = Credentials(
        refresh_token=data["refresh_token"],
        client_id=data["client_id"],
        client_secret=data["client_secret"],
        token_uri=data.get("token_uri", "https://oauth2.googleapis.com/token"),
        scopes=data.get("scopes", SCOPES),
    )

    if "expiry" in data:
        creds.expiry = parser.parse(data["expiry"])

    return creds


try:
    _credentials = initialize_credentials()
    logger.info("✅ Google Ads credentials initialized successfully")
except Exception as e:
    logger.error(f"❌ Google Ads credentials failed: {e}")
    _credentials = None


def get_credentials() -> Credentials:
    if not _credentials:
        raise ValueError("Google Ads credentials not initialized")
    return _credentials


def format_customer_id(cid: str) -> str:
    return "".join(c for c in cid if c.isdigit()).zfill(10)


def get_headers(creds: Credentials) -> dict:
    token = os.environ.get("GOOGLE_ADS_DEVELOPER_TOKEN")
    if not token:
        raise ValueError("GOOGLE_ADS_DEVELOPER_TOKEN not set")

    creds.refresh(AuthRequest())

    headers = {
        "Authorization": f"Bearer {creds.token}",
        "developer-token": token,
        "content-type": "application/json",
    }

    login_id = os.environ.get("GOOGLE_ADS_LOGIN_CUSTOMER_ID")
    if login_id:
        headers["login-customer-id"] = format_customer_id(login_id)

    return headers


# --------------------------------------------------
# MCP
# --------------------------------------------------

mcp = FastMCP(name="Google Ads MCP")

@mcp.resource("health://status")
def health():
    return json.dumps({
        "status": "ok",
        "google_ads_connected": _credentials is not None,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }, indent=2)


# --------------------------------------------------
# TOOLS
# --------------------------------------------------

@mcp.tool()
async def generate_keyword_ideas(
    seed_keywords: list[str] = Field(description="Seed keywords"),
    language_id: str = Field(default="1000", description="1000 = German"),
    location_ids: list[str] = Field(default=["2276"], description="2276 = Germany"),
    min_avg_monthly_searches: int = Field(default=10),
    max_results: int = Field(default=50),
) -> str:
    """
    Generates NEW keyword ideas from seed keywords (NO URL).
    Seed keywords themselves are filtered out.
    """
    try:
        creds = get_credentials()
        headers = get_headers(creds)

        customer_id = os.environ.get("GOOGLE_ADS_KEYWORD_CUSTOMER_ID") or os.environ.get("GOOGLE_ADS_LOGIN_CUSTOMER_ID")
        if not customer_id:
            raise ToolError("Customer-ID missing in environment")

        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{format_customer_id(customer_id)}:generateKeywordIdeas"

        seed_set = {s.lower().strip() for s in seed_keywords}

        body = {
            "language": f"languageConstants/{language_id}",
            "geoTargetConstants": [f"geoTargetConstants/{l}" for l in location_ids],
            "keywordPlanNetwork": "GOOGLE_SEARCH_AND_PARTNERS",
            "keywordSeed": {"keywords": seed_keywords},
        }

        r = requests.post(url, headers=headers, json=body)
        if r.status_code != 200:
            raise ToolError(r.text)

        ideas = []
        for item in r.json().get("results", []):
            text = (item.get("text") or "").strip()
            metrics = item.get("keywordIdeaMetrics", {}) or {}
            avg = metrics.get("avgMonthlySearches")

            if text.lower() in seed_set:
                continue
            if not avg or avg < min_avg_monthly_searches:
                continue

            ideas.append({
                "text": text,
                "avg": avg,
                "competition": metrics.get("competition"),
                "low": metrics.get("lowTopOfPageBidMicros"),
                "high": metrics.get("highTopOfPageBidMicros"),
            })

        ideas.sort(key=lambda x: x["avg"], reverse=True)

        if not ideas:
            return "Keine neuen Keyword-Ideen gefunden."

        out = []
        for i in ideas[:max_results]:
            out.append(
                f"Keyword: {i['text']}\n"
                f"  Avg. monthly searches: {i['avg']}\n"
                f"  Competition: {i['competition']}\n"
                f"  Low bid: {i['low']}\n"
                f"  High bid: {i['high']}\n"
            )

        return "\n".join(out)

    except Exception as e:
        raise ToolError(str(e))


@mcp.tool()
async def get_keyword_search_volume(
    keywords: list[str] = Field(description="Keywords to evaluate"),
    language_id: str = Field(default="1000"),
    location_ids: list[str] = Field(default=["2276"]),
) -> str:
    """
    Returns search volume for a fixed keyword list.
    """
    try:
        creds = get_credentials()
        headers = get_headers(creds)

        customer_id = os.environ.get("GOOGLE_ADS_KEYWORD_CUSTOMER_ID") or os.environ.get("GOOGLE_ADS_LOGIN_CUSTOMER_ID")
        if not customer_id:
            raise ToolError("Customer-ID missing in environment")

        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{format_customer_id(customer_id)}:generateKeywordIdeas"

        body = {
            "language": f"languageConstants/{language_id}",
            "geoTargetConstants": [f"geoTargetConstants/{l}" for l in location_ids],
            "keywordSeed": {"keywords": keywords},
        }

        r = requests.post(url, headers=headers, json=body)
        if r.status_code != 200:
            raise ToolError(r.text)

        wanted = {k.lower().strip() for k in keywords}
        out = []

        for item in r.json().get("results", []):
            text = (item.get("text") or "").strip()
            if text.lower() not in wanted:
                continue

            metrics = item.get("keywordIdeaMetrics", {}) or {}
            out.append(
                f"Keyword: {text}\n"
                f"  Avg. monthly searches: {metrics.get('avgMonthlySearches')}\n"
                f"  Competition: {metrics.get('competition')}\n"
                f"  Low bid: {metrics.get('lowTopOfPageBidMicros')}\n"
                f"  High bid: {metrics.get('highTopOfPageBidMicros')}\n"
            )

        return "\n".join(out) if out else "Keine Daten gefunden."

    except Exception as e:
        raise ToolError(str(e))


# --------------------------------------------------
# RUN
# --------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    mcp.run(transport="streamable-http", host="0.0.0.0", port=port)
