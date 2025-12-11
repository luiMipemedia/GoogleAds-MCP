#!/usr/bin/env python3
"""
Google Ads MCP Server - FastMCP Implementation
Simplified for use with OpenAI Agent Builder (no external MCP auth).

Tools:
- list_accounts
- get_search_keywords
- get_search_terms
- generate_keyword_ideas        (Seed-Begriffe -> Keyword-Ideen + Suchvolumen)
- get_keyword_search_volume     (Keywords -> Suchvolumen + Metriken)
"""

import os
import json
import base64
import logging
import warnings
from datetime import datetime, timezone
from dateutil import parser
from typing import Any

# Suppress noisy deprecation warnings
warnings.filterwarnings("ignore", category=DeprecationWarning, module="websockets")
warnings.filterwarnings("ignore", category=DeprecationWarning, module="uvicorn")

import requests
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as AuthRequest

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from pydantic import Field

# -----------------------------------------------------
# Basic setup
# -----------------------------------------------------

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("google_ads_mcp")

SCOPES = ["https://www.googleapis.com/auth/adwords"]
API_VERSION = "v20"  # ggf. anpassen falls du eine andere Version nutzen willst


def initialize_credentials() -> Credentials:
    """
    Initialize OAuth credentials from the base64-encoded JSON stored in
    GOOGLE_ADS_OAUTH_TOKENS_BASE64.
    """
    oauth_tokens_base64 = os.environ.get("GOOGLE_ADS_OAUTH_TOKENS_BASE64")
    if not oauth_tokens_base64:
        raise ValueError("GOOGLE_ADS_OAUTH_TOKENS_BASE64 environment variable not set")

    try:
        oauth_tokens_json = base64.b64decode(oauth_tokens_base64).decode("utf-8")
        oauth_tokens = json.loads(oauth_tokens_json)

        credentials = Credentials(
            token=oauth_tokens.get("token"),
            refresh_token=oauth_tokens.get("refresh_token"),
            token_uri=oauth_tokens.get("token_uri", "https://oauth2.googleapis.com/token"),
            client_id=oauth_tokens.get("client_id"),
            client_secret=oauth_tokens.get("client_secret"),
            scopes=oauth_tokens.get("scopes", SCOPES),
        )

        # Optional: handle expiry if provided
        if "expiry" in oauth_tokens:
            expiry_str = oauth_tokens["expiry"]
            credentials.expiry = parser.parse(expiry_str)

        return credentials

    except Exception as e:
        logger.error(f"Error initializing OAuth credentials: {e}")
        raise


# Initialize Google Ads credentials once at startup
try:
    _credentials = initialize_credentials()
    logger.info("✅ Google Ads credentials initialized successfully")
except Exception as e:
    logger.error(f"❌ Failed to initialize Google Ads credentials: {e}")
    _credentials = None


def get_credentials() -> Credentials:
    """Return initialized credentials or raise if missing."""
    if not _credentials:
        raise ValueError("Google Ads credentials not initialized")
    return _credentials


def format_customer_id(customer_id: str) -> str:
    """
    Ensure customer ID is 10 digits without dashes.
    Accepts things like '123-456-7890' or '"1234567890"' and normalizes them.
    """
    customer_id = str(customer_id)
    customer_id = customer_id.replace('"', "")
    digits = "".join(ch for ch in customer_id if ch.isdigit())
    return digits.zfill(10)


def get_headers(creds: Credentials) -> dict[str, str]:
    """
    Build headers for Google Ads REST API calls.
    Requires:
    - GOOGLE_ADS_DEVELOPER_TOKEN
    - (optional) GOOGLE_ADS_LOGIN_CUSTOMER_ID
    """
    developer_token = os.environ.get("GOOGLE_ADS_DEVELOPER_TOKEN")
    if not developer_token:
        raise ValueError("GOOGLE_ADS_DEVELOPER_TOKEN environment variable not set")

    login_customer_id = os.environ.get("GOOGLE_ADS_LOGIN_CUSTOMER_ID", "")

    # Always refresh before using
    auth_req = AuthRequest()
    creds.refresh(auth_req)

    headers = {
        "Authorization": f"Bearer {creds.token}",
        "developer-token": developer_token,
        "content-type": "application/json",
    }

    if login_customer_id:
        headers["login-customer-id"] = format_customer_id(login_customer_id)

    return headers


def _execute_gaql_query_internal(customer_id: str, query: str) -> str:
    """
    Internal helper to execute a GAQL query via the Google Ads REST API.
    Returns a formatted string with up to 50 results.
    """
    try:
        creds = get_credentials()
        headers = get_headers(creds)

        formatted_customer_id = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}/googleAds:search"

        payload = {"query": query}
        response = requests.post(url, headers=headers, json=payload)

        if response.status_code != 200:
            return f"Error executing query: {response.text}"

        results = response.json()
        if not results.get("results"):
            return "No results found for the query."

        out: list[str] = [f"Query Results for Account {formatted_customer_id}:", "-" * 80]

        for i, result in enumerate(results["results"][:50], 1):
            out.append(f"\nResult {i}:")
            out.append(json.dumps(result, indent=2))

        return "\n".join(out)

    except Exception as e:
        return f"Error executing GAQL query: {e}"


# -----------------------------------------------------
# FastMCP server (no external MCP auth)
# -----------------------------------------------------

public_domain = os.environ.get("RAILWAY_PUBLIC_DOMAIN")
if public_domain:
    base_url = f"https://{public_domain}"
else:
    base_url = "http://localhost:8080"

mcp = FastMCP(name="Google Ads MCP")

logger.info("=" * 60)
logger.info("🚀 Google Ads MCP Server Started (no external MCP auth)")
logger.info(f"📍 Base URL (informational): {base_url}")
logger.info("🔐 MCP auth: disabled (use only in trusted environments)")
logger.info("=" * 60)


# ===========================
# Health Check Resource
# ===========================

@mcp.resource("health://status")
def mcp_health_status() -> str:
    """Simple health check for monitoring."""
    status = {
        "status": "healthy",
        "auth_enabled": False,
        "auth_method": "none",
        "google_ads_connected": _credentials is not None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "1.0.0-keywords",
    }
    return json.dumps(status, indent=2)


# ===========================
# Tools
# ===========================

@mcp.tool()
async def list_accounts() -> str:
    """Lists all accessible Google Ads accounts for the current login customer."""
    try:
        creds = get_credentials()
        headers = get_headers(creds)

        url = f"https://googleads.googleapis.com/{API_VERSION}/customers:listAccessibleCustomers"
        response = requests.get(url, headers=headers)

        if response.status_code != 200:
            return f"Error accessing accounts: {response.text}"

        customers = response.json()
        if not customers.get("resourceNames"):
            return "No accessible accounts found."

        result_lines: list[str] = ["Accessible Google Ads Accounts:", "-" * 50]

        for resource_name in customers["resourceNames"]:
            customer_id = resource_name.split("/")[-1]
            formatted_id = format_customer_id(customer_id)
            result_lines.append(f"Account ID: {formatted_id}")

        return "\n".join(result_lines)

    except Exception as e:
        return f"Error listing accounts: {e}"


@mcp.tool()
async def get_search_keywords(
    customer_id: str = Field(
        description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"
    ),
    days: int = Field(default=7, description="Number of days to look back"),
) -> str:
    """
    Holt Keyword-Performance für bestehende Keywords im Konto (kein Generator).
    Nutzt GAQL auf keyword_view.
    """
    query = f"""
        SELECT
            ad_group_criterion.keyword.text,
            campaign.name,
            ad_group.name,
            ad_group_criterion.system_serving_status,
            ad_group_criterion.keyword.match_type,
            ad_group_criterion.approval_status,
            ad_group_criterion.final_urls,
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
    customer_id: str = Field(
        description="Google Ads customer ID (10 digits, no dashes). Example: '9873186703'"
    ),
    days: int = Field(default=7, description="Number of days to look back"),
) -> str:
    """
    Holt tatsächliche Suchbegriffe (Search Terms Report) für ein Konto.
    """
    query = f"""
        SELECT
            search_term_view.search_term,
            segments.keyword.info.match_type,
            search_term_view.status,
            campaign.name,
            ad_group.name,
            metrics.clicks,
            metrics.impressions,
            metrics.ctr,
            metrics.average_cpc,
            metrics.cost_micros,
            campaign.advertising_channel_type
        FROM search_term_view
        WHERE segments.date DURING LAST_{days}_DAYS
        ORDER BY metrics.impressions DESC
        LIMIT 100
    """
    return _execute_gaql_query_internal(customer_id, query)


@mcp.tool()
async def generate_keyword_ideas(
    seed_keywords: list[str] = Field(
        description="Liste von Begriffen/Keywords, aus denen neue Keyword-Ideen mit Suchvolumen generiert werden sollen."
    ),
    language_id: str = Field(
        default="1000",
        description="Language Constant ID, z. B. 1000 für Deutsch."
    ),
    location_ids: list[str] = Field(
        default=["2760"],
        description="Liste von GeoTarget-IDs, z. B. 2760 für Deutschland."
    ),
) -> str:
    """
    Nutzt den Google Ads KeywordPlanIdeaService.generateKeywordIdeas-Endpunkt, um
    aus seed_keywords neue Keyword-Ideen zu erzeugen und direkt Suchvolumen + Metriken
    zurückzugeben. Customer-ID wird intern aus der Umgebung gelesen und
    ist von außen nicht sichtbar.
    """
    try:
        creds = get_credentials()
        headers = get_headers(creds)

        # Customer-ID nur intern benutzen, niemals nach außen geben
        customer_id = os.environ.get("GOOGLE_ADS_KEYWORD_CUSTOMER_ID") or os.environ.get(
            "GOOGLE_ADS_LOGIN_CUSTOMER_ID"
        )
        if not customer_id:
            raise ToolError(
                "Es ist keine Customer-ID gesetzt. Lege in Railway GOOGLE_ADS_KEYWORD_CUSTOMER_ID oder GOOGLE_ADS_LOGIN_CUSTOMER_ID an."
            )

        formatted_customer_id = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}:generateKeywordIdeas"

        language_resource = f"languageConstants/{language_id}"
        geo_resources = [f"geoTargetConstants/{loc_id}" for loc_id in location_ids]

        body = {
            "language": language_resource,
            "geoTargetConstants": geo_resources,
            "keywordSeed": {
                "keywords": seed_keywords
            }
        }

        response = requests.post(url, headers=headers, json=body)
        if response.status_code != 200:
            raise ToolError(f"Fehler bei generateKeywordIdeas: {response.text}")

        data = response.json()
        results = data.get("results", [])

        if not results:
            return "Für diese Eingaben wurden keine Keyword-Ideen gefunden."

        lines: list[str] = []
        for res in results:
            text = res.get("text")
            metrics = res.get("keywordIdeaMetrics", {}) or {}

            avg_monthly = metrics.get("avgMonthlySearches")
            competition = metrics.get("competition")
            low_bid = metrics.get("lowTopOfPageBidMicros")
            high_bid = metrics.get("highTopOfPageBidMicros")

            lines.append(
                f"Keyword-Idee: {text}\n"
                f"  Durchschnittl. monatliche Suchanfragen: {avg_monthly}\n"
                f"  Wettbewerb (enum): {competition}\n"
                f"  Low Top of Page Bid (Micros): {low_bid}\n"
                f"  High Top of Page Bid (Micros): {high_bid}\n"
            )

        return "\n".join(lines)

    except Exception as e:
        raise ToolError(f"Fehler in generate_keyword_ideas: {str(e)}")


@mcp.tool()
async def get_keyword_search_volume(
    keywords: list[str] = Field(
        description="Liste von Keywords, für die explizit Suchvolumen & Metriken ausgegeben werden sollen."
    ),
    language_id: str = Field(
        default="1000",
        description="Language Constant ID, z. B. 1000 für Deutsch."
    ),
    location_ids: list[str] = Field(
        default=["2760"],
        description="Liste von GeoTarget-IDs, z. B. 2760 für Deutschland."
    ),
) -> str:
    """
    Holt für eine konkrete Liste von Keywords das jeweilige Suchvolumen und
    relevante Metriken. Intern wird generateKeywordIdeas verwendet,
    danach aber auf genau die übergebenen Keywords gefiltert.
    """
    try:
        creds = get_credentials()
        headers = get_headers(creds)

        customer_id = os.environ.get("GOOGLE_ADS_KEYWORD_CUSTOMER_ID") or os.environ.get(
            "GOOGLE_ADS_LOGIN_CUSTOMER_ID"
        )
        if not customer_id:
            raise ToolError(
                "Es ist keine Customer-ID gesetzt. Lege in Railway GOOGLE_ADS_KEYWORD_CUSTOMER_ID oder GOOGLE_ADS_LOGIN_CUSTOMER_ID an."
            )

        formatted_customer_id = format_customer_id(customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers/{formatted_customer_id}:generateKeywordIdeas"

        language_resource = f"languageConstants/{language_id}"
        geo_resources = [f"geoTargetConstants/{loc_id}" for loc_id in location_ids]

        body = {
            "language": language_resource,
            "geoTargetConstants": geo_resources,
            "keywordSeed": {
                "keywords": keywords
            }
        }

        response = requests.post(url, headers=headers, json=body)
        if response.status_code != 200:
            raise ToolError(f"Fehler bei generateKeywordIdeas: {response.text}")

        data = response.json()
        results = data.get("results", [])

        if not results:
            return "Für diese Keywords wurden keine Daten gefunden."

        # Set für exakte Filterung auf unsere Eingabe-Keywords
        keyword_set = {k.lower().strip() for k in keywords}
        lines: list[str] = []

        for res in results:
            text_raw = res.get("text") or ""
            text = text_raw.lower().strip()
            if text not in keyword_set:
                continue

            metrics = res.get("keywordIdeaMetrics", {}) or {}
            avg_monthly = metrics.get("avgMonthlySearches")
            competition = metrics.get("competition")
            low_bid = metrics.get("lowTopOfPageBidMicros")
            high_bid = metrics.get("highTopOfPageBidMicros")

            lines.append(
                f"Keyword: {text_raw}\n"
                f"  Durchschnittl. monatliche Suchanfragen: {avg_monthly}\n"
                f"  Wettbewerb (enum): {competition}\n"
                f"  Low Top of Page Bid (Micros): {low_bid}\n"
                f"  High Top of Page Bid (Micros): {high_bid}\n"
            )

        if not lines:
            return "Für die angegebenen Keywords wurden keine exakten Volumen-Daten gefunden."

        return "\n".join(lines)

    except Exception as e:
        raise ToolError(f"Fehler in get_keyword_search_volume: {str(e)}")


# -----------------------------------------------------
# Main entrypoint
# -----------------------------------------------------

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))

    logger.info("=" * 60)
    logger.info("🚀 Starting Google Ads MCP Server (keywords edition)")
    logger.info(f"📍 Port: {port}")
    logger.info(f"🌐 Base URL (informational): {base_url}")
    logger.info("=" * 60)

    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",
        port=port,
    )
