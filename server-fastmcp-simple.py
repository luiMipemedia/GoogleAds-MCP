import os
import time
import json
import asyncio
import base64
from typing import Any, Dict, List

from fastmcp import FastMCP

from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

import requests


# ------------------------------------------------------------
# MCP app
# ------------------------------------------------------------
mcp = FastMCP("google_ads_mcp")


# ------------------------------------------------------------
# Helpers
# ------------------------------------------------------------
def _must_get_env(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        raise RuntimeError(f"Missing required env var: {name}")
    return v


def _parse_scopes() -> List[str]:
    raw = os.environ.get("GOOGLE_SCOPES", "").strip()
    if not raw:
        # Safe default for Google Ads API usage (adjust if your repo uses a different scope set)
        return ["https://www.googleapis.com/auth/adwords"]

    # allow comma-separated or JSON list
    if raw.startswith("["):
        return json.loads(raw)
    return [s.strip() for s in raw.split(",") if s.strip()]


def _decode_b64_json_env(name: str) -> Dict[str, Any]:
    """
    Reads env var that can be either:
    - raw JSON
    - base64-encoded JSON
    """
    raw = _must_get_env(name).strip()
    try:
        # Try raw JSON first
        return json.loads(raw)
    except Exception:
        pass

    try:
        decoded = base64.b64decode(raw).decode("utf-8")
        return json.loads(decoded)
    except Exception as e:
        raise RuntimeError(f"Env var {name} is neither valid JSON nor base64 JSON: {e}")


async def _refresh_access_token() -> str:
    """
    Refresh access token using installed client secrets + refresh token.
    This must be async-safe (no run_until_complete inside).
    """
    # If you store the OAuth client info as base64 JSON, keep using that.
    # Expected fields:
    # - client_id
    # - client_secret
    # - token_uri (optional; defaults to Google)
    oauth_client = _decode_b64_json_env("GOOGLE_OAUTH_CLIENT_JSON_B64")

    refresh_token = _must_get_env("GOOGLE_REFRESH_TOKEN")

    token_uri = oauth_client.get("token_uri", "https://oauth2.googleapis.com/token")
    client_id = oauth_client["client_id"]
    client_secret = oauth_client["client_secret"]

    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "refresh_token": refresh_token,
        "grant_type": "refresh_token",
    }

    # run blocking request in thread
    def _do():
        r = requests.post(token_uri, data=data, timeout=30)
        r.raise_for_status()
        return r.json()["access_token"]

    return await asyncio.to_thread(_do)


async def get_credentials() -> Credentials:
    token = await _refresh_access_token()
    return Credentials(token=token, scopes=_parse_scopes())


def _google_ads_headers(creds: Credentials) -> Dict[str, str]:
    developer_token = _must_get_env("GOOGLE_ADS_DEVELOPER_TOKEN")
    login_customer_id = os.environ.get("GOOGLE_ADS_LOGIN_CUSTOMER_ID", "").strip()
    headers = {
        "Authorization": f"Bearer {creds.token}",
        "developer-token": developer_token,
        "Content-Type": "application/json",
    }
    if login_customer_id:
        headers["login-customer-id"] = login_customer_id
    return headers


def _base_url() -> str:
    # Google Ads API base
    return "https://googleads.googleapis.com"


def _api_version() -> str:
    # Adjust to the version you use in the repo
    return os.environ.get("GOOGLE_ADS_API_VERSION", "v17")


def _customer_id() -> str:
    # Must be digits only (no dashes)
    cid = _must_get_env("GOOGLE_ADS_CUSTOMER_ID").replace("-", "").strip()
    if not cid.isdigit():
        raise RuntimeError("GOOGLE_ADS_CUSTOMER_ID must be digits only (dashes are allowed but will be removed).")
    return cid


# ------------------------------------------------------------
# Tools
# ------------------------------------------------------------

@mcp.tool()
async def generate_new_keywords(seed_terms: List[str], language_code: str = "de", geo_target_constant: str = "geoTargetConstants/2276") -> Dict[str, Any]:
    """
    Generates keyword ideas from seed terms using Google Ads KeywordPlanIdeaService.

    IMPORTANT: You said "it must be new ones".
    "New" can mean:
    - not equal to seed terms
    - not duplicates
    - optionally filtered against your existing keyword list (needs another input/list)
    This tool ensures at least: not identical to input + deduped.
    """
    if not seed_terms:
        return {"keywords": [], "note": "No seed_terms provided."}

    creds = await get_credentials()
    headers = _google_ads_headers(creds)

    customer_id = _customer_id()
    version = _api_version()

    # KeywordPlanIdeaService: generateKeywordIdeas
    url = f"{_base_url()}/{version}/customers/{customer_id}:generateKeywordIdeas"

    # language_code -> languageConstants/<id> normally.
    # If you prefer passing the full resource name, adjust.
    # For simplicity you can pass env var GOOGLE_ADS_LANGUAGE_CONSTANT like "languageConstants/1000"
    language_constant = os.environ.get("GOOGLE_ADS_LANGUAGE_CONSTANT", "languageConstants/1000")

    payload = {
        "customerId": customer_id,
        "language": language_constant,
        "geoTargetConstants": [geo_target_constant],
        "keywordSeed": {"keywords": seed_terms},
        # you can add "includeAdultKeywords": False,
        # or "keywordPlanNetwork": "GOOGLE_SEARCH_AND_PARTNERS"
    }

    def _do():
        r = requests.post(url, headers=headers, json=payload, timeout=60)
        r.raise_for_status()
        return r.json()

    data = await asyncio.to_thread(_do)

    # Parse results
    ideas = data.get("results", []) or []
    out = []
    seed_lower = {s.strip().lower() for s in seed_terms if s and s.strip()}

    for item in ideas:
        text = (item.get("text") or "").strip()
        if not text:
            continue
        if text.lower() in seed_lower:
            continue
        out.append(text)

    # dedupe, preserve order
    seen = set()
    deduped = []
    for k in out:
        kl = k.lower()
        if kl in seen:
            continue
        seen.add(kl)
        deduped.append(k)

    return {"keywords": deduped, "count": len(deduped)}


@mcp.tool()
async def get_search_volumes(keywords: List[str], geo_target_constant: str = "geoTargetConstants/2276") -> Dict[str, Any]:
    """
    Gets search volume metrics for keywords using KeywordPlanIdeaService (historical metrics are embedded in results).
    """
    if not keywords:
        return {"items": [], "note": "No keywords provided."}

    creds = await get_credentials()
    headers = _google_ads_headers(creds)

    customer_id = _customer_id()
    version = _api_version()
    url = f"{_base_url()}/{version}/customers/{customer_id}:generateKeywordIdeas"

    language_constant = os.environ.get("GOOGLE_ADS_LANGUAGE_CONSTANT", "languageConstants/1000")

    payload = {
        "customerId": customer_id,
        "language": language_constant,
        "geoTargetConstants": [geo_target_constant],
        "keywordSeed": {"keywords": keywords},
    }

    def _do():
        r = requests.post(url, headers=headers, json=payload, timeout=60)
        r.raise_for_status()
        return r.json()

    data = await asyncio.to_thread(_do)

    results = data.get("results", []) or []
    items = []
    kw_set = {k.strip().lower() for k in keywords if k and k.strip()}

    for r in results:
        text = (r.get("text") or "").strip()
        if not text or text.lower() not in kw_set:
            continue

        metrics = r.get("keywordIdeaMetrics", {}) or {}
        avg_monthly = metrics.get("avgMonthlySearches")
        competition = metrics.get("competition")
        comp_index = metrics.get("competitionIndex")
        low_bid = metrics.get("lowTopOfPageBidMicros")
        high_bid = metrics.get("highTopOfPageBidMicros")

        items.append(
            {
                "keyword": text,
                "avg_monthly_searches": avg_monthly,
                "competition": competition,
                "competition_index": comp_index,
                "low_top_of_page_bid_micros": low_bid,
                "high_top_of_page_bid_micros": high_bid,
            }
        )

    return {"items": items, "count": len(items)}


# ------------------------------------------------------------
# Health endpoints (useful for Railway / uptime checks)
# ------------------------------------------------------------
@mcp.resource("/health")
def health() -> Dict[str, Any]:
    return {"ok": True, "service": "google_ads_mcp", "ts": int(time.time())}


@mcp.resource("/ready")
def ready() -> Dict[str, Any]:
    # Could add a lightweight env sanity check here if you want.
    return {"ready": True, "ts": int(time.time())}


# ------------------------------------------------------------
# Entrypoint: IMPORTANT for Railway + Agent Builder
# ------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8000))
    # Remote MCP over HTTP (what Agent Builder expects)
    mcp.run(transport="streamable-http", host="0.0.0.0", port=port)
