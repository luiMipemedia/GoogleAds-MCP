import os
import json
import asyncio
import base64
from typing import Any, Dict, List

import requests
from google.oauth2.credentials import Credentials
from fastmcp import FastMCP

mcp = FastMCP("google_ads_mcp")


def _must_get_env(name: str) -> str:
    v = os.environ.get(name)
    if not v:
        raise RuntimeError(f"Missing required env var: {name}")
    return v


def _parse_scopes() -> List[str]:
    raw = os.environ.get("GOOGLE_SCOPES", "").strip()
    if not raw:
        return ["https://www.googleapis.com/auth/adwords"]
    if raw.startswith("["):
        return json.loads(raw)
    return [s.strip() for s in raw.split(",") if s.strip()]


def _decode_b64_json_env(name: str) -> Dict[str, Any]:
    raw = _must_get_env(name).strip()
    try:
        return json.loads(raw)
    except Exception:
        pass

    decoded = base64.b64decode(raw).decode("utf-8")
    return json.loads(decoded)


async def _refresh_access_token() -> str:
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
    return "https://googleads.googleapis.com"


def _api_version() -> str:
    return os.environ.get("GOOGLE_ADS_API_VERSION", "v17")


def _customer_id() -> str:
    cid = _must_get_env("GOOGLE_ADS_CUSTOMER_ID").replace("-", "").strip()
    if not cid.isdigit():
        raise RuntimeError("GOOGLE_ADS_CUSTOMER_ID must be digits only (dashes allowed).")
    return cid


def _language_constant() -> str:
    return os.environ.get("GOOGLE_ADS_LANGUAGE_CONSTANT", "languageConstants/1000")


@mcp.tool()
async def generate_new_keywords(
    seed_terms: List[str],
    geo_target_constant: str = "geoTargetConstants/2276",
) -> Dict[str, Any]:
    if not seed_terms:
        return {"keywords": [], "count": 0, "note": "No seed_terms provided."}

    creds = await get_credentials()
    headers = _google_ads_headers(creds)

    customer_id = _customer_id()
    version = _api_version()
    url = f"{_base_url()}/{version}/customers/{customer_id}:generateKeywordIdeas"

    payload = {
        "customerId": customer_id,
        "language": _language_constant(),
        "geoTargetConstants": [geo_target_constant],
        "keywordSeed": {"keywords": seed_terms},
    }

    def _do():
        r = requests.post(url, headers=headers, json=payload, timeout=60)
        r.raise_for_status()
        return r.json()

    data = await asyncio.to_thread(_do)

    ideas = data.get("results", []) or []
    seed_lower = {s.strip().lower() for s in seed_terms if s and s.strip()}

    out: List[str] = []
    for item in ideas:
        text = (item.get("text") or "").strip()
        if not text:
            continue
        if text.lower() in seed_lower:
            continue
        out.append(text)

    # dedupe (case-insensitive), preserve order
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
async def get_search_volumes(
    keywords: List[str],
    geo_target_constant: str = "geoTargetConstants/2276",
) -> Dict[str, Any]:
    if not keywords:
        return {"items": [], "count": 0, "note": "No keywords provided."}

    creds = await get_credentials()
    headers = _google_ads_headers(creds)

    customer_id = _customer_id()
    version = _api_version()
    url = f"{_base_url()}/{version}/customers/{customer_id}:generateKeywordIdeas"

    payload = {
        "customerId": customer_id,
        "language": _language_constant(),
        "geoTargetConstants": [geo_target_constant],
        "keywordSeed": {"keywords": keywords},
    }

    def _do():
        r = requests.post(url, headers=headers, json=payload, timeout=60)
        r.raise_for_status()
        return r.json()

    data = await asyncio.to_thread(_do)

    results = data.get("results", []) or []
    kw_set = {k.strip().lower() for k in keywords if k and k.strip()}

    items = []
    for r in results:
        text = (r.get("text") or "").strip()
        if not text or text.lower() not in kw_set:
            continue
        metrics = r.get("keywordIdeaMetrics", {}) or {}
        items.append(
            {
                "keyword": text,
                "avg_monthly_searches": metrics.get("avgMonthlySearches"),
                "competition": metrics.get("competition"),
                "competition_index": metrics.get("competitionIndex"),
                "low_top_of_page_bid_micros": metrics.get("lowTopOfPageBidMicros"),
                "high_top_of_page_bid_micros": metrics.get("highTopOfPageBidMicros"),
            }
        )

    return {"items": items, "count": len(items)}


if __name__ == "__main__":
    port = int(os.environ.get("PORT", "8080"))
    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",
        port=port,
        path="/mcp",
    )
