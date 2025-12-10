#!/usr/bin/env python3
"""
Google Ads MCP Server - FastMCP Implementation
Simplified for use with OpenAI Agent Builder (no OAuth server auth)
"""

import os
import json
import base64
import logging
import time
import warnings
from datetime import datetime, timezone, timedelta
from dateutil import parser
from typing import Any

# Suppress deprecation warnings from websockets library
warnings.filterwarnings("ignore", category=DeprecationWarning, module="websockets")
warnings.filterwarnings("ignore", category=DeprecationWarning, module="uvicorn")

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as AuthRequest
import requests

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from pydantic import Field

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('google_ads_server')

# Constants
SCOPES = ['https://www.googleapis.com/auth/adwords']
API_VERSION = "v20"  # Updated to v20

# -------------------------------------------------------------------
# Google Ads OAuth Credentials (für API-Zugriff, nicht für MCP-Auth)
# -------------------------------------------------------------------

def initialize_credentials():
    """Initialize OAuth credentials from base64 encoded token file"""
    oauth_tokens_base64 = os.environ.get("GOOGLE_ADS_OAUTH_TOKENS_BASE64")
    if not oauth_tokens_base64:
        raise ValueError("GOOGLE_ADS_OAUTH_TOKENS_BASE64 environment variable not set")
    
    try:
        oauth_tokens_json = base64.b64decode(oauth_tokens_base64).decode('utf-8')
        oauth_tokens = json.loads(oauth_tokens_json)
        
        credentials = Credentials(
            token=oauth_tokens.get('token'),
            refresh_token=oauth_tokens.get('refresh_token'),
            token_uri=oauth_tokens.get('token_uri', 'https://oauth2.googleapis.com/token'),
            client_id=oauth_tokens.get('client_id'),
            client_secret=oauth_tokens.get('client_secret'),
            scopes=oauth_tokens.get('scopes', SCOPES)
        )
        
        if 'expiry' in oauth_tokens:
            expiry_str = oauth_tokens['expiry']
            credentials.expiry = parser.parse(expiry_str)
            
            if credentials.expiry and credentials.expiry < datetime.now(timezone.utc):
                logger.info("Token expired, refreshing...")
                auth_req = AuthRequest()
                credentials.refresh(auth_req)
                logger.info("Token refreshed successfully")
        
        return credentials
        
    except Exception as e:
        logger.error(f"Error initializing OAuth credentials: {str(e)}")
        raise

# Initialize credentials
try:
    _credentials = initialize_credentials()
    logger.info("Google Ads credentials initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize Google Ads credentials: {str(e)}")
    _credentials = None

def get_credentials():
    """Get the initialized credentials"""
    if not _credentials:
        raise ValueError("Google Ads credentials not initialized")
    return _credentials

def format_customer_id(customer_id: str) -> str:
    """Format customer ID to ensure it's 10 digits without dashes."""
    customer_id = str(customer_id)
    customer_id = customer_id.replace('\"', '').replace('"', '')
    customer_id = ''.join(char for char in customer_id if char.isdigit())
    return customer_id.zfill(10)

def get_headers(creds):
    """Get headers for Google Ads API requests."""
    developer_token = os.environ.get("GOOGLE_ADS_DEVELOPER_TOKEN")
    if not developer_token:
        raise ValueError("GOOGLE_ADS_DEVELOPER_TOKEN environment variable not set")
    
    login_customer_id = os.environ.get("GOOGLE_ADS_LOGIN_CUSTOMER_ID", "")
    
    auth_req = AuthRequest()
    creds.refresh(auth_req)
    
    headers = {
        'Authorization': f'Bearer {creds.token}',
        'developer-token': developer_token,
        'content-type': 'application/json'
    }
    
    if login_customer_id:
        headers['login-customer-id'] = format_customer_id(login_customer_id)
    
    return headers

# Get server URL from environment (nur für Logging / Health-Info)
public_domain = os.environ.get("RAILWAY_PUBLIC_DOMAIN")
if public_domain:
    base_url = f"https://{public_domain}"
else:
    base_url = "http://localhost:8080"

# -------------------------------------------------
# MCP-Server ohne externe Auth (für Agent Builder)
# -------------------------------------------------

mcp = FastMCP(
    name="Google Ads MCP",
    # keine auth-Provider mehr – der Agent Builder kann direkt verbinden
)

logger.info("=" * 60)
logger.info("Google Ads MCP Server Started (no external MCP auth)")
logger.info(f"📍 Base URL (for info): {base_url}")
logger.info("🔐 Google Ads API auth is still required via GOOGLE_ADS_* env vars")
logger.info("=" * 60)

# ===========================
# Health Check Resources
# ===========================

@mcp.resource("health://status")
def mcp_health_status() -> str:
    """MCP health check endpoint for monitoring"""
    status = {
        "status": "healthy",
        "auth_enabled": False,
        "auth_method": "none",
        "google_ads_connected": _credentials is not None,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": "3.0.0"
    }
    return json.dumps(status, indent=2)

# -------------------------------------------------
# Ab hier: deine bestehenden Tools 1:1 übernommen
# (GAQL-Helper, get_search_keywords, get_search_terms, usw.)
# -------------------------------------------------

def _execute_gaql_query_internal(customer_id: str, query: str) -> str:
    """Internal function to execute a custom GAQL query"""
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
        if not results.get('results'):
            return "No results found for the query."
        
        # Format results
        result_lines = [f"Query Results for Account {formatted_customer_id}:"]
        result_lines.append("-" * 80)
        
        for i, result in enumerate(results['results'][:50], 1):
            result_lines.append(f"\nResult {i}:")
            result_lines.append(json.dumps(result, indent=2))
        
        return "\n".join(result_lines)
    
    except Exception as e:
        return f"Error executing GAQL query: {str(e)}"

# ---- ab hier alle @mcp.tool(), @mcp.resource(), @mcp.prompt()
#      aus deiner bisherigen Datei UNVERÄNDERT übernehmen ----
# (list_accounts, execute_gaql_query, get_campaign_performance,
#  get_search_keywords, get_search_terms, etc.)
# ------------------------------------------------------------
# Ich kürze hier nur im Chat – in deiner Datei lässt du alles
# wie vorher, nur der Kopf & das __main__ ändern sich.
# ------------------------------------------------------------

# ... (ALLE Tools / Prompts aus deiner aktuellen Datei) ...

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    
    logger.info("=" * 60)
    logger.info("🚀 Starting Google Ads MCP Server (no external MCP auth)")
    logger.info(f"📍 Port: {port}")
    logger.info(f"🌐 Base URL: {base_url}")
    logger.info("=" * 60)
    
    # Run FastMCP server with streamable-http transport
    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",
        port=port
    )
