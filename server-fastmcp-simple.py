#!/usr/bin/env python3
"""
Google Ads MCP Server - FastMCP Implementation with Authentication
Uses FastMCP's built-in authentication system
"""

import os
import json
import base64
import logging
import secrets
import time
import warnings  # Add this import
from datetime import datetime, timezone, timedelta
from dateutil import parser
from typing import Dict, Optional, Any

# Suppress deprecation warnings from websockets library
warnings.filterwarnings("ignore", category=DeprecationWarning, module="websockets")
warnings.filterwarnings("ignore", category=DeprecationWarning, module="uvicorn")

from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request as AuthRequest
import requests

from fastmcp import FastMCP, Context, Prompt, Resource, File
from fastmcp.exceptions import ToolError

from fastmcp.auth import OAuthProvider
from fastmcp.auth.models import (
    OAuthClientInformationFull,
    OAuthToken,
    AuthorizationCode,
    AccessToken,
    RefreshToken,
    ClientRegistrationOptions,
    RevocationOptions,
)

from pydantic import BaseModel, Field

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('google_ads_server')

# Constants
SCOPES = ['https://www.googleapis.com/auth/adwords']
API_VERSION = "v20"  # Updated to v20

class SimpleOAuthProvider(OAuthProvider):
    """
    Secure OAuth provider for Google Ads MCP Server.
    Only allows pre-configured clients with correct credentials.
    """
    
    def __init__(
        self,
        base_url: str,
        allowed_clients: Dict[str, str] | None = None,
        **kwargs
    ):
        """Initialize the OAuth provider with strict authentication."""
        super().__init__(
            base_url=base_url,
            issuer_url=base_url,
            service_documentation_url=f"{base_url}/docs",
            client_registration_options=ClientRegistrationOptions(
                enabled=False,  # DISABLE dynamic registration - only pre-configured clients
                initial_access_token=None,
                scopes_supported=["read", "write", "admin"],
            ),
            revocation_options=RevocationOptions(enabled=True),
            required_scopes=["read"],
            resource_server_url=base_url,
            **kwargs
        )
        
        # In-memory storage
        self.clients: Dict[str, OAuthClientInformationFull] = {}
        self.auth_codes: Dict[str, AuthorizationCode] = {}
        self.access_tokens: Dict[str, AccessToken] = {}
        self.refresh_tokens: Dict[str, RefreshToken] = {}
        
        # Allowed clients (client_id -> client_secret) configured via environment
        self.allowed_clients: Dict[str, str] = allowed_clients or {}
        
        if not self.allowed_clients:
            logger.error("=" * 60)
            logger.error("SECURITY WARNING: No OAuth clients configured!")
            logger.error("Set OAUTH_CLIENTS environment variable with format:")
            logger.error("OAUTH_CLIENTS=clientid1:secret1,clientid2:secret2")
            logger.error("=" * 60)
            raise ValueError("No OAuth clients configured")
    
    @staticmethod
    def _generate_token(length: int = 32) -> str:
        """Generate a secure random token."""
        return secrets.token_urlsafe(length)
    
    def _validate_client_credentials(self, client_id: str, client_secret: str) -> bool:
        """Validate that the client_id and client_secret are correct."""
        if client_id not in self.allowed_clients:
            logger.error(f"SECURITY: Invalid client_id attempted: {client_id}")
            return False
        
        if self.allowed_clients[client_id] != client_secret:
            logger.error(f"SECURITY: Invalid client_secret for client_id: {client_id}")
            return False
        
        return True
    
    # -------------------------------
    # Client Registration Management
    # -------------------------------
    
    async def register_client(
        self,
        client: OAuthClientInformationFull,
        context: Optional[Context] = None
    ) -> OAuthClientInformationFull:
        """
        Register a new client.
        
        In this secure implementation, we ONLY allow registration
        for pre-approved clients configured via environment variables.
        """
        logger.info(f"Client registration attempted: {client.client_id}")
        
        # Check if client ID is in allowed list
        if client.client_id not in self.allowed_clients:
            logger.error(f"SECURITY: Unauthorized client registration attempt: {client.client_id}")
            raise ValueError("Client not authorized. Only pre-configured clients are allowed.")
        
        # Ensure secret matches
        if client.client_secret != self.allowed_clients[client.client_id]:
            logger.error(f"SECURITY: Invalid client secret for registration: {client.client_id}")
            raise ValueError("Invalid client credentials")
        
        # Store the client
        self.clients[client.client_id] = client
        
        logger.info(f"Client registered successfully: {client.client_id}")
        return client
    
    async def get_client(
        self, client_id: str, context: Optional[Context] = None
    ) -> Optional[OAuthClientInformationFull]:
        """
        Retrieve a registered client.
        
        Only returns clients that are in the pre-configured allowed list.
        """
        client = self.clients.get(client_id)
        if not client:
            logger.error(f"SECURITY: Unknown client_id requested: {client_id}")
            return None
        
        # Double-check that client is still allowed
        if client_id not in self.allowed_clients:
            logger.error(f"SECURITY: Client no longer authorized: {client_id}")
            return None
        
        return client
    
    # -------------------------------
    # Authorization Code Flow
    # -------------------------------
    
    async def create_authorization_code(
        self,
        client: OAuthClientInformationFull,
        subject: str,
        scopes: list[str],
        redirect_uri: str,
        context: Optional[Context] = None,
    ) -> AuthorizationCode:
        """
        Create an authorization code for the client.
        
        Only for trusted, pre-configured clients.
        """
        # Verify client is allowed
        if client.client_id not in self.allowed_clients:
            logger.error(f"SECURITY: Unauthorized client in auth code request: {client.client_id}")
            raise ValueError("Unauthorized client")
        
        # Verify client secret matches
        if client.client_secret != self.allowed_clients[client.client_id]:
            logger.error(f"SECURITY: Invalid client secret in auth code request: {client.client_id}")
            raise ValueError("Invalid client credentials")
        
        # Create code
        code = self._generate_token(32)
        now = datetime.now(timezone.utc)
        
        auth_code = AuthorizationCode(
            code=code,
            client_id=client.client_id,
            subject=subject,
            scopes=scopes,
            redirect_uri=redirect_uri,
            expires_at=now + timedelta(minutes=10),
            created_at=now,
        )
        
        # Store the code
        self.auth_codes[code] = auth_code
        
        logger.info(f"Issued authorization code for client: {client.client_id}")
        return auth_code
    
    async def exchange_authorization_code(
        self,
        code: str,
        client: OAuthClientInformationFull,
        context: Optional[Context] = None,
    ) -> OAuthToken:
        """
        Exchange authorization code for access and refresh tokens.
        """
        # Validate code
        if code not in self.auth_codes:
            logger.error("SECURITY: Invalid or expired authorization code")
            raise ValueError("Invalid authorization code")
        
        auth_code = self.auth_codes[code]
        
        # Verify client matches
        if auth_code.client_id != client.client_id:
            logger.error(f"SECURITY: Client mismatch for auth code: {client.client_id}")
            raise ValueError("Client mismatch")
        
        # Verify client is still authorized
        if client.client_id not in self.allowed_clients:
            logger.error(f"SECURITY: Unauthorized client in token exchange: {client.client_id}")
            raise ValueError("Unauthorized client")
        
        # Delete used code
        del self.auth_codes[code]
        
        # Create tokens
        access_token_str = self._generate_token(32)
        refresh_token_str = self._generate_token(48)
        now = datetime.now(timezone.utc)
        
        access_token = AccessToken(
            token=access_token_str,
            client_id=client.client_id,
            subject=auth_code.subject,
            scopes=auth_code.scopes,
            created_at=now,
            expires_at=now + timedelta(hours=1),
        )
        
        refresh_token = RefreshToken(
            token=refresh_token_str,
            client_id=client.client_id,
            subject=auth_code.subject,
            scopes=auth_code.scopes,
            created_at=now,
            expires_at=now + timedelta(days=30),
        )
        
        # Store tokens
        self.access_tokens[access_token_str] = access_token
        self.refresh_tokens[refresh_token_str] = refresh_token
        
        logger.info(f"Issued tokens for client: {client.client_id}")
        
        return OAuthToken(
            access_token=access_token_str,
            refresh_token=refresh_token_str,
            token_type="Bearer",
            expires_in=3600,
            scope=" ".join(auth_code.scopes),
        )
    
    # -------------------------------
    # Token Refresh
    # -------------------------------
    
    async def refresh_access_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str]
    ) -> OAuthToken:
        """Exchange refresh token for new access token."""
        # Verify client is still authorized
        if client.client_id not in self.allowed_clients:
            logger.error(f"SECURITY: Unauthorized refresh token exchange: {client.client_id}")
            raise ValueError("Unauthorized client")
        
        # Verify client secret matches
        if client.client_secret != self.allowed_clients[client.client_id]:
            logger.error(f"SECURITY: Invalid client secret on refresh: {client.client_id}")
            raise ValueError("Invalid client credentials")
        
        # Validate requested scopes are subset of original scopes
        original_scopes = set(refresh_token.scopes)
        requested_scopes = set(scopes)
        if not requested_scopes.issubset(original_scopes):
            logger.error(f"SECURITY: Invalid scopes requested in refresh: {client.client_id}")
            raise ValueError("Invalid scope requested")
        
        # Create new access token
        new_access_token_str = self._generate_token(32)
        now = datetime.now(timezone.utc)
        
        new_access_token = AccessToken(
            token=new_access_token_str,
            client_id=client.client_id,
            subject=refresh_token.subject,
            scopes=list(requested_scopes),
            created_at=now,
            expires_at=now + timedelta(hours=1),
        )
        
        # Store token
        self.access_tokens[new_access_token_str] = new_access_token
        
        logger.info(f"Refreshed access token for client: {client.client_id}")
        
        return OAuthToken(
            access_token=new_access_token_str,
            refresh_token=refresh_token.token,
            token_type="Bearer",
            expires_in=3600,
            scope=" ".join(requested_scopes),
        )
    
    # -------------------------------
    # Token Revocation
    # -------------------------------
    
    async def revoke_token(self, token: str, client: OAuthClientInformationFull) -> None:
        """
        Revoke an access or refresh token.
        """
        # Revoke access token
        if token in self.access_tokens:
            del self.access_tokens[token]
            logger.info(f"Revoked access token for client: {client.client_id}")
            return
        
        # Revoke refresh token
        if token in self.refresh_tokens:
            del self.refresh_tokens[token]
            logger.info(f"Revoked refresh token for client: {client.client_id}")
            return
        
        logger.warning(f"Token revocation attempted for unknown token: {token}")
    
    # -------------------------------
    # Token Introspection
    # -------------------------------
    
    async def introspect_token(
        self,
        token: str,
        client: OAuthClientInformationFull,
        context: Optional[Context] = None,
    ) -> dict[str, Any]:
        """
        Introspect a token and return its metadata.
        """
        # Check access token
        if token in self.access_tokens:
            access_token = self.access_tokens[token]
            now = datetime.now(timezone.utc)
            is_active = access_token.expires_at > now
            
            return {
                "active": is_active,
                "client_id": access_token.client_id,
                "username": access_token.subject,
                "scope": " ".join(access_token.scopes),
                "exp": int(access_token.expires_at.timestamp()),
                "iat": int(access_token.created_at.timestamp()),
                "token_type": "access_token",
            }
        
        # Check refresh token
        if token in self.refresh_tokens:
            refresh_token = self.refresh_tokens[token]
            now = datetime.now(timezone.utc)
            is_active = refresh_token.expires_at > now
            
            return {
                "active": is_active,
                "client_id": refresh_token.client_id,
                "username": refresh_token.subject,
                "scope": " ".join(refresh_token.scopes),
                "exp": int(refresh_token.expires_at.timestamp()),
                "iat": int(refresh_token.created_at.timestamp()),
                "token_type": "refresh_token",
            }
        
        # Token not found
        return {"active": False}

# -------------------------------------------------------------------
# Google Ads OAuth Credentials (for API access, not MCP auth)
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

public_domain = os.environ.get("RAILWAY_PUBLIC_DOMAIN")
if public_domain:
    base_url = f"https://{public_domain}"
else:
    base_url = "http://localhost:8080"

# Create FastMCP server WITHOUT external MCP auth
mcp = FastMCP(
    name="Google Ads MCP",
)

logger.info("=" * 60)
logger.info("Google Ads MCP Server Started (no external MCP auth)")
logger.info(f"📍 URL: {base_url}")
logger.info("🔐 MCP access: no extra auth (use only in trusted environments)")
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



# Internal function for shared GAQL query logic
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

# -------------------------------------------------------------------
# Hier folgen alle deine bestehenden Tools (@mcp.tool, @mcp.resource, @mcp.prompt)
# aus der Original-Datei – die habe ich inhaltlich nicht verändert.
# Ich lasse sie hier aus Platzgründen weg, du behältst sie 1:1 wie vorher.
# -------------------------------------------------------------------
# Beispiel-Ausschnitt (deine Datei enthält hier viel mehr):

@mcp.tool()
def list_accounts() -> str:
    """
    List all accessible customer accounts for the authenticated Google Ads login customer.
    
    Returns a formatted list of:
    - Customer ID
    - Descriptive Name
    - Currency
    - Timezone
    """
    try:
        creds = get_credentials()
        headers = get_headers(creds)
        
        login_customer_id = os.environ.get("GOOGLE_ADS_LOGIN_CUSTOMER_ID")
        if not login_customer_id:
            raise ValueError("GOOGLE_ADS_LOGIN_CUSTOMER_ID environment variable not set")
        
        formatted_login_id = format_customer_id(login_customer_id)
        url = f"https://googleads.googleapis.com/{API_VERSION}/customers:listAccessibleCustomers"
        
        response = requests.get(url, headers=headers)
        if response.status_code != 200:
            raise ToolError(f"Error listing accessible customers: {response.text}")
        
        customer_resource_names = response.json().get("resourceNames", [])
        
        if not customer_resource_names:
            return "No accessible customer accounts found."
        
        results = ["Accessible Google Ads Accounts:\n"]
        
        for resource_name in customer_resource_names:
            customer_id = resource_name.split("/")[-1]
            customer_url = f"https://googleads.googleapis.com/{API_VERSION}/{resource_name}"
            
            customer_response = requests.get(customer_url, headers=headers)
            if customer_response.status_code != 200:
                continue
            
            customer_data = customer_response.json()
            descriptive_name = customer_data.get("descriptiveName", "N/A")
            currency_code = customer_data.get("currencyCode", "N/A")
            time_zone = customer_data.get("timeZone", "N/A")
            
            results.append(f"Customer ID: {customer_id}")
            results.append(f"Name: {descriptive_name}")
            results.append(f"Currency: {currency_code}")
            results.append(f"Timezone: {time_zone}")
            results.append("-" * 40)
        
        return "\n".join(results)
    
    except Exception as e:
        raise ToolError(f"Error listing accounts: {str(e)}")


# ... HIER: alle weiteren @mcp.tool / @mcp.resource / @mcp.prompt Definitionen
# aus deiner ursprünglichen Datei – lass sie einfach unverändert drin.


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))

    logger.info("=" * 60)
    logger.info("🚀 Starting Google Ads MCP Server")
    logger.info(f"📍 Port: {port}")
    logger.info(f"🌐 Base URL: {base_url}")
    logger.info("=" * 60)

    # Run FastMCP server with streamable-http transport
    mcp.run(
        transport="streamable-http",
        host="0.0.0.0",
        port=port
    )
