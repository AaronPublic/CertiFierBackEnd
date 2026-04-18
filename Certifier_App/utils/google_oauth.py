# ...existing code...
"""
Google OAuth utilities for handling Google authentication flow
"""
import base64
import secrets
import os
import json
import requests
from urllib.parse import urlencode, parse_qs, urlparse
from django.conf import settings
from google.auth.transport.requests import Request
from google.oauth2 import id_token
from urllib.parse import quote

GOOGLE_OAUTH_CLIENT_ID = getattr(settings, 'GOOGLE_OAUTH_CLIENT_ID', os.getenv('GOOGLE_OAUTH_CLIENT_ID'))
GOOGLE_OAUTH_CLIENT_SECRET = getattr(settings, 'GOOGLE_OAUTH_CLIENT_SECRET', os.getenv('GOOGLE_OAUTH_CLIENT_SECRET'))
GOOGLE_OAUTH_REDIRECT_URI = getattr(
    settings,
    'GOOGLE_OAUTH_REDIRECT_URI',
    os.getenv('GOOGLE_OAUTH_REDIRECT_URI', 'https://certifierbackend.onrender.com/api/auth/google/callback/')
)

GOOGLE_OAUTH_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth'
GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token'
GOOGLE_USERINFO_URL = 'https://www.googleapis.com/oauth2/v1/userinfo'


def _clean_env(value):
    if value is None:
        return ''
    cleaned = str(value).strip().strip('"').strip("'")
    if cleaned.lower() in {'none', 'null', ''}:
        return ''
    return cleaned


def _first_nonempty(values):
    for value in values:
        cleaned = _clean_env(value)
        if cleaned:
            return cleaned
    return ''


def _normalize_key(key):
    return ''.join(ch for ch in str(key).lower() if ch.isalnum())


def _env_by_aliases(*aliases):
    alias_set = {_normalize_key(alias) for alias in aliases}
    for key, value in os.environ.items():
        if _normalize_key(key) in alias_set:
            cleaned = _clean_env(value)
            if cleaned:
                return cleaned
    return ''


def _get_oauth_config():
    # Prefer Django settings, then process env, then common alternate env names.
    client_id = _first_nonempty([
        getattr(settings, 'GOOGLE_OAUTH_CLIENT_ID', None),
        os.getenv('GOOGLE_OAUTH_CLIENT_ID'),
        os.getenv('GOOGLE_CLIENT_ID'),
        _env_by_aliases('GOOGLE_OAUTH_CLIENT_ID', 'GOOGLE_CLIENT_ID', 'GOOGLECLIENTID'),
    ])
    client_secret = _first_nonempty([
        getattr(settings, 'GOOGLE_OAUTH_CLIENT_SECRET', None),
        os.getenv('GOOGLE_OAUTH_CLIENT_SECRET'),
        os.getenv('GOOGLE_CLIENT_SECRET'),
        _env_by_aliases('GOOGLE_OAUTH_CLIENT_SECRET', 'GOOGLE_CLIENT_SECRET', 'GOOGLECLIENTSECRET'),
    ])
    redirect_uri = _first_nonempty([
        getattr(settings, 'GOOGLE_OAUTH_REDIRECT_URI', None),
        os.getenv('GOOGLE_OAUTH_REDIRECT_URI'),
        os.getenv('GOOGLE_REDIRECT_URI'),
        _env_by_aliases('GOOGLE_OAUTH_REDIRECT_URI', 'GOOGLE_REDIRECT_URI', 'GOOGLEREDIRECTURI'),
        'https://certifierbackend.onrender.com/api/auth/google/callback/',
    ])
    return client_id, client_secret, redirect_uri

def _encode_state(data: dict) -> str:
    raw = json.dumps(data).encode()
    return base64.urlsafe_b64encode(raw).decode()


def _decode_state(state: str) -> dict:
    try:
        raw = base64.urlsafe_b64decode(state.encode())
        return json.loads(raw)
    except Exception:
        return {}

def get_google_auth_url(return_to, hd='ua.edu.ph'):
    client_id, _, redirect_uri = _get_oauth_config()

    if not client_id:
        raise ValueError("Missing GOOGLE_OAUTH_CLIENT_ID")

    # ✅ STATE now contains return_to (no session needed)
    state_payload = {
        "nonce": secrets.token_urlsafe(16),
        "return_to": return_to,
    }

    state = _encode_state(state_payload)

    params = {
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': 'openid email profile',
        'state': state,
        'hd': hd,
        'access_type': 'offline',
        'prompt': 'consent',
    }

    return f"{GOOGLE_OAUTH_AUTH_URL}?{urlencode(params)}"


def exchange_code_for_token(code):
    """
    Exchange authorization code for access token
    
    Args:
        code: Authorization code from Google
    
    Returns:
        Dictionary with access_token, id_token, etc.
    """
    client_id, client_secret, redirect_uri = _get_oauth_config()
    if not client_id:
        raise ValueError('Google OAuth is not configured: GOOGLE_OAUTH_CLIENT_ID is missing.')
    if not client_secret:
        raise ValueError('Google OAuth is not configured: GOOGLE_OAUTH_CLIENT_SECRET is missing.')
    if not redirect_uri:
        raise ValueError('Google OAuth is not configured: GOOGLE_OAUTH_REDIRECT_URI is missing.')

    payload = {
        'client_id': client_id,
        'client_secret': client_secret,
        'code': code,
        'grant_type': 'authorization_code',
        'redirect_uri': redirect_uri,
    }
    
    response = requests.post(GOOGLE_TOKEN_URL, data=payload)
    response.raise_for_status()
    return response.json()


def _normalize_userinfo(raw):
    if not isinstance(raw, dict):
        return {}
    return {
        "email": raw.get("email"),
        "email_verified": bool(raw.get("email_verified", False)),
        "name": raw.get("name") or raw.get("email"),
        "picture": raw.get("picture"),
        "sub": raw.get("sub") or raw.get("id"),
        "hd": raw.get("hd"),
    }


def get_user_info_from_id_token(id_token_str):
    """
    Decode and verify Google ID token to get user info.
    Falls back to userinfo endpoint if verification fails.

    Returns normalized dict with keys: email, email_verified, name, picture, sub, hd
    """
    client_id, _, _ = _get_oauth_config()
    if not client_id:
        raise ValueError('Google OAuth is not configured: GOOGLE_OAUTH_CLIENT_ID is missing.')

    try:
        # Verify and decode the ID token
        idinfo = id_token.verify_oauth2_token(id_token_str, Request(), client_id)

        # Verify hosted domain if present
        hd = idinfo.get('hd')
        if hd and hd != 'ua.edu.ph':
            raise ValueError(f"Invalid hosted domain: {hd}")

        return _normalize_userinfo(idinfo)
    except Exception:
        # If token verification fails, try to treat the provided token as an access token
        try:
            raw = get_user_info_from_access_token(id_token_str)
            return _normalize_userinfo(raw)
        except Exception:
            # Re-raise original verification exception if fallback also fails
            raise


def get_user_info_from_access_token(access_token):
    """
    Fetch user info using access token (fallback method)
    
    Args:
        access_token: Google access token
    
    Returns:
        Dictionary with user info
    """
    headers = {'Authorization': f'Bearer {access_token}'}
    response = requests.get(GOOGLE_USERINFO_URL, headers=headers)
    response.raise_for_status()
    return response.json()


def validate_school_email(email):
    """
    Validate that email belongs to school domain
    
    Args:
        email: Email address to validate
    
    Returns:
        True if valid school email, False otherwise
    """
    if not email:
        return False
    return email.lower().endswith('@ua.edu.ph')

__all__ = [
    'get_google_auth_url',
    'exchange_code_for_token',
    'get_user_info_from_id_token',
    'get_user_info_from_access_token',
    'validate_school_email',
    '_decode_state',  
    '_encode_state',  
]