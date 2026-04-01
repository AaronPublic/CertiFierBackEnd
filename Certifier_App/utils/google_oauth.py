"""
Google OAuth utilities for handling Google authentication flow
"""
import os
import json
import requests
from urllib.parse import urlencode, parse_qs, urlparse
from django.conf import settings
from google.auth.transport.requests import Request
from google.oauth2 import id_token
from urllib.parse import quote


GOOGLE_OAUTH_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth'
GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token'
GOOGLE_USERINFO_URL = 'https://www.googleapis.com/oauth2/v1/userinfo'


def _clean_env(value):
    if value is None:
        return ''
    cleaned = str(value).strip()
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


def get_google_auth_url(state, hd='ua.edu.ph'):
    client_id, _, redirect_uri = _get_oauth_config()

    if not client_id:
        raise ValueError("Missing GOOGLE_OAUTH_CLIENT_ID")

    params = {
        'client_id': client_id,
        'redirect_uri': redirect_uri,
        'response_type': 'code',
        'scope': 'openid email profile',
        'state': state,
        'hd': hd,
        'access_type': 'offline',
        'prompt': 'consent',  # ✅ important
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


def get_user_info_from_id_token(id_token_str):
    """
    Decode and verify Google ID token to get user info
    
    Args:
        id_token_str: ID token from Google
    
    Returns:
        Dictionary with user info (email, name, picture, etc.)
    """
    try:
        client_id, _, _ = _get_oauth_config()
        if not client_id:
            raise ValueError('Google OAuth is not configured: GOOGLE_OAUTH_CLIENT_ID is missing.')

        # Verify and decode the ID token
        idinfo = id_token.verify_oauth2_token(
            id_token_str,
            Request(),
            client_id
        )
        
        # Verify hosted domain
        if 'hd' in idinfo:
            if idinfo['hd'] != 'ua.edu.ph':
                raise ValueError(f"Invalid hosted domain: {idinfo['hd']}")
        
        return idinfo
    except Exception as e:
        # Fallback: fetch user info from API if token verification fails
        return get_user_info_from_access_token(id_token_str)


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
    return email.lower().endswith('@ua.edu.ph')
