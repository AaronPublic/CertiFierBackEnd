"""
Google OAuth utilities for handling Google authentication flow
"""
import os
import json
import requests
from urllib.parse import urlencode, parse_qs, urlparse
from google.auth.transport.requests import Request
from google.oauth2 import id_token


GOOGLE_OAUTH_CLIENT_ID = os.getenv('GOOGLE_OAUTH_CLIENT_ID')
GOOGLE_OAUTH_CLIENT_SECRET = os.getenv('GOOGLE_OAUTH_CLIENT_SECRET')
GOOGLE_OAUTH_REDIRECT_URI = os.getenv(
    'GOOGLE_OAUTH_REDIRECT_URI',
    'http://127.0.0.1:8000/api/auth/google/callback/'
)

GOOGLE_OAUTH_AUTH_URL = 'https://accounts.google.com/o/oauth2/v2/auth'
GOOGLE_TOKEN_URL = 'https://oauth2.googleapis.com/token'
GOOGLE_USERINFO_URL = 'https://www.googleapis.com/oauth2/v1/userinfo'


def get_google_auth_url(state, return_to=None, hd='ua.edu.ph'):
    """
    Generate Google OAuth authorization URL
    
    Args:
        state: CSRF token for security
        return_to: Redirect URI after auth (stored in state or session)
        hd: Hosted domain restriction (e.g., ua.edu.ph for school accounts)
    
    Returns:
        Authorization URL string
    """
    params = {
        'client_id': GOOGLE_OAUTH_CLIENT_ID,
        'redirect_uri': GOOGLE_OAUTH_REDIRECT_URI,
        'response_type': 'code',
        'scope': 'openid email profile',
        'state': state,
        'hd': hd,  # Restrict to school domain
        'access_type': 'offline',
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
    payload = {
        'client_id': GOOGLE_OAUTH_CLIENT_ID,
        'client_secret': GOOGLE_OAUTH_CLIENT_SECRET,
        'code': code,
        'grant_type': 'authorization_code',
        'redirect_uri': GOOGLE_OAUTH_REDIRECT_URI,
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
        # Verify and decode the ID token
        idinfo = id_token.verify_oauth2_token(
            id_token_str,
            Request(),
            GOOGLE_OAUTH_CLIENT_ID
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
